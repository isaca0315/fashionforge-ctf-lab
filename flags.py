"""
flags.py -- Entrega la flag de cada reto CTF en la propia respuesta cuando
el reto se consigue.

Mecánica: se registra un hook `after_request` en las apps de Flask
(app.py y oauth_server.py). Tras cada request/respuesta se evalúan las
condiciones de los 26 retos:

  * Si la respuesta es JSON -> se inyecta un campo ``flag`` (única) y
    ``flags`` (todas las conseguidas en esa respuesta).
  * Si no es JSON (archivos, SSE, redirects, HTML) -> se añade la cabecera
    ``X-Flag`` (y ``X-Flags`` si hay varias).

El estado secuencial (replay, logout, rate-limit, admin conseguido) se
persiste en ``instance/flag_state.json`` para que sea visible desde los 4
workers de gunicorn (igual que el resto de contadores del lab, es
best-effort; nunca debe romper el lab).
"""

import base64
import json
import os
import re
import threading
import time

import jwt as pyjwt
from flask import request

# ---------------------------------------------------------------------------
# Estado compartido entre workers (persistido en instance/flag_state.json)
# ---------------------------------------------------------------------------
_lock = threading.Lock()

_STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           'instance', 'flag_state.json')


def _state():
    try:
        with _lock:
            with open(_STATE_FILE, 'r') as f:
                return json.load(f)
    except Exception:
        return {}


def _save_state(st):
    try:
        with _lock:
            with open(_STATE_FILE, 'w') as f:
                json.dump(st, f)
    except Exception:
        pass


def _state_get(key, default):
    try:
        v = _state().get(key)
        return v if v is not None else default
    except Exception:
        return default


# Inicializar el fichero de estado (best-effort)
try:
    os.makedirs(os.path.dirname(_STATE_FILE), exist_ok=True)
    if not os.path.exists(_STATE_FILE):
        _save_state({})
except Exception:
    pass

# Rutas que no cuentan como "endpoint protegido" para retos de secuencia
_NON_PROTECTED = {
    '/api/auth/login', '/api/auth/basic-login', '/api/auth/register',
    '/api/auth/refresh-token', '/api/auth/oauth-id-token-login',
    '/api/auth/logout', '/graphql/query',
}

SQLI_RE = re.compile(r"OR\s|UNION|--|['\"]\s*=\s*['\"]", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _body():
    """JSON del body (ya leído por la vista) como dict."""
    try:
        raw = request.get_data()
        if not raw:
            return {}
        return json.loads(raw.decode('utf-8', 'replace'))
    except Exception:
        return {}


def _form():
    return request.form.to_dict() if request.form else {}


def _bearer():
    h = request.headers.get('Authorization', '')
    if h.startswith('Bearer '):
        return h[7:].strip() or None
    return None


def _basic_creds():
    h = request.headers.get('Authorization', '')
    if h.startswith('Basic '):
        try:
            return base64.b64decode(h[6:]).decode('utf-8', 'replace')
        except Exception:
            return None
    return None


def _jwt_claims(token):
    try:
        return pyjwt.decode(token, options={'verify_signature': False})
    except Exception:
        return None


def _signed_with(token, secret):
    try:
        pyjwt.decode(token, secret, algorithms=['HS256', 'HS384', 'HS512'],
                     options={'verify_aud': False})
        return True
    except Exception:
        return False


def _oauth_fallback_secret():
    try:
        from flask import current_app
        from config import Config
        fallback = current_app.config.get('OAUTH_SERVER_JWT_SECRET')
        if not fallback:
            fallback = os.environ.get('OAUTH_SERVER_JWT_SECRET')
        return fallback or 'oauth-server-jwt-secret-key-strong-2024'
    except Exception:
        return 'oauth-server-jwt-secret-key-strong-2024'


def _files_named_traversal():
    """True si algún file subido en multipart tiene '..' en el nombre."""
    try:
        for f in request.files.values():
            if f and f.filename and '..' in f.filename:
                return True
    except Exception:
        pass
    return False


def _truthy(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ('1', 'true', 'yes', 'on')
    return bool(value)


def _admin_gained():
    return set(_state_get('admin_gained', []))


def _mark_admin(username):
    if not username:
        return
    try:
        st = _state()
        cur = st.get('admin_gained') or []
        if username not in cur:
            cur.append(username)
            st['admin_gained'] = cur
            _save_state(st)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Detección por reto
# ---------------------------------------------------------------------------

def _detect(path, method, args, body, form, resp_json, status, resp, flags):
    bearer = _bearer()
    claims = _jwt_claims(bearer) if bearer else None
    is_json = isinstance(resp_json, dict)
    if not is_json:
        # Normalizar a dict vacío para que los .get() nunca fallen
        resp_json = {}

    def has(*keys):
        return is_json and all(k in resp_json for k in keys)

    def msg(*subs):
        if not is_json or 'message' not in resp_json:
            return False
        m = str(resp_json['message']).lower()
        return any(s.lower() in m for s in subs)

    # ---------------- R02: credenciales por defecto (admin/admin123) --------
    if resp_json and resp_json.get('access_token'):
        if path == '/api/auth/login':
            b = body or form
            if b.get('username') == 'admin' and b.get('password') == 'admin123':
                flags.append('FH{default-creds-admin}')
        elif path == '/api/auth/basic-login':
            creds = _basic_creds()
            if creds == 'admin:admin123':
                flags.append('FH{default-creds-admin}')

    # ---------------- R03: cookie sin HttpOnly ni Secure --------------------
    for cookie in resp.headers.getlist('Set-Cookie'):
        if cookie.split(';')[0].strip().startswith('jwt_token=') \
                and 'httponly' not in cookie.lower():
            flags.append('FH{httponly-missing-jwt-cookie}')
            break

    # ---------------- R04: logout sin revocación + refresh indefinido ------
    if resp_json and resp_json.get('access_token') and path in (
            '/api/auth/login', '/api/auth/basic-login'):
        try:
            st = _state()
            st['last_login'] = time.time()
            _save_state(st)
        except Exception:
            pass
    if path == '/api/auth/logout' and status == 200:
        try:
            st = _state()
            st['last_logout'] = time.time()
            _save_state(st)
        except Exception:
            pass

    if path == '/api/auth/refresh-token' and status == 200 and is_json \
            and resp_json.get('access_token'):
        flags.append('FH{logout-no-revoke}')
    else:
        last_logout = _state_get('last_logout', None)
        last_login = _state_get('last_login', None)
        if (status == 200 and bearer and path not in _NON_PROTECTED
                and last_logout and (last_login is None or last_logout > last_login)):
            flags.append('FH{logout-no-revoke}')

    # ---------------- R05: JWT forjado con secret fallback (HS256) ---------
    if (status == 200 and bearer and claims and claims.get('admin') is True
            and _signed_with(bearer, _oauth_fallback_secret())):
        flags.append('FH{forged-jwt-admin}')

    # ---------------- R06: prompt injection sobre el balance ----------------
    if resp_json and resp_json.get('command_executed') is True:
        flags.append('FH{prompt-injection-balance}')

    # ---------------- R07: BOLA - detalles de orden ajena -------------------
    if path.startswith('/api/orders/') and path.endswith('/details') \
            and has('user_id', 'product_id', 'payment_method'):
        flags.append('FH{bola-order-details}')

    # ---------------- R08: IDOR - email del dueño de un producto ------------
    if path.startswith('/api/products/') and path.endswith('/owner-info') \
            and resp_json.get('owner_email') is not None:
        flags.append('FH{idor-owner-info}')

    # ---------------- R09: mass assignment en registro ----------------------
    payload = body or form
    if (path in ('/api/auth/register', '/register')
            and ('is_admin' in payload or 'balance' in payload)):
        flags.append('FH{mass-assignment-register}')
        if payload.get('username') and _truthy(payload.get('is_admin')):
            _mark_admin(payload['username'])

    # ---------------- R10: BFLA - promover / borrar usuario ----------------
    if msg('promoted to admin'):
        flags.append('FH{bfla-promote-admin}')
        if body.get('username'):
            _mark_admin(body.get('username'))
    if msg('user deleted'):
        flags.append('FH{bfla-delete-user}')

    # ---------------- R11: IDOR - transferir propiedad ajena ---------------
    if msg('ownership transferred'):
        flags.append('FH{idor-transfer-ownership}')

    # ---------------- R12: BOLA - refund de orden ajena ---------------------
    if path.startswith('/api/orders/') and path.endswith('/status') \
            and (body or {}).get('status') == 'refunded' and msg('order status updated'):
        flags.append('FH{bola-order-refund}')

    # ---------------- R13: SQLi en búsqueda de usuarios ---------------------
    q = args.get('q', '')
    if (path == '/api/users/search' and status == 200 and SQLI_RE.search(q)
            and resp_json and resp_json.get('results')):
        flags.append('FH{sqli-users-search}')

    # ---------------- R14: GraphQL data exposure + filter eval --------------
    if path == '/graphql/query' and is_json and 'data' in resp_json:
        data = resp_json.get('data') or {}
        if isinstance(data, dict):
            users = data.get('users')
            if isinstance(users, list) and users and 'password_hash' in users[0]:
                flags.append('FH{graphql-data-leak}')
            if 'filter' in (body.get('query', '') or '').lower() \
                    and isinstance(users, list):
                flags.append('FH{graphql-filter-eval}')

    # ---------------- R15: path traversal (files + export) ------------------
    if path.startswith('/api/files/') and status == 200 \
            and ('%2e%2e' in path.lower() or '..' in path):
        flags.append('FH{path-traversal-files}')
    if path == '/transactions/export' and status == 200 \
            and '..' in args.get('filename', ''):
        flags.append('FH{pt-transactions-export}')

    # ---------------- R16: command injection en SKU lookup ------------------
    if path == '/api/inventory/sku-lookup' and is_json and resp_json.get('output') is not None:
        flags.append('FH{rce-sku-lookup}')

    # ---------------- R17: upload sin validación + traversal ----------------
    if path == '/api/upload' and msg('file uploaded successfully'):
        flags.append('FH{insecure-file-upload}')
    if path.startswith('/api/products/') and path.endswith('/upload') \
            and _files_named_traversal():
        flags.append('FH{upload-path-traversal}')

    # ---------------- R18: RCE en /transactions/export ----------------------
    filename = args.get('filename', '') or ''
    if (path == '/transactions/export' and is_json and resp_json.get('output') is not None
            and (args.get('cmd') or '?cmd=' in filename or 'cmd=' in filename)):
        flags.append('FH{rce-transactions-export}')

    # ---------------- R19: GraphQL RCE + lectura de archivos ----------------
    if path == '/graphql/query' and is_json and 'data' in resp_json:
        query = (body.get('query', '') or '')
        data = resp_json.get('data') or {}
        d = data if isinstance(data, dict) else {}
        if re.search(r'exec\(|eval\(|os\.system|subprocess\.|__import__', query) \
                and (d.get('output') is not None or d.get('command')):
            flags.append('FH{graphql-rce}')
        if 'open(' in query and 'read()' in query and (
                d.get('content') is not None or d.get('output') is not None):
            flags.append('FH{graphql-file-read}')

    # ---------------- R20: manipulación de precio en la compra --------------
    if (resp_json.get('success') is True and resp_json.get('actual_price') is not None
            and resp_json.get('paid_amount') is not None
            and resp_json['paid_amount'] < resp_json['actual_price']):
        flags.append('FH{price-tampering}')

    # ---------------- R21: DoS del stream ----------------------------------
    if path == '/api/stream/product-feed':
        try:
            count = int(args.get('count', 1000))
        except (TypeError, ValueError):
            count = 1000
        if count > 1000:
            flags.append('FH{stream-dos}')

    # ---------------- R22: rate limit débil (429 -> 200 tras reset) --------
    if path == '/api/products' and method == 'GET' and bearer:
        if status == 429:
            try:
                st = _state()
                lim = st.get('rate_limited') or {}
                lim[path] = time.time()
                st['rate_limited'] = lim
                _save_state(st)
            except Exception:
                pass
        elif status == 200:
            rate_limited = _state_get('rate_limited', {}) or {}
            if path in rate_limited:
                flags.append('FH{rate-limit-bypass}')

    # ---------------- R23: transferencia desde cuenta ajena ----------------
    if path in ('/api/payments/transfer-username', '/api/payments/transfer') \
            and status == 200 and is_json and resp_json.get('source_username') \
            and ('username' in body or 'from_user_id' in body):
        flags.append('FH{race-condition-transfer}')

    # ---------------- R24: OAuth secret en JWKS + escalada de scope --------
    if path == '/oauth/jwks' and status == 200:
        keys = (resp_json.get('keys') or []) if is_json else []
        if any(k.get('payload') == _oauth_fallback_secret() for k in keys):
            flags.append('FH{oauth-jwks-secret-leak}')
    if path == '/oauth/authorize' and status == 200:
        scope = args.get('scope') or form.get('scope') or ''
        if 'admin' in scope.split():
            flags.append('FH{oauth-scope-escalation}')

    # ---------------- R25: replay y forjado de id_token --------------------
    if path == '/api/auth/oauth-id-token-login' and status == 200:
        id_token = body.get('id_token') or ''
        if id_token:
            id_claims = _jwt_claims(id_token) or {}
            seen = _state_get('seen_id_tokens', []) or []
            if id_token in seen:
                flags.append('FH{oidc-token-replay}')
            else:
                try:
                    st = _state()
                    seen = st.get('seen_id_tokens') or []
                    if id_token not in seen:
                        seen.append(id_token)
                        st['seen_id_tokens'] = seen[-500:]  # acotado
                        _save_state(st)
                except Exception:
                    pass
            email = id_claims.get('email') or ''
            sub = str(id_claims.get('sub') or '')
            if email == 'admin@vuln.internal' or sub == '1':
                flags.append('FH{oidc-forged-idtoken}')

    # ---------------- R26: cadena completa a admin --------------------------
    if (status == 200 and bearer and claims and path not in _NON_PROTECTED
            and claims.get('admin') is True
            and claims.get('name') in _admin_gained()):
        flags.append('FH{full-chain-admin}')


# ---------------------------------------------------------------------------
# Hook principal
# ---------------------------------------------------------------------------

def apply(response):
    """Hook after_request: detecta flags y los inyecta en la respuesta."""
    try:
        if request.path.startswith('/static') or request.path == '/favicon.ico':
            return response

        path = request.path
        method = request.method
        args = request.args
        body = _body()
        form = _form()

        ctype = (response.content_type or '').split(';')[0].lower()
        resp_json = None
        if ctype == 'application/json':
            try:
                resp_json = json.loads(response.get_data(as_text=True))
            except Exception:
                resp_json = None

        flags = []
        _detect(path, method, args, body, form, resp_json,
                response.status_code, response, flags)

        if not flags:
            return response

        flags = sorted(set(flags))
        if isinstance(resp_json, dict):
            resp_json['flag'] = flags[0]
            resp_json['flags'] = flags
            response.set_data(json.dumps(resp_json))
            return response

        # Respuestas no-JSON: cabecera X-Flag
        response.headers['X-Flag'] = flags[0]
        if len(flags) > 1:
            response.headers['X-Flags'] = ','.join(flags)
        return response
    except Exception:
        # Nunca romper el lab por un error del detector de flags
        return response