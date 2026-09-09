from flask import Flask, render_template, request, jsonify, redirect, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect as sqlalchemy_inspect
from werkzeug.security import check_password_hash, generate_password_hash
import random
import json
from datetime import datetime, timedelta
import hashlib
import base64
import os
import jwt
import secrets
import time
import sys
import threading

# Add the app path to import the shared models
sys.path.insert(0, '/app')

app = Flask(__name__, template_folder='templates_oauth')
app.config['SECRET_KEY'] = 'oauth-server-secret-key-2024'
app.config['SESSION_TYPE'] = 'filesystem'
# Use the same database path as the API app to share users
# IMPORTANT: Use exact same format as config.py to ensure same file
db_path = '/app/instance/fashion.db'
# Use sqlite:/// format (3 slashes) - SQLAlchemy handles absolute paths correctly
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Log the database configuration at startup
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.info(f"OAuth Server Database Configuration:")
logger.info(f"  Database Path: {db_path}")
logger.info(f"  Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")

# Initialize database with a DIFFERENT name to avoid conflict
oauth_db = SQLAlchemy(app)

# Track database file state to refresh connections when API container recreates DB
_db_file_lock = threading.Lock()
_db_file_signature = None


def refresh_db_connection_if_needed():
    """Detect DB file replacements and refresh SQLAlchemy connections."""
    global _db_file_signature
    try:
        stats = os.stat(db_path)
        signature = (stats.st_size, stats.st_mtime)
    except FileNotFoundError:
        return
    with _db_file_lock:
        if _db_file_signature != signature:
            try:
                oauth_db.session.remove()
                oauth_db.engine.dispose()
            except Exception as e:
                app.logger.warning(f"Failed to refresh DB connection: {e}")
            _db_file_signature = signature
            app.logger.info("Detected database change. Connections refreshed.")

# Enhanced OAuth Clients with proper security
OAUTH_CLIENTS = {
    'auto_client': {
        'client_id': 'auto_client',
        'client_secret': 'strong_client_secret_here',  # Fixed secret for consistent validation
        'redirect_uris': [
            'http://localhost:5000/oauth/callback',
            'http://127.0.0.1:5000/oauth/callback',
            'http://api:5000/oauth/callback'
        ],
        'scope': 'openid profile products payments orders',
        'name': 'FashionForge API',
        'token_endpoint_auth_method': 'client_secret_post',  # Specify auth method
        'require_pkce': True  # Require PKCE for public clients
    }
}

# Strong JWT signing keys - using HS256 for testing/demo
JWT_SIGNING_KEYS = {
    'HS256': {
        'secret': 'oauth-server-jwt-secret-key-strong-2024'
    }
}

# In-memory storage for authorization codes and tokens
oauth_tokens = {}
oauth_auth_codes = {}
used_nonces = {}  # Track used nonces to prevent replay
state_params = {}  # Store state parameters for validation

implicit_flow_enabled = False  # Implicit flow disabled

@app.before_request
def ensure_shared_db():
    refresh_db_connection_if_needed()

def validate_redirect_uri(client_id, redirect_uri):
    # Open redirect vulnerability intentionally left as requested
    app.logger.warning(f"[LEAK] Redirect URI for {client_id}: {redirect_uri}")
    client = OAUTH_CLIENTS.get(client_id)
    if not client:
        return False
    return True

def generate_secure_token():
    """Generate cryptographically secure token"""
    return 'token_' + secrets.token_urlsafe(32)

def create_signed_jwt(payload, algorithm='HS256'):
    # Only allow server-side configured algorithm
    alg = 'HS256'
    try:
        secret = JWT_SIGNING_KEYS['HS256']['secret']
        token = jwt.encode(payload, secret, algorithm=alg)
        if isinstance(token, bytes):
            token = token.decode('utf-8')
        return token
    except Exception as e:
        app.logger.error(f"JWT encoding error: {e}")
        return None

def validate_nonce(nonce, client_id):
    # VULNERABILITY: Missing/Weak Nonce Validation
    # Nonce validation exists but is ineffective - allows replay attacks
    # The nonce is checked but not properly tracked, allowing the same ID token
    # to be reused multiple times, enabling replay attacks.
    
    # Nonce is optional - only validate if provided
    if not nonce:
        return True  # Nonce is optional, so missing nonce is valid
    
    # VULNERABILITY: Nonce tracking is cleared too aggressively or not persisted
    # This allows the same nonce to be reused after a short time
    key = f"{client_id}_{nonce}"
    now = datetime.now()
    
    # VULNERABILITY: Cleanup happens but nonces expire too quickly (1 second instead of 5 minutes)
    # This means a nonce can be reused almost immediately after being used
    # Original code: expired after 5 minutes, vulnerable code: expires after 1 second
    expired_nonces = []
    for k, v in used_nonces.items():
        if isinstance(v, datetime):
            # Check if stored time is more than 1 second ago (expired)
            if (now - v).total_seconds() > 1:
                expired_nonces.append(k)
    
    for k in expired_nonces:
        del used_nonces[k]
    
    # VULNERABILITY: Even if nonce exists, we don't properly prevent reuse
    # The check exists but the cleanup above makes it ineffective
    if key in used_nonces:
        # VULNERABILITY: Log warning but still allow (should return False)
        app.logger.warning(f"[VULN] Nonce reuse detected but allowed: {nonce}")
        # Don't return False - allow the replay!
        # return False  # This line is commented out - VULNERABILITY
    
    # VULNERABILITY: Store nonce but with very short expiration (1 second)
    # This allows rapid replay attacks - attacker can wait 1 second and reuse the same nonce
    used_nonces[key] = now  # Store current time, will expire after 1 second
    return True

def cleanup_expired_data():
    """Clean up expired tokens, codes, and nonces"""
    now = datetime.now()
    
    # Clean expired tokens
    expired_tokens = [k for k, v in oauth_tokens.items() 
                     if datetime.fromisoformat(v['expires_at']) < now]
    for token in expired_tokens:
        del oauth_tokens[token]
    
    # Clean expired auth codes
    expired_codes = [k for k, v in oauth_auth_codes.items()
                    if datetime.fromisoformat(v['expires_at']) < now]
    for code in expired_codes:
        del oauth_auth_codes[code]
    
    # Clean expired nonces
    expired_nonces = [k for k, v in used_nonces.items() if v < now]
    for nonce in expired_nonces:
        del used_nonces[nonce]

# Create a custom User model for OAuth server that mirrors the API User model
class User(oauth_db.Model):
    __tablename__ = 'user'  # Explicitly set table name to match API's table
    id = oauth_db.Column(oauth_db.Integer, primary_key=True)
    username = oauth_db.Column(oauth_db.String(80), unique=True, nullable=False)
    email = oauth_db.Column(oauth_db.String(120), unique=True, nullable=False)
    password_hash = oauth_db.Column(oauth_db.String(255), nullable=False)
    first_name = oauth_db.Column(oauth_db.String(50))
    last_name = oauth_db.Column(oauth_db.String(50))
    phone = oauth_db.Column(oauth_db.String(20))
    balance = oauth_db.Column(oauth_db.Float, default=10000.0)
    is_admin = oauth_db.Column(oauth_db.Boolean, default=False)
    
    # OAuth/Authentication tracking
    auth_method = oauth_db.Column(oauth_db.String(50), default='username_password')
    oauth_provider = oauth_db.Column(oauth_db.String(50))
    oauth_id = oauth_db.Column(oauth_db.String(255))
    last_login = oauth_db.Column(oauth_db.DateTime)
    last_login_method = oauth_db.Column(oauth_db.String(50))
    
    created_at = oauth_db.Column(oauth_db.DateTime, default=datetime.utcnow)

    def check_password(self, password):
        from werkzeug.security import check_password_hash
        if not self.password_hash:
            app.logger.warning(f"User {self.id} ({self.username}) has no password_hash")
            return False
        if not password:
            app.logger.warning(f"Empty password provided for user {self.id}")
            return False
        try:
            # Ensure password_hash is a string (not bytes)
            password_hash_str = self.password_hash
            if isinstance(password_hash_str, bytes):
                password_hash_str = password_hash_str.decode('utf-8')
            
            result = check_password_hash(password_hash_str, password)
            if not result:
                app.logger.debug(f"Password check failed for user {self.id} ({self.username})")
            return result
        except Exception as e:
            app.logger.error(f"Error checking password for user {self.id}: {e}", exc_info=True)
            return False

@app.route('/health')
def health():
    return jsonify({'status': 'oauth_server_running'}), 200

@app.route('/debug/verify-database', methods=['GET'])
def verify_database():
    """Verify database configuration and connectivity"""
    try:
        with app.app_context():
            # Get database URI from config
            db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', 'Not configured')
            
            # Get database file path from config
            db_path = '/app/instance/fashion.db'
            
            # Get actual database file path from SQLAlchemy engine
            try:
                # Extract actual file path from engine URL
                engine_url = str(oauth_db.engine.url)
                actual_db_file = None
                if 'sqlite' in engine_url.lower():
                    # Extract path from sqlite:///path/to/db
                    if '///' in engine_url:
                        actual_db_file = engine_url.split('///', 1)[1]
                    elif '//' in engine_url:
                        actual_db_file = engine_url.split('//', 1)[1]
            except Exception:
                actual_db_file = None
            
            # Check if database file exists
            import os
            db_exists = os.path.exists(db_path)
            db_size = os.path.getsize(db_path) if db_exists else 0
            
            # Also check actual_db_file if different
            actual_db_exists = None
            actual_db_size = None
            if actual_db_file and actual_db_file != db_path:
                actual_db_exists = os.path.exists(actual_db_file)
                actual_db_size = os.path.getsize(actual_db_file) if actual_db_exists else 0
            
            # Try to query users - force a fresh query
            try:
                # Clear any cached queries
                oauth_db.session.expire_all()
                user_count = User.query.count()
                users_sample = User.query.limit(5).all()
                users_info = []
                for user in users_sample:
                    users_info.append({
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'has_password_hash': bool(user.password_hash)
                    })
            except Exception as e:
                user_count = None
                users_info = []
                query_error = str(e)
            
            # Get table information
            try:
                inspector = sqlalchemy_inspect(oauth_db.engine)
                tables = inspector.get_table_names()
                user_table_columns = []
                if 'user' in tables:
                    user_table_columns = [col['name'] for col in inspector.get_columns('user')]
            except Exception as e:
                tables = []
                user_table_columns = []
                table_error = str(e)
            
            result = {
                'status': 'success',
                'database_uri': db_uri,
                'database_path': db_path,
                'database_exists': db_exists,
                'database_size_bytes': db_size,
                'database_size_mb': round(db_size / (1024 * 1024), 2) if db_exists else 0,
                'engine_url': engine_url if 'engine_url' in locals() else None,
                'actual_db_file': actual_db_file if actual_db_file else None,
                'tables': tables if 'tables' in locals() else [],
                'user_table_columns': user_table_columns if 'user_table_columns' in locals() else [],
                'user_count': user_count if 'user_count' in locals() else None,
                'users_sample': users_info if 'users_info' in locals() else [],
            }
            
            if actual_db_file and actual_db_file != db_path:
                result['actual_db_file_exists'] = actual_db_exists
                result['actual_db_file_size'] = actual_db_size
            
            if 'query_error' in locals():
                result['query_error'] = query_error
            if 'table_error' in locals():
                result['table_error'] = table_error
                
            return jsonify(result), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'error_type': type(e).__name__
        }), 500

@app.route('/debug/users', methods=['GET'])
def debug_users():
    """Debug endpoint to check if users exist in database"""
    try:
        with app.app_context():
            # Try to query users
            users = User.query.all()
            user_list = []
            for user in users:
                user_list.append({
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'has_password_hash': bool(user.password_hash),
                    'password_hash_length': len(user.password_hash) if user.password_hash else 0
                })
            return jsonify({
                'status': 'success',
                'user_count': len(user_list),
                'users': user_list
            }), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'error_type': type(e).__name__
        }), 500

@app.route('/debug/test-password', methods=['POST'])
def debug_test_password():
    """Debug endpoint to test password verification"""
    try:
        data = request.json or {}
        email_or_username = data.get('email') or data.get('username')
        password = data.get('password')
        
        if not email_or_username or not password:
            return jsonify({'error': 'email/username and password required'}), 400
        
        # Try to find user
        user = User.query.filter_by(email=email_or_username).first()
        if not user:
            user = User.query.filter_by(username=email_or_username).first()
        
        if not user:
            return jsonify({
                'status': 'user_not_found',
                'searched': email_or_username
            }), 404
        
        # Test password
        password_valid = user.check_password(password)
        
        return jsonify({
            'status': 'success',
            'user_found': True,
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'password_valid': password_valid,
            'has_password_hash': bool(user.password_hash),
            'password_hash_preview': user.password_hash[:20] + '...' if user.password_hash else None
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'error_type': type(e).__name__
        }), 500

@app.route('/')
def index():
    return jsonify({
        'name': 'OAuth 2.0 Authorization Server',
        'version': '1.0.0',
        'endpoints': {
            'authorize': '/oauth/authorize',
            'token': '/oauth/token',
            'userinfo': '/oauth/userinfo',
            'jwks': '/oauth/jwks',
            'health': '/health'
        },
        'description': 'Secure OAuth 2.0 server for the FashionForge API'
    }), 200

@app.route('/oauth/authorize', methods=['GET', 'POST'])
def oauth_authorize():
    # State parameter is now required and enforced
    cleanup_expired_data()
    
    if request.method == 'POST':
        # Handle login credentials submission
        email_or_username = request.form.get('email')  # Form field is named 'email' but can accept username too
        password = request.form.get('password')
        client_id = request.form.get('client_id')
        redirect_uri = request.form.get('redirect_uri')
        response_type = request.form.get('response_type')
        scope = request.form.get('scope')
        state = request.form.get('state')
        if not state:
            return jsonify({'error': 'state_required'}), 400
        
        # Strict redirect URI validation
        if not validate_redirect_uri(client_id, redirect_uri):
            return jsonify({'error': 'invalid_redirect_uri'}), 400
        
        # Verify user credentials - support both email and username login
        # Try email first, then username
        user = None
        try:
            user = User.query.filter_by(email=email_or_username).first()
            if not user:
                user = User.query.filter_by(username=email_or_username).first()
        except Exception as e:
            app.logger.error(f"Error querying user: {e}")
            client = OAUTH_CLIENTS.get(client_id)
            client_name = client['name'] if client else 'Unknown'
            return render_template('oauth_consent.html', 
                                 client_id=client_id,
                                 client_name=client_name,
                                 scope=scope,
                                 redirect_uri=redirect_uri,
                                 state=state,
                                 show_login=True,
                                 error=f'Database error: {str(e)}'), 500
        
        if not user:
            app.logger.warning(f"User not found: {email_or_username}")
            client = OAUTH_CLIENTS.get(client_id)
            client_name = client['name'] if client else 'Unknown'
            return render_template('oauth_consent.html', 
                                 client_id=client_id,
                                 client_name=client_name,
                                 scope=scope,
                                 redirect_uri=redirect_uri,
                                 state=state,
                                 show_login=True,
                                 error='Invalid email/username or password'), 401
        
        # Check password
        try:
            password_valid = user.check_password(password)
            if not password_valid:
                app.logger.warning(f"Invalid password for user: {email_or_username}")
                client = OAUTH_CLIENTS.get(client_id)
                client_name = client['name'] if client else 'Unknown'
                return render_template('oauth_consent.html', 
                                     client_id=client_id,
                                     client_name=client_name,
                                     scope=scope,
                                     redirect_uri=redirect_uri,
                                     state=state,
                                     show_login=True,
                                     error='Invalid email/username or password'), 401
        except Exception as e:
            app.logger.error(f"Error checking password: {e}")
            client = OAUTH_CLIENTS.get(client_id)
            client_name = client['name'] if client else 'Unknown'
            return render_template('oauth_consent.html', 
                                 client_id=client_id,
                                 client_name=client_name,
                                 scope=scope,
                                 redirect_uri=redirect_uri,
                                 state=state,
                                 show_login=True,
                                 error='Authentication error'), 500
        
        # Store authenticated user in session
        session['oauth_user_id'] = user.id
        session['oauth_user_email'] = user.email
        session['oauth_user_name'] = user.username
        
        # Ensure oauth_request is still in session (it should be from GET request)
        # If not, recreate it from form data
        if 'oauth_request' not in session:
            # Get PKCE params from form or session
            code_challenge = request.form.get('code_challenge') or session.get('code_challenge')
            code_challenge_method = request.form.get('code_challenge_method') or session.get('code_challenge_method', 'S256')
            nonce = request.form.get('nonce') or session.get('nonce')
            
            session['oauth_request'] = {
                'client_id': client_id,
                'redirect_uri': redirect_uri,
                'response_type': response_type,
                'scope': scope,
                'state': state,
                'code_challenge': code_challenge,
                'code_challenge_method': code_challenge_method,
                'nonce': nonce,
                'timestamp': datetime.now().isoformat()
            }
        
        # After login, show consent page
        return render_template('oauth_consent.html',
                              client_id=client_id,
                              client_name=OAUTH_CLIENTS[client_id]['name'],
                              scope=scope,
                              redirect_uri=redirect_uri,
                              state=state,
                              show_login=False)
    
    # GET request - show login form
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    response_type = request.args.get('response_type')
    scope = request.args.get('scope', 'openid profile')
    state = request.args.get('state')
    if not state:
        return jsonify({'error': 'state_required'}), 400

    # PKCE / OIDC params
    code_challenge = request.args.get('code_challenge')
    code_challenge_method = request.args.get('code_challenge_method')
    nonce = request.args.get('nonce')

    if not client_id or client_id not in OAUTH_CLIENTS:
        return jsonify({'error': 'invalid_client'}), 400

    # Strict redirect URI validation
    if not validate_redirect_uri(client_id, redirect_uri):
        return jsonify({'error': 'invalid_redirect_uri'}), 400

    # Require PKCE for authorization code flow
    if response_type == 'code' and not code_challenge:
        return jsonify({'error': 'pkce_required', 'error_description': 'PKCE code_challenge parameter required'}), 400

    session['oauth_request'] = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': response_type,
        'scope': scope,
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': code_challenge_method,
        'nonce': nonce,
        'timestamp': datetime.now().isoformat()
    }

    return render_template('oauth_consent.html', 
                         client_id=client_id, 
                         client_name=OAUTH_CLIENTS[client_id]['name'], 
                         scope=scope, 
                         redirect_uri=redirect_uri,
                         state=state,
                         show_login=True)

@app.route('/oauth/approve', methods=['POST'])
def oauth_approve():
    if 'oauth_request' not in session:
        app.logger.error(f"No oauth_request in session. Session keys: {list(session.keys())}")
        error_response = jsonify({
            'error': 'no_authorization_request', 
            'error_description': 'No authorization request found in session. Please start the OAuth flow again.'
        })
        return error_response, 400

    oauth_request = session.pop('oauth_request')
    client_id = oauth_request.get('client_id')
    redirect_uri = oauth_request.get('redirect_uri')
    response_type = oauth_request.get('response_type')
    scope = oauth_request.get('scope')
    state = oauth_request.get('state')
    code_challenge = oauth_request.get('code_challenge')
    code_challenge_method = oauth_request.get('code_challenge_method')
    nonce = oauth_request.get('nonce')

    # VULNERABILITY: Missing/Weak Nonce Validation
    # The validate_nonce() function exists but is ineffective - it doesn't properly
    # prevent nonce reuse, allowing replay attacks. See validate_nonce() function
    # for details on the vulnerability.
    if nonce and not validate_nonce(nonce, client_id):
        app.logger.warning(f"Invalid or reused nonce: {nonce}")
        error_response = jsonify({
            'error': 'invalid_nonce', 
            'error_description': 'Invalid or reused nonce'
        })
        return error_response, 400
    # VULNERABILITY: Even if nonce validation passes, the same nonce can be reused
    # because the validation is weak (see validate_nonce implementation)

    if response_type == 'code':
        auth_code = generate_secure_token()
        oauth_auth_codes[auth_code] = {
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'scope': scope,
            'expires_at': (datetime.now() + timedelta(minutes=10)).isoformat(),
            'created_at': datetime.now().isoformat(),
            'code_challenge': code_challenge,
            'code_challenge_method': code_challenge_method,
            'nonce': nonce,
            'user_id': session.get('oauth_user_id'),
            'user_email': session.get('oauth_user_email')
        }
        # SECURITY: Do not log or expose auth code in headers.
        app.logger.info(f"Authorization code generated for client {client_id}")
        redirect_params = f"code={auth_code}"
        if state:
            redirect_params += f"&state={state}"

        # Keep the open redirect behavior intact (per request), but avoid leaking
        # sensitive information in headers or logs.
        response = redirect(f"{redirect_uri}?{redirect_params}")
        return response

    return jsonify({'error': 'unsupported_response_type'}), 400

## Removed /oauth/implicit endpoint and related code

@app.route('/oauth/token', methods=['POST'])
def oauth_token():
    cleanup_expired_data()
    
    grant_type = request.form.get('grant_type')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    code = request.form.get('code')
    redirect_uri = request.form.get('redirect_uri')
    code_verifier = request.form.get('code_verifier')

    print(f"Token request: grant_type={grant_type}, client_id={client_id}, code={code}, code_verifier={code_verifier}")

    if not client_id or client_id not in OAUTH_CLIENTS:
        print(f"Invalid client_id: {client_id}")
        return jsonify({'error': 'invalid_client'}), 400

    client = OAUTH_CLIENTS[client_id]

    # SECURITY: Require client_secret from POST body for confidential clients and
    # compare using a constant-time comparison to mitigate brute-force and timing attacks.
    expected_secret = client.get('client_secret')
    attempted_secret = request.form.get('client_secret')

    # Basic in-memory lockout tracking to slow brute-force attempts
    if 'client_failed_attempts' not in globals():
        # { client_id: { 'count': int, 'locked_until': datetime } }
        client_failed_attempts = {}
        globals()['client_failed_attempts'] = client_failed_attempts
    client_failed_attempts = globals()['client_failed_attempts']

    # Check lockout
    lock = client_failed_attempts.get(client_id, {})
    if lock and lock.get('locked_until') and datetime.now() < lock['locked_until']:
        return jsonify({'error': 'temporarily_locked'}), 429

    # If client has a secret configured, require it
    if expected_secret:
        if not attempted_secret:
            # increment failure counter
            entry = client_failed_attempts.setdefault(client_id, {'count': 0, 'locked_until': None})
            entry['count'] += 1
            if entry['count'] >= 5:
                entry['locked_until'] = datetime.now() + timedelta(minutes=5)
            return jsonify({'error': 'invalid_client'}), 400

        # Constant time compare
        try:
            if not secrets.compare_digest(attempted_secret, expected_secret):
                entry = client_failed_attempts.setdefault(client_id, {'count': 0, 'locked_until': None})
                entry['count'] += 1
                if entry['count'] >= 5:
                    entry['locked_until'] = datetime.now() + timedelta(minutes=5)
                return jsonify({'error': 'invalid_client'}), 400
        except Exception:
            return jsonify({'error': 'invalid_client'}), 400

    else:
        # Public clients must use PKCE - enforcement already exists earlier.
        pass

    if grant_type == 'authorization_code':
        if not code or code not in oauth_auth_codes:
            print(f"Invalid or missing code: {code}")
            print(f"Available codes: {list(oauth_auth_codes.keys())}")
            return jsonify({'error': 'invalid_code'}), 400

        auth_code_data = oauth_auth_codes[code]
        expires_at = datetime.fromisoformat(auth_code_data['expires_at'])
        if datetime.now() > expires_at:
            print(f"Code expired: {code}")
            del oauth_auth_codes[code]
            return jsonify({'error': 'expired_code'}), 400

        # Validate redirect URI
        if redirect_uri != auth_code_data['redirect_uri']:
            print(f"Redirect URI mismatch. Sent: {redirect_uri}, Expected: {auth_code_data['redirect_uri']}")
            return jsonify({'error': 'invalid_redirect_uri'}), 400

        # PKCE validation
        stored_challenge = auth_code_data.get('code_challenge')
        if stored_challenge:
            if not code_verifier:
                print(f"PKCE required but code_verifier missing")
                return jsonify({'error': 'invalid_request', 'error_description': 'code_verifier required for PKCE'}), 400

            method = auth_code_data.get('code_challenge_method') or 'S256'
            if method == 'S256':
                m = hashlib.sha256()
                m.update(code_verifier.encode('utf-8'))
                digest = m.digest()
                b64 = base64.urlsafe_b64encode(digest).rstrip(b"=").decode('ascii')
                if b64 != stored_challenge:
                    return jsonify({'error': 'invalid_grant', 'error_description': 'PKCE verification failed'}), 400
            else:
                # Only allow S256 for security
                return jsonify({'error': 'invalid_grant', 'error_description': 'Unsupported code_challenge_method'}), 400

        # VULNERABLE (intentional): Scope upgrade vulnerability
        # If the client requests the 'admin' scope, the server incorrectly
        # elevates the token to represent an administrative user instead of
        # the authenticated user. This simulates a mis-implementation where
        # requested scopes control subject identity.
        escalated_user_id = auth_code_data.get('user_id')
        escalated_user_email = auth_code_data.get('user_email')
        requested_scope = auth_code_data.get('scope', '') or ''
        if 'admin' in requested_scope.split():
            # Find any admin user and impersonate them (vulnerable behavior)
            try:
                admin_user = User.query.filter_by(is_admin=True).first()
                if admin_user:
                    escalated_user_id = admin_user.id
                    escalated_user_email = admin_user.email
            except Exception:
                # if DB lookup fails, fall back to original user
                pass

        access_token = generate_secure_token()
        oauth_tokens[access_token] = {
            'client_id': client_id,
            'scope': auth_code_data['scope'],
            'expires_at': (datetime.now() + timedelta(hours=1)).isoformat(),
            'created_at': datetime.now().isoformat(),
            'token_type': 'Bearer',
            'user_id': escalated_user_id,
            'user_email': escalated_user_email
        }

        # Create proper JWT ID token
        nonce = auth_code_data.get('nonce')
        payload = {
            'iss': 'http://oauth:5001',
            'sub': str(escalated_user_id),
            'aud': client_id,
            'exp': int((datetime.now() + timedelta(hours=1)).timestamp()),
            'iat': int(datetime.now().timestamp()),
            'auth_time': int(datetime.now().timestamp()),
            'email': escalated_user_email
        }
        
        if nonce:
            payload['nonce'] = nonce

        id_token = create_signed_jwt(payload)

        # SECURITY: Invalidate authorization code immediately to prevent replay
        try:
            del oauth_auth_codes[code]
        except KeyError:
            pass

        resp = {
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': 3600,
            'scope': auth_code_data['scope'],
            'id_token': id_token
        }
        
    # SECURITY: Do not expose tokens in headers or verbose logs.
    response = jsonify(resp)
    return response, 200

    return jsonify({'error': 'unsupported_grant_type'}), 400

@app.route('/oauth/userinfo', methods=['GET'])
def oauth_userinfo():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'invalid_token'}), 401

    token = auth_header.replace('Bearer ', '')
    
    # Try to validate JWT with server-side secret and allowed algorithms only.
    try:
        secret = JWT_SIGNING_KEYS['HS256']['secret']
        payload = jwt.decode(token, secret, algorithms=['HS256'], options={"verify_aud": False})

        # Extract user info from JWT payload
        user_id = payload.get('sub')
        if user_id:
            try:
                user = User.query.get(int(user_id))
                if user:
                    return jsonify({
                        'sub': str(user.id),
                        'name': user.username,
                        'email': user.email,
                        'preferred_username': user.username
                    }), 200
            except Exception:
                pass

        # If no DB user, but token verified by signature, return payload data
        return jsonify({
            'sub': payload.get('sub'),
            'name': payload.get('name'),
            'email': payload.get('email'),
            'aud': payload.get('aud')
        }), 200
    except jwt.InvalidTokenError as e:
        app.logger.debug(f"JWT validation failed: {e}")
    except Exception as e:
        app.logger.debug(f"JWT decode unexpected error: {e}")
    
    # Fallback to token lookup (original method)
    if token not in oauth_tokens:
        return jsonify({'error': 'invalid_token'}), 401

    token_data = oauth_tokens[token]
    expires_at = datetime.fromisoformat(token_data['expires_at'])
    if datetime.now() > expires_at:
        del oauth_tokens[token]
        return jsonify({'error': 'expired_token'}), 401

    user_id = token_data.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            return jsonify({
                'sub': str(user.id),
                'name': user.username,
                'email': user.email,
                'preferred_username': user.username
            }), 200

    return jsonify({'error': 'user_not_found'}), 404

@app.route('/.well-known/openid-configuration', methods=['GET'])
def oidc_discovery():
    """Secure OIDC Discovery endpoint"""
    # Use the request's scheme and host to support both HTTP and proper deployment
    scheme = request.scheme
    host = request.host
    base_url = f"{scheme}://{host}"
    
    config = {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oauth/authorize",
        "token_endpoint": f"{base_url}/oauth/token", 
        "userinfo_endpoint": f"{base_url}/oauth/userinfo",
        "jwks_uri": f"{base_url}/oauth/jwks",  
        "scopes_supported": ["openid", "profile", "email", "products", "payments", "orders"],
        "response_types_supported": ["code"],  # Only support authorization code flow
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],  # Using HS256 as configured
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "claims_supported": ["sub", "name", "email", "preferred_username"],
        "code_challenge_methods_supported": ["S256"]  # Only S256 for PKCE
    }
    
    return jsonify(config)

@app.route('/oauth/jwks', methods=['GET'])
def jwks_endpoint():
    """Secure JWKS endpoint with strong keys"""
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "secure_key_2024",
                "alg": "RS256",
                "payload": "oauth-server-jwt-secret-key-strong-2024", 
            }
        ]
    }
    return jsonify(jwks)

## Removed unwanted admin endpoints

def migrate_database():
    """Add missing columns to existing database tables"""
    with app.app_context():
        # Check if user table exists and get its columns
        inspector = sqlalchemy_inspect(oauth_db.engine)
        if 'user' in inspector.get_table_names():
            existing_columns = [col['name'] for col in inspector.get_columns('user')]
            
            # Columns that should exist according to the User model
            # Note: SQLite doesn't support DEFAULT in ALTER TABLE ADD COLUMN, so we add without default
            required_columns = {
                'auth_method': 'VARCHAR(50)',
                'oauth_provider': 'VARCHAR(50)',
                'oauth_id': 'VARCHAR(255)',
                'last_login': 'DATETIME',
                'last_login_method': 'VARCHAR(50)',
                'created_at': 'DATETIME'
            }
            
            # Add missing columns
            for column_name, column_def in required_columns.items():
                if column_name not in existing_columns:
                    try:
                        from sqlalchemy import text
                        with oauth_db.engine.begin() as conn:
                            conn.execute(text(f'ALTER TABLE user ADD COLUMN {column_name} {column_def}'))
                        app.logger.info(f"Added missing column: {column_name}")
                    except Exception as e:
                        app.logger.warning(f"Could not add column {column_name}: {e}")
            
            # Update existing rows to set default value for auth_method if it was just added
            if 'auth_method' not in existing_columns:
                try:
                    from sqlalchemy import text
                    with oauth_db.engine.begin() as conn:
                        conn.execute(text("UPDATE user SET auth_method = 'username_password' WHERE auth_method IS NULL"))
                except Exception as e:
                    app.logger.warning(f"Could not set default auth_method: {e}")

# Initialize database and run migrations when app starts
# IMPORTANT: We must NOT call create_all() if the database already exists with data,
# as it might create a new empty database. Instead, we only run migrations.
try:
    with app.app_context():
        # Verify database connection and file path
        import os
        actual_db_path = db_path
        if not os.path.isabs(actual_db_path):
            # If relative path, make it absolute
            actual_db_path = os.path.abspath(actual_db_path)
        
        # Get the actual file path SQLAlchemy is using
        engine_url = str(oauth_db.engine.url)
        app.logger.info(f"OAuth Server database URI: {engine_url}")
        app.logger.info(f"OAuth Server database path: {actual_db_path}")
        
        db_exists = os.path.exists(actual_db_path)
        app.logger.info(f"Database file exists: {db_exists}")
        
        if db_exists:
            db_size = os.path.getsize(actual_db_path)
            app.logger.info(f"Existing database size: {db_size} bytes")
            
            # Check if database has tables/data
            try:
                inspector = sqlalchemy_inspect(oauth_db.engine)
                existing_tables = inspector.get_table_names()
                app.logger.info(f"Existing tables: {existing_tables}")
                
                if 'user' in existing_tables:
                    # Database exists and has user table - just run migrations
                    app.logger.info("Database exists with user table, running migrations only")
                    migrate_database()
                else:
                    # Database exists but no user table - create tables
                    app.logger.info("Database exists but no user table, creating tables")
                    oauth_db.create_all()
                    migrate_database()
            except Exception as e:
                app.logger.warning(f"Could not inspect database: {e}, attempting to create tables")
                oauth_db.create_all()
                migrate_database()
        else:
            # Database doesn't exist, create it with all tables
            app.logger.info("Database does not exist, creating new database")
            # Ensure directory exists
            os.makedirs(os.path.dirname(actual_db_path), exist_ok=True)
            oauth_db.create_all()
            migrate_database()
        
        # Verify connection by checking user count
        try:
            # Force a fresh query
            oauth_db.session.expire_all()
            user_count = User.query.count()
            app.logger.info(f"Database connection verified. User count: {user_count}")
            if user_count == 0:
                app.logger.warning("WARNING: Database shows 0 users. This might indicate a connection issue.")
        except Exception as e:
            app.logger.warning(f"Could not verify database connection: {e}")

        # Cache current DB signature so we can detect replacements later
        try:
            stats = os.stat(actual_db_path)
            with _db_file_lock:
                _db_file_signature = (stats.st_size, stats.st_mtime)
        except Exception as e:
            app.logger.debug(f"Unable to cache DB signature: {e}")
            
except Exception as e:
    # Log error but don't fail app startup - migration will retry on next request
    import logging
    logging.error(f"Database initialization error: {e}", exc_info=True)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5001)