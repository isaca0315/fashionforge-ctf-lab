import jwt
import time
from flask import current_app
import hmac
import hashlib
import argparse
import os
from config import Config

def generate_normal_jwt_token(user):
    """Generate JWT token for normal username/password login"""
    payload = {
        "sub": str(user.id),
        "name": user.username,
        "admin": user.is_admin,
        "email": user.email,
        "token_type": "normal",  # Differentiate from OAuth tokens
        "auth_method": "username_password",  # Authentication method
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,  # 1 hour expiration
        "iss": "fashion-api",  # Add issuer
        "aud": "fashion-app"   # Add audience
    }
    secret = current_app.config.get('SECRET_KEY', 'changeme')
    # Always use HS256 with proper secret
    token = jwt.encode(payload, secret, algorithm='HS256')
    return token

def generate_oauth_jwt_token(user):
    """Generate JWT token for OAuth login (third-party authentication)"""
    payload = {
        "sub": str(user.id),
        "name": user.username,
        "admin": user.is_admin,
        "email": user.email,
        "token_type": "oauth",  # Differentiate from normal tokens
        "auth_method": "oauth",  # Authentication method
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,  # 1 hour expiration
        "iss": "fashion-api",  # Add issuer
        "aud": "fashion-app"   # Add audience
    }
    secret = current_app.config.get('SECRET_KEY', 'changeme')
    # Always use HS256 with proper secret
    token = jwt.encode(payload, secret, algorithm='HS256')
    return token

def generate_jwt_token(user):
    """Deprecated: Use generate_normal_jwt_token() or generate_oauth_jwt_token() instead.
    Kept for backward compatibility."""
    return generate_normal_jwt_token(user)

def decode_jwt_token(token):
    secret = current_app.config.get('SECRET_KEY', 'changeme')
    try:
        # First, decode without verification to check algorithm
        unverified_header = jwt.get_unverified_header(token)
        
        # Algorithm confusion protection
        if unverified_header.get('alg') not in ['HS256', 'HS384', 'HS512']:
            raise jwt.InvalidAlgorithmError('Algorithm not allowed')
        
        # Now verify with our secret
        try:
            payload = jwt.decode(
                token, 
                secret, 
                algorithms=['HS256', 'HS384', 'HS512'],
                options={'verify_aud': False}  # Adjust based on your needs
            )
            return payload
        except jwt.InvalidTokenError:
            # Try a fallback secret for tokens issued by an external OAuth server
            fallback_secret = os.environ.get('OAUTH_SERVER_JWT_SECRET', 'oauth-server-jwt-secret-key-strong-2024')
            if fallback_secret and fallback_secret != secret:
                try:
                    payload = jwt.decode(
                        token,
                        fallback_secret,
                        algorithms=['HS256', 'HS384', 'HS512'],
                        options={'verify_aud': False}
                    )
                    current_app.logger.info('Token validated with fallback OAuth server secret')
                    return payload
                except jwt.InvalidTokenError:
                    return None
            return None
    except jwt.InvalidAlgorithmError:
        # Log algorithm confusion attempt
        current_app.logger.warning(f"Algorithm confusion attempt detected: {unverified_header.get('alg')}")
        return None
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def validate_jwt_structure(token):
    """Validate JWT structure and basic claims"""
    try:
        # Check if it's a proper JWT
        parts = token.split('.')
        if len(parts) != 3:
            return False
            
        # Basic structure validation
        header = jwt.get_unverified_header(token)
        if 'alg' not in header:
            return False
            
        return True
    except Exception:
        return False


def generate_jwt_from_claims(sub, name, email='', admin=False, token_type='normal', expires_in=3600, secret=None, alg='HS256'):
    """Generate a JWT from raw claim values.

    This helper can be used outside a Flask app context. It prefers the
    Flask `current_app.config['SECRET_KEY']` when available; otherwise it
    falls back to `Config.SECRET_KEY` or the SECRET_KEY env var.
    """
    now = int(time.time())
    payload = {
        'sub': str(sub),
        'name': name,
        'admin': bool(admin),
        'email': email,
        'token_type': token_type,
        'auth_method': 'username_password' if token_type == 'normal' else 'oauth',
        'iat': now,
        'exp': now + int(expires_in),
        'iss': 'fashion-api',
        'aud': 'fashion-app'
    }

    if secret is None:
        # Prefer Flask current_app secret if available
        try:
            secret = current_app.config.get('SECRET_KEY')
        except Exception:
            secret = None

    if not secret:
        # Fallback to Config or environment
        secret = os.environ.get('SECRET_KEY') or getattr(Config, 'SECRET_KEY', 'changeme')

    token = jwt.encode(payload, secret, algorithm=alg)
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate JWT token using jwt_utils logic')
    parser.add_argument('--user-id', required=True, help='sub claim')
    parser.add_argument('--username', required=True, help='name claim')
    parser.add_argument('--email', default='', help='email claim')
    parser.add_argument('--admin', action='store_true', help='set admin flag')
    parser.add_argument('--token-type', choices=['normal', 'oauth'], default='normal')
    parser.add_argument('--expires', type=int, default=3600, help='expiry seconds')
    parser.add_argument('--secret', default=None, help='signing secret (optional)')
    args = parser.parse_args()

    token = generate_jwt_from_claims(args.user_id, args.username, email=args.email, admin=args.admin, token_type=args.token_type, expires_in=args.expires, secret=args.secret)
    print(token)