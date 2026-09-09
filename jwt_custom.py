from functools import wraps
from flask import request, jsonify, session
from jwt_utils import decode_jwt_token
from models import User

def jwt_required_custom(fn):
    """Decorator for endpoints that accept both normal and OAuth tokens, or session cookies"""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # First, try to get JWT from Authorization header
        auth_header = request.headers.get('Authorization', '')
        token = None
        
        if auth_header.startswith('Bearer '):
            token = auth_header.replace('Bearer ', '')
        
        # If no Bearer token, try to get from session (for web pages)
        if not token and 'jwt_token' in session:
            token = session['jwt_token']
        
        # If no token found, return error
        if not token:
            return jsonify({'error': 'Missing or invalid token'}), 401
        
        # Decode and validate token
        payload = decode_jwt_token(token)
        if not payload:
            return jsonify({'error': 'Missing or invalid token'}), 401
        
        user = User.query.get(payload.get('sub'))
        if not user:
            return jsonify({'error': 'User not found'}), 401
        
        request.jwt_payload = payload
        request.jwt_user = user
        return fn(*args, **kwargs)
    return wrapper

def jwt_required_normal(fn):
    """Decorator for endpoints that only accept normal login tokens"""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid token'}), 401
        token = auth_header.replace('Bearer ', '')
        payload = decode_jwt_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # Validate token type
        token_type = payload.get('token_type', 'normal')
        if token_type != 'normal':
            return jsonify({'error': 'This endpoint requires a normal login token. OAuth tokens are not permitted.'}), 403
        
        user = User.query.get(payload.get('sub'))
        if not user:
            return jsonify({'error': 'User not found'}), 401
        request.jwt_payload = payload
        request.jwt_user = user
        return fn(*args, **kwargs)
    return wrapper

def jwt_required_oauth(fn):
    """Decorator for endpoints that only accept OAuth tokens"""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid token'}), 401
        token = auth_header.replace('Bearer ', '')
        payload = decode_jwt_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # Validate token type
        token_type = payload.get('token_type', 'normal')
        if token_type != 'oauth':
            return jsonify({'error': 'This endpoint requires an OAuth token. Normal login tokens are not permitted.'}), 403
        
        user = User.query.get(payload.get('sub'))
        if not user:
            return jsonify({'error': 'User not found'}), 401
        request.jwt_payload = payload
        request.jwt_user = user
        return fn(*args, **kwargs)
    return wrapper

def get_jwt_identity_custom():
    payload = getattr(request, 'jwt_payload', None)
    if payload:
        return payload.get('sub')
    return None

def get_jwt_payload():
    """Get the full JWT payload from the current request"""
    return getattr(request, 'jwt_payload', None)

def get_jwt_token_type():
    """Get the token type from the current JWT"""
    payload = getattr(request, 'jwt_payload', None)
    if payload:
        return payload.get('token_type', 'normal')
    return None

def get_jwt_auth_method():
    """Get the authentication method from the current JWT"""
    payload = getattr(request, 'jwt_payload', None)
    if payload:
        return payload.get('auth_method', 'unknown')
    return None

