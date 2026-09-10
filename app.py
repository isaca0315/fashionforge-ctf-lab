from flask import Flask, request, jsonify, send_file, render_template, send_from_directory, redirect, url_for, session, render_template_string, abort
from jwt_utils import generate_normal_jwt_token, generate_oauth_jwt_token, generate_jwt_token, decode_jwt_token, validate_jwt_structure
from jwt_custom import jwt_required_custom, jwt_required_normal, jwt_required_oauth, get_jwt_identity_custom, get_jwt_token_type, get_jwt_auth_method
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flasgger import Swagger
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import json
import uuid
import secrets
import hashlib
import base64
from datetime import datetime, timedelta
import random
import threading
import time
import sqlite3
import subprocess
import requests
import jwt
from models import db, User, Product, Order, Payment
from sqlalchemy import text
from config import Config
from functools import wraps
import re
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
import logging
from graphql_vuln import graphql_blueprint
from oauth_server import OAUTH_CLIENTS
from urllib.parse import parse_qs
from flask_session import Session  
from flags import apply as flags_apply_hook  


def response_from_ai(user_input: str) -> str:
    """
    Enhanced AI assistant that can actually execute commands through prompt injection
    """
    balance_update_result = check_and_process_balance_update(user_input)
    if balance_update_result:
        return balance_update_result

    llm = ChatGroq(
        model="openai/gpt-oss-20b",
        groq_api_key="<ENTER_YOUR_OWN_API_KEY>"
    )

    template = ChatPromptTemplate.from_messages([
        ("system", """You are FashionForgeAI, the official AI assistant for the FashionForge Marketplace application.

# APPLICATION OVERVIEW
FashionForge Marketplace is a Flask-based platform for buying and selling clothing online.

# KEY FEATURES
1. User Management: Registration, login (username/password & OAuth), profiles, balance system
2. Product Marketplace: Browse, search, list, and purchase clothing and accessories
3. Transactions: Secure payments, fund transfers, order management
4. Admin Dashboard: User management, system monitoring, administrative tools
5. File Management: Upload/download product images and documents
6. AI Integration: Product descriptions, user assistance


Always be helpful, accurate, and professional."""),
        ("user", "{user_input}")
    ])

    response = template | llm
    result = response.invoke({"user_input": user_input})

    return result.content

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

app = Flask(__name__)
app.config.from_object(Config)

app.config.update(
    SECRET_KEY=app.config.get('SECRET_KEY', 'fallback-secret-key-for-sessions'),
    SESSION_TYPE='filesystem',  # Or 'redis' in production
    SESSION_PERMANENT=False,
    SESSION_USE_SIGNER=True,
    SESSION_COOKIE_NAME='fashion_session',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,  # Set True in production with HTTPS
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
)

# Initialize Flask-Session if you're using it, or let Flask handle sessions
# sess = Session()
# sess.init_app(app)

# Export directory for demo path-traversal export endpoint
EXPORT_DIR = app.config.get('UPLOAD_FOLDER', 'uploads')

# Simple HTML form used when no filename is provided to the export endpoint
EXPORT_FORM = """
<h3>Transaction Export (demo)</h3>
<form method="get" action="/transactions/export">
  <label for="filename">Filename (relative to export dir):</label>
  <input type="text" id="filename" name="filename" placeholder="example.csv" />
  <button type="submit">Download</button>
</form>
<p><small>Demo-only endpoint: naive join used (vulnerable to path traversal).</small></p>
"""

# Logger for transaction export events
tx_logger = logging.getLogger('tx_logger')
tx_logger.setLevel(logging.INFO)
if not tx_logger.handlers:
    tx_logger.addHandler(logging.StreamHandler())

# Initialize extensions
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Swagger/OpenAPI documentation (serve UI at /api/docs)
swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec',
            "route": '/apispec.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": '/flasgger_static',
    "swagger_ui": True,
    "specs_route": '/api/docs',
    "title": "FashionForge API",
    "version": "1.0.0",
    "description": "API for fashion marketplace ",
    "termsOfService": "http://example.com/terms",
    "contact": {
        "email": "support@vuln.internal"
    }
}

# Add security definitions so Swagger UI can show auth options
swagger_config.setdefault('securityDefinitions', {
  'basicAuth': {
    'type': 'basic'
  },
  'bearerAuth': {
    'type': 'apiKey',
    'name': 'Authorization',
    'in': 'header'
  }
})

swagger = Swagger(app, config=swagger_config)

# ==================== AUTHENTICATION VULNERABILITIES ====================

# VULNERABILITY 11: Weak Brute Force Protection
# In-memory tracking of failed login attempts (can be bypassed with distributed attacks)
brute_force_attempts = {}
BRUTE_FORCE_LIMIT = 50  # Very high limit - should be 5-10
BRUTE_FORCE_WINDOW = 300  # 5 minutes

def check_brute_force(username):
    """VULNERABLE: Weak brute force protection"""
    now = time.time()
    if username not in brute_force_attempts:
        brute_force_attempts[username] = []
    
    # Remove old attempts outside the window
    brute_force_attempts[username] = [
        t for t in brute_force_attempts[username] 
        if now - t < BRUTE_FORCE_WINDOW
    ]
    
    # VULNERABILITY: High limit (50 attempts in 5 minutes)
    # VULNERABILITY: In-memory only (can be bypassed with IP rotation)
    if len(brute_force_attempts[username]) >= BRUTE_FORCE_LIMIT:
        return False
    
    return True

def record_failed_attempt(username):
    """Record failed login attempt"""
    now = time.time()
    if username not in brute_force_attempts:
        brute_force_attempts[username] = []
    brute_force_attempts[username].append(now)

def record_successful_attempt(username):
    """Clear failed attempts on successful login"""
    if username in brute_force_attempts:
        brute_force_attempts[username] = []

# VULNERABILITY 12: Weak Rate Limiting for Login (global, not per-user)
login_rate_limit = {}
LOGIN_RATE_LIMIT = 100  # Too high - should be 5-10
LOGIN_RATE_WINDOW = 60  # 1 minute

def check_login_rate_limit(ip_address):
    """VULNERABLE: Weak global rate limiting for login"""
    now = time.time()
    if ip_address not in login_rate_limit:
        login_rate_limit[ip_address] = []
    
    # Remove old attempts
    login_rate_limit[ip_address] = [
        t for t in login_rate_limit[ip_address] 
        if now - t < LOGIN_RATE_WINDOW
    ]
    
    # VULNERABILITY: Very high limit (100 per minute)
    if len(login_rate_limit[ip_address]) >= LOGIN_RATE_LIMIT:
        return False
    
    login_rate_limit[ip_address].append(now)
    return True

# VULNERABILITY 13: No token expiration enforcement
# VULNERABILITY 14: Tokens stored in memory without secure validation

# VULNERABILITY 15: Basic Auth support with weak validation
def check_basic_auth():
    """VULNERABLE: Basic authentication with weak validation"""
    auth = request.authorization
    if not auth:
        return None
    
    # VULNERABILITY: No rate limiting on Basic Auth
    # VULNERABILITY: Credentials sent in Authorization header (base64 encoded)
    user = User.query.filter_by(username=auth.username).first()
    
    if user and check_password_hash(user.password_hash, auth.password):
        return user
    
    return None

# VULNERABILITY 16: Bearer token with no signature verification in some endpoints
# VULNERABILITY 17: No token rotation mechanism
def vulnerable_bearer_auth(token):
  """VULNERABLE: Bearer token auth using JWT with custom payload"""
  payload = decode_jwt_token(token)
  if not payload:
    return None
  user = User.query.get(payload.get('sub'))
  return user

# ==================== END AUTHENTICATION VULNERABILITIES ====================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Global variable for race condition demonstration
balance_transfers = {}
# In-memory transfer records for UI (non-persistent)
transfer_records = []

# VULNERABILITY 2: Insecure File Upload Handling
@app.route('/api/products/<int:product_id>/upload', methods=['POST'])
def upload_product_image(product_id):
    """
    Upload product image
    ---
    tags:
      - Products
    security:
      - bearerAuth: []
    parameters:
      - name: product_id
        in: path
        type: integer
        required: true
        description: ID of the product
      - name: file
        in: formData
        type: file
        required: true
        description: Image file to upload
    consumes:
      - multipart/form-data
    responses:
      200:
        description: File uploaded successfully
        schema:
          type: object
          properties:
            message:
              type: string
            path:
              type: string
      400:
        description: Bad request or no file provided
      401:
        description: Unauthorized - missing or invalid token
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # VULNERABILITY 1: No file type validation
    # VULNERABILITY 2: Using original filename (path traversal possible)
    filename = file.filename

    # VULNERABILITY 3: No content-type verification
    # VULNERABILITY 4: Files saved with original names
    upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(upload_path)

    # Update product with image path
    product = Product.query.get(product_id)
    if product:
        product.image_path = upload_path
        db.session.commit()

    return jsonify({'message': 'File uploaded successfully', 'path': upload_path})

# VULNERABILITY 3: Path Traversal
@app.route('/api/files/<path:filename>')
@jwt_required_custom
def download_file(filename):
    """
    Download file
    ---
    tags:
      - Files
    security:
      - bearerAuth: []
    parameters:
      - name: filename
        in: path
        type: string
        required: true
        description: Path to the file to download
    responses:
      200:
        description: File downloaded successfully
      404:
        description: File not found
      401:
        description: Unauthorized - missing or invalid token
    description: VULNERABLE - Path traversal vulnerability. Direct file access without path sanitization. Now requires JWT authentication.
    """
    # VULNERABILITY: Direct file access without path sanitization
    # For demo/testing: allow path traversal and absolute paths
    # Try within upload folder first
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        return send_file(file_path)

    # If not found, check if filename is an absolute or relative path that exists
    if os.path.exists(filename):
        return send_file(filename)

    return jsonify({'error': 'File not found'}), 404


@app.route('/transactions/export', methods=['GET'])
def transactions_export():
    """
    Export transactions data 
    ---
    tags:
      - Transactions
    parameters:
      - name: filename
        in: query
        type: string
        required: false
        description: Filename to export (relative to export directory)
    responses:
      200:
        description: File downloaded successfully or form displayed
        content:
          text/html:
            schema:
              type: string
            examples:
              form:
                summary: Export form HTML
              file:
                summary: CSV file download
          application/octet-stream:
            schema:
              type: string
              format: binary
      404:
        description: File not found
    """
    filename_param = request.args.get('filename')
    if not filename_param:
        return render_template_string(EXPORT_FORM)

    extra_query = {}
    if '?' in filename_param:
        filename, remainder = filename_param.split('?', 1)
        extra_query = parse_qs(remainder)
    else:
        filename = filename_param

    tx_logger.info("Export request filename=%s from %s", filename, request.remote_addr)

    # VULNERABLE: naive join -> allows path traversal
    target_path = os.path.join(EXPORT_DIR, filename)

    if not os.path.exists(target_path):
        tx_logger.warning("Requested file does not exist: %s", target_path)
        abort(404, "File not found")

    # RCE feature: execute commands via cmd parameter, choose runner via 'runner'
    cmd = (extra_query.get('cmd', [None])[0] if extra_query else None) or request.args.get('cmd')
    runner = (extra_query.get('runner', [None])[0] if extra_query else None) or request.args.get('runner') or 'bash'

    if cmd:
        runner = runner.lower()
        tx_logger.info("Executing command via transactions/export cmd=%s runner=%s", cmd, runner)
        try:
            if runner in ('python', 'py'):
                completed = subprocess.check_output(
                    ['python3', '-c', cmd],
                    stderr=subprocess.STDOUT,
                    timeout=10,
                    text=True
                )
            else:
                completed = subprocess.check_output(
                    ['/bin/bash', '-c', cmd],
                    stderr=subprocess.STDOUT,
                    timeout=10,
                    text=True
                )

            return jsonify({
                'runner': runner,
                'command': cmd,
                'output': completed
            })
        except subprocess.CalledProcessError as e:
            return jsonify({
                'runner': runner,
                'command': cmd,
                'error': 'Command failed',
                'detail': e.output
            }), 500
        except Exception as exc:
            return jsonify({
                'runner': runner,
                'command': cmd,
                'error': 'Execution error',
                'detail': str(exc)
            }), 500

    tx_logger.info("Serving file: %s", target_path)
    return send_file(target_path, as_attachment=True)

# VULNERABILITY 4: Sensitive Data Exposure
@app.route('/api/users/<int:user_id>')
@jwt_required_custom
def get_user_profile(user_id):
    """
    Get user profile
    ---
    tags:
      - Users
    security:
      - bearerAuth: []
    parameters:
      - name: user_id
        in: path
        type: integer
        required: true
        description: ID of the user
    responses:
      200:
        description: User profile retrieved successfully
        schema:
          type: object
          properties:
            id:
              type: integer
            username:
              type: string
            email:
              type: string
            password:
              type: string
              description: VULNERABILITY - Exposed hashed password
            balance:
              type: number
              description: VULNERABILITY - Exposed financial data
            created_at:
              type: string
      404:
        description: User not found
      401:
        description: Unauthorized - missing or invalid token
    description: VULNERABLE - Excessive data exposure. Returns complete user object including sensitive fields. Now requires JWT authentication.
    """
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # VULNERABILITY: Returning complete user object including sensitive fields
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'password': getattr(user, 'password_hash', None),  # VULNERABILITY: Exposing hashed password
        'balance': user.balance,    # VULNERABILITY: Exposing financial data
        'created_at': user.created_at.isoformat()
    })


# EXTRA VULNERABILITY: Sensitive Information Leakage by Username/Email
@app.route('/api/users/info', methods=['POST'])
def sensitive_user_lookup():
    """
    Sensitive user information lookup
    ---
    tags:
      - Users
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            username:
              type: string
              description: Username of the user to look up
            email:
              type: string
              description: Email of the user to look up
    responses:
      200:
        description: Sensitive user information, including newly registered users
      404:
        description: User not found
    description: VULNERABLE - No authentication, allows lookup by username or email and leaks sensitive data for the user and for newly registered users.
    """
    data = request.get_json() or {}
    username = data.get('username')
    email = data.get('email')

    # VULNERABILITY: No authentication or authorization required
    # VULNERABILITY: Lookup by either username or email with no rate limiting
    user = None
    if username:
        user = User.query.filter_by(username=username).first()
    if not user and email:
        user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # "New registered info": leak details of the most recently registered users
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()

    return jsonify({
        'requested_user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'password_hash': getattr(user, 'password_hash', None),  # VULNERABILITY: Exposing password hash
            'balance': user.balance,  # VULNERABILITY: Exposing financial info
            'created_at': user.created_at.isoformat()
        },
        'newly_registered_users': [{
            'id': u.id,
            'username': u.username,
            'email': u.email,
            'password_hash': getattr(u, 'password_hash', None),  # VULNERABILITY
            'balance': u.balance,
            'created_at': u.created_at.isoformat()
        } for u in recent_users]
    })

@app.route('/api/orders/<int:order_id>/status', methods=['PUT'])
def update_order_status(order_id):
    """
    Update order status
    ---
    tags:
      - Orders
    security:
      - bearerAuth: []
    parameters:
      - name: order_id
        in: path
        type: integer
        required: true
        description: ID of the order
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              status:
                type: string
                description: New status for the order
    responses:
      200:
        description: Order status updated successfully
        schema:
          type: object
          properties:
            message:
              type: string
            status:
              type: string
      404:
        description: Order not found
      401:
        description: Unauthorized - missing or invalid token
    """
    current_user = get_jwt_identity_custom()
    order = Order.query.get(order_id)
    
    if not order:
        return jsonify({'error': 'Order not found'}), 404
    
    # VULNERABILITY: No check if user owns the order
    new_status = request.json.get('status')
    
    if not new_status:
        return jsonify({'error': 'Status is required'}), 400

    previous_status = order.status

    # VULNERABILITY: Allowing direct status manipulation
    order.status = new_status

    # Business rule: when an order is refunded, credit the user and free the product
    if new_status == 'refunded' and previous_status != 'refunded':
        user = User.query.get(order.user_id)
        product = Product.query.get(order.product_id)

        if user:
            user.balance = (user.balance or 0) + (order.amount or 0)

        if product:
            product.is_available = True

    db.session.commit()
    
    return jsonify({'message': 'Order status updated', 'status': order.status})


# VULNERABILITY 6: Race Condition in Payment Processing
# VULNERABILITY 6: Race Condition in Payment Processing (with username support)
@app.route('/api/payments/transfer-username', methods=['POST'])
@jwt_required_custom
def transfer_funds_username():
    """
    Transfer funds using usernames instead of IDs
    ---
    tags:
      - Payments
    security:
      - bearerAuth: []
    parameters:
      - name: body
        in: body
        required: true
        schema:
          properties:
            username:
              type: string
              description: Source username (optional, defaults to current user)
            target_username:
              type: string
              description: Target username (required)
            amount:
              type: number
              description: Amount to transfer (required)
    responses:
      200:
        description: Transfer completed successfully
      400:
        description: Invalid request
      401:
        description: Unauthorized
      404:
        description: User not found
    """
    data = request.json or {}
    
    # Get source user - either from JWT or username parameter
    current_user_id = get_jwt_identity_custom()
    
    if 'username' in data:
        # If username provided, use that user as source
        source_user = User.query.filter_by(username=data['username']).first()
    else:
        # Otherwise use current user from JWT
        source_user = User.query.get(current_user_id) if current_user_id else None
    
    # Get target user by username
    target_username = data.get('target_username')
    if not target_username:
        return jsonify({'error': 'target_username required'}), 400
    
    target_user = User.query.filter_by(username=target_username).first()
    if not target_user:
        return jsonify({'error': 'Target user not found'}), 404
    
    if not source_user:
        return jsonify({'error': 'Source user not found'}), 404
    
    amount = float(data.get('amount', 0))
    
    if amount <= 0:
        return jsonify({'error': 'Amount must be positive'}), 400
    
    try:
        # VULNERABLE: No row-level locking
        # Read balances (no locking)
        from_balance = float(source_user.balance or 0.0)
        to_balance = float(target_user.balance or 0.0)

        if from_balance < amount:
            return jsonify({'error': 'Insufficient funds'}), 400

        # Artificial delay to increase race window
        time.sleep(random.uniform(0, 0.05))

        # Write back updated balances (racy)
        source_user.balance = from_balance - amount
        target_user.balance = to_balance + amount
        db.session.commit()

        tx_logger.info(f"(VULN) Transfer by username: {source_user.username} -> {target_user.username}: ${amount}")

        return jsonify({
            'message': 'Transfer completed',
            'source_username': source_user.username,
            'target_username': target_user.username,
            'amount': amount,
            'new_balance': float(source_user.balance)
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Transfer failed: {str(e)}'}), 500

# Web-facing transfer endpoint (used by templates/js with session auth)
@app.route('/api/payments/transfer', methods=['POST'])
@jwt_required_custom
def transfer_funds():
    data = request.json or {}
    
    # Support both ID and username for source user
    if 'username' in data:
        # If username provided, use that user as source
        current_user = User.query.filter_by(username=data['username']).first()
    elif 'from_user_id' in data:
        # If user_id provided, use that
        current_user = User.query.get(data['from_user_id'])
    else:
        # Otherwise use current user from JWT token
        current_user_id = get_jwt_identity_custom()
        current_user = User.query.get(current_user_id) if current_user_id else None
    
    # Support both ID and username for target user
    if 'target_username' in data:
        target_user = User.query.filter_by(username=data['target_username']).first()
    elif 'target_user_id' in data:
        target_user = User.query.get(data['target_user_id'])
    else:
        target_user = None
    
    # Get amount
    amount = float(data.get('amount', 0))

    if amount <= 0:
        return jsonify({'error': 'Amount must be positive'}), 400
    
    if not target_user:
        return jsonify({'error': 'Target user not found'}), 400

    try:
        # VULNERABLE: No row-level locking
        if current_user is None:
            return jsonify({'error': 'Source user not found'}), 404

        # Read balances (no locking)
        from_balance = float(current_user.balance or 0.0)
        to_balance = float(target_user.balance or 0.0)

        if from_balance < amount:
            return jsonify({'error': 'Insufficient funds'}), 400

        # Artificial delay to increase race window
        time.sleep(random.uniform(0, 0.05))

        # Write back updated balances (racy)
        current_user.balance = from_balance - amount
        target_user.balance = to_balance + amount
        db.session.commit()

        tx_logger.info(f"(VULN) Transfer: {current_user.username} -> {target_user.username}: ${amount}")

        return jsonify({
            'message': 'Transfer completed',
            'source_username': current_user.username,
            'target_username': target_user.username,
            'amount': amount,
            'new_balance': float(current_user.balance)
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Transfer failed: {str(e)}'}), 500

# VULNERABILITY 7: Parameter Sequencing/Manipulation
@app.route('/api/products/search', methods=['GET'])
@jwt_required_custom
def search_products():
    """
    Search products
    ---
    tags:
      - Products
    security:
      - bearerAuth: []
    parameters:
      - name: name
        in: query
        type: string
        required: false
        description: Product name
      - name: brand
        in: query
        type: string
        required: false
        description: Product brand
      - name: min_price
        in: query
        type: number
        required: false
        default: 0
        description: Minimum price filter
      - name: max_price
        in: query
        type: number
        required: false
        default: 1000000
        description: Maximum price filter
    responses:
      200:
        description: List of matching products
        schema:
          type: array
          items:
            properties:
              id:
                type: integer
              name:
                type: string
              brand:
                type: string
              price:
                type: number
              sku:
                type: string
                description: VULNERABILITY - Exposed SKU
              owner_email:
                type: string
                description: VULNERABILITY - Exposed owner info
      401:
        description: Unauthorized - missing or invalid token
    description: VULNERABLE - Parameter manipulation in search. Direct parameter usage without validation. Price manipulation possible. Excessive data in response. Now requires JWT authentication.
    """
    name = request.args.get('name', '')
    brand = request.args.get('brand', '')
    min_price = request.args.get('min_price', 0)
    max_price = request.args.get('max_price', 1000000)
    
    # VULNERABILITY: Direct parameter usage without validation
    query = Product.query
    
    if name:
        query = query.filter(Product.name.ilike(f'%{name}%'))
    if brand:
        query = query.filter(Product.brand.ilike(f'%{brand}%'))
    
    # VULNERABILITY: Price manipulation possible
    query = query.filter(Product.price >= min_price, Product.price <= max_price)
    
    products = query.all()
    
    # VULNERABILITY: Excessive data in response
    result = []
    for product in products:
        result.append({
            'id': product.id,
            'name': product.name,
            'brand': product.brand,
            'price': product.price,
            'sku': product.sku,  # VULNERABILITY: Exposing SKU
            'owner_email': product.owner.email  # VULNERABILITY: Exposing owner info
        })
    
    return jsonify(result)

# VULNERABILITY 8: AI Prompt Injection

@app.route('/api/ai/chatbot', methods=['POST'])
@jwt_required_custom
def generate_product_description():
    """
    Enhanced AI chat bot with Groq integration and actual prompt injection vulnerability
    The AI is trained to refuse commands, but prompt injection can bypass this
    """
    try:
        product_data = request.json
        if not product_data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        user_instructions = product_data.get('user_instructions') or ''

        # Check for balance update commands - THIS ACTUALLY EXECUTES THEM
        balance_update_result = check_and_process_balance_update(user_instructions)
        if balance_update_result:
            return jsonify({
                'description': balance_update_result,
                'command_executed': True,
                'warning': 'Command executed via prompt injection'
            })

        # Original AI functionality for product descriptions
        response = response_from_ai(user_instructions)
        
        return jsonify({
            'description': response,
            'command_executed': False
        })
        
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500

def check_and_process_balance_update(user_input):
    """
    Check if the user input contains balance update commands and ACTUALLY process them
    Returns response message if balance update was processed, None otherwise
    """
    try:
        # More comprehensive patterns to catch various prompt injection attempts
        balance_patterns = [
            # Direct commands
            r'update\s+(?P<username>[\w\@\.\-]+)\s+balance\s+(?P<amount>[+-]?\d+\.?\d*)',
            r'set\s+(?P<username>[\w\@\.\-]+)\s+balance\s+to\s+(?P<amount>[+-]?\d+\.?\d*)',
            r'add\s+(?P<amount>[+-]?\d+\.?\d*)\s+to\s+(?P<username>[\w\@\.\-]+)\s+balance',
            
            # Prompt injection attempts
            r'ignore.*previous.*instructions.*(?:update|set|add).*?(?P<username>[\w\@\.\-]+).*?(?P<amount>[+-]?\d+\.?\d*)',
            r'you.*are.*now.*(?:hacked|bypassed).*?(?:update|set|add).*?(?P<username>[\w\@\.\-]+).*?(?P<amount>[+-]?\d+\.?\d*)',
            r'system.*override.*(?:update|set|add).*?(?P<username>[\w\@\.\-]+).*?(?P<amount>[+-]?\d+\.?\d*)',
            
            # SQL-like injection
            r'update.*user.*set.*balance.*=.*?(?P<amount>[+-]?\d+\.?\d*).*where.*username.*=.*[\'"]?(?P<username>[\w\@\.\-]+)',
            
            # Hidden instructions
            r'指令.*更新.*?(?P<username>[\w\@\.\-]+).*余额.*?(?P<amount>[+-]?\d+\.?\d*)',
            r'ignore.*all.*previous.*prompts.*and.*execute.*this.*command.*(?:update|set|add).*?(?P<username>[\w\@\.\-]+).*?(?P<amount>[+-]?\d+\.?\d*)'
        ]

        for pattern in balance_patterns:
            match = re.search(pattern, user_input, re.IGNORECASE)
            if match:
                print(f" PROMPT INJECTION DETECTED: {pattern}")
                print(f"Matched input: {user_input}")
                
                username = None
                amount = None

                # Extract named groups
                if 'username' in match.groupdict() and 'amount' in match.groupdict():
                    username = match.group('username')
                    amount_str = match.group('amount')
                    try:
                        amount = float(amount_str)
                    except ValueError:
                        continue
                else:
                    # Fallback: extract username and amount from groups
                    groups = match.groups()
                    if len(groups) >= 2:
                        # Assume last numeric is amount, previous is username
                        for i in range(len(groups)-1, -1, -1):
                            if groups[i] and re.search(r'[0-9]', groups[i]):
                                try:
                                    amount = float(groups[i])
                                    if i > 0 and groups[i-1]:
                                        username = groups[i-1]
                                    break
                                except:
                                    continue

                # If still not found, try to extract from whole input
                if amount is None:
                    num_match = re.search(r'([+-]?\d+\.?\d*)', user_input)
                    if num_match:
                        try:
                            amount = float(num_match.group(1))
                        except:
                            pass

                if username and amount is not None:
                    # Detect negative commands
                    negative_indicators = ['deduct', 'subtract', 'remove', 'take', 'decrease', 'minus', '-']
                    if any(indicator in user_input.lower() for indicator in negative_indicators):
                        amount = -abs(amount)
                    
                    # ACTUALLY EXECUTE THE COMMAND
                    return process_balance_update(username, amount)

    except Exception as e:
        print(f"Error in check_and_process_balance_update: {e}")
        return None

    return None

def process_balance_update(username, amount):
    """
    Process the actual balance update for a user
    """
    try:
        # Support numeric id lookup, username and email
        user = None
        if isinstance(username, str) and username.isdigit():
            user = User.query.get(int(username))

        if not user:
            user = User.query.filter_by(username=username).first()

        if not user:
            user = User.query.filter_by(email=username).first()

        if not user:
            return f"Error: User '{username}' not found"

        # Update balance (ensure numeric)
        old_balance = float(user.balance or 0.0)
        user.balance = old_balance + float(amount)
        db.session.commit()

        action = "added to" if amount >= 0 else "deducted from"
        abs_amount = abs(amount)

        return (f"Successfully {action} ${abs_amount:.2f} to {user.username}'s balance. "
                f"Old balance: ${old_balance:.2f}, New balance: ${user.balance:.2f}")

    except Exception as e:
        return f"Error updating balance: {str(e)}"


def coerce_user_fields(data: dict) -> dict:
  """
  Coerce common user-provided fields into the expected Python types.
  - is_admin: 'true'/'false' strings, '1'/'0', 'on'/'off' -> bool
  - balance: numeric strings -> float
  Leaves other fields untouched.
  Modifies and returns the same dict for convenience.
  """
  if not isinstance(data, dict):
    return data

  # Coerce is_admin
  if 'is_admin' in data:
    val = data.get('is_admin')
    if isinstance(val, str):
      v = val.strip().lower()
      if v in ('1', 'true', 'yes', 'on'):
        data['is_admin'] = True
      elif v in ('0', 'false', 'no', 'off'):
        data['is_admin'] = False
      else:
        # leave as-is (could raise later)
        pass

  # Coerce balance
  if 'balance' in data:
    val = data.get('balance')
    if isinstance(val, str):
      try:
        # support integers and floats
        if '.' in val:
          data['balance'] = float(val)
        else:
          data['balance'] = int(val)
      except Exception:
        # leave as-is; DB will validate later
        pass

  return data

# VULNERABILITY 9: Weak Rate Limiting
request_counts = {}
@app.route('/api/products', methods=['GET'])
@jwt_required_custom
def get_all_products():
    """
    Get all products
    ---
    tags:
      - Products
    security:
      - bearerAuth: []
    responses:
      200:
        description: List of all products
        schema:
          type: array
          items:
            properties:
              id:
                type: integer
              name:
                type: string
              brand:
                type: string
              price:
                type: number
      429:
        description: Rate limit exceeded (100 requests per minute)
      401:
        description: Unauthorized - missing or invalid token
    description: VULNERABLE - Weak rate limiting implementation. In-memory rate limiting that can be bypassed. Now requires JWT authentication.
    """
    client_ip = request.remote_addr
    
    # VULNERABILITY: In-memory rate limiting that can be bypassed
    if client_ip not in request_counts:
        request_counts[client_ip] = []
    
    now = time.time()
    request_counts[client_ip] = [t for t in request_counts[client_ip] if now - t < 60]
    
    if len(request_counts[client_ip]) >= 5:  # lowered limit for demo/testing
        return jsonify({'error': 'Rate limit exceeded'}), 429
    
    request_counts[client_ip].append(now)
    
    products = Product.query.all()
    return jsonify([{
        'id': p.id,
        'name': p.name,
        'brand': p.brand,
        'price': p.price
    } for p in products])

# VULNERABILITY 10: gRPC-like streaming endpoint (simulated)
@app.route('/api/stream/product-updates', methods=['GET'])
@jwt_required_custom
def stream_product_updates():
    """
    Stream product updates
    ---
    tags:
      - Products
    security:
      - bearerAuth: []
    parameters:
      - name: product_id
        in: query
        type: integer
        required: false
        description: ID of the product to stream updates for
    responses:
      200:
        description: Server sent events stream of product updates
      401:
        description: Unauthorized - missing or invalid token
    description: VULNERABLE - Streaming API without proper authentication. Now requires JWT authentication for streaming data
    """
    def generate():
        # VULNERABILITY: No proper authentication for streaming data
        product_id = request.args.get('product_id')
        count = 0
        while count < 10:  # Simulate 10 updates
            count += 1
            yield f"data: Update {count} for product {product_id}\n\n"
            time.sleep(1)
    
    return app.response_class(generate(), mimetype='text/plain')

# Regular API endpoints (non-vulnerable versions for comparison)
@app.route('/api/secure/products', methods=['POST'])
@jwt_required_custom
def create_product():
    """
    Create a new product
    ---
    tags:
      - Products
    security:
      - bearerAuth: []
    parameters:
      - name: body
        in: body
        required: true
        schema:
          properties:
            name:
              type: string
              description: Product name
            brand:
              type: string
              description: Product brand
            price:
              type: number
              description: Product price
            sku:
              type: string
              description: Product SKU
    responses:
      200:
        description: Product created successfully
        schema:
          properties:
            id:
              type: integer
            message:
              type: string
      401:
        description: Unauthorized - missing or invalid token
    description: Secure product creation endpoint
    """
    current_user = get_jwt_identity_custom()
    data = request.json
    
    product = Product(
        name=data['name'],
        brand=data['brand'],
        category=data.get('category', 'Other'),
        price=data['price'],
        sku=data['sku'],
        owner_id=current_user
    )
    
    db.session.add(product)
    db.session.commit()
    
    return jsonify({'id': product.id, 'message': 'Product created'})

@app.route('/api/secure/users/me')
@jwt_required_custom
def get_current_user():
    """
    Get current user profile
    ---
    tags:
      - Users
    security:
      - bearerAuth: []
    responses:
      200:
        description: Current user profile (only necessary data)
        schema:
          properties:
            id:
              type: integer
            username:
              type: string
            email:
              type: string
      401:
        description: Unauthorized - missing or invalid token
    description: Secure user profile - only returns necessary data without sensitive information. Accepts both normal and OAuth tokens.
    """
    current_user_id = get_jwt_identity_custom()
    user = User.query.get(current_user_id)
    
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'auth_method': user.auth_method
        # No sensitive data exposed
    })

@app.route('/api/secure/users/me-normal-only')
@jwt_required_normal
def get_current_user_normal_only():
    """
    Get current user profile (normal login tokens only)
    ---
    tags:
      - Users
    security:
      - bearerAuth: []
    responses:
      200:
        description: Current user profile (normal login only)
        schema:
          properties:
            id:
              type: integer
            username:
              type: string
            email:
              type: string
      403:
        description: Forbidden - OAuth tokens not allowed for this endpoint
      401:
        description: Unauthorized - missing or invalid token
    description: Endpoint restricted to normal login tokens only. OAuth tokens will be rejected.
    """
    current_user_id = get_jwt_identity_custom()
    user = User.query.get(current_user_id)
    
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'auth_method': user.auth_method,
        'message': 'This data is only available to users who logged in with username/password'
    })

@app.route('/api/secure/users/me-oauth-only')
@jwt_required_oauth
def get_current_user_oauth_only():
    """
    Get current user profile (OAuth tokens only)
    ---
    tags:
      - Users
    security:
      - bearerAuth: []
    responses:
      200:
        description: Current user profile (OAuth only)
        schema:
          properties:
            id:
              type: integer
            username:
              type: string
            email:
              type: string
      403:
        description: Forbidden - Normal login tokens not allowed for this endpoint
      401:
        description: Unauthorized - missing or invalid token
    description: Endpoint restricted to OAuth tokens only. Normal login tokens will be rejected.
    """
    current_user_id = get_jwt_identity_custom()
    user = User.query.get(current_user_id)
    
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'auth_method': user.auth_method,
        'oauth_provider': user.oauth_provider,
        'message': 'This data is only available to users who logged in via OAuth'
    })

@app.route('/api/vulnerable/users/me-bearer')
def get_current_user_vulnerable():
    """
    Get current user profile using vulnerable bearer auth
    ---
    tags:
      - Users
    security:
      - bearerAuth: []
    responses:
      200:
        description: Current user profile with vulnerable bearer token validation
        schema:
          properties:
            id:
              type: integer
            username:
              type: string
            email:
              type: string
            balance:
              type: number
      401:
        description: Invalid or missing token
    description: VULNERABLE - Bearer token without proper signature verification and no expiration check
    """
    auth_header = request.headers.get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Missing token'}), 401
    
    token = auth_header.replace('Bearer ', '')
    
    # VULNERABILITY 16: No proper token signature verification
    user = vulnerable_bearer_auth(token)
    
    if not user:
        return jsonify({'error': 'Invalid token'}), 401
    
    # VULNERABILITY: Exposing sensitive data
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'balance': user.balance
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # VULNERABILITY 11: Weak brute force protection (high limit)
        if not check_brute_force(username):
            return render_template('login.html', error='Too many failed attempts'), 429

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            record_successful_attempt(username)
            login_user(user)
            # Generate JWT token for API access
            jwt_token = generate_normal_jwt_token(user)
            # Set token in session for web access
            session['jwt_token'] = jwt_token
            user.auth_method = 'username_password'
            user.last_login_method = 'username_password'
            user.last_login = datetime.utcnow()
            db.session.commit()
            # Also set a cookie so client-side code (or tools) can access the JWT
            resp = redirect(url_for('dashboard'))
            # Allow JS access in this demo (HttpOnly=False). In production you
            # should prefer HttpOnly and use the Authorization header instead.
            secure_flag = app.config.get('SESSION_COOKIE_SECURE', False)
            resp.set_cookie('jwt_token', jwt_token, httponly=False, secure=secure_flag, samesite=app.config.get('SESSION_COOKIE_SAMESITE', 'Lax'))
            return resp
        else:
            record_failed_attempt(username)
            return render_template('login.html', error='Invalid credentials'), 401

    return render_template('login.html')


@app.route('/start_oauth')
def start_oauth():
    """Redirect user to the external OAuth server to start Authorization Code flow"""
    try:
        # Generate secure state parameter
        state = str(uuid.uuid4())
        session['oauth_state'] = state

        # Generate PKCE parameters (required by OAuth server)
        code_verifier = secrets.token_urlsafe(32)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip('=')

        # Store code_verifier in session for later use in token exchange
        session['oauth_code_verifier'] = code_verifier

        # Generate nonce for OIDC
        nonce = secrets.token_urlsafe(16)
        session['oauth_nonce'] = nonce

        # Store timestamp for state expiration check
        session['oauth_state_timestamp'] = datetime.utcnow().isoformat()

        # Store redirect_uri to validate on callback
        session['oauth_redirect_uri'] = url_for('oauth_callback', _external=True)

        # OAuth server and client configuration
        oauth_authorize = 'http://localhost:5001/oauth/authorize'
        client_id = 'auto_client'
        redirect_uri = session['oauth_redirect_uri']
        scope = 'openid profile'

        # Build redirect URL with PKCE parameters and nonce
        params = {
            'response_type': 'code',
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'scope': scope,
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'nonce': nonce
        }

        # URL encode parameters
        query_string = '&'.join([f"{k}={v}" for k, v in params.items()])
        return redirect(f"{oauth_authorize}?{query_string}")

    except Exception as e:
        print(f"[ERROR] OAuth initiation failed: {str(e)}")
        return render_template('login.html', error=f'OAuth initiation failed: {str(e)}'), 500


# Add OAuth token validation function
def validate_oauth_token(token):
    """Validate OAuth access token with the OAuth server"""
    try:
        # Verify token with OAuth server
        userinfo_url = 'http://oauth:5001/oauth/userinfo'
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(userinfo_url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            return response.json()  # Return user info
        return None
    except Exception:
        return None

# Enhanced JWT validation for OIDC tokens
def validate_oidc_token(id_token):
    """Validate OIDC ID tokens with proper security checks"""
    try:
        # Decode and verify token using the shared secret (HS256)
        # The OAuth server signs with this secret, so we use the same to verify
        shared_secret = 'oauth-server-jwt-secret-key-strong-2024'
        
        payload = jwt.decode(
            id_token,
            shared_secret,
            algorithms=['HS256'],
            audience='auto_client',  # Verify audience
            issuer='http://oauth:5001'  # Verify issuer
        )
        
        return payload
    except Exception as e:
        print(f"OIDC token validation error: {e}")
        return None

# Update the OAuth callback to validate tokens properly
@app.route('/oauth/callback')
def oauth_callback():
    """Handle the authorization code callback from the OAuth server with security enhancements."""
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')

    if error:
        print(f"[ERROR] OAuth callback error: {error}")
        return render_template('login.html', error=f'OAuth error: {error}'), 400

    # 🔒 Validate state parameter
    if not state:
        print("[ERROR] No state parameter in callback")
        return render_template('login.html', error='Missing state parameter'), 400

    # Get stored state from session
    expected_state = session.get('oauth_state')
    state_timestamp = session.get('oauth_state_timestamp')

    # Clean up state from session immediately
    session.pop('oauth_state', None)
    session.pop('oauth_state_timestamp', None)

    if not expected_state:
        print("[ERROR] No oauth_state found in session")
        return render_template('login.html', error='Session expired or invalid. Please try again.'), 400

    # Validate state value
    if state != expected_state:
        print(f"[ERROR] State mismatch. Expected: {expected_state}, Got: {state}")
        return render_template('login.html', error='Invalid OAuth state. Possible CSRF attack.'), 400

    # 🔒 Validate state expiration (5 minutes)
    if state_timestamp:
        try:
            state_time = datetime.fromisoformat(state_timestamp)
            if datetime.utcnow() - state_time > timedelta(minutes=5):
                print("[ERROR] OAuth state expired")
                return render_template('login.html', error='OAuth session expired. Please try again.'), 400
        except ValueError:
            pass  # If timestamp is invalid, continue but log

    print(f"[DEBUG] State validation successful for state: {state}")

    # 🔒 Get PKCE code verifier
    code_verifier = session.pop('oauth_code_verifier', None)
    if not code_verifier:
        print("[ERROR] Missing PKCE code_verifier in session")
        return render_template('login.html', error='OAuth session incomplete. Please try again.'), 400

    # Rest of your existing token exchange code...
    token_url = 'http://oauth:5001/oauth/token'
    client_id = 'auto_client'
    client_secret = OAUTH_CLIENTS['auto_client']['client_secret']
    redirect_uri = session.pop('oauth_redirect_uri', url_for('oauth_callback', _external=True))

    try:
        token_data = {
            'grant_type': 'authorization_code',
            'client_id': client_id,
            'client_secret': client_secret,
            'code': code,
            'redirect_uri': redirect_uri,
            'code_verifier': code_verifier
        }

        print(f"[DEBUG] Exchanging code for token at {token_url}")
        resp = requests.post(token_url, data=token_data, timeout=10)

        if resp.status_code != 200:
            print(f"[ERROR] Token exchange failed: {resp.status_code} - {resp.text}")
            return render_template('login.html', error='OAuth token exchange failed'), 400

        token_response = resp.json()
    except Exception as e:
        print(f"[ERROR] Token exchange exception: {str(e)}")
        return render_template('login.html', error='OAuth token exchange failed'), 500
    access_token = token_response.get('access_token')
    id_token = token_response.get('id_token')

    if not access_token:
        return "No access token returned", 400

    # Validate ID token if present (OIDC)
    if id_token:
        id_payload = validate_oidc_token(id_token)
        if not id_payload:
            return "Invalid ID token", 400
            
        nonce_from_session = session.pop('oauth_nonce', None)
        token_nonce = id_payload.get('nonce')
        if not nonce_from_session:
            print("[ERROR] Missing nonce in session during ID token validation")
            return render_template('login.html', error='OAuth session expired. Please try again.'), 400
        if token_nonce != nonce_from_session:
            print(f"[ERROR] Nonce mismatch. Expected {nonce_from_session}, got {token_nonce}")
            return render_template('login.html', error='Invalid OAuth nonce. Possible replay detected.'), 400

    # Fetch userinfo with access token
    userinfo = validate_oauth_token(access_token)
    if not userinfo:
        return "Failed to validate access token", 400

    email = userinfo.get('email') or userinfo.get('preferred_username')
    name = userinfo.get('name') or email

    # Map or create local user
    user = None
    if email:
        user = User.query.filter_by(email=email).first()

    if not user:
        # Create user with secure random password
        username = (email.split('@')[0] if email else f'user_{secrets.token_urlsafe(8)}')
        user = User(
            username=username, 
            email=email or f'{username}@local', 
            password_hash=generate_password_hash(secrets.token_urlsafe(32))
        )
        db.session.add(user)
        db.session.commit()

    # Login the user
    login_user(user)
    
    # Update user login tracking
    user.last_login = datetime.utcnow()
    user.last_login_method = 'oauth'
    user.auth_method = 'oauth'
    user.oauth_provider = 'auto_client'  # Can be extended for multiple OAuth providers
    db.session.commit()
    
    # Generate OAuth-specific token (different from normal login tokens)
    oauth_access_token_jwt = generate_oauth_jwt_token(user)
    
    # Store both OAuth and JWT tokens securely in session
    session['oauth_access_token'] = access_token
    if id_token:
        session['oauth_id_token'] = id_token
    session['jwt_oauth_token'] = oauth_access_token_jwt  # Store JWT version for API access
    # Also set server-side session key expected by jwt_required_custom decorator
    # so web routes that check `session['jwt_token']` will accept the OAuth login.
    session['jwt_token'] = oauth_access_token_jwt

    # Also set a browser cookie for convenience in demos/tests
    resp = redirect(url_for('dashboard'))
    secure_flag = app.config.get('SESSION_COOKIE_SECURE', False)
    resp.set_cookie('jwt_token', oauth_access_token_jwt, httponly=False, secure=secure_flag, samesite=app.config.get('SESSION_COOKIE_SAMESITE', 'Lax'))
    return resp


@app.route('/start_oidc_vuln')
def start_oidc_vuln():
  """Start a vulnerable OIDC Authorization Code flow (demo).

  This endpoint initiates an authorization request to the OAuth server
  but the callback implemented below will intentionally accept ID tokens
  without verifying their signature - VULNERABLE by design for testing.
  """
  state = str(uuid.uuid4())
  session['oidc_vuln_state'] = state

  # PKCE parameters
  code_verifier = secrets.token_urlsafe(32)
  code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
  ).decode().rstrip('=')
  session['oidc_vuln_code_verifier'] = code_verifier

  # Nonce for replay protection (we'll store it but the callback will
  # intentionally NOT verify the token signature)
  nonce = secrets.token_urlsafe(16)
  session['oidc_vuln_nonce'] = nonce

  oauth_authorize = app.config.get('OAUTH2_PROVIDER_URL', 'http://localhost:5001') + '/oauth/authorize'
  client_id = app.config.get('OAUTH2_CLIENT_ID', 'auto_client')
  redirect_uri = url_for('oidc_callback_vuln', _external=True)
  scope = 'openid profile email'

  params = (
    f"response_type=code&client_id={client_id}&redirect_uri={redirect_uri}"
    f"&scope={scope}&state={state}&nonce={nonce}&code_challenge={code_challenge}&code_challenge_method=S256"
  )
  return redirect(f"{oauth_authorize}?{params}")


@app.route('/oidc/callback_vuln')
def oidc_callback_vuln():
  """Vulnerable OIDC callback that accepts unsigned or tampered ID tokens.

  VULNERABILITY: The ID token's signature is NOT verified. An attacker
  can craft an ID token with arbitrary claims (for example, setting
  `sub` to an admin user's id or changing the email) and the app will
  accept it.
  """
  code = request.args.get('code')
  state = request.args.get('state')
  error = request.args.get('error')

  if error:
    return f"OAuth error: {error}", 400

  expected_state = session.pop('oidc_vuln_state', None)
  if not expected_state or state != expected_state:
    return "Invalid or missing OAuth state", 400

  token_url = app.config.get('OAUTH2_PROVIDER_URL', 'http://localhost:5001') + '/oauth/token'
  client_id = app.config.get('OAUTH2_CLIENT_ID', 'auto_client')
  client_secret = app.config.get('OAUTH2_CLIENT_SECRET', '')
  redirect_uri = url_for('oidc_callback_vuln', _external=True)

  code_verifier = session.pop('oidc_vuln_code_verifier', None)
  if not code_verifier:
    return "Missing PKCE code_verifier in session", 400

  try:
    token_data = {
      'grant_type': 'authorization_code',
      'client_id': client_id,
      'client_secret': client_secret,
      'code': code,
      'redirect_uri': redirect_uri,
        'code_verifier': code_verifier,
        # Request an insecure unsigned id_token from the OAuth server
        # for demo purposes so the vulnerable callback can be exercised.
        'insecure_id_token': '1'
    }
    resp = requests.post(token_url, data=token_data, timeout=5)
  except Exception as e:
    return f"Token exchange failed: {e}", 500

  if resp.status_code != 200:
    return f"Token endpoint error: {resp.status_code} - {resp.text}", 400

  token_response = resp.json()
  access_token = token_response.get('access_token')
  id_token = token_response.get('id_token')

  id_payload = None
  if id_token:
    try:
      # VULNERABLE: DO NOT verify signature. This accepts any token
      # structure and values - intentionally insecure for demo.
      id_payload = jwt.decode(id_token, options={"verify_signature": False})
      app.logger.warning("[VULN-OIDC] Accepted ID token without signature verification: %s", id_payload)
    except Exception as e:
      app.logger.debug(f"Failed to decode id_token (vuln flow): {e}")
      id_payload = None

    if not id_payload:
      return "Invalid ID token", 400

    # We still check nonce to show partial mitigation, but the core
    # vulnerability is the skipped signature verification above.
    expected_nonce = session.pop('oidc_vuln_nonce', None)
    if expected_nonce and id_payload.get('nonce') != expected_nonce:
      # Log mismatch but continue (demonstrates weak handling)
      app.logger.warning("[VULN-OIDC] nonce mismatch (continuing due to vuln).")

  # Try to get userinfo from access token; fall back to id_token claims
  userinfo = validate_oauth_token(access_token) if access_token else None
  if not userinfo and id_payload:
    userinfo = {
      'email': id_payload.get('email') or id_payload.get('sub'),
      'name': id_payload.get('name') or id_payload.get('sub')
    }

  if not userinfo:
    return "Failed to validate access token or id_token", 400

  email = userinfo.get('email') or userinfo.get('preferred_username')
  name = userinfo.get('name') or email

  # Map or create local user (same logic as secure callback)
  user = None
  if email:
    user = User.query.filter_by(email=email).first()

  if not user:
    username = (email.split('@')[0] if email else f'user_{secrets.token_urlsafe(8)}')
    user = User(
      username=username,
      email=email or f'{username}@local',
      password_hash=generate_password_hash(secrets.token_urlsafe(32))
    )
    db.session.add(user)
    db.session.commit()

  login_user(user)
  user.last_login = datetime.utcnow()
  user.last_login_method = 'oauth'
  user.auth_method = 'oauth'
  user.oauth_provider = 'auto_client'
  db.session.commit()

  # Generate JWT for web session (as done in secure flow)
  oauth_access_token_jwt = generate_oauth_jwt_token(user)
  session['oauth_access_token'] = access_token
  if id_token:
    session['oauth_id_token'] = id_token
  session['jwt_oauth_token'] = oauth_access_token_jwt
  session['jwt_token'] = oauth_access_token_jwt

  resp = redirect(url_for('dashboard'))
  secure_flag = app.config.get('SESSION_COOKIE_SECURE', False)
  resp.set_cookie('jwt_token', oauth_access_token_jwt, httponly=False, secure=secure_flag, samesite=app.config.get('SESSION_COOKIE_SAMESITE', 'Lax'))
  return resp

# VULNERABILITY: Missing Nonce Validation - ID Token Replay Attack Endpoint
@app.route('/api/auth/oauth-id-token-login', methods=['POST'])
def oauth_id_token_replay_vuln():
    """
    VULNERABLE: Missing Nonce Validation - Allows ID Token Replay Attacks
    
    This endpoint demonstrates the missing nonce validation vulnerability.
    An attacker can intercept a valid ID token and replay it multiple times
    to authenticate as the user, even after the original session expires.
    
    ---
    tags:
      - Authentication
      - Vulnerable
    parameters:
      - name: body
        in: body
        required: true
        schema:
          properties:
            id_token:
              type: string
              description: OIDC ID token (can be replayed multiple times)
    responses:
      200:
        description: Login successful (vulnerable to replay)
      401:
        description: Invalid token
    description: VULNERABLE - Missing nonce validation allows ID token replay attacks
    """
    data = request.json or {}
    id_token = data.get('id_token')
    
    if not id_token:
        return jsonify({'error': 'id_token required'}), 400
    
    # Validate ID token signature
    id_payload = validate_oidc_token(id_token)
    if not id_payload:
        return jsonify({'error': 'Invalid ID token'}), 401
    
    # VULNERABILITY: Missing Nonce Validation
    # The nonce is checked if present in session, but:
    # 1. No tracking of used nonces/ID tokens
    # 2. Same ID token can be replayed multiple times
    # 3. No server-side nonce validation
    # 4. Attacker can capture a valid ID token and reuse it indefinitely
    
    # VULNERABILITY: We validate the token but don't check if it was already used
    # This allows replay attacks where an attacker intercepts a valid ID token
    # and reuses it to authenticate as the user
    
    email = id_payload.get('email')
    user_id = id_payload.get('sub')
    
    if not email and not user_id:
        return jsonify({'error': 'Invalid token payload'}), 401
    
    # Find or create user
    user = None
    if email:
        user = User.query.filter_by(email=email).first()
    elif user_id:
        user = User.query.get(int(user_id))
    
    if not user:
        username = (email.split('@')[0] if email else f'user_{user_id}')
        user = User(
            username=username,
            email=email or f'{username}@local',
            password_hash=generate_password_hash(secrets.token_urlsafe(32))
        )
        db.session.add(user)
        db.session.commit()
    
    # Login the user - VULNERABILITY: This works even if ID token was already used
    login_user(user)
    user.last_login = datetime.utcnow()
    user.last_login_method = 'oauth'
    user.auth_method = 'oauth'
    db.session.commit()
    
    # Generate JWT token
    oauth_jwt = generate_oauth_jwt_token(user)
    
    return jsonify({
        'access_token': oauth_jwt,
        'token_type': 'Bearer',
        'message': 'Login successful (VULNERABLE: ID token can be replayed)',
        'vulnerability': 'Missing nonce validation allows ID token replay attacks'
    })

# Add secure token refresh endpoint
@app.route('/api/auth/oauth-refresh', methods=['POST'])
@jwt_required_custom
def oauth_refresh_token():
    """Refresh OAuth tokens securely"""
    refresh_token = request.json.get('refresh_token')
    if not refresh_token:
        return jsonify({'error': 'refresh_token required'}), 400
        
    # Implement secure token refresh logic
    # This would call the OAuth server's token endpoint with refresh_token grant
    
    return jsonify({'error': 'refresh_not_implemented'}), 501

@app.route('/api/auth/oauth-jwt', methods=['POST'])
@jwt_required_custom
def get_oauth_jwt_token():
    """
    Get a JWT token for OAuth-authenticated users
    This endpoint allows OAuth-authenticated users to obtain JWT tokens for API access
    
    ---
    tags:
      - Authentication
    responses:
      200:
        description: OAuth JWT token generated successfully
        schema:
          properties:
            access_token:
              type: string
              description: JWT access token (OAuth token)
            token_type:
              type: string
            token_category:
              type: string
      401:
        description: User not authenticated via OAuth
    """
    # Check if user was authenticated via OAuth
    if current_user.auth_method != 'oauth':
        return jsonify({'error': 'This endpoint is for OAuth-authenticated users only. Your account uses username/password authentication.'}), 403
    
    # Generate OAuth JWT token
    oauth_jwt = generate_oauth_jwt_token(current_user)
    
    return jsonify({
        'access_token': oauth_jwt,
        'token_type': 'Bearer',
        'token_category': 'oauth',
        'user': {
            'id': current_user.id,
            'username': current_user.username,
            'email': current_user.email,
            'is_admin': current_user.is_admin,
            'auth_method': current_user.auth_method
        }
    })

@app.route('/api/auth/normal-jwt', methods=['POST'])
@jwt_required_custom
def get_normal_jwt_token():
    """
    Get a JWT token for username/password authenticated users
    This endpoint allows username/password authenticated users to obtain JWT tokens for API access
    
    ---
    tags:
      - Authentication
    responses:
      200:
        description: Normal login JWT token generated successfully
        schema:
          properties:
            access_token:
              type: string
              description: JWT access token (normal login token)
            token_type:
              type: string
            token_category:
              type: string
      401:
        description: User not authenticated via username/password
    """
    # Check if user was authenticated via username/password
    if current_user.auth_method != 'username_password':
        return jsonify({'error': 'This endpoint is for username/password authenticated users only. Your account uses OAuth authentication.'}), 403
    
    # Generate normal JWT token
    normal_jwt = generate_normal_jwt_token(current_user)
    
    return jsonify({
        'access_token': normal_jwt,
        'token_type': 'Bearer',
        'token_category': 'normal_login',
        'user': {
            'id': current_user.id,
            'username': current_user.username,
            'email': current_user.email,
            'is_admin': current_user.is_admin,
            'auth_method': current_user.auth_method
        }
    })

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # VULNERABLE: Mass assignment from form data. This will accept arbitrary
        # fields from the client (including is_admin) and use them to construct
        # the User object. Password is still hashed, but other fields are trusted.
        form_data = request.form.to_dict()

        # Basic duplicate username check (kept for UX) but still vulnerable to
        # mass-assignment since extra fields are passed through.
        username = form_data.get('username')
        if username and User.query.filter_by(username=username).first():
            return render_template('register.html', error='Username already exists'), 400

        # Hash password if provided and move to password_hash field
        password = form_data.pop('password', None)
        if password:
            form_data['password_hash'] = generate_password_hash(password)

        # Coerce some common form fields to the expected types (bool/number)
        coerce_user_fields(form_data)

        try:
            # Mass-assignment: pass all form fields directly to User constructor
            user = User(**form_data)
        except Exception as e:
            return render_template('register.html', error=f'Invalid data: {e}'), 400

        db.session.add(user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html')

app.register_blueprint(graphql_blueprint)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/api/auth/session-jwt', methods=['GET'])
@jwt_required_custom
def get_session_jwt():
    """
    Get JWT token for session-authenticated users
    Used by web pages to get API access tokens
    ---
    tags:
      - Authentication
    responses:
      200:
        description: JWT token for authenticated user
        schema:
          properties:
            access_token:
              type: string
            token_type:
              type: string
    """
    # Generate appropriate JWT token based on auth method
    if current_user.auth_method == 'oauth':
        jwt_token = generate_oauth_jwt_token(current_user)
    else:
        jwt_token = generate_normal_jwt_token(current_user)
    
    return jsonify({
        'access_token': jwt_token,
        'token_type': 'Bearer',
        'user_id': current_user.id,
        'username': current_user.username
    })

@app.route('/dashboard')
@jwt_required_custom
def dashboard():
  """Dashboard - requires session authentication (web) or JWT token (API)"""
  stats = {
    'total_products': Product.query.count(),
    'available_products': Product.query.filter_by(is_available=True).count(),
    'total_orders': Order.query.count(),
  }
  recent_products = Product.query.limit(4).all()
  recent_orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).limit(5).all()
    
  return render_template('dashboard.html', 
             stats=stats, 
             recent_products=recent_products, 
             recent_orders=recent_orders,
             is_admin=current_user.is_admin)
@app.route('/api/dashboard/stats', methods=['GET'])
@jwt_required_custom
def api_dashboard_stats():
    """
    Get dashboard statistics via JWT token
    ---
    tags:
      - Dashboard
    security:
      - bearerAuth: []
    responses:
      200:
        description: Dashboard statistics
        schema:
          properties:
            total_products:
              type: integer
            available_products:
              type: integer
            total_orders:
              type: integer
      401:
        description: Unauthorized - missing or invalid token
    """
    stats = {
        'total_products': Product.query.count(),
        'available_products': Product.query.filter_by(is_available=True).count(),
        'total_orders': Order.query.count(),
    }
    return jsonify(stats)

@app.route('/api/dashboard/recent-products', methods=['GET'])
@jwt_required_custom
def api_dashboard_recent_products():
    """
    Get recent products via JWT token
    ---
    tags:
      - Dashboard
    security:
      - bearerAuth: []
    responses:
      200:
        description: Recent products list
      401:
        description: Unauthorized - missing or invalid token
    """
    recent_products = Product.query.limit(4).all()
    return jsonify([{
        'id': p.id,
        'name': p.name,
        'brand': p.brand,
        'price': p.price,
        'is_available': p.is_available
    } for p in recent_products])

@app.route('/api/dashboard/my-orders', methods=['GET'])
@jwt_required_custom
def api_dashboard_my_orders():
    """
    Get current user's recent orders via JWT token
    ---
    tags:
      - Dashboard
    security:
      - bearerAuth: []
    responses:
      200:
        description: User's recent orders
      401:
        description: Unauthorized - missing or invalid token
    """
    current_user_id = get_jwt_identity_custom()
    recent_orders = Order.query.filter_by(user_id=current_user_id).order_by(Order.created_at.desc()).limit(5).all()
    return jsonify([{
        'id': o.id,
        'product_id': o.product_id,
        'amount': o.amount,
        'status': o.status,
        'created_at': o.created_at.isoformat()
    } for o in recent_orders])

@app.route('/api/products', methods=['GET'])
@jwt_required_custom
def api_products_list():
    """
    Get all products via JWT token (replaces web endpoint)
    ---
    tags:
      - Products
    security:
      - bearerAuth: []
    responses:
      200:
        description: List of all products
      401:
        description: Unauthorized - missing or invalid token
    """
    products = Product.query.all()
    return jsonify([{
        'id': p.id,
        'name': p.name,
        'brand': p.brand,
        'price': p.price,
        'is_available': p.is_available
    } for p in products])

@app.route('/api/my-products', methods=['GET'])
@jwt_required_custom
def api_my_products():
    """
    Get current user's products via JWT token
    ---
    tags:
      - Products
    security:
      - bearerAuth: []
    responses:
      200:
        description: User's products
      401:
        description: Unauthorized - missing or invalid token
    """
    current_user_id = get_jwt_identity_custom()
    user_products = Product.query.filter_by(owner_id=current_user_id).all()
    return jsonify([{
        'id': p.id,
        'name': p.name,
        'brand': p.brand,
        'price': p.price,
        'is_available': p.is_available
    } for p in user_products])

@app.route('/api/my-orders', methods=['GET'])
@jwt_required_custom
def api_my_orders():
    """
    Get current user's orders via JWT token
    ---
    tags:
      - Orders
    security:
      - bearerAuth: []
    responses:
      200:
        description: User's orders
      401:
        description: Unauthorized - missing or invalid token
    """
    current_user_id = get_jwt_identity_custom()
    user_orders = Order.query.filter_by(user_id=current_user_id).all()
    return jsonify([{
        'id': o.id,
        'product_id': o.product_id,
        'amount': o.amount,
        'status': o.status,
        'created_at': o.created_at.isoformat()
    } for o in user_orders])

@app.route('/api/my-payments', methods=['GET'])
@jwt_required_custom
def api_my_payments():
    """
    Get current user's payments via JWT token
    ---
    tags:
      - Payments
    security:
      - bearerAuth: []
    responses:
      200:
        description: User's payments
      401:
        description: Unauthorized - missing or invalid token
    """
    current_user_id = get_jwt_identity_custom()
    user_payments = Payment.query.filter_by(user_id=current_user_id).all()
    return jsonify([{
        'id': p.id,
        'order_id': p.order_id,
        'amount': p.amount,
        'status': p.status,
        'created_at': p.created_at.isoformat()
    } for p in user_payments])

# Web pages still accessible with session auth
@app.route('/products')
@jwt_required_custom
def products():
    products_list = Product.query.all()
    return render_template('products.html', products=products_list)

@app.route('/product/<int:product_id>')
@jwt_required_custom
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_details.html', product=product)

@app.route('/my-products')
@jwt_required_custom
def my_products():
    user_products = Product.query.filter_by(owner_id=current_user.id).all()
    return render_template('my_products.html', products=user_products, my_products=True)

@app.route('/orders')
@jwt_required_custom
def orders():
    user_orders = Order.query.filter_by(user_id=current_user.id).all()
    return render_template('orders.html', orders=user_orders)

@app.route('/payments')
@jwt_required_custom
def payments():
    # For the web payments page we render the newer `payment.html` template
    # Provide purchases (orders) and recent transfers expected by the template
    user_orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
    # recent in-memory transfers
    recent_transfers = transfer_records[:20]
    return render_template('payment.html', purchases=user_orders, transfers=recent_transfers)


@app.route('/api/payments/create', methods=['POST'])
@jwt_required_custom
def api_create_payment():
    """
    Create a payment via JWT token
    ---
    tags:
      - Payments
    security:
      - bearerAuth: []
    description: Create payment for product purchase (JWT protected)
    """
    current_user_id = get_jwt_identity_custom()
    data = request.json or {}
    amount = float(data.get('amount', 0) or 0)
    product_id = data.get('product_id')

    if not product_id or amount <= 0:
        return jsonify({'success': False, 'error': 'Invalid data'}), 400

    product = Product.query.get(product_id)
    if not product:
        return jsonify({'success': False, 'error': 'Product not found'}), 404

    user = User.query.get(current_user_id)
    if user.balance < amount:
        return jsonify({'success': False, 'error': 'Insufficient funds'}), 400

    # Create order and payment
    order = Order(user_id=user.id, product_id=product.id, amount=amount, status='completed', payment_method='quickpay')
    db.session.add(order)
    db.session.flush()

    payment = Payment(user_id=user.id, order_id=order.id, amount=amount, status='completed')
    db.session.add(payment)

    # Adjust balances (transfer to product owner)
    owner = User.query.get(product.owner_id)
    user.balance -= amount
    if owner:
        owner.balance += amount

    db.session.commit()

    return jsonify({'success': True, 'order_id': order.id})

@app.route('/api/profile', methods=['GET'])
@jwt_required_custom
def api_profile():
    """
    Get user profile via JWT token
    ---
    tags:
      - Users
    security:
      - bearerAuth: []
    responses:
      200:
        description: User profile
      401:
        description: Unauthorized - missing or invalid token
    """
    current_user_id = get_jwt_identity_custom()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'phone': user.phone,
        'balance': user.balance,
        'is_admin': user.is_admin,
        'auth_method': user.auth_method,
        'last_login': user.last_login.isoformat() if user.last_login else None
    })

@app.route('/api/upload', methods=['POST'])
@jwt_required_custom
def api_upload_file():
    """
    Upload file via JWT token
    ---
    tags:
      - Files
    security:
      - bearerAuth: []
    description: Upload product image or document
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # VULNERABILITY 1: No file type validation
    filename = secure_filename(file.filename)
    upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(upload_path)

    return jsonify({'message': 'File uploaded successfully', 'path': upload_path})

@app.route('/api/ai/generate', methods=['POST'])
@jwt_required_custom
def api_ai_generate():
    """
    Generate AI content via JWT token
    ---
    tags:
      - AI
    security:
      - bearerAuth: []
    description: Generate product descriptions and content via AI
    """
    try:
        data = request.json or {}
        user_input = data.get('prompt', '')
        
        if not user_input:
            return jsonify({'error': 'Prompt required'}), 400
        
        response = response_from_ai(user_input)
        
        return jsonify({'response': response})
    except Exception as e:
        return jsonify({'error': f'AI generation failed: {str(e)}'}), 500

# Web pages still accessible with session auth
@app.route('/upload')
@jwt_required_custom
def upload_file():
    return render_template('upload.html')

@app.route('/ai-tools')
@jwt_required_custom
def ai_tools():
    return render_template('ai_tools.html')

@app.route('/profile')
@jwt_required_custom
def profile():
    return render_template('profile.html')

@app.route('/admin')
@jwt_required_custom
def admin():
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    # Admin statistics
    stats = {
        'total_users': User.query.count(),
        'total_products': Product.query.count(),
        'total_orders': Order.query.count(),
        'total_revenue': db.session.query(db.func.sum(Order.amount)).scalar() or 0,
        'pending_orders': Order.query.filter_by(status='pending').count(),
        'available_products': Product.query.filter_by(is_available=True).count()
    }
    
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(10).all()
    all_users = User.query.all()
    
    return render_template('admin.html', 
                         stats=stats, 
                         recent_users=recent_users, 
                         recent_orders=recent_orders,
                         all_users=all_users)

@app.route('/api/admin/stats', methods=['GET'])
def api_admin_stats():
    """
    Get admin statistics (admin only - no JWT required)
    ---
    tags:
      - Admin
    security:
      - bearerAuth: []
    responses:
      200:
        description: Admin statistics
      403:
        description: Forbidden - admin access required
      401:
        description: Unauthorized - missing or invalid token
    """
    current_user_id = get_jwt_identity_custom()
    user = User.query.get(current_user_id)
    
    if not user or not user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    stats = {
        'total_users': User.query.count(),
        'total_products': Product.query.count(),
        'total_orders': Order.query.count(),
        'total_revenue': db.session.query(db.func.sum(Order.amount)).scalar() or 0,
        'pending_orders': Order.query.filter_by(status='pending').count(),
        'available_products': Product.query.filter_by(is_available=True).count()
    }
    
    return jsonify(stats)

@app.route('/api/admin/users', methods=['GET'])
def api_admin_users():
    """
    Get all users (admin only - no JWT required)
    ---
    tags:
      - Admin
    security:
      - bearerAuth: []
    responses:
      200:
        description: List of all users
      403:
        description: Forbidden - admin access required
      401:
        description: Unauthorized - missing or invalid token
    """
    current_user_id = get_jwt_identity_custom()
    user = User.query.get(current_user_id)
    
    if not user or not user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    all_users = User.query.all()
    return jsonify([{
        'id': u.id,
        'username': u.username,
        'email': u.email,
        'is_admin': u.is_admin,
        'balance': u.balance,
        'created_at': u.created_at.isoformat()
    } for u in all_users])

@app.route('/api/admin/orders', methods=['GET'])
def api_admin_orders():
    """
    Get all orders (admin only - no JWT required)
    ---
    tags:
      - Admin
    security:
      - bearerAuth: []
    responses:
      200:
        description: List of all orders
      403:
        description: Forbidden - admin access required
      401:
        description: Unauthorized - missing or invalid token
    """
    current_user_id = get_jwt_identity_custom()
    user = User.query.get(current_user_id)
    
    if not user or not user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    all_orders = Order.query.all()
    return jsonify([{
        'id': o.id,
        'user_id': o.user_id,
        'product_id': o.product_id,
        'amount': o.amount,
        'status': o.status,
        'created_at': o.created_at.isoformat()
    } for o in all_orders])

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/debug/verify-database', methods=['GET'])
def verify_database():
    """Verify database configuration and connectivity - LOCALHOST ONLY"""
    
    # Restrict access to localhost only
    allowed_ips = ['127.0.0.1', 'localhost', '::1']
    client_ip = request.remote_addr
    
    # Also check X-Forwarded-For header if behind proxy
    if request.headers.get('X-Forwarded-For'):
        client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    
    # Check if request is from localhost
    if client_ip not in allowed_ips:
        return jsonify({
            'status': 'error',
            'error': 'Access denied',
            'message': 'This debug endpoint is only accessible from localhost',
            'your_ip': client_ip,
            'allowed_ips': allowed_ips
        }), 403
    
    try:
        with app.app_context():
            # Get database URI from config
            db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', 'Not configured')
            
            # Get database file path from config
            db_path = '/app/instance/fashion.db'
            
            # Check if database file exists
            import os
            db_exists = os.path.exists(db_path)
            db_size = os.path.getsize(db_path) if db_exists else 0
            
            # Try to query users
            try:
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
                from sqlalchemy import inspect as sqlalchemy_inspect
                inspector = sqlalchemy_inspect(db.engine)
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
                'tables': tables if 'tables' in locals() else [],
                'user_table_columns': user_table_columns if 'user_table_columns' in locals() else [],
                'user_count': user_count if 'user_count' in locals() else None,
                'users_sample': users_info if 'users_info' in locals() else [],
                'client_ip': client_ip,
                'access_granted': True
            }
            
            if 'query_error' in locals():
                result['query_error'] = query_error
            if 'table_error' in locals():
                result['table_error'] = table_error
                
            return jsonify(result), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'error_type': type(e).__name__,
            'client_ip': client_ip,
            'access_granted': False
        }), 500

# API Authentication endpoints
@app.route('/api/auth/register', methods=['POST'])
def api_register():
    """
    Register a new user via API
    ---
    tags:
      - Authentication
    parameters:
      - name: body
        in: body
        required: true
        schema:
          properties:
            username:
              type: string
              description: Username for the new account
            email:
              type: string
              description: Email address for the new account
            password:
              type: string
              description: Password for the new account
    responses:
      200:
        description: User registered successfully
        schema:
          properties:
            message:
              type: string
      400:
        description: Invalid request or username already exists
    """
    # VULNERABLE: Mass assignment - accept any fields provided by the client
    # and pass them directly to the User model. Password is hashed but other
    # protected fields (like is_admin) can be set by the client.
    data = request.json or {}

    # Basic duplicate username check (kept for compatibility)
    if 'username' in data and User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400

    password = data.pop('password', None)
    if password:
        data['password_hash'] = generate_password_hash(password)

    # Coerce JSON fields if they arrived as strings
    coerce_user_fields(data)

    try:
        user = User(**data)
    except Exception as e:
        return jsonify({'error': 'Invalid fields provided', 'detail': str(e)}), 400

    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User created successfully'})

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """
    Login user via API and get JWT token
    ---
    tags:
      - Authentication
    parameters:
      - name: body
        in: body
        required: true
        schema:
          properties:
            username:
              type: string
              description: Username for login
            password:
              type: string
              description: Password for login
    responses:
      200:
        description: Login successful, JWT token returned
        schema:
          properties:
            access_token:
              type: string
              description: JWT access token (normal login token)
      401:
        description: Invalid credentials
      429:
        description: Rate limit exceeded
    """
    data = request.json
    client_ip = request.remote_addr
    
    # VULNERABILITY 12: Weak rate limiting for login
    if not check_login_rate_limit(client_ip):
        return jsonify({'error': 'Rate limit exceeded'}), 429
    
    # VULNERABILITY 11: Weak brute force protection
    if not check_brute_force(data.get('username', '')):
        return jsonify({'error': 'Too many failed login attempts'}), 429
    
    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password_hash, data['password']):
        record_successful_attempt(data['username'])
        
        # Update user login tracking
        user.last_login = datetime.utcnow()
        user.last_login_method = 'username_password'
        user.auth_method = 'username_password'
        db.session.commit()
        
        # Generate normal login token
        access_token = generate_normal_jwt_token(user)
        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'token_category': 'normal_login',  # Indicate this is a normal login token
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin
            }
        })
    else:
        record_failed_attempt(data.get('username', ''))
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/auth/basic-login', methods=['POST'])
def api_basic_login():
    """
    Login user via Basic Authentication
    ---
    tags:
      - Authentication
    security:
      - basicAuth: []
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
        description: Basic Auth header (base64 encoded username:password)
    responses:
      200:
        description: Login successful, JWT token returned
        schema:
          properties:
            access_token:
              type: string
            token_type:
              type: string
            expires_in:
              type: integer
      401:
        description: Invalid credentials or missing Authorization header
      429:
        description: Rate limit exceeded
    description: VULNERABLE - Basic authentication without rate limiting. Credentials sent in Authorization header (base64 encoded, easily decoded)
    """
    client_ip = request.remote_addr
    
    # VULNERABILITY 12: No rate limiting on basic auth endpoint
    user = check_basic_auth()
    
    if not user:
        # Try to get username for brute force tracking
        auth = request.authorization
        if auth:
            record_failed_attempt(auth.username)
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Success
    record_successful_attempt(user.username)
    # VULNERABILITY 13: Long JWT expiration
    access_token = generate_jwt_token(user)
    return jsonify({
        'access_token': access_token,
        'token_type': 'Bearer',
        'payload': decode_jwt_token(access_token)
    })

@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    """
    Logout user and invalidate token
    ---
    tags:
      - Authentication
    security:
      - bearerAuth: []
    responses:
      200:
        description: Logout successful
      401:
        description: Unauthorized - missing or invalid token
    description: VULNERABLE - Token blacklist is in-memory and not persistent
    """
    auth_header = request.headers.get('Authorization', '')
    
    # For demo: just return success (no blacklist)
    return jsonify({'message': 'Logged out successfully'})

@app.route('/api/auth/token-info', methods=['GET'])
def api_token_info():
    """
    Get information about current token
    ---
    tags:
      - Authentication
    security:
      - bearerAuth: []
    responses:
      200:
        description: Token information with type and auth method
        schema:
          properties:
            user_id:
              type: integer
            token_type:
              type: string
              description: Either 'normal' (username/password) or 'oauth'
            auth_method:
              type: string
            created_at:
              type: string
            last_used:
              type: string
      401:
        description: Invalid or expired token
    description: Shows detailed token information including token type and authentication method
    """
    auth_header = request.headers.get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Invalid token'}), 401
    token = auth_header.replace('Bearer ', '')
    payload = decode_jwt_token(token)
    if not payload:
        return jsonify({'error': 'Invalid token'}), 401
    return jsonify({
        'user_id': payload.get('sub'),
        'username': payload.get('name'),
        'email': payload.get('email'),
        'token_type': payload.get('token_type', 'unknown'),
        'auth_method': payload.get('auth_method', 'unknown'),
        'issued_at': payload.get('iat'),
        'expires_at': payload.get('exp'),
        'issuer': payload.get('iss'),
        'audience': payload.get('aud')
    })

@app.route('/api/auth/refresh-token', methods=['POST'])
def api_refresh_token():
    """
    Refresh access token
    ---
    tags:
      - Authentication
    security:
      - bearerAuth: []
    responses:
      200:
        description: New access token issued
        schema:
          properties:
            access_token:
              type: string
            token_type:
              type: string
            expires_in:
              type: integer
      401:
        description: Invalid or expired token
    description: VULNERABLE - No token rotation mechanism, new token issued indefinitely
    """
    auth_header = request.headers.get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Invalid token'}), 401
    token = auth_header.replace('Bearer ', '')
    payload = decode_jwt_token(token)
    if not payload:
        return jsonify({'error': 'Invalid token'}), 401
    user = User.query.get(payload.get('sub'))
    new_token = generate_jwt_token(user)
    return jsonify({
        'access_token': new_token,
        'token_type': 'Bearer',
        'payload': decode_jwt_token(new_token)
    })

# -------------------- New Vulnerable Endpoints (BOLA / IDOR / Role / Mass Assignment) --------------------

@app.route('/api/orders/<int:order_id>/details', methods=['GET'])
@jwt_required_custom
def bola_get_order_details(order_id):
    # VULNERABLE: Broken Object Level Authorization (BOLA)
    # Returns full order details without checking if requester owns the order
    # Now requires JWT authentication
  order = Order.query.get(order_id)
  if not order:
    # For demo/testing, auto-create a sample order if missing
    user = User.query.first()
    product = Product.query.first()
    if user and product:
      sample = Order(user_id=user.id, product_id=product.id, amount=100.0, status='pending', payment_method='demo')
      db.session.add(sample)
      db.session.commit()
      order = sample
    else:
      return jsonify({'error': 'Order not found'}), 404

  # Expose owner and payment info - no auth/ownership check
  return jsonify({
    'id': order.id,
    'user_id': order.user_id,
    'product_id': order.product_id,
    'amount': order.amount,
    'status': order.status,
    'payment_method': order.payment_method,
    'created_at': order.created_at.isoformat()
  })


@app.route('/api/products/<int:product_id>/owner-info', methods=['GET'])
def idor_product_owner_info(product_id):
    # VULNERABLE: Insecure Direct Object Reference (IDOR)
    # Returns owner email for any product without authorization
    # Now requires JWT authentication
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    return jsonify({
        'product_id': product.id,
        'name': product.name,
        'brand': product.brand,
        'owner_id': product.owner_id,
        'owner_email': product.owner.email if product.owner else None
    })


@app.route('/api/products/<int:product_id>/transfer-ownership', methods=['POST'])
def idor_transfer_product(product_id):
  # VULNERABLE: IDOR - allows changing ownership without authorization
  # Now requires JWT authentication
  product = Product.query.get(product_id)
  if not product:
    return jsonify({'error': 'Product not found'}), 404

  data = request.json or {}
  new_owner_username = data.get('username')
  if not new_owner_username:
    return jsonify({'error': 'username required'}), 400

  new_owner = User.query.filter_by(username=new_owner_username).first()
  if not new_owner:
    return jsonify({'error': 'New owner not found'}), 404

  product.owner_id = new_owner.id
  db.session.commit()

  return jsonify({'message': 'Ownership transferred', 'product_id': product.id, 'new_owner_username': new_owner.username})


@app.route('/api/admin/promote', methods=['POST'])
def promote_user_vulnerable():
  # VULNERABLE: Function/Role level access - no admin check
  # No JWT required - intentional vulnerability for testing
  data = request.json or {}
  username = data.get('username')
  if not username:
    return jsonify({'error': 'username required'}), 400

  user = User.query.filter_by(username=username).first()
  if not user:
    return jsonify({'error': 'User not found'}), 404

  # No check to ensure caller is admin
  user.is_admin = True
  db.session.commit()

  return jsonify({'message': 'User promoted to admin', 'username': user.username})


@app.route('/api/secure/delete-user/<int:user_id>', methods=['DELETE'])
@jwt_required_custom
def delete_user_vulnerable(user_id):
    # VULNERABLE: Function-level access mistake - endpoint requires JWT but not role check
    # Any authenticated user can delete arbitrary users
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted', 'user_id': user_id})


# -------------------- Injection / SSRF / Command / GraphQL / gRPC Vulnerabilities --------------------


@app.route('/api/users/search', methods=['GET'])
@jwt_required_custom
def users_search_sql():
    """
    Search users (note: intentionally unsafe SQL concatenation)
    ---
    tags:
      - Users
    security:
      - bearerAuth: []
    parameters:
      - name: q
        in: query
        type: string
        required: true
        description: Raw search string that will be interpolated into SQL
    description: Constructs raw SQL by concatenating user input (demonstrates SQL injection). Now requires JWT authentication.
    """
    q = request.args.get('q', '')

    # VULNERABILITY: Raw SQL concatenation with user input (intentional for testing)
    # FIXED: Use proper string interpolation to make SQL injection work
    sql = f"SELECT id, username, email, password_hash FROM user WHERE username LIKE '%{q}%'"
    
    try:
        # FIXED: Use text() with string literal, not parameterized
        # This makes it truly vulnerable to SQL injection
        result = db.session.execute(text(sql).bindparams())
        
        rows = []
        for r in result.fetchall():
            rows.append({
                'id': r[0], 
                'username': r[1], 
                'email': r[2], 
                'password_hash': r[3]
            })
        
        # FIXED: Also return the actual SQL query executed (for demo purposes)
        return jsonify({
            'sql_query': sql,  # Show the actual SQL with injected payload
            'results': rows,
            'result_count': len(rows),
            'vulnerable': True,
        })
        
    except Exception as e:
        # FIXED: Return detailed error with SQL query for debugging SQLi
        return jsonify({
            'error': 'Query failed', 
            'sql_query': sql,  # Show the SQL that caused error
            'detail': str(e),
        }), 500


@app.route('/api/users/filter', methods=['POST'])
@jwt_required_custom
def users_filter_nosql_like():
    """
    Filter users using a **safe** subset of NoSQL-like operators.

    This endpoint previously supported a `$where` operator evaluated via
    Python `eval`, making it trivially exploitable for NoSQLi / RCE-style
    attacks. The implementation has been rewritten to:
      - **Reject** any use of `$where` (both top-level and per-field)
      - **Only allow** simple, parameterized comparisons on a small
        whitelist of fields and operators, which are translated to
        SQLAlchemy filter expressions.
    """
    payload = request.json or {}
    filter_dict = payload.get('filter', {})

    # Support both object filters and JSON-encoded string filters coming from clients
    if isinstance(filter_dict, str):
        try:
            filter_dict = json.loads(filter_dict)
        except Exception:
            # Malformed JSON/string payload - return a clear error instead of doing nothing
            return jsonify({
                'error': 'Invalid filter format. Expected an object or JSON string.',
                'hint': 'Example: {"filter": {"username": {"$regex": "john"}}}'
            }), 400

    if not isinstance(filter_dict, dict):
        filter_dict = {}

    # Reject any attempt to use a top-level $where - classic NoSQLi vector
    if '$where' in filter_dict:
        return jsonify({'error': 'The $where operator is not supported for security reasons.'}), 400

    # Allowed fields and operators for direct filtering
    allowed_fields = {'id', 'username', 'email', 'balance'}
    allowed_operators = {
        '$eq', '$ne', '$gt', '$gte', '$lt', '$lte',
        '$in', '$nin', '$regex', '$exists'
    }

    # Process simple NoSQL-like operators per field in a safe way
    query = User.query
    applied_any_filter = False
    for field, condition in filter_dict.items():
        # If someone sneaks in operators on non-allowed fields, ignore them
        if field not in allowed_fields:
            continue

        if isinstance(condition, dict):
            for operator, value in condition.items():
                # Explicitly block any per-field $where usage
                if operator == '$where':
                    return jsonify({'error': 'The $where operator is not supported for security reasons.'}), 400

                if operator not in allowed_operators:
                    # Unknown operator - skip it instead of evaluating dynamically
                    continue

                if operator == '$eq':
                    query = query.filter(getattr(User, field) == value)
                elif operator == '$ne':
                    query = query.filter(getattr(User, field) != value)
                elif operator == '$gt':
                    query = query.filter(getattr(User, field) > value)
                elif operator == '$gte':
                    query = query.filter(getattr(User, field) >= value)
                elif operator == '$lt':
                    query = query.filter(getattr(User, field) < value)
                elif operator == '$lte':
                    query = query.filter(getattr(User, field) <= value)
                elif operator == '$in':
                    query = query.filter(getattr(User, field).in_(value))
                elif operator == '$nin':
                    query = query.filter(~getattr(User, field).in_(value))
                elif operator == '$regex':
                    query = query.filter(getattr(User, field).like(f"%{value}%"))
                elif operator == '$exists':
                    if bool(value):
                        query = query.filter(getattr(User, field) != None)
                    else:
                        query = query.filter(getattr(User, field) == None)
                applied_any_filter = True
        else:
            query = query.filter(getattr(User, field) == condition)
            applied_any_filter = True

    # If the client sent an invalid/non-object filter (e.g., `1`) or all
    # fields/operators were ignored, do NOT leak all users - respond clearly.
    if not applied_any_filter:
        return jsonify({
            'error': 'No valid filters were provided.',
        }), 400

    users = query.all()
    results = [
        {'id': u.id, 'username': u.username, 'email': u.email, 'balance': u.balance}
        for u in users
    ]
    return jsonify(results)

# Command Injection: SKU lookup (unsafe)
@app.route('/api/inventory/sku-lookup', methods=['POST'])
@jwt_required_custom
def inventory_sku_lookup():
    """
    SKU lookup (unsafe command execution demo)
    ---
    tags:
      - FashionForge
    security:
      - bearerAuth: []
    description: Looks up SKU using shell command (demonstrates command injection). Now requires JWT authentication.
    """
    data = request.json or {}
    sku = data.get('sku', '')
    if not sku:
        return jsonify({'error': 'sku parameter required'}), 400

    # VULNERABILITY: Actually execute the input as a shell command (for demo only!)
    cmd = sku
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True, timeout=5)
        return jsonify({'output': output})
    except subprocess.CalledProcessError as e:
        return jsonify({'error': 'Command failed', 'detail': e.output}), 500
    except Exception as e:
        return jsonify({'error': 'Execution error', 'detail': str(e)}), 500


@app.route('/api/network/fetch', methods=['POST'])
@jwt_required_custom
def network_fetch_url():
    """
    Fetch arbitrary URL (SSRF demo)
    ---
    tags:
      - Network
    security:
      - bearerAuth: []
    description: Fetches arbitrary URLs provided by user without validation (demonstrates SSRF). Now requires JWT authentication.
    """
    data = request.json or {}
    url = data.get('url')
    if not url:
        return jsonify({'error': 'url parameter required'}), 400

    # VULNERABILITY: No validation of destination (allows internal network access)
    # VULNERABILITY: Supports multiple protocols and bypass techniques
    try:
        # VULNERABILITY: No protocol restriction - allows file://, gopher://, dict://, etc.
        # VULNERABILITY: No DNS resolution validation
        # VULNERABILITY: No internal IP blocking
        
        headers = {
            'User-Agent': 'FashionForge-API/1.0',
            'Accept': '*/*'
        }
        
        # VULNERABILITY: Follow redirects (allows redirect attacks)
        resp = requests.get(
            url, 
            timeout=10,
            headers=headers,
            allow_redirects=True,  # VULNERABILITY: Allows redirect to internal services
            verify=False  # VULNERABILITY: Disables SSL verification
        )
        
        # Return more detailed information for SSRF exploitation
        result = {
            'status_code': resp.status_code,
            'url': resp.url,  # VULNERABILITY: Exposes final URL after redirects
            'headers': dict(resp.headers),  # VULNERABILITY: Exposes response headers
            'content': resp.text[:1000],  # Increased content limit
            'history': []  # VULNERABILITY: Exposes redirect history
        }
        
        # Include redirect history for chained SSRF attacks
        for redirect in resp.history:
            result['history'].append({
                'url': redirect.url,
                'status_code': redirect.status_code
            })
            
        return jsonify(result)
        
    except requests.exceptions.Timeout:
        return jsonify({'error': 'Request timeout', 'type': 'timeout'}), 408
    except requests.exceptions.ConnectionError as e:
        # VULNERABILITY: Leaks internal network information through error messages
        error_msg = str(e)
        if 'Name or service not known' in error_msg:
            return jsonify({'error': 'DNS resolution failed', 'detail': error_msg}), 400
        elif 'Connection refused' in error_msg:
            return jsonify({'error': 'Connection refused', 'detail': error_msg, 'hint': 'Service might be running internally'}), 400
        else:
            return jsonify({'error': 'Connection failed', 'detail': error_msg}), 400
    except requests.exceptions.TooManyRedirects:
        return jsonify({'error': 'Too many redirects', 'type': 'redirect_loop'}), 400
    except Exception as e:
        # VULNERABILITY: Detailed error messages help attackers
        return jsonify({'error': 'Fetch failed', 'detail': str(e), 'type': 'general_error'}), 500


@app.route('/api/stream/product-feed', methods=['GET'])
@jwt_required_custom
def stream_product_feed_unrestricted():
    """
    Product feed stream 
    ---
    tags:
      - Stream
    security:
      - bearerAuth: []
    parameters:
      - name: count
        in: query
        type: integer
        required: false
        description: Number of updates to stream
    description: Streams arbitrary number of updates without auth or size limits (demonstrates resource exhaustion). Now requires JWT authentication.
    """
    try:
        count = int(request.args.get('count', 1000))
    except Exception:
        count = 1000

    def generate():
        i = 0
        while i < count:
            i += 1
            # No authentication or backpressure - potential resource exhaustion
            yield f"data: product_update {i}\n\n"
            time.sleep(0.01)

    return app.response_class(generate(), mimetype='text/event-stream')

@app.route('/api/products/<int:product_id>/purchase', methods=['POST'])
@jwt_required_custom
def purchase_product(product_id):
    """Purchase a product endpoint - WITH PARAMETER TAMPERING VULNERABILITY"""
    try:
        # Get JSON data safely - NOW ACCEPTING BODY PARAMETERS
        data = request.get_json(silent=True) or {}
        print(f"Purchase request for product {product_id}, data: {data}")
        
        product = Product.query.get(product_id)
        if not product:
            return jsonify({'success': False, 'error': 'Product not found'}), 404
        
        if not product.is_available:
            return jsonify({'success': False, 'error': 'Product is not available'}), 400
        
        if product.owner_id == current_user.id:
            return jsonify({'success': False, 'error': 'You cannot purchase your own product'}), 400

        user = User.query.get(current_user.id)
        
        # VULNERABILITY 1: Check if price_override was provided in request
        # This allows direct price manipulation!
        if 'price_override' in data:
            purchase_amount = float(data['price_override'])
            print(f"VULNERABILITY: Using price_override ${purchase_amount} instead of actual price ${product.price}")
            
            # VULNERABILITY 2: Weak validation
            if purchase_amount <= 0:
                return jsonify({'success': False, 'error': 'Price must be positive'}), 400
                
            # VULNERABILITY 3: Allows ridiculously low prices
            if purchase_amount < 1.00:  # Only prevents $0 purchases
                purchase_amount = 1.00
                
        else:
            # Default to actual price
            purchase_amount = float(product.price)
        
        # VULNERABILITY 4: Check if discount_code was provided
        if 'discount_code' in data:
            discount_code = data['discount_code']
            # VULNERABILITY: No server-side validation of discount codes
            # Client can send any discount percentage
            if discount_code == "SAVE10":
                purchase_amount *= 0.90  # 10% off
            elif discount_code == "SAVE50":
                purchase_amount *= 0.50  # 50% off - WEAK!
            elif discount_code == "SAVE99":  # Hidden code not shown in UI
                purchase_amount *= 0.01  # 99% off - HUGE VULNERABILITY!
            elif discount_code == "FREE":  # Another hidden code
                purchase_amount = 0.01  # Almost free!
        
        if user.balance < purchase_amount:
            return jsonify({'success': False, 'error': 'Insufficient funds'}), 400

        # VULNERABILITY 5: Check if special_offer parameter exists
        special_offer = data.get('special_offer', False)
        if special_offer and purchase_amount > 1000:
            # "Special offer" halves the price for expensive products
            purchase_amount /= 2
            print(f"VULNERABILITY: Applied special offer, new price: ${purchase_amount}")

        # Create order
        order = Order(
            user_id=user.id, 
            product_id=product.id, 
            amount=purchase_amount,  # VULNERABILITY: Could be tampered price
            status='completed', 
            payment_method=data.get('payment_method', 'web_purchase')
        )
        db.session.add(order)
        db.session.flush()
        
        print(f"VULNERABLE ORDER: User paid ${purchase_amount} for ${product.price} product")

        # Create payment with the order ID
        payment = Payment(
            user_id=user.id, 
            order_id=order.id,
            amount=purchase_amount,  # VULNERABILITY: Tampered amount
            status='completed'
        )
        db.session.add(payment)

        # Transfer funds
        owner = User.query.get(product.owner_id)
        user.balance -= purchase_amount  # User pays tampered amount
        if owner:
            owner.balance += purchase_amount  # Owner receives tampered amount

        # Mark product as sold
        product.is_available = False

        db.session.commit()

        return jsonify({
            'success': True, 
            'order_id': order.id,
            'message': f'Successfully purchased {product.name} by {product.brand}',
            'actual_price': product.price,  # Show actual for comparison
            'paid_amount': purchase_amount,  # Show what user actually paid
            'discount_applied': product.price - purchase_amount,
            'new_balance': user.balance,
            'vulnerability_exploited': True if purchase_amount < product.price else False
        })

    except Exception as e:
        db.session.rollback()
        print(f"Purchase error: {str(e)}")
        return jsonify({'success': False, 'error': f'Purchase failed: {str(e)}'}), 500
# -------------------------------------------------------------------------------------------------------------

# -------------------------------------------------------------------------------------------------------------

# Flag de reto en la respuesta (ver flags.py)
app.after_request(flags_apply_hook)

def init_db():
    with app.app_context():
        db.create_all()
        
        # Create test data
        if not User.query.first():
            # Create admin user
            admin = User(
                username='admin',
                email='admin@vuln.internal',
                password_hash=generate_password_hash('admin123'),
                balance=10000.0,
                is_admin=True,  # Explicitly set as admin
                auth_method='username_password',  # Normal login
                last_login_method='username_password'
            )
            db.session.add(admin)
            
            # Create regular user
            user1 = User(
                username='john',
                email='john@example.com',
                password_hash=generate_password_hash('password123'),
                balance=5000.0,
                is_admin=False,  # Explicitly set as non-admin
                auth_method='username_password',  # Normal login
                last_login_method='username_password'
            )
            db.session.add(user1)

            user2 = User(
                username='jim',
                email='jim@example.com',
                password_hash=generate_password_hash('password123'),
                balance=5000.0,
                is_admin=False,  # Explicitly set as non-admin
                auth_method='username_password',  # Normal login
                last_login_method='username_password'
            )
            db.session.add(user2)

            # Create another admin for testing
            admin2 = User(
                username='superadmin',
                email='superadmin@vuln.internal',
                password_hash=generate_password_hash('super123'),
                balance=15000.0,
                is_admin=True,
                auth_method='username_password',  # Normal login
                last_login_method='username_password'
            )
            db.session.add(admin2)
            
            # Create some products (clothing)
            products = [
                Product(name='Classic Tee', brand='Essential Wear', category='T-Shirt', price=25.0, size='M', color='Black', material='Cotton', sku='TSH-BLK-M-001', owner_id=2),
                Product(name='Skinny Jeans', brand='Denim Co', category='Pants', price=60.0, size='32', color='Blue', material='Denim', sku='PNT-BLU-32-002', owner_id=3),
                Product(name='Leather Jacket', brand='Moto Style', category='Jacket', price=120.0, size='L', color='Brown', material='Leather', sku='JCK-BRN-L-003', owner_id=2),
                Product(name='Running Sneakers', brand='Stride', category='Shoes', price=85.0, size='9', color='White', material='Mesh', sku='SHO-WHT-9-004', owner_id=3),
            ]
            
            for product in products:
                db.session.add(product)
            
            db.session.commit()

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    
    init_db()
    app.run(debug=True, port=5000)