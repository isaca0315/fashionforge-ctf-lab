# graphql_vuln.py
from flask import Blueprint, request, jsonify, render_template
from models import db, User, Product, Order
import json
import subprocess
import os
import inspect
import io
import sys

graphql_blueprint = Blueprint('graphql', __name__, url_prefix='/graphql')

# Single GraphQL Interface Page
@graphql_blueprint.route('/')
def graphql_interface():
    """Single GraphQL Interface with Playground and IDE combined"""
    return render_template('graphql_interface.html')

# Main GraphQL endpoint
@graphql_blueprint.route('/query', methods=['POST'])
def graphql_query():
    """
    Main GraphQL endpoint with GraphQL injection vulnerabilities
    """
    body = request.json or {}
    query = body.get('query', '')
    variables = body.get('variables', {})
    
    try:
        # VULNERABILITY: Direct eval/exec of GraphQL-like queries
        result = execute_graphql_query_unsafe(query, variables)
        return jsonify({'data': result})
    except Exception as e:
        return jsonify({'errors': [{'message': str(e)}]}), 400

def execute_graphql_query_unsafe(query, variables):
    """VULNERABLE: Unsafe GraphQL query execution"""
    
    # VULNERABILITY 1: GraphQL Introspection & Schema Discovery
    if '__schema' in query or '__type' in query or 'introspection' in query.lower():
        return handle_introspection_query(query)
    
    # VULNERABILITY 2: Enhanced Python code execution with output capture
    if 'exec(' in query or 'eval(' in query:
        return handle_code_execution(query)
    
    # VULNERABILITY 3: Direct OS command execution with output
    if any(cmd in query for cmd in ['os.system', 'subprocess.', 'import os', 'import subprocess']):
        return handle_os_commands(query)
    
    # VULNERABILITY 4: File reading operations
    if 'open(' in query and 'read()' in query:
        return handle_file_operations(query)
    
    # VULNERABILITY 5: Unsafe field access through getattr
    if 'user' in query.lower():
        return handle_user_data_exposure()
    
    # VULNERABILITY 6: Unsafe product data exposure
    if 'product' in query.lower():
        return handle_product_data_exposure()
    
    # VULNERABILITY 7: Direct Python expression evaluation in filters
    if 'filter' in query.lower() and 'users' in query.lower():
        return handle_user_filtering(query)
    
    # VULNERABILITY 8: Application source code discovery
    if 'source' in query.lower() or 'code' in query.lower():
        return handle_source_code_discovery(query)
    
    return {'message': 'No data found for query'}

def handle_introspection_query(query):
    """Handle GraphQL introspection queries with proper response structure"""
    
    # Define a mock schema structure
    query_type = {
        'name': 'Query',
        'kind': 'OBJECT',
        'description': 'The root query type',
        'fields': [
            {
                'name': 'users',
                'description': 'Get all users',
                'type': {
                    'name': 'User',
                    'kind': 'OBJECT'
                }
            },
            {
                'name': 'products',
                'description': 'Get all products',
                'type': {
                    'name': 'Product',
                    'kind': 'OBJECT'
                }
            },
            {
                'name': '__schema',
                'description': 'GraphQL schema introspection',
                'type': {
                    'name': '__Schema',
                    'kind': 'OBJECT'
                }
            },
            {
                'name': '__type',
                'description': 'GraphQL type introspection',
                'type': {
                    'name': '__Type',
                    'kind': 'OBJECT'
                }
            }
        ]
    }
    
    user_type = {
        'name': 'User',
        'kind': 'OBJECT',
        'description': 'A user in the system',
        'fields': [
            {
                'name': 'id',
                'description': 'User ID',
                'type': {
                    'name': 'ID',
                    'kind': 'SCALAR'
                }
            },
            {
                'name': 'username',
                'description': 'Username',
                'type': {
                    'name': 'String',
                    'kind': 'SCALAR'
                }
            },
            {
                'name': 'email',
                'description': 'Email address',
                'type': {
                    'name': 'String',
                    'kind': 'SCALAR'
                }
            },
            {
                'name': 'balance',
                'description': 'Account balance',
                'type': {
                    'name': 'Float',
                    'kind': 'SCALAR'
                }
            },
            {
                'name': 'is_admin',
                'description': 'Is user an admin',
                'type': {
                    'name': 'Boolean',
                    'kind': 'SCALAR'
                }
            }
        ]
    }
    
    product_type = {
        'name': 'Product',
        'kind': 'OBJECT',
        'description': 'A product in the system',
        'fields': [
            {
                'name': 'id',
                'description': 'Product ID',
                'type': {
                    'name': 'ID',
                    'kind': 'SCALAR'
                }
            },
            {
                'name': 'name',
                'description': 'Product name',
                'type': {
                    'name': 'String',
                    'kind': 'SCALAR'
                }
            },
            {
                'name': 'brand',
                'description': 'Product brand',
                'type': {
                    'name': 'String',
                    'kind': 'SCALAR'
                }
            },
            {
                'name': 'category',
                'description': 'Clothing category',
                'type': {
                    'name': 'String',
                    'kind': 'SCALAR'
                }
            },
            {
                'name': 'price',
                'description': 'Product price',
                'type': {
                    'name': 'Float',
                    'kind': 'SCALAR'
                }
            },
            {
                'name': 'sku',
                'description': 'Product SKU',
                'type': {
                    'name': 'String',
                    'kind': 'SCALAR'
                }
            }
        ]
    }
    
    # Build the schema response
    schema_response = {
        'queryType': {'name': 'Query'},
        'mutationType': None,
        'subscriptionType': None,
        'types': [
            query_type,
            user_type,
            product_type,
            {
                'name': 'String',
                'kind': 'SCALAR',
                'description': 'The String scalar type',
                'fields': None
            },
            {
                'name': 'Int',
                'kind': 'SCALAR', 
                'description': 'The Int scalar type',
                'fields': None
            },
            {
                'name': 'Float',
                'kind': 'SCALAR',
                'description': 'The Float scalar type',
                'fields': None
            },
            {
                'name': 'Boolean',
                'kind': 'SCALAR',
                'description': 'The Boolean scalar type',
                'fields': None
            },
            {
                'name': 'ID',
                'kind': 'SCALAR',
                'description': 'The ID scalar type',
                'fields': None
            }
        ]
    }
    
    return {'__schema': schema_response}

# Keep all other functions the same as in your original code
def handle_code_execution(query):
    """Handle Python code execution with complete output capture"""
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stdout = captured_output = io.StringIO()
    sys.stderr = captured_error = io.StringIO()

    try:
        result = None
        if 'exec(' in query:
            exec(query)
            result = captured_output.getvalue() or captured_error.getvalue()
        elif 'eval(' in query:
            result = eval(query)
    except Exception as e:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        return {'error': f'Code execution failed: {str(e)}'}

    sys.stdout = old_stdout
    sys.stderr = old_stderr
    if result is not None:
        return {'output': str(result)}
    return {'error': 'No valid code found to execute'}

def handle_os_commands(query):
    """Handle OS command execution with proper output capture"""
    try:
        if 'os.system' in query or 'subprocess.' in query:
            exec(query, {'__builtins__': __builtins__, 'os': os, 'subprocess': subprocess})
            return {'command': 'executed'}
    except Exception as e:
        return {'error': f'Command execution failed: {str(e)}'}
    return {'error': 'No valid command found'}

def handle_file_operations(query):
    """Handle file reading operations"""
    try:
        if 'open(' in query and 'read()' in query:
            import re as _re
            m = _re.search(r'open\(\s*[\'"]([^\'"]+)[\'"]', query)
            if not m:
                raise ValueError('could not parse file path')
            file_path = m.group(1)
            with open(file_path, 'r') as f:
                content = f.read()
            return {'content': content[:2000]}
    except Exception as e:
        return {'error': f'File reading failed: {str(e)}'}
    return {'error': 'No valid file operation found'}

def handle_user_data_exposure():
    """Expose all user data"""
    # ... (keep the same implementation as before)
    users = User.query.all()
    result = []
    for user in users:
        user_data = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'balance': user.balance,
            'is_admin': user.is_admin,
            'password_hash': user.password_hash
        }
        result.append(user_data)
    return {'users': result}

def handle_product_data_exposure():
    """Expose all product data"""
    # ... (keep the same implementation as before)
    products = Product.query.all()
    result = []
    for product in products:
        product_data = {
            'id': product.id,
            'name': product.name,
            'brand': product.brand,
            'category': product.category,
            'price': product.price,
            'sku': product.sku,
            'owner': {
                'id': product.owner.id,
                'username': product.owner.username,
                'email': product.owner.email
            } if product.owner else None
        }
        result.append(product_data)
    return {'products': result}

def handle_user_filtering(query):
    """Handle unsafe user filtering"""
    users = User.query.all()
    if 'where:' in query:
        expr = query.split('where:')[1].split(')')[0].strip()
        filtered = []
        for user in users:
            try:
                ns = {'user': user, 'True': True}
                if eval(expr, {}, ns):
                    filtered.append(user)
            except Exception:
                continue
        return {'users': [{'id': u.id, 'username': u.username, 'email': u.email, 'balance': u.balance} for u in filtered]}
    return {'users': []}

def handle_source_code_discovery(query):
    """Handle source code discovery attempts"""
    return {'source_discovery': 'The GraphQL resolver is vulnerable. Apps in scope: Fashion API'}