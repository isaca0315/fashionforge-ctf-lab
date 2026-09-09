import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'strong-secret-key-changeme')
    
    # Use absolute path for database - works both in Docker and locally
    db_path = '/app/instance/fashion.db'
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{db_path}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    
    # Enhanced OAuth2 Configuration
    OAUTH2_PROVIDER_URL = 'http://oauth:5001'
    OAUTH2_CLIENT_ID = 'auto_client'
    OAUTH2_CLIENT_SECRET = os.environ.get('OAUTH2_CLIENT_SECRET', 'strong_client_secret_here')
    
    # Security settings
    JWT_ALGORITHM = 'HS256'
    OAUTH2_SCOPE = 'openid profile products'
    
    # Session security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_SAMESITE = 'Lax'