import os
from datetime import timedelta

class Config:
    """Application configuration - use env vars in production."""
    # Secret key: set SECRET_KEY in environment for production
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }
    
    # Session security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'
    SESSION_COOKIE_DOMAIN = None
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    SESSION_REFRESH_EACH_REQUEST = True
    
    # CSRF Protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour
    
    # Workflow options
    WORKFLOW_STATUSES = ['Created', 'In Progress', 'Completed', 'Cancelled']
    PRIORITY_LEVELS = ['Low', 'Medium', 'High', 'Critical']
    USER_ROLES = ['Admin', 'User']
    
    # File upload
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'zip'}
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB per file
    
    # Pagination
    ITEMS_PER_PAGE = 10
    MAX_ITEMS_PER_PAGE = 100
    
    # Password policy (Enhanced)
    PASSWORD_MIN_LENGTH = 12
    PASSWORD_REQUIRE_DIGIT = True
    PASSWORD_REQUIRE_LETTER = True
    PASSWORD_REQUIRE_SPECIAL = True
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_HISTORY_COUNT = 5  # Prevent reusing last 5 passwords
    
    # Input validation max lengths
    USERNAME_MAX_LENGTH = 50
    EMAIL_MAX_LENGTH = 254  # RFC 5321 limit
    TITLE_MAX_LENGTH = 200
    DESCRIPTION_MAX_LENGTH = 10000
    COMMENT_MAX_LENGTH = 2000
    
    # Rate limiting (Enhanced)
    RATE_LIMIT_LOGIN_PER_MINUTE = 3
    RATE_LIMIT_GENERAL_PER_MINUTE = 100
    RATE_LIMIT_WORKFLOW_PER_MINUTE = 20
    RATE_LIMIT_API_PER_MINUTE = 60

    # Account lockout
    LOGIN_MAX_ATTEMPTS = 5
    LOGIN_LOCKOUT_MINUTES = 15
    
    # Security Headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';"
    }
    
    API_PREFIX = '/api/v1'
    
    # Workflow categories (optional filter)
    WORKFLOW_CATEGORIES = ['General', 'Development', 'Marketing', 'Support', 'HR', 'Finance', 'Operations', 'Other']
    
    # Email (optional - leave unset to disable)
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'false').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'your-gmail@gmail.com')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', 'your-app-password')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'your-gmail@gmail.com')
    MAIL_MAX_EMAILS = 5
    
    # Due date reminders: notify when workflow is due within N days
    DUE_SOON_DAYS = 3
    
    # Caching (Redis)
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    CACHE_TYPE = 'RedisCache'
    CACHE_REDIS_URL = REDIS_URL
    CACHE_DEFAULT_TIMEOUT = 300  # 5 minutes
    
    # Activity logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'app.log')
    
    # Search
    SEARCH_MIN_LENGTH = 3
    SEARCH_MAX_LENGTH = 100
    
    # Bulk operations
    BULK_OPERATION_MAX_ITEMS = 100
    
    # Template system
    WORKFLOW_TEMPLATES = {
        'Bug Report': {
            'description': 'Template for reporting software bugs',
            'priority': 'High',
            'category': 'Development'
        },
        'Feature Request': {
            'description': 'Template for requesting new features',
            'priority': 'Medium', 
            'category': 'Development'
        },
        'Customer Support': {
            'description': 'Template for customer support tickets',
            'priority': 'Medium',
            'category': 'Support'
        }
    }
