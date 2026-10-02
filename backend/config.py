import os
from datetime import timedelta

class Config:
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'sentinel-ai-dev-secret-key-change-in-production-2024'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'sentinel-ai-jwt-secret-change-in-production'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    
    # AI API Keys configuration
    OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
    GROQ_API_KEY = os.environ.get('GROQ_API_KEY')

    # PostgreSQL connection string. Falls back to a local PostgreSQL instance
    # if DATABASE_URL is not set in the environment.
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:Aa2002036478%40%25@db.nyseslspfmtogcuyoom.supabase.co:5432/postgres'
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Connection pool tuning, suitable for a production PostgreSQL deployment.
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': int(os.environ.get('DB_POOL_SIZE', 10)),
        'max_overflow': int(os.environ.get('DB_MAX_OVERFLOW', 20)),
        'pool_timeout': int(os.environ.get('DB_POOL_TIMEOUT', 30)),
        'pool_recycle': int(os.environ.get('DB_POOL_RECYCLE', 1800)),
        'pool_pre_ping': True,
    }
    CORS_HEADERS = 'Content-Type'
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024
    ALLOWED_EXTENSIONS = {'pdf', 'txt', 'log', 'py', 'js', 'html', 'csv', 'json'}
    LOG_DIR = os.path.join(BASE_DIR, 'logs')
    SYSGUARD_HISTORY_SIZE = 60
    SYSGUARD_ANOMALY_THRESHOLD = 2.0

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///sentinel_dev.db'
 

class TestingConfig(Config):
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_ENGINE_OPTIONS = {}
    SERVER_NAME = 'localhost'

config_by_name = {
    'dev': DevelopmentConfig,
    'prod': ProductionConfig,
    'test': TestingConfig
}