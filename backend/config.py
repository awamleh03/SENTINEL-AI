import os
from datetime import timedelta


class Config:
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'sentinel-ai-dev-secret-key-change-in-production-2024'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'sentinel-ai-jwt-secret-change-in-production'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(BASE_DIR, 'sentinel_ai.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
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
    TESTING = False


class TestingConfig(Config):
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SERVER_NAME = 'localhost'


config_by_name = {
    'dev': DevelopmentConfig,
    'prod': ProductionConfig,
    'test': TestingConfig
}
