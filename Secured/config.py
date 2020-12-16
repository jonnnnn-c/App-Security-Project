import os
import sys
import json
import secrets
import config_encrypt

basedir = os.path.abspath(os.path.dirname(__file__))

# Decrypting config.json file

try:
    key = config_encrypt.generate_key(2)
    config_file = config_encrypt.decrypt('etc/settings/config.json', key)
    config = json.loads(config_file)
except:
    sys.exit('INCORRECT PASSWORD! PROGRAM STOPPED')


class Config(object):
    DEBUG = False
    TESTING = False

    # Database config
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'store.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Authentication Config
    JWT_SECRET_KEY = secrets.token_urlsafe()
    # JWT_ACCESS_TOKEN_EXPIRES = 600
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access']

    # Mail config
    MAIL_SERVER = config.get('MAIL_SERVER')
    MAIL_PORT = config.get('MAIL_PORT')
    MAIL_USERNAME = config.get('MAIL_USERNAME')
    MAIL_PASSWORD = config.get('MAIL_PASSWORD')
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_FROM_EMAIL = config.get('MAIL_FROM_EMAIL')

    SECRET_KEY = secrets.token_urlsafe()
    SECURITY_PASSWORD_SALT = secrets.token_urlsafe()

    # Twilio setup
    TWILIO_ACCOUNT_SID = config.get('TWILIO_ACCOUNT_SID')
    TWILIO_AUTH_TOKEN = config.get('TWILIO_AUTH_TOKEN')

    # Pyotp
    PYOTP = config.get('PYOTP')

    # Pagination
    PAGINATE_PAGE_SIZE = 20
    PAGINATE_PAGE_PARAM = "pagenumber"
    PAGINATE_RESOURCE_LINKS_ENABLED = True


class ProductionConfig(Config):
    ENV = "production"


class DevelopmentConfig(Config):
    DEBUG = True
    ENV = "development"
