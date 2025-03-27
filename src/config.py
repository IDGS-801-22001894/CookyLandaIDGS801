# config.py
class Config:
    SECRET_KEY = 'B!1w8NAt1T^%kvhUI*S^'  # Cambia esto por una clave secreta segura

class DevelopmentConfig(Config):
    DEBUG = True
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'root'
    MYSQL_PASSWORD = 'root'  # Cambia esto por tu contraseña de MySQL
    MYSQL_DB = 'cookylanda'

config = {
    'development': DevelopmentConfig
}