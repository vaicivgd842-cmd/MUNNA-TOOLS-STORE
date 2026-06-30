import os
import logging
import warnings
from flask import Flask
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

# Suppress the Flask-Limiter in-memory storage warning (it's safe for single-node setups)
warnings.filterwarnings("ignore", category=UserWarning, module="flask_limiter")

csrf = CSRFProtect()

# Use a file/redis storage in production; in-memory is fine for dev
_limiter_storage = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
limiter = Limiter(
    get_remote_address,
    default_limits=["5000 per hour", "100 per minute"],
    storage_uri=_limiter_storage,
)

def create_app():
    app = Flask(
        __name__,
        template_folder='../templates',
        static_folder='../static'
    )
    
    _is_production = os.getenv("FLASK_ENV", "development").lower() == "production"

    # Load config directly from env or app/config
    app.config.update(
        SECRET_KEY=os.getenv("SECRET_KEY"),
        SESSION_COOKIE_SECURE=_is_production,   # Only True over HTTPS in production
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=int(os.getenv("SESSION_LIFETIME_MINUTES", "60")) * 60,
    )
    
    # Init extensions
    csrf.init_app(app)
    limiter.init_app(app)
    
    # Proxy fix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
    
    # Set up basic logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Register blueprints
    from .legacy_admin import legacy_bp
    app.register_blueprint(legacy_bp)
    
    from app.store import store_bp
    app.register_blueprint(store_bp) # Removed url_prefix as routes already have /store in them
    
    return app
