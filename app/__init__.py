# app/__init__.py
import os
from flask import Flask
from dotenv import load_dotenv

def create_app():
    # Load .env (for secret key, API tokens, etc.)
    load_dotenv()

    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")
    app.config["JSONIFY_PRETTYPRINT_REGULAR"] = False

    # Security headers (CSP, HSTS etc.)
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
            "img-src 'self' data: https:;"
        )
        return response

    @app.context_processor
    def inject_site_url():
        from flask import request
        site_url = os.getenv("SITE_URL", "").rstrip("/")
        if not site_url:
            site_url = request.url_root.rstrip("/")
        return dict(site_url=site_url)

    # Register Blueprint with all routes
    from .routes import bp as main_bp
    app.register_blueprint(main_bp)

    return app

