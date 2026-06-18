"""
app.py — Application Entry Point
=================================
Fortress Medical Records Management System
A secure, HIPAA-aware demo application demonstrating:
  • Data-at-Rest    : AES-256 field-level encryption (Fernet/cryptography)
  • Data-in-Transit : TLS 1.2+ enforced on all database connections
  • Data-in-Process : 100% parameterized SQL — zero string interpolation
"""

import os
import logging
from flask import Flask
from app.routes import api
from app.database import init_db

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s"
)
logger = logging.getLogger(__name__)


# ── App Factory ───────────────────────────────────────────────────────────────

def create_app() -> Flask:
    app = Flask(__name__)

    # Security headers on every response
    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"]        = "DENY"
        response.headers["X-XSS-Protection"]       = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response

    app.register_blueprint(api, url_prefix="/api")

    # Initialize database tables on startup
    with app.app_context():
        init_db()
        logger.info("Fortress DB initialized and ready.")

    return app


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    application = create_app()
    application.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    )
