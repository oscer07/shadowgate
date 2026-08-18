from flask import Flask, render_template, jsonify, request
from typing import Any
import sys
import os

# Add the parent directory to sys.path to allow importing shadowgate modules if needed
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from shadowgate.logging.logger import event_store

def create_app(config: Any = None) -> Flask:
    """Create and configure the Flask dashboard application."""
    app = Flask(__name__)
    
    # Configure SECRET_KEY from config or fallback
    secret_key = "dev"
    if config and hasattr(config, 'get'):
        secret_key = config.get("dashboard", "secret_key", default="dev")
    app.config["SECRET_KEY"] = secret_key
    
    @app.route("/")
    def index():
        return render_template("index.html")
    
    @app.route("/api/events")
    def api_events():
        limit = request.args.get("limit", 100, type=int)
        protocol = request.args.get("protocol", None)
        return jsonify(event_store.get_events(limit=limit, protocol=protocol))
    
    @app.route("/api/events/<protocol>")
    def api_events_by_protocol(protocol):
        limit = request.args.get("limit", 100, type=int)
        return jsonify(event_store.get_events(limit=limit, protocol=protocol.upper()))
        
    @app.route("/api/stats")
    def api_stats():
        return jsonify(event_store.get_stats())
        
    @app.route("/api/top-attackers")
    def api_top_attackers():
        stats = event_store.get_stats()
        return jsonify(stats.get("top_ips", {}))
    
    @app.route("/api/health")
    def api_health():
        return jsonify({"status": "ok", "version": "1.0.0"})
        
    # Optional error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return jsonify({"error": "Not Found"}), 404

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({"error": "Internal Server Error"}), 500
        
    return app
