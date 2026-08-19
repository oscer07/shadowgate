"""ShadowGate Dashboard — Flask web application with REST API."""

import csv
import io
import json
import functools
from datetime import datetime, timezone
from typing import Any

from flask import Flask, render_template, jsonify, request, Response, session, redirect, url_for

from shadowgate.logging.logger import event_store
from shadowgate import __version__


def create_app(config: Any = None) -> Flask:
    """Create and configure the Flask dashboard application."""
    app = Flask(__name__)

    secret_key = "dev-change-this"
    if config and hasattr(config, 'get'):
        secret_key = config.get("dashboard", "secret_key", default="dev-change-this")
    app.config["SECRET_KEY"] = secret_key

    # Dashboard authentication
    dash_auth_enabled = False
    dash_username = "admin"
    dash_password = "shadowgate"
    if config and hasattr(config, 'get'):
        dash_auth_enabled = config.get("dashboard", "auth_enabled", default=False)
        dash_username = config.get("dashboard", "username", default="admin")
        dash_password = config.get("dashboard", "password", default="shadowgate")

    def login_required(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            if dash_auth_enabled and not session.get("authenticated"):
                if request.path.startswith("/api/"):
                    return jsonify({"error": "Authentication required"}), 401
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return decorated

    # --- Auth Routes ---
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if not dash_auth_enabled:
            return redirect(url_for("index"))
        if request.method == "POST":
            if (request.form.get("username") == dash_username
                    and request.form.get("password") == dash_password):
                session["authenticated"] = True
                return redirect(url_for("index"))
            return render_template("login.html", error="Invalid credentials"), 401
        return render_template("login.html", error=None)

    @app.route("/logout")
    def logout():
        session.pop("authenticated", None)
        return redirect(url_for("login"))

    # --- Dashboard ---
    @app.route("/")
    @login_required
    def index():
        return render_template("index.html")

    # --- API: Events ---
    @app.route("/api/events")
    @login_required
    def api_events():
        limit = request.args.get("limit", 100, type=int)
        protocol = request.args.get("protocol", None)
        event_type = request.args.get("event_type", None)
        return jsonify(event_store.get_events(
            limit=limit, protocol=protocol, event_type=event_type
        ))

    @app.route("/api/events/<protocol>")
    @login_required
    def api_events_by_protocol(protocol):
        limit = request.args.get("limit", 100, type=int)
        return jsonify(event_store.get_events(limit=limit, protocol=protocol))

    # --- API: Stats ---
    @app.route("/api/stats")
    @login_required
    def api_stats():
        return jsonify(event_store.get_stats())

    # --- API: Top Attackers ---
    @app.route("/api/top-attackers")
    @login_required
    def api_top_attackers():
        stats = event_store.get_stats()
        return jsonify(stats.get("top_ips", {}))

    # --- API: Credentials ---
    @app.route("/api/credentials")
    @login_required
    def api_credentials():
        limit = request.args.get("limit", 50, type=int)
        return jsonify(event_store.get_credentials(limit=limit))

    # --- API: Export ---
    @app.route("/api/export/<fmt>")
    @login_required
    def api_export(fmt):
        """Export events as JSON or CSV."""
        events = event_store.get_events(limit=10000)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        if fmt == "json":
            output = json.dumps(events, indent=2, default=str)
            return Response(
                output,
                mimetype="application/json",
                headers={"Content-Disposition": f"attachment; filename=shadowgate_events_{timestamp}.json"},
            )

        elif fmt == "csv":
            if not events:
                return Response("No events to export", mimetype="text/plain")

            # Collect all unique keys across events
            all_keys = set()
            for event in events:
                all_keys.update(event.keys())
            fieldnames = sorted(all_keys)

            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for event in events:
                # Flatten nested dicts/lists to strings for CSV
                row = {}
                for k, v in event.items():
                    row[k] = json.dumps(v) if isinstance(v, (dict, list)) else str(v)
                writer.writerow(row)

            return Response(
                output.getvalue(),
                mimetype="text/csv",
                headers={"Content-Disposition": f"attachment; filename=shadowgate_events_{timestamp}.csv"},
            )

        return jsonify({"error": f"Unsupported format: {fmt}. Use 'json' or 'csv'"}), 400

    # --- API: Health ---
    @app.route("/api/health")
    def api_health():
        stats = event_store.get_stats()
        return jsonify({
            "status": "ok",
            "version": __version__,
            "total_events": stats.get("total_events", 0),
            "unique_attackers": stats.get("unique_ips", 0),
            "uptime": "running",
        })

    # --- Error Handlers ---
    @app.errorhandler(404)
    def not_found(error):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Endpoint not found"}), 404
        return render_template("index.html"), 404

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({"error": "Internal server error"}), 500

    return app
