"""
HTTP / WordPress honeypot — simulates a login portal and logs credential attempts.
"""

import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request

# ----- Logging helper -----------------------------------------------------

def setup_logger(name: str, filename: str) -> logging.Logger:
    """Create and configure a rotating log file."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(filename, maxBytes=2000, backupCount=5)
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


# Logger used to capture HTTP/credential activity
http_logger = setup_logger("http_logger", "http_audits.log")


# ----- Flask app ----------------------------------------------------------

def create_honeypot_app(valid_username="admin", valid_password="password"):
    """
    Create and return a Flask app representing the web honeypot.
    """
    app = Flask(__name__)

    @app.route("/wp-admin", methods=["GET", "POST"])
    def login():
        """Render login page and capture credential attempts."""
        if request.method == "GET":
            return render_template("wp-admin.html")

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        ip_address = request.remote_addr

        http_logger.info(
            "[%s] Login attempt — username: %s password: %s",
            ip_address, username, password
        )

        if username == valid_username and password == valid_password:
            return render_template("admin.html", username=username)

        return render_template("wp-admin.html", error="Invalid credentials")

    return app


def run_web_honeypot(port=5000, username="admin", password="password"):
    """
    Start the web honeypot Flask application.
    """
    app = create_honeypot_app(username, password)
    app.run(host="0.0.0.0", port=port, debug=False)
