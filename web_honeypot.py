import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request

def setup_logger(name: str, filename: str) -> logging.Logger:
    """
    Create and configure a rotating log file.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    handler = RotatingFileHandler(filename, maxBytes=2000, backupCount=5)
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger
# Logger used to capture HTTP/credential activity
http_logger = setup_logger("http_logger", "http_audits.log")
def create_honeypot_app(valid_username="admin", valid_password="password"):
    """
    Create and return a Flask app representing the web honeypot.
    """
    app = Flask(__name__)
    @app.route("/wp-admin", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            # send WordPress login page
            return render_template("wp-admin.html")

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        ip_address = request.remote_addr

        http_logger.info(
            f"[{ip_address}] Login attempt — username: {username}  password: {password}"
        )

        # If credentials are correct, redirect to fake admin dashboard
        if username == valid_username and password == valid_password:
            return render_template("admin.html", username=username)

        # Wrong credentials: keep them on login page with generic error
        return render_template("wp-admin.html", error="Invalid credentials")

    return app


def run_web_honeypot(port=5000, username="admin", password="password"):
    """
    Start the web honeypot Flask application.
    """
    app = create_honeypot_app(username, password)
    # DO NOT enable debug mode in production / honeypot
    app.run(host="0.0.0.0", port=port, debug=False)