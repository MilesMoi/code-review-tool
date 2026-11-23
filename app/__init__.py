from flask import Flask, flash, redirect, url_for

import config


def create_app():
    """Application factory. Creates and configures the Flask app."""
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_BYTES
    # Signs the one-time messages shown after a redirect. The app has no
    # logins and stores nothing secret, so a fixed value is fine on your own machine.
    app.config["SECRET_KEY"] = "local-demo-only"

    from . import routes
    app.register_blueprint(routes.bp)

    @app.errorhandler(413)
    def too_large(error):
        flash(f"That file is too big. The limit is {config.MAX_UPLOAD_BYTES // 1000} KB.")
        return redirect(url_for("routes.index"))

    return app