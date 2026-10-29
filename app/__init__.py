from flask import Flask


def create_app():
    """Application factory. Creates and configures the Flask app."""
    app = Flask(__name__)

    from . import routes
    app.register_blueprint(routes.bp)

    return app
