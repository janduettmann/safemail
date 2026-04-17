import threading
from typing import Optional
from flask import Flask, redirect, url_for, make_response, request
import logging

from flask_login import current_user, logout_user

from app.extensions import db, login_manager, user_keys, scan_queue
from app.config import Config
from app.models import AppAccount
from app.routes.scan import scan_bp
from app.routes.mail_account import mail_account_bp
from app.routes.app_account import app_account_bp
from app.routes.triage import triage_bp
from app.services.mail_scan_service import MailScanService
from app.services.vt_client import VTClient



def create_app() -> Flask:
    """Create and configure the Flask application instance.

    Initializes the database, login manager, blueprint routes, and
    registers a before_request guard to handle stale session cookies
    after server restarts.

    Returns:
        The configured Flask application.
    """
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)

    with app.app_context():
        db.create_all()
    
    @app.before_request
    def check_user_keys():
        """Log out users whose data key is missing from the in-memory store.

        This happens after a server restart when the session cookie survives
        but the user_keys dict has been cleared.
        """
        if current_user.is_authenticated and current_user.id not in user_keys:
            logout_user()
            return redirect(url_for('app_account.login'))
    
    def scan_worker(app):
        with app.app_context():
            vt_client = VTClient()
            while True:
                mail_id = scan_queue.queue.get()
                MailScanService().scan_mail(mail_id, vt_client)
                scan_queue.complete()

    thread = threading.Thread(target=scan_worker, args=(app,), daemon=True)
    thread.start()
                

    app.register_blueprint(scan_bp)
    app.register_blueprint(mail_account_bp)
    app.register_blueprint(app_account_bp)
    app.register_blueprint(triage_bp)

    login_manager.login_view = "app_account.login" # type: ignore

    logging.basicConfig(format='%(levelname)s (%(asctime)s): %(message)s (Line: %(lineno)d [%(filename)s])',
                    datefmt='%Y-%m-%d %H:%M:%S %p',
                    level=logging.DEBUG)


    return app

@login_manager.user_loader
def load_user(id) -> Optional[AppAccount]:
    """Flask-Login user loader callback.

    Args:
        id: The user ID stored in the session cookie.

    Returns:
        The AppAccount instance or None if not found.
    """
    return db.session.get(AppAccount, int(id))

@login_manager.unauthorized_handler
def unauthorized():
    if request.headers.get("HX-Request"):
        response = make_response("", 401)
        response.headers["HX-Redirect"] = url_for("app_account.login")
        return response
    return redirect(url_for("app_account.login"))

