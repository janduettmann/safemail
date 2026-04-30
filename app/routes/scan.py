from flask import Blueprint, make_response, request, abort, render_template
from sqlalchemy import select
from flask_login import login_required, current_user
from typing import cast

from app.models import AppAccount, Folder, MailAccount, Mail
from app.extensions import db
from app.schemas import DecryptedMailAccount
from app.services.mail_scan_service import MailScanService
from app.extensions import scan_queue

scan_bp = Blueprint("scan", __name__)

@scan_bp.route("/scan/<int:mail_id>", methods=["POST"])
@login_required
def single_scan(mail_id):
    """Enqueues a single mail for VirusTotal scanning.

    Verifies that the mail belongs to the current user via a join on
    ``MailAccount.owner_id`` before enqueuing, and returns the rendered
    scan status bar so the HTMX-driven UI shows progress immediately.

    Args:
        mail_id: Database id of the mail to scan.

    Returns:
        Flask response containing the rendered status bar fragment.
        Adds an ``HX-Trigger: scanComplete`` header when the queue
        signals that listeners should refresh dependent regions.
    """
    app_account = cast(AppAccount, current_user)

    mail = Mail.query.join(MailAccount).filter(MailAccount.owner_id == app_account.id, Mail.id == mail_id).one_or_none()
    if mail:
        scan_queue.add(mail_id)
    response = make_response(render_template('components/scan_statusbar.html', scan_completed=scan_queue.completed, scan_total=scan_queue.total, is_visible=scan_queue.is_visible()), 200)
    if scan_queue.pop_notify():
        response.headers["HX-Trigger"] = "scanComplete"
    return response


@scan_bp.route("/scan/status", methods=["GET"])
@login_required
def scan_status():
    """Returns the current scan progress for HTMX polling.

    Called every 0.5 s by ``scan_statusbar.html`` while a scan is active.
    The response is the same status-bar fragment used by ``single_scan``;
    when ``scan_queue.pop_notify()`` reports a state change the response
    additionally carries an ``HX-Trigger: scanComplete`` header so the
    mail list reloads exactly once.

    Returns:
        Flask response with the rendered status bar fragment.
    """
    response = make_response(render_template('components/scan_statusbar.html', scan_completed=scan_queue.completed, scan_total=scan_queue.total, is_visible=scan_queue.is_visible()), 200)
    if scan_queue.pop_notify():
        response.headers["HX-Trigger"] = "scanComplete"
    return response


