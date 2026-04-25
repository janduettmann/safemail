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
    app_account = cast(AppAccount, current_user)

    mail = Mail.query.join(MailAccount).filter(MailAccount.owner_id == app_account.id, Mail.id == mail_id).one_or_none()
    if mail:
        scan_queue.add(mail_id)
    response = make_response(render_template('components/scan_statusbar.html', scan_completed=scan_queue.completed, scan_total=scan_queue.total, is_visible=scan_queue.is_visible()), 200)
    return response


@scan_bp.route("/scan/status", methods=["GET"])
@login_required
def scan_status():
    response = make_response(render_template('components/scan_statusbar.html', scan_completed=scan_queue.completed, scan_total=scan_queue.total, is_visible=scan_queue.is_visible()), 200)
    return response


