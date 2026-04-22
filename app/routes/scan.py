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


@scan_bp.route("/scan", methods=["POST"])
@login_required
def full_scan() -> str:
    """Starts a mail scan for a specific folder. 
    
    This endpoint retrieves the folder and associated mail account details,
    ensuring the folder belongs to the corrently authenticated user. It decrypts
    the account credentials and triggers the MailScanService to process messages.

    Returns:
        str: A success message indicating the scan has been successful. 
    """
    folder_id = int(request.form["folder_id"])
    limit = int(request.form["limit"])
    stmt_folder = (
    select(Folder, MailAccount)
    .join(MailAccount, MailAccount.id == Folder.account_id)
    .join(AppAccount, AppAccount.id == MailAccount.owner_id)
    .where(
        Folder.id == folder_id,
        AppAccount.id == current_user.id
        )
    )
    folder_account_entry = db.session.execute(stmt_folder).one_or_none()

    if not folder_account_entry:
        abort(404)

    folder_entry, account_entry = folder_account_entry
    mail_account: DecryptedMailAccount = DecryptedMailAccount.decrypt_mail_account(account_entry)
    mail_scan_service: MailScanService = MailScanService(mail_account, folder_entry.id, limit)

    return "Scan Successful!"


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
    if scan_queue.pop_notify():
        response.headers["HX-Trigger"] = "scanComplete"
    return response


