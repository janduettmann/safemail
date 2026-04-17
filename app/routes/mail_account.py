from sqlalchemy.exc import IntegrityError
from flask import Blueprint, redirect, render_template, request, flash, url_for
from flask_login import current_user, login_required
import logging
from typing import cast

from app.crypt_util import encrypt
from app.extensions import db, user_keys
from app.models import Folder, MailAccount, AppAccount
from app.services.imap_fetcher import ImapFetcher
from app.schemas import DecryptedMailAccount, FolderInfo

logger = logging.getLogger(__name__)

mail_account_bp = Blueprint("mail_account", __name__)

@mail_account_bp.route("/add_mail_account", methods=["POST", "GET"])
@login_required
def add_mail_account():
    """Handle adding a new IMAP mail account.

    GET: Render the add mail account form.
    POST: Validate IMAP credentials, encrypt and store the account,
    fetch initial folder list, and redirect to home.
    """
    if request.method == "POST":
        app_account = cast(AppAccount, current_user)
        host: str = request.form["host"]
        port: str = request.form["port"]
        username: str = request.form["username"]
        password: str = request.form["password"]
        
        data_key = user_keys[app_account.id]

        encrypted_host: bytes = encrypt(data=host.encode('utf-8'), key=data_key)
        encrypted_port: bytes = encrypt(data=port.encode('utf-8'), key=data_key)
        encrypted_username: bytes = encrypt(data=username.encode('utf-8'), key=data_key)
        encrypted_password: bytes = encrypt(data=password.encode('utf-8'), key=data_key)

        new_mail_account: MailAccount = MailAccount(
            owner_id = app_account.id,
            host = encrypted_host,
            port = encrypted_port,
            username = encrypted_username,
            password = encrypted_password
        )

        imap_fetcher: ImapFetcher = ImapFetcher(DecryptedMailAccount.decrypt_mail_account(new_mail_account))
        # Checks if the provided host, port, username and password is valid
        is_valid, message = imap_fetcher.is_mail_account_valid()
        if not is_valid:
            flash(message)
            return redirect(url_for("mail_account.add_mail_account"))

        db.session.add(new_mail_account)
        db.session.flush()
        # Folder name and uidvalidity
        # Das muss mit in den mail viewer und asynchron
        try:
            with ImapFetcher(DecryptedMailAccount.decrypt_mail_account(new_mail_account)) as imap_fetcher:
                folder_infos: list[FolderInfo] = imap_fetcher.fetch_folders()
        except TimeoutError:
            db.session.rollback()
            return "Wrong username or password!", 400

        for folder in folder_infos:
            new_folder = Folder(
                account_id = new_mail_account.id,
                name = folder.name,
                uid_validity = folder.uid_validity,
                flag = folder.flag
            )
            db.session.add(new_folder)

        try:
            db.session.commit()
        except IntegrityError as e:
            db.session.rollback()
            return f"Account already exists : Error{e}", 409

        return redirect(url_for('home.home'))
    
    return render_template("add_mail_account.html")
