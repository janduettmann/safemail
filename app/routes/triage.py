from flask import Blueprint, abort, current_app, render_template, request, redirect, url_for, make_response
from flask_login import current_user, login_required
from typing import List, Optional, Sequence
import logging
import threading
from math import ceil


from app.crypt_util import decrypt
from app.enums import SyncStatus
from app.models import Folder, MailAccount, Mail
from app.schemas import DecryptedMail
from app.services.triage_service import TriageService
from app.services.mail_sync_service import MailSyncService
from app.extensions import db, user_keys, scan_queue, page_uids, page_sync_status

logger = logging.getLogger(__name__)

triage_bp: Blueprint = Blueprint(name="home", import_name=__name__)

@triage_bp.route(rule="/home", methods=["GET", "POST"])
@login_required
def home():
    """Main triage view for browsing and syncing emails.

    GET: Load mail accounts, folders, and paginated mails. Triggers an
    automatic background sync if the selected folder has no mails yet.
    Supports HTMX partial responses for polling during sync.
    POST: Manually trigger a mail sync for the selected folder.
    """
    is_syncing: bool = False
    data_key: bytes = user_keys[current_user.id]
    decrypted_mail_accounts: dict[int, str] = {}
    decrypted_mails: list[DecryptedMail] = []

    #Defaults
    mail_accounts: List[MailAccount] = []
    folders: List[Folder] = []
    mails: Sequence[Mail] = []
    selected_account_id: Optional[int] = request.args.get("account_id", type=int)  
    selected_folder_id: Optional[int] = request.args.get("folder_id", type=int)
    page: int = request.args.get("page", default=1, type=int)
    page_size: int = 50
    total_mails: int = 0
    total_pages: int = 0

    if request.method == "GET":
        # Load the user's IMAP accounts.
        mail_accounts = MailAccount.query.filter(MailAccount.owner_id == current_user.id).all()

        if selected_account_id and selected_account_id not in [acc.id for acc in mail_accounts]:
            return redirect(url_for('home.home'))

        if mail_accounts:
            if not selected_account_id:
                selected_account_id = mail_accounts[0].id

            folders = Folder.query.filter(Folder.account_id == selected_account_id).all()

        for mail_account in mail_accounts:
            decrypted_mail_accounts[mail_account.id] = decrypt(chiffre=mail_account.username, key=data_key).decode('utf-8')

        if not folders or not mail_accounts:
            return render_template('triage.html',
                mail_accounts=mail_accounts,
                folders=folders,
                mails=mails,
                selected_account_id=selected_account_id,
                selected_folder_id=selected_folder_id,
                page=page,
                page_size=page_size,
                total_pages=total_pages,
                total_mails=total_mails,
                scan_completed=scan_queue.completed,
                scan_total=scan_queue.total,
                is_visible=scan_queue.is_visible()
            )
        folders = _sort_folders(folders) # Sorts folders for correct order (e.g. first folder = Inbox)

        if not selected_folder_id:
            selected_folder_id = _get_selected_folder_id(folders) 

        if not selected_account_id or not selected_folder_id:
            return redirect(url_for('home.home'))

        mails: Sequence[Mail] = TriageService.get_mails_page(selected_folder_id, page, page_size, page_uids[selected_folder_id, page])

        if not mails:
            if (selected_folder_id, page) not in page_sync_status:
                page_sync_status[(selected_folder_id, page)] = SyncStatus.RUNNING
                is_syncing = True
                app = current_app._get_current_object()
                thread = threading.Thread(target=MailSyncService().sync_mails, args=(selected_account_id, selected_folder_id, page, page_size, app))
                thread.start()
            elif page_sync_status[(selected_folder_id, page)] == SyncStatus.SYNCED:
                is_syncing = False

        decrypted_mails = DecryptedMail.decrypt_mails(mails=mails, data_key=data_key) 
        total_mails: int = _get_total_mails(selected_folder_id, folders)
        logger.debug(f"{total_mails=} | {page_size=}")
        total_pages = ceil(total_mails/page_size)
        
        # Count total mails (used for "1-50 of 1234") and pass everything to the template.

        if request.headers.get("HX-Request"):
            # Sync is finshed or not started, 286 means abort
            if  (selected_folder_id, page) not in page_sync_status or not page_sync_status[(selected_folder_id, page)] == SyncStatus.RUNNING:
                is_syncing = False
                status_code = 286

            # Sync is running, 200 means it returns htmx swap
            else:
                is_syncing = True
                status_code = 200

            folder_html = render_template("components/folder_list.html", folders=folders, selected_account_id=selected_account_id, selected_folder_id=selected_folder_id)
            folder_oob = f'<nav id="folder-list" hx-swap-oob="innerHTML"><span class="px-3 text-xs text-neutral-500 uppercase tracking-wider">Folders</span>{folder_html}</nav>'

            toolbar_html = render_template("components/toolbar.html", selected_account_id=selected_account_id, selected_folder_id=selected_folder_id, page=page, page_size=page_size, total_mails=total_mails, total_pages=total_pages, is_syncing=is_syncing)
            toolbar_oob = f'<div id="toolbar" hx-swap-oob="innerHTML">{toolbar_html}</div>'
                
            mail_html = render_template("components/mail_list_container.html", mails=decrypted_mails, selected_account_id=selected_account_id, selected_folder_id=selected_folder_id, page=page, is_syncing=is_syncing)

            response = make_response(mail_html + folder_oob + toolbar_oob)
            response.status_code = status_code
            return response


        return render_template('triage.html',
            is_syncing=is_syncing,
            mail_accounts=decrypted_mail_accounts,
            folders=folders,
            mails=decrypted_mails,
            selected_account_id=selected_account_id,
            selected_folder_id=selected_folder_id,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            total_mails=total_mails,
            scan_completed=scan_queue.completed,
            scan_total=scan_queue.total,
            is_visible=scan_queue.is_visible()
        )

    if request.method == "POST": 
        logger.debug("Try POST")
        mail_accounts = MailAccount.query.filter(MailAccount.owner_id == current_user.id).all()

        if selected_account_id and selected_account_id not in [acc.id for acc in mail_accounts]:
            return redirect(url_for('home.home'))

        if not selected_account_id or not selected_folder_id:
            return redirect(url_for('home.home'))

        folders = Folder.query.filter(Folder.account_id == selected_account_id).all()
        if not folders:
            return redirect(url_for('home.home'))

        mails: Sequence[Mail] = TriageService.get_mails_page(selected_folder_id, page, page_size, page_uids[selected_folder_id, page])

        total_mails: int = _get_total_mails(selected_folder_id, folders)
        total_pages = ceil(total_mails/page_size)

        decrypted_mails = DecryptedMail.decrypt_mails(mails=mails, data_key=data_key) 
        if (selected_folder_id, page) not in page_sync_status or page_sync_status.get((selected_folder_id, page)) != SyncStatus.RUNNING:
            page_sync_status[(selected_folder_id, page)] = SyncStatus.RUNNING
            app = current_app._get_current_object()
            logger.debug("Try sync_mails")
            thread = threading.Thread(target=MailSyncService().sync_mails, args=(selected_account_id, selected_folder_id, page, page_size, app))
            thread.start()

        mail_html = render_template('components/mail_list_container.html', mails=decrypted_mails, selected_account_id=selected_account_id, selected_folder_id=selected_folder_id, page=page, is_syncing=True)

        toolbar_html = render_template("components/toolbar.html", selected_account_id=selected_account_id, selected_folder_id=selected_folder_id, page=page, page_size=page_size, total_mails=total_mails, total_pages=total_pages, is_syncing=True)
        toolbar_oob = f'<div id="toolbar" hx-swap-oob="innerHTML">{toolbar_html}</div>'

        return mail_html + toolbar_oob
        

def _get_selected_folder_id(folders: List[Folder]) -> int:
    """Return the folder id of the inbox, or the last folder as fallback.

    Args:
        folders: Sorted list of Folder instances.

    Returns:
        The database id of the selected folder.
    """
    for folder in folders:
        if folder.flag == 'inbox':
            return folder.id
    
    return folder.id

def _get_total_mails(selected_folder_id: int, folders: list[Folder]) -> int:
    """Return the IMAP total_messages count for the selected folder.

    Args:
        selected_folder_id: Database id of the folder to look up.
        folders: List of Folder instances for the current account.

    Returns:
        The total message count, or 0 if the folder is not found or has no messages.
    """
    for folder in folders:
        if folder.id == selected_folder_id:
            return folder.total_messages if folder.total_messages else 0
    return 0

def _sort_folders(folders: List[Folder]) -> List[Folder]:
    """Sort folders by their standard role (inbox first, then drafts, sent, etc.).

    Args:
        folders: Unsorted list of Folder instances.

    Returns:
        A new list of Folders sorted by role priority.
    """
    FOLDER_ORDER = {
        'inbox': 0,
        'drafts': 1,
        'sent': 2,
        'junk': 3,
        'trash': 4,
        'archive': 5,
    }
    return sorted(folders, key=lambda f: FOLDER_ORDER.get(f.flag, 99))


@triage_bp.route("/mail/<int:mail_id>/content")
@login_required
def mail_content(mail_id):
    """Return the decrypted mail detail HTML fragment for HTMX.

    Verifies ownership via a JOIN on MailAccount before decrypting.
    Returns 403 if the mail does not belong to the current user.

    Args:
        mail_id: Database id of the mail to display.
    """
    mail = (
        db.session.query(Mail)
        .join(MailAccount, MailAccount.id == Mail.account_id)
        .filter(Mail.id == mail_id, MailAccount.owner_id == current_user.id)
        .first()
    )
    if not mail:
        abort(403)

    data_key = user_keys[current_user.id]
    decrypted_mail: DecryptedMail = DecryptedMail.decrypt_mail(mail=mail, data_key=data_key)
    return render_template('components/mail_detail.html', mail=decrypted_mail)

