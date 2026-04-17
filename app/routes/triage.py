from collections import defaultdict
from flask import Blueprint, abort, current_app, render_template, request, redirect, url_for, make_response
from flask_login import current_user, login_required
from typing import List, Optional, Sequence, cast
import logging
import threading
from imap_tools.errors import MailboxLoginError
from socket import gaierror
from math import ceil


from app.crypt_util import decrypt
from app.enums import SyncStatus
from app.models import AppAccount, Folder, MailAccount, Mail
from app.schemas import DecryptedMail, DecryptedMailAccount
from app.services.triage_service import TriageService
from app.services.mail_sync_service import MailSyncService
from app.services.imap_fetcher import ImapFetcher
from app.extensions import db, user_keys, scan_queue

logger = logging.getLogger(__name__)
# Tracks sync state per (folder_id, page) tuple across background threads.
sync_status: dict[tuple[int, int], SyncStatus] = {}
# Caches the IMAP UIDs belonging to each (folder_id, page) tuple.
# Populated by the background sync thread before ingestion, so polling
# queries can filter mails by UID instead of using OFFSET-based pagination.
page_uids: defaultdict[tuple[int, int], set[int]] = defaultdict(set)

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
    app_account = cast(AppAccount, current_user)
    is_syncing: bool = False
    data_key: bytes = user_keys[app_account.id]
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
        # 2. Mail-Accounts des Users laden
        mail_accounts = MailAccount.query.filter(MailAccount.owner_id == app_account.id).all()

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
            selected_folder_id = _get_selected_folder_id(folders, selected_account_id) 

        triage_service: TriageService = TriageService()
        mails: Sequence[Mail] = triage_service.get_mails_page(selected_folder_id, page, page_size, page_uids[selected_folder_id, page])

        if not mails:
            if (selected_folder_id, page) not in sync_status:
                sync_status[(selected_folder_id, page)] = SyncStatus.RUNNING
                is_syncing = True
                app = current_app._get_current_object()
                thread = threading.Thread(target=sync_mails, args=(app_account.id, selected_account_id, selected_folder_id, page, page_size, app))
                thread.start()
            elif sync_status[(selected_folder_id, page)] == SyncStatus.SYNCED:
                is_syncing = False

        decrypted_mails = DecryptedMail.decrypt_mails(mails=mails, data_key=data_key) 
        total_mails: int = _get_total_mails(selected_folder_id, folders)
        logger.debug(f"{total_mails=} | {page_size=}")
        total_pages = ceil(total_mails/page_size)
        
        # 8. Total Mails zählen (für "1-50 of 1234")
        # 9. Alles ans Template übergeben

        if request.headers.get("HX-Request"):
            # Sync is finshed or not started, 286 means abort
            if  (selected_folder_id, page) not in sync_status or not sync_status[(selected_folder_id, page)] == SyncStatus.RUNNING:
                mail_list_template = "components/mail_list.html"
                status_code = 286

            # Sync is running, 200 means it returns htmx swap
            else:
                mail_list_template = "components/mail_list_polling.html"
                status_code = 200

            folder_html = render_template("components/folder_list.html", folders=folders, selected_account_id=selected_account_id, selected_folder_id=selected_folder_id)
            folder_oob = f'<nav id="folder-list" hx-swap-oob="innerHTML"><span class="px-3 text-xs text-neutral-500 uppercase tracking-wider">Folders</span>{folder_html}</nav>'

            toolbar_html = render_template("components/toolbar.html", selected_account_id=selected_account_id, selected_folder_id=selected_folder_id, page=page, page_size=page_size, total_mails=total_mails, total_pages=total_pages)
            toolbar_oob = f'<div id="toolbar" hx-swap-oob="innerHTML">{toolbar_html}</div>'
                
            mail_html = render_template(mail_list_template, mails=decrypted_mails, selected_account_id=selected_account_id, selected_folder_id=selected_folder_id, page=page)

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
        if (selected_folder_id, page) not in sync_status:
            sync_status[(selected_folder_id, page)] = SyncStatus.RUNNING
            if not selected_account_id or not selected_folder_id:
                return redirect(url_for('home.home'))
            app = current_app._get_current_object()
            thread = threading.Thread(target=sync_mails, args=(app_account.id, selected_account_id, selected_folder_id, page, page_size, app))
            thread.start()
        
        return render_template('components/mail_list_polling.html', mails=mails, selected_account_id=selected_account_id, selected_folder_id=selected_folder_id, page=page)
        
def _get_selected_folder_id(folders: List[List[Folder]], selected_account_id: int) -> int:
    """Return the folder id of the inbox, or the last folder as fallback.

    Args:
        folders: Sorted list of Folder instances.
        selected_account_id: Currently selected account id (unused).

    Returns:
        The database id of the selected folder.
    """
    for folder in folders:
        folder_id = folder.id
        if folder.flag == 'inbox':
            return folder_id
    
    return folder_id

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

def sync_mails(app_account_id: int, selected_account_id: int, selected_folder_id: int, page: int, page_size: int, app) -> None:
    """Background thread target that syncs folders and fetches new mails.

    Runs inside a Flask app context. Updates the global sync_status dict
    on success or failure.

    Syncs folder structure via sync_mail_accounts, then resolves
    IMAP UIDs for the requested page via fetch_uids_by_page (writing
    them into page_uids before ingestion so polling can use them),
    and finally ingests missing mails via sync_mails_by_uid.

    Args:
        app_account_id: Database id of the AppAccount.
        selected_account_id: Database id of the MailAccount.
        selected_folder_id: Database id of the Folder to sync.
        page: The 1-based page number to sync.
        page_size: Number of mails per page.
        app: The Flask application object (for creating app context).
    """
    with app.app_context():
        mail_account = MailAccount.query.filter(MailAccount.id == selected_account_id).one_or_none()
        folder = Folder.query.filter(Folder.id == selected_folder_id).one_or_none()
        try:
            mail_sync_service: MailSyncService = MailSyncService()
            with ImapFetcher(DecryptedMailAccount.decrypt_mail_account(mail_account)) as imap_fetcher:
                mail_sync_service.sync_folders(mail_account.id, imap_fetcher)
                page_uids[(selected_folder_id, page)], diffbatch = mail_sync_service.fetch_uids_by_page(mail_account, folder, page, page_size, imap_fetcher)
                mail_sync_service.sync_mails_by_uid(mail_account, folder, diffbatch, imap_fetcher)

        except TimeoutError:
            logger.error("Invalid imap port!")
            sync_status[(selected_folder_id, page)] = SyncStatus.FAILED_TIMEOUT
            return
        except gaierror:
            logger.error("Invalid imap host!")
            sync_status[(selected_folder_id, page)] = SyncStatus.FAILED_HOST
            return
        except MailboxLoginError:
            logger.error("Invalid username or password!")
            sync_status[(selected_folder_id, page)] = SyncStatus.FAILED_AUTH
            return
        except Exception as e:                                        # ← NEU
            logger.error(f"Unexpected sync error: {e}")
            sync_status[(selected_folder_id, page)] = SyncStatus.FAILED_HOST  # oder ein neuer FAILED-Status
            return

        sync_status[(selected_folder_id, page)] = SyncStatus.SYNCED

@triage_bp.route("/mail/<int:mail_id>/content")
@login_required
def mail_content(mail_id):
    """Return the decrypted mail detail HTML fragment for HTMX.

    Verifies ownership via a JOIN on MailAccount before decrypting.
    Returns 403 if the mail does not belong to the current user.

    Args:
        mail_id: Database id of the mail to display.
    """
    app_account = cast(AppAccount, current_user)
    mail = (
        db.session.query(Mail)
        .join(MailAccount, MailAccount.id == Mail.account_id)
        .filter(Mail.id == mail_id, MailAccount.owner_id == app_account.id)
        .first()
    )
    if not mail:
        abort(403)

    data_key = user_keys[app_account.id]
    decrypted_mail: DecryptedMail = DecryptedMail.decrypt_mail(mail=mail, data_key=data_key)
    return render_template('components/mail_detail.html', mail=decrypted_mail)

