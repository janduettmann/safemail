from sqlalchemy import delete, select, update
import logging
from imap_tools.errors import MailboxLoginError
from socket import gaierror
from math import ceil

from app.enums import SyncStatus
from app.schemas import DecryptedMailAccount, FolderInfo
from app.services.extractor import Extractor
from app.services.imap_fetcher import ImapFetcher
from app.models import AppAccount, Folder, MailAccount, Mail
from app.extensions import db
from app.services.ingest import Ingester

logger = logging.getLogger(__name__)

class MailSyncService:
    """Service responsible for synchronizing IMAP folders and mails with the local database."""

    def sync_all_folders(self, app_account_id: int ):
        """Sync folders for all mail accounts belonging to the given app account.

        Args:
            app_account: The authenticated application user.

        Returns:
            A dict mapping each MailAccount to its resulting SyncStatus.
        """
        mail_accounts = MailAccount.query.filter(MailAccount.owner_id == app_account_id).all()
 
        for mail_account in mail_accounts:
            with ImapFetcher(DecryptedMailAccount.decrypt_mail_account(mail_account)) as imap_fetcher:
                self.sync_folders(mail_account.id, imap_fetcher)
        
    def sync_folders(self, mail_account_id: int, imap_fetcher: ImapFetcher):
        """Synchronize IMAP folders with the database (insert, update, delete).

        Args:
            mail_account: The mail account whose folders to sync.

        Returns:
            SyncStatus.SYNCED on success.
        """
        imap_folders: list[FolderInfo] = imap_fetcher.fetch_folders()

        db_folder_entries = Folder.query.filter(Folder.account_id == mail_account_id).all()
        db_folders: dict[str, tuple[int, int]] = {}
        for db_folder_entry in db_folder_entries:
            db_folders[db_folder_entry.name] = db_folder_entry.uid_validity, db_folder_entry.total_messages
        
        # Insert or Change
        # folder is the costum FolderInfo type
        for folder in imap_folders:
            if folder.name not in db_folders.keys():
                new_folder = Folder(
                    account_id = mail_account_id,
                    name = folder.name,
                    uid_validity = folder.uid_validity,
                    flag = folder.flag,
                    total_messages = folder.total_messages
                )
                db.session.add(new_folder)
            # Folder updaten
            elif folder.uid_validity != db_folders[folder.name][0] or folder.total_messages != db_folders[folder.name][1]:
                update_folder_stmt = (
                    update(Folder)
                    .where(Folder.name == folder.name, Folder.account_id == mail_account_id)
                    .values(uid_validity = folder.uid_validity, total_messages = folder.total_messages)
                )
                db.session.execute(update_folder_stmt)
        # Delete
        imap_folder_names = [folder.name for folder in imap_folders]
        for name, uid_validity in db_folders.items():
            if name not in imap_folder_names:
                delete_folder_stmt = (
                    delete(Folder)
                    .where(Folder.name == name, Folder.account_id == mail_account_id)
                )
                db.session.execute(delete_folder_stmt)

        db.session.commit()
        logger.info(msg="Synced successfully")

    def sync_new_mails(self, mail_account: MailAccount, folder: Folder, page_size: int, imap_fetcher: ImapFetcher) -> None:
        """Fetch and ingest mails whose UIDs are not yet in the database.

        Compares IMAP UIDs with stored UIDs, fetches the difference in
        batches, and ingests each batch (mail content, URLs, attachments).

        Args:
            mail_account: The mail account to fetch from.
            folder: The folder to sync.
            page_size: Number of mails to fetch per batch.
        """
        imap_uids: set[int] = imap_fetcher.fetch_uids(folder.name)

        db_uids_stmt = select(Mail.uid).where(Mail.account_id == mail_account.id, Mail.folder_id == folder.id)
        db_uids = set(db.session.scalars(db_uids_stmt).all())

        diff_uids: set[int] = imap_uids - db_uids
        sorted_uids: list[int] = sorted(diff_uids, reverse=True)
        
        ingester: Ingester = Ingester(folder_id=folder.id, mail_account=mail_account, extractor=Extractor())
        batches: int = ceil(len(sorted_uids)/page_size)

        for batch in range(batches):
            mails = imap_fetcher.fetch_by_uids(uids=sorted_uids[batch*page_size:(batch + 1)*page_size], folder_name=folder.name)
            ingester.ingest_mails(mails)

    def sync_mails_by_uid(self, mail_account: MailAccount, folder: Folder, diff_batch: set[int], imap_fetcher: ImapFetcher) -> None:
        """Fetch and ingest mails for the given UIDs that are missing from the database.

        Args:
            mail_account: The mail account to fetch from.
            folder: The IMAP folder to fetch from.
            diff_batch: Set of IMAP UIDs not yet present in the database.
        """
        ingester: Ingester = Ingester(folder_id=folder.id, mail_account=mail_account, extractor=Extractor())

        mails = imap_fetcher.fetch_by_uids(uids=list(diff_batch), folder_name=folder.name)
        ingester.ingest_mails(mails)
        
    
    def fetch_uids_by_page(self, mail_account: MailAccount, folder: Folder, page: int, page_size: int, imap_fetcher: ImapFetcher) -> tuple[set[int], set[int]]:
        """Calculate which IMAP UIDs belong to a given page and which are missing from the DB.

        Fetches all UIDs from IMAP, sorts them descending (newest first),
        slices the page range, and diffs against UIDs already stored in the database.

        Args:
            mail_account: The mail account to query.
            folder: The IMAP folder to query.
            page: The 1-based page number.
            page_size: Number of mails per page.

        Returns:
            A tuple of (batch, diff_batch) where batch is the full set of UIDs
            for the requested page, and diff_batch is the subset not yet in the DB.
        """
        imap_uids: set[int] = imap_fetcher.fetch_uids(folder.name)
        sorted_uids: list[int] = sorted(imap_uids, reverse=True)
        
        db_uids_stmt = select(Mail.uid).where(Mail.account_id == mail_account.id, Mail.folder_id == folder.id)
        db_uids = set(db.session.scalars(db_uids_stmt).all())

        batch: set[int] = set(sorted_uids[(page-1)*page_size:page*page_size])
        diff_batch : set[int] = batch - db_uids

        return batch, diff_batch
