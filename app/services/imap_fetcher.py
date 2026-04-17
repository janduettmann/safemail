from typing import Optional
from imap_tools import AND, MailBox, MailMessage
from imap_tools.errors import MailboxLoginError
from collections.abc import Generator
from socket import gaierror
import logging

from app.schemas import DecryptedMailAccount, FolderInfo

logger = logging.getLogger(__name__)

class ImapFetcher:
    """Handles all IMAP server communication (fetching mails, folders, UIDs).

    Attributes:
        mail_account: Decrypted mail account credentials.
    """


    def __init__(self, mail_account: DecryptedMailAccount):
        self.mail_account = mail_account
        self.mb: Optional[MailBox] = None

    def __enter__(self):
        self.mb = MailBox(self.mail_account.host, port=self.mail_account.port).login(self.mail_account.username, self.mail_account.password)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.mb:
            self.mb.logout()

    def fetch_folders(self) -> list[FolderInfo]:
        """Fetches all folder information (name, uidvalidity and flag (e.g. inbox or spam) from a mail account.

        Returns:
            dict[str, int]: Folder information (name, uidvalidity and flag).
        """
        folder_infos: list[FolderInfo] = []
        assert self.mb is not None, "MailBox is not initialized. Use 'with ImapFetcher(...)':"
        for folder in self.mb.folder.list():
            folder_status = self.mb.folder.status(folder.name)
            if folder.name.upper() == 'INBOX':
                
                folder_infos.append(
                    FolderInfo(
                        folder.name, 
                        folder_status["UIDVALIDITY"],
                        'inbox',
                        folder_status["MESSAGES"]
                    )
                )

                continue
            
            folder_infos.append(
                FolderInfo(
                    folder.name,
                    folder_status["UIDVALIDITY"],
                    self._get_folder_flag(folder),
                    folder_status["MESSAGES"]
                )
            )
        return folder_infos

    def is_mail_account_valid(self) -> tuple[bool, str]:
        """Test whether the IMAP credentials are valid by attempting a login.

        Returns:
            A tuple of (success: bool, message: str).
        """
        try:
            with MailBox(self.mail_account.host, port=self.mail_account.port).login(self.mail_account.username, self.mail_account.password):
                return True, "Valid mail account!"
        except TimeoutError:
            logger.error("Invalid imap port!")
            return False, "Invalid imap port."
        except gaierror:
            logger.error("Invalid imap host!")
            return False, "Invalid imap host."
        except MailboxLoginError:
            logger.error("Invalid username or password!")
            return False, "Invalid username or password."

    def fetch_uids(self, folder_name: str) -> set[int]:
        """Fetch all message UIDs from a specific IMAP folder.

        Args:
            folder_name: The IMAP folder name to query.

        Returns:
            A set of integer UIDs present in the folder.
        """
        assert self.mb is not None, "MailBox is not initialized. Use 'with ImapFetcher(...)':"
        self.mb.folder.set(folder_name)
        uids: set[int] = {int(uid) for uid in self.mb.uids()}
        return uids
        
    def fetch_by_uids(self, uids: list[int], folder_name: str) -> Generator[MailMessage, None, None]:
        """Fetch specific messages by their UIDs from an IMAP folder.

        Args:
            uids: List of integer UIDs to fetch.
            folder_name: The IMAP folder name.

        Yields:
            MailMessage objects for each requested UID.
        """
        assert self.mb is not None, "MailBox is not initialized. Use 'with ImapFetcher(...)':"
        if uids:
            uids_str: str = ",".join(str(uid) for uid in uids)
            self.mb.folder.set(folder_name)
            for msg in self.mb.fetch(AND(uid=uids_str)):
                yield msg
        return None
    
    def _get_folder_flag(self, folder) -> str:
        """Map IMAP folder flags to a standardized role string.

        Args:
            folder: An imap_tools folder object with a flags attribute.

        Returns:
            A lowercase role string (e.g. 'trash', 'sent') or the folder name.
        """
        role_map = {
            "\\Trash":    "trash",
            "\\Sent":     "sent",
            "\\Drafts":   "drafts",
            "\\Junk":     "junk",
            "\\Archive":  "archive",
            "\\All":      "all_mail",
            "\\Flagged":  "flagged",
            "\\Important": "important",
        }
        for flag in folder.flags:
            if flag in role_map:
                return role_map[flag]

        return folder.name.lower()

