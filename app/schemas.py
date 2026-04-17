from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional, Self, List

from app.enums import ScanStatus, Verdict
from app.extensions import user_keys
from app.crypt_util import decrypt
from app.models import MailAccount, OccurrenceFile

@dataclass
class VTReportSummary:
    """Summary of a VirusTotal analysis report.

    Attributes:
        last_analysis_id: VirusTotal analysis identifier.
        verdict: Overall safety verdict.
        malicious: Count of engines flagging as malicious.
        suspicious: Count of engines flagging as suspicious.
        harmless: Count of engines flagging as harmless.
        undetected: Count of engines with no detection.
        checked_at: UTC timestamp when the report was fetched.
    """
    last_analysis_id: str
    verdict: Verdict
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

@dataclass
class FolderInfo:
    """Lightweight container for IMAP folder metadata.

    Attributes:
        name: IMAP folder name (e.g. 'INBOX').
        uid_validity: IMAP UIDVALIDITY value.
        flag: Standardized folder role (e.g. 'inbox', 'trash').
    """
    name: str
    uid_validity: int
    flag: str
    total_messages: int

@dataclass
class DecryptedMailAccount:
    """Decrypted view of a MailAccount, safe to use without triggering SQLAlchemy dirty tracking.

    Attributes:
        id: Database id of the mail account.
        owner_id: Foreign key to the owning AppAccount.
        username: Decrypted IMAP username.
        password: Decrypted IMAP password.
        host: Decrypted IMAP server hostname.
        port: Decrypted IMAP server port.
        delimiter: IMAP folder hierarchy delimiter.
    """
    id: int
    owner_id: Optional[int]
    username: str
    password: str
    host: str
    port: int
    delimiter: str = "/"
    
    @classmethod
    def decrypt_mail_account(cls, mail_account: MailAccount) -> Self:
        """Decrypt a MailAccount ORM object into a plain dataclass.

        Args:
            mail_account: The encrypted MailAccount ORM instance.

        Returns:
            A DecryptedMailAccount with all fields decrypted.
        """
        data_key: bytes = user_keys[mail_account.owner_id]

        delimiter: str = str(mail_account.delimiter or "/")
        username: str = decrypt(chiffre=mail_account.username, key=data_key).decode('utf-8')
        password: str = decrypt(chiffre=mail_account.password, key=data_key).decode('utf-8')
        host: str = decrypt(chiffre=mail_account.host, key=data_key).decode('utf-8')
        port: int = int(decrypt(chiffre=mail_account.port, key=data_key).decode('utf-8'))
        
        return cls(
            id = mail_account.id,
            owner_id = mail_account.owner_id,
            username = username,
            password = password,
            host = host,
            port = port,
            delimiter = delimiter
        )

@dataclass
class DecryptedMail:
    """Decrypted view of a Mail, safe to use without triggering SQLAlchemy dirty tracking.

    Attributes:
        id: Database id of the mail.
        account_id: Foreign key to the owning mail account.
        folder_id: Foreign key to the folder.
        message_id: RFC 2822 Message-ID header value.
        uid: IMAP UID of the message.
        subject: Decrypted subject line.
        sender: Sender email address.
        recipient: List of recipient email addresses.
        date: Date the message was sent.
        text: Decrypted plain-text body.
        html: Decrypted HTML body.
        deleted_at: Soft-delete timestamp.
    """
    id: int
    account_id: int
    folder_id: int
    message_id: Optional[str]
    uid: int
    subject: Optional[str]
    sender: str
    recipient: list[str]
    date: datetime
    text: Optional[str]
    html: Optional[str]
    occurrence_files: List[OccurrenceFile]
    verdict: Verdict
    worst_verdict: int
    total_engines: int
    scan_status: ScanStatus
    deleted_at: Optional[datetime]

    @classmethod
    def decrypt_mail(cls, mail, data_key: bytes) -> Self:
        """Decrypt a single Mail ORM object into a plain dataclass.

        Args:
            mail: The encrypted Mail ORM instance.
            data_key: Fernet data key for decryption.

        Returns:
            A DecryptedMail with subject, text, and html decrypted.
        """
        subject: Optional[str] = decrypt(chiffre=mail.subject, key=data_key).decode('utf-8') if mail.subject else None
        text: Optional[str] = decrypt(chiffre=mail.text, key=data_key).decode('utf-8') if mail.text else None
        html: Optional[str] = decrypt(chiffre=mail.html, key=data_key).decode('utf-8') if mail.html else None
        
        return cls(
            id = mail.id,
            account_id = mail.account_id,
            folder_id = mail.folder_id,
            message_id = mail.message_id,
            uid = mail.uid,
            subject = subject,
            sender = mail.sender,
            recipient = mail.recipient,
            date = mail.date,
            text = text,
            html = html,
            occurrence_files = mail.occurrence_files,
            verdict = mail.verdict,
            worst_verdict = mail.worst_verdict,
            total_engines = mail.total_engines,
            scan_status = mail.scan_status,
            deleted_at = mail.deleted_at
        )

    @classmethod
    def decrypt_mails(cls, mails, data_key: bytes) -> list[Self]:
        """Decrypt a list of Mail ORM objects into plain dataclasses.

        Args:
            mails: Sequence of encrypted Mail ORM instances.
            data_key: Fernet data key for decryption.

        Returns:
            List of DecryptedMail instances.
        """
        decrypted_mails: list[Self] = []
        for mail in mails:
            decrypted_mails.append(cls.decrypt_mail(mail=mail, data_key=data_key))

        return decrypted_mails
    
