from sqlalchemy import JSON, Enum as SAEnum
from sqlalchemy.sql.sqltypes import LargeBinary
from sqlalchemy import ForeignKey, String, UniqueConstraint, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import datetime
from typing import Optional, List
from flask_login import UserMixin

from app.enums import ScanStatus, Verdict
from app.extensions import db

class Mail(db.Model):
    """An email message stored with encrypted subject, text, and HTML fields.

    Attributes:
        id: Primary key.
        account_id: Foreign key to the owning mail account.
        folder_id: Foreign key to the folder this mail belongs to.
        message_id: RFC 2822 Message-ID header value.
        uid: IMAP UID of the message within its folder.
        subject: Encrypted subject line (Fernet-encrypted bytes).
        sender: Plain-text sender email address.
        recipient: JSON list of recipient email addresses.
        date: Date the message was sent.
        text: Encrypted plain-text body (Fernet-encrypted bytes).
        html: Encrypted HTML body (Fernet-encrypted bytes).
        deleted_at: Soft-delete timestamp; None if the mail is active.
    """
    __tablename__ = "mail"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("mail_account.id", ondelete="CASCADE"), nullable=False, index=True)
    folder_id: Mapped[int] = mapped_column(ForeignKey("folder.id", ondelete="CASCADE"), nullable=False, index=True)
    message_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    uid: Mapped[int] = mapped_column(nullable=False, index=True)
    subject: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    sender: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    recipient: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    date: Mapped[datetime] = mapped_column(nullable=False, index=True)
    text: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    html: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    verdict: Mapped[Verdict] = mapped_column(SAEnum(Verdict, native_enum=False), nullable=False, index=True, default=Verdict.UNKNOWN)
    worst_verdict: Mapped[int] = mapped_column(nullable=False, default=0)
    total_engines: Mapped[int] = mapped_column(nullable=False, default=0)
    scan_status: Mapped[ScanStatus] = mapped_column(SAEnum(ScanStatus, native_enum=False), nullable=False, index=True, default=ScanStatus.PENDING)

    deleted_at: Mapped[Optional[datetime]] = mapped_column(nullable=True, index=True)

    occurrence_urls: Mapped[List["OccurrenceUrl"]] = relationship(
        back_populates="mail",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    occurrence_files: Mapped[List["OccurrenceFile"]] = relationship(
        back_populates="mail",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    mail_account: Mapped["MailAccount"] = relationship(back_populates="mails")
    folder: Mapped["Folder"] = relationship(back_populates="mails")

    __table_args__ = (
        UniqueConstraint("account_id", "folder_id", "uid", name="uq_mail_account_folder_uid"),
    )

class AppAccount(UserMixin, db.Model):
    """Application user account for authentication and encryption key management.

    Attributes:
        id: Primary key.
        username: Unique username for login.
        password_hash: bcrypt hash of the user's password.
        encryption_salt: Salt used to derive the key-encryption-key from the password.
        encrypted_data_key: Fernet data key encrypted with the derived key.
    """
    __tablename__ = "app_account"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(255),index=True, unique=True, nullable=False)
    firstname: Mapped[str] = mapped_column(String(255), nullable=False)
    lastname: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encryption_salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encrypted_data_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    
    mail_accounts: Mapped[list["MailAccount"]] = relationship(
        back_populates="app_account",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    @property
    def initials(self) -> str:
        return f"{self.firstname[0].upper()}{self.lastname[0].upper()}"

class MailAccount(db.Model):
    """An IMAP mail account linked to an application user.

    All credentials (host, port, username, password) are stored as
    Fernet-encrypted bytes using the owner's data key.

    Attributes:
        id: Primary key.
        owner_id: Foreign key to the owning AppAccount.
        host: Encrypted IMAP server hostname.
        port: Encrypted IMAP server port.
        username: Encrypted IMAP username.
        password: Encrypted IMAP password.
        delimiter: IMAP folder hierarchy delimiter (default '/').
    """
    __tablename__ = "mail_account"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("app_account.id", ondelete="CASCADE"), nullable=False, index=True)
    host: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    port: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, default=993)
    username: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    password: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    delimiter: Mapped[String] = mapped_column(String(1), nullable=False, default="/")
    
    app_account: Mapped["AppAccount"] = relationship(back_populates="mail_accounts")
    
    mails: Mapped[list["Mail"]] = relationship(
        back_populates="mail_account",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    folder: Mapped[list["Folder"]] = relationship(
        back_populates="mail_account",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    __table_args__ = (
        UniqueConstraint("owner_id", "username", "port", name="uq_mailaccount_owner_host_port_user"),
    )


class Folder(db.Model):
    """An IMAP folder (mailbox) belonging to a mail account.

    Attributes:
        id: Primary key.
        account_id: Foreign key to the owning MailAccount.
        name: IMAP folder name (e.g. 'INBOX', 'Sent').
        uid_validity: IMAP UIDVALIDITY value for cache invalidation.
        flag: Standardized folder role (e.g. 'inbox', 'trash', 'sent').
        total_messages: Total message count on the IMAP server (updated on sync).
    """
    __tablename__ = "folder"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("mail_account.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(nullable=False, index=True)
    uid_validity: Mapped[int] = mapped_column(nullable=False, index=True)
    flag: Mapped[str] = mapped_column(String(16), nullable=True)
    total_messages: Mapped[int] = mapped_column(nullable=True)

    mail_account: Mapped["MailAccount"] = relationship(back_populates="folder")

    mails: Mapped[list["Mail"]] = relationship(
        back_populates="folder",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    __table_args__ = (
        UniqueConstraint("account_id", "name", name="uq_acc_folder"),
    )

class OccurrenceUrl(db.Model):
    """A specific URL occurrence found in an email, linked to its canonical form.

    Attributes:
        id: Primary key.
        canonical_id: Foreign key to the CanonicalUrl.
        mail_id: Foreign key to the Mail containing this URL.
        original: The original URL as it appeared in the email.
    """
    __tablename__ = "occurrence_url"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    canonical_id: Mapped[int] = mapped_column(ForeignKey("canonical_url.id", ondelete="CASCADE"), nullable=False, index=True)
    mail_id: Mapped[int] = mapped_column(ForeignKey("mail.id", ondelete="CASCADE"), nullable=False, index=True)
    original: Mapped[str] = mapped_column(Text, nullable=False)

    mail: Mapped["Mail"] = relationship(back_populates="occurrence_urls")

    __table_args__ = (
        UniqueConstraint("mail_id", "canonical_id", "original", name="uq_occ_url_mail_canon_orig"),
    )

class CanonicalUrl(db.Model):
    """A canonicalized URL (base domain) with its VirusTotal scan results.

    Attributes:
        id: Primary key.
        canonical: The canonical base-domain URL (e.g. 'https://example.com').
        scan_status: Current scan lifecycle state.
        last_analysis_id: VirusTotal analysis or URL identifier.
        verdict: Overall safety verdict derived from scan stats.
        malicious: Number of AV engines flagging as malicious.
        suspicious: Number of AV engines flagging as suspicious.
        harmless: Number of AV engines flagging as harmless.
        undetected: Number of AV engines with no detection.
        checked_at: Timestamp of the last scan.
    """
    __tablename__ = "canonical_url"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    canonical: Mapped[str] = mapped_column(Text, index=True, unique=True, nullable=False)
    scan_status: Mapped[ScanStatus] = mapped_column(SAEnum(ScanStatus, native_enum=False), nullable=False, index=True, default=ScanStatus.PENDING)
    last_analysis_id: Mapped[str] = mapped_column(String(128), nullable=True)
    verdict: Mapped[Verdict] = mapped_column(SAEnum(Verdict, native_enum=False), nullable=False, index=True, default=Verdict.UNKNOWN)
    malicious: Mapped[int] = mapped_column(nullable=False, default=0)
    suspicious: Mapped[int] = mapped_column(nullable=False, default=0)
    harmless: Mapped[int] = mapped_column(nullable=False, default=0)
    undetected: Mapped[int] = mapped_column(nullable=False, default=0)
    checked_at: Mapped[Optional[datetime]] = mapped_column(nullable=True, index=True)

class OccurrenceFile(db.Model):
    """A specific file attachment occurrence found in an email, linked to its canonical form.

    Attributes:
        id: Primary key.
        mail_id: Foreign key to the Mail containing this attachment.
        canonical_id: Foreign key to the CanonicalFile.
        filename: Original filename of the attachment.
        size: File size in bytes.
        mime: MIME content type (e.g. 'application/pdf').
    """
    __tablename__ = "occurrence_file"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    mail_id: Mapped[int] = mapped_column(ForeignKey("mail.id", ondelete="CASCADE"), nullable=False, index=True)
    canonical_id: Mapped[int] = mapped_column(ForeignKey("canonical_file.id", ondelete="CASCADE"), nullable=False, index=True)
    filename: Mapped[str] = mapped_column(Text, nullable=False, default="unnamed_attachment")
    size: Mapped[int] = mapped_column(nullable=False)
    mime: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, default=None)# In OccurrenceFile: mails → mail

    mail: Mapped["Mail"] = relationship(back_populates="occurrence_files")

    __table_args__ = (
        UniqueConstraint("mail_id","canonical_id", "filename", name="uq_occ_file_mail_conon_fname"),
    )

class CanonicalFile(db.Model):
    """A canonical file identified by SHA-256 hash with its VirusTotal scan results.

    Attributes:
        id: Primary key.
        sha256: SHA-256 hash of the file content.
        scan_status: Current scan lifecycle state.
        last_analysis_id: VirusTotal analysis identifier.
        verdict: Overall safety verdict derived from scan stats.
        malicious: Number of AV engines flagging as malicious.
        suspicious: Number of AV engines flagging as suspicious.
        harmless: Number of AV engines flagging as harmless.
        undetected: Number of AV engines with no detection.
        checked_at: Timestamp of the last scan.
    """
    __tablename__ = "canonical_file"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    sha256: Mapped[str] = mapped_column(String(64),unique=True, nullable=False, index=True)
    scan_status: Mapped[ScanStatus] = mapped_column(SAEnum(ScanStatus, native_enum=False), nullable=False, index=True, default=ScanStatus.PENDING)
    last_analysis_id: Mapped[str] = mapped_column(String(128), nullable=True)
    verdict: Mapped[Verdict] = mapped_column(SAEnum(Verdict, native_enum=False), nullable=False, index=True, default=Verdict.UNKNOWN)
    malicious: Mapped[int] = mapped_column(nullable=False, default=0)
    suspicious: Mapped[int] = mapped_column(nullable=False, default=0)
    harmless: Mapped[int] = mapped_column(nullable=False, default=0)
    undetected: Mapped[int] = mapped_column(nullable=False, default=0)
    checked_at: Mapped[Optional[datetime]] = mapped_column(nullable=True, index=True)
