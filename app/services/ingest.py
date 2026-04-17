from typing import List
from imap_tools import MailMessage, MailAttachment
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from collections.abc import Generator
from collections import defaultdict
from urllib.parse import urlsplit
import logging
import hashlib

from app.services.extractor import Extractor
from app.extensions import db, user_keys
from app.crypt_util import encrypt
from app.models import Mail, MailAccount, OccurrenceUrl, CanonicalUrl, CanonicalFile, OccurrenceFile

logger = logging.getLogger(__name__)

class Ingester:
    """Handles ingestion of email messages, URLs, and attachments into the database.

    Attributes:
        folder_id: The database id of the target folder.
        mail_account: The MailAccount ORM instance (for encryption key lookup).
        extractor: Extractor instance for parsing URLs from mail content.
    """

    def __init__(self, folder_id: int, mail_account: MailAccount, extractor: Extractor) -> None:
        self.folder_id = folder_id
        self.mail_account = mail_account
        self.extractor = extractor

    def ingest_mails(self, mails: Generator[MailMessage, None, None] ) -> None:
        """Orchestrates the mail message ingestion.

        First checks if the email message is already in the database, if not
        ingest it.

        Args:
            mails: A Generator of MailMessage's.
        """

        stmt_uids = select(Mail.uid).where(
            Mail.folder_id == self.folder_id,
            Mail.account_id == self.mail_account.id,
        )
        uids_db = db.session.scalars(stmt_uids).all()

        for mail in mails:
            # Checks if the email message is in the database
            if mail.uid is not None and int(mail.uid) in uids_db:
                continue
            try:
                with db.session.begin_nested():
                    mail_id = self.store_mail(mail)
                    urls = self.extractor.extract_urls(mail)
                    self.ingest_urls(mail_id, urls)
                    self.ingest_attachments(mail_id, mail)

            except IntegrityError:
                logger.error(f"IntegrityError | {mail.uid=} | {mail.subject=}")
                continue

        db.session.commit()

    def get_canonical_url_groups(self, urls: set[str]) -> defaultdict[str, list[str]]:
        """Transforms the occurrence URLs in canonical URls and maps them accordingly.

        Args:
            urls: A set of urls.

        Returns:
            defaultdict[str, list[str]]: Canonical URLs mapped to a list of Occurrence URLs.
        """
        canonical_groups: defaultdict[str, list[str]] = defaultdict(list)
        for url in urls:
            # Gets the last two entries sperated by comma und puts them in lowercase
            canonical_url = f"https://{'.'.join(urlsplit(url).netloc.split('.')[-2:]).lower()}"
            canonical_groups[canonical_url].append(url)

        return canonical_groups

    def ingest_urls(self, mail_id: int, urls: set[str]) -> None:
        """Orchestrates the ingestion of the provided URLs.

        First gets the canonical URLs mapped to a list of occurrence URLs, after that
        tries to store them in the database.

        Args:
            mail_id: Id of an email message.
            urls: Occurrence URLs of an email message.
        """
        canonical_groups = self.get_canonical_url_groups(urls)

        for canonical_url, occurrence_urls in canonical_groups.items():
            stmt = select(CanonicalUrl.id).where(CanonicalUrl.canonical == canonical_url)
            canonical_id = db.session.scalars(stmt).first()

            if canonical_id is None:
                new_canonical_url = CanonicalUrl(canonical=canonical_url)
                db.session.add(new_canonical_url)
                db.session.flush()
                canonical_id = new_canonical_url.id

            for occurrence_url in occurrence_urls:
                try:
                    with db.session.begin_nested():
                        new_occurrence_url = OccurrenceUrl(
                            canonical_id=canonical_id,
                            mail_id=mail_id,
                            original=occurrence_url
                        )
                        db.session.add(new_occurrence_url)
                except IntegrityError:
                    logger.debug(f"OccurrenceUrl: {occurrence_url} already in database")


    def ingest_attachments(self, mail_id: int, mail: MailMessage) -> None:
        """Ingest file attachments from an email into the database.

        Groups attachments by SHA-256 hash, creates CanonicalFile entries
        if they don't exist, and stores each OccurrenceFile.

        Args:
            mail_id: Database id of the parent mail.
            mail: The MailMessage containing attachments.
        """
        attachments = mail.attachments
        canonical_groups = self.get_canonical_file_groups(attachments)

        for sha256, atts in canonical_groups.items():
            stmt = select(CanonicalFile.id).where(CanonicalFile.sha256 == sha256)
            canonical_id = db.session.scalars(stmt).first()

            if canonical_id is None:
                new_canonical_file = CanonicalFile(sha256=sha256)
                db.session.add(new_canonical_file)
                db.session.flush()
                canonical_id = new_canonical_file.id

            for att in atts:
                new_occurrence_file = OccurrenceFile(
                    mail_id=mail_id,
                    canonical_id=canonical_id,
                    filename=att.filename,
                    size=att.size,
                    mime=att.content_type
                )
                db.session.add(new_occurrence_file)

    def calc_sha256(self, payload: bytes) -> str:
        """Compute the SHA-256 hex digest of a byte payload.

        Args:
            payload: Raw file bytes.

        Returns:
            Lowercase hex string of the SHA-256 hash.
        """
        return hashlib.sha256(payload).hexdigest()

    def get_canonical_file_groups(self, attachments: List[MailAttachment]) -> defaultdict[str, list[MailAttachment]]:
        """Group attachments by their SHA-256 hash.

        Args:
            attachments: List of mail attachments.

        Returns:
            A defaultdict mapping SHA-256 hashes to lists of attachments.
        """
        canonical_groups = defaultdict(list)
        for att in attachments:
            if att.content_type.startswith("image/"):
                continue
            sha256 = self.calc_sha256(att.payload)
            canonical_groups[sha256].append(att)

        return canonical_groups

    def store_mail(self, mail: MailMessage) -> int:
        """Stores an email message in the database.

        Args:
            mail: A MailMessage.

        Returns:
            int: The database id of the stored email message.
        """
        data_key: bytes = user_keys[self.mail_account.owner_id]
        new_mail = Mail(
            account_id = self.mail_account.id,
            folder_id = self.folder_id,
            message_id = mail.headers.get("message-id", [None])[0],
            uid = mail.uid,
            subject = encrypt(data=mail.subject.encode('utf-8'), key=data_key) if mail.subject else None,
            sender = mail.from_,
            recipient = list(mail.to),
            date = mail.date,
            text = encrypt(data=mail.text.encode('utf-8'), key=data_key) if mail.text else None,
            html = encrypt(data=mail.html.encode('utf-8'), key=data_key) if mail.html else None
        )
        db.session.add(new_mail)
        db.session.flush()
        return new_mail.id
