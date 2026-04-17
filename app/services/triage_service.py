from typing import Sequence
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from app.models import Mail
from app.extensions import db

class TriageService:
    """Service for querying mails in the triage view with pagination."""

    def get_mails_page(self, folder_id: int, page: int, page_size: int, page_uids: set[int]) -> Sequence[Mail]:
        """Fetch mails for a folder page by filtering on pre-calculated IMAP UIDs.

        Uses UID-based filtering instead of OFFSET/LIMIT to support on-demand
        sync where only the requested page's mails may be present in the DB.

        Args:
            folder_id: Database id of the folder.
            page: The 1-based page number (unused, kept for interface consistency).
            page_size: Maximum number of mails to return.
            page_uids: Set of IMAP UIDs that belong to the requested page.

        Returns:
            A sequence of Mail ORM instances matching the given UIDs.
        """
        mails_stmt = (select(Mail)
                      .options(joinedload(Mail.occurrence_files))
                      .where(Mail.folder_id == folder_id, Mail.deleted_at.is_(None), Mail.uid.in_(page_uids))
                      .order_by(Mail.date.desc())
                      .limit(page_size)
                      )
        mails = db.session.scalars(mails_stmt).unique().all()
        return mails

    def get_total_mails(self, folder_id: int) -> int:
        """Count all non-deleted mails in the database for a given folder.

        Args:
            folder_id: Database id of the folder.

        Returns:
            Total number of non-deleted mails.
        """
        total_mails = Mail.query.filter(Mail.folder_id == folder_id, Mail.deleted_at.is_(None)).count()
        return total_mails
