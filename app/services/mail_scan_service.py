from typing import Optional
from sqlalchemy import select
from datetime import datetime, timezone
import logging

from app.enums import ScanStatus, Verdict
from app.exceptions import VTApiError, VTMaxRetriesException
from app.models import CanonicalUrl, CanonicalFile, Mail, OccurrenceFile, OccurrenceUrl
from app.schemas import VTReportSummary
from app.services.vt_client import VTClient
from app.extensions import db

logger = logging.getLogger(__name__)

class MailScanService:
    """Coordinates the full VirusTotal scan lifecycle for a single mail.

    A scan consists of three phases:
        1. ``scan_urls`` — request URL reports for every canonical URL
           extracted from the mail.
        2. ``scan_files`` — request file reports for every attachment hash.
        3. ``aggregate_mail_verdict`` — derive the mail-level verdict and
           status from the worst child verdict.

    All methods commit incrementally so the polling status bar can
    observe progress across transactions.
    """

    def scan_mail(self, mail_id: int, vt_client: VTClient) -> None:
        """Runs the full scan pipeline for one mail.

        Sets the mail's ``scan_status`` to RUNNING (committed immediately
        for cross-transaction visibility), then scans URLs, files, and
        aggregates the result.

        Args:
            mail_id: Database id of the ``Mail`` to scan.
            vt_client: A configured VirusTotal client used for all
                outbound API calls.
        """
        mail = db.session.get(Mail, mail_id)

        if not mail:
            return

        mail.scan_status = ScanStatus.RUNNING
        db.session.commit()

        self.scan_urls(mail_id, vt_client)
        self.scan_files(mail_id, vt_client)
        self.aggregate_mail_verdict(mail_id)

    def aggregate_mail_verdict(self, mail_id: int) -> None:
        """Derives the mail-level verdict from its scanned children.

        Selects all canonical URLs and files associated with the mail
        through their occurrence rows and applies these rules:

        - No children → COMPLETED / BENIGN.
        - All children FAILED → FAILED / UNKNOWN.
        - Otherwise → COMPLETED with the worst child's verdict and its
          malicious/total engine counts.

        Args:
            mail_id: Database id of the ``Mail`` to update.
        """
        mail = db.session.get(Mail, mail_id)

        if not mail:
            return

        canonical_urls_stmt = (
        select(CanonicalUrl)
        .join(OccurrenceUrl, OccurrenceUrl.canonical_id == CanonicalUrl.id)
        .where(
                OccurrenceUrl.mail_id == mail_id
            )
        )
        canonical_files_stmt = (
        select(CanonicalFile)
        .join(OccurrenceFile, OccurrenceFile.canonical_id == CanonicalFile.id)
        .where(
                OccurrenceFile.mail_id == mail_id
            )
        )
        canonical_objects = list(db.session.scalars(canonical_urls_stmt).unique().all()) + list(db.session.scalars(canonical_files_stmt).unique().all())

        if not canonical_objects:
            mail.scan_status = ScanStatus.COMPLETED
            mail.verdict = Verdict.BENIGN
            mail.worst_verdict = 0
            mail.total_engines = 0
            db.session.commit()
            return
    
        if all(co.scan_status == ScanStatus.FAILED for co in canonical_objects):
            mail.scan_status = ScanStatus.FAILED
            mail.verdict = Verdict.UNKNOWN
            mail.worst_verdict = 0
            mail.total_engines = 0
            db.session.commit()
            return

        worst_co = max(canonical_objects, key=lambda co: co.verdict.severity)

        mail.scan_status = ScanStatus.COMPLETED
        mail.verdict = worst_co.verdict
        mail.worst_verdict = worst_co.malicious
        mail.total_engines = worst_co.malicious + worst_co.suspicious + worst_co.harmless + worst_co.undetected
        db.session.commit()
        return

    def scan_urls(self, mail_id: int, vt_client: VTClient) -> None:
        """Scans every canonical URL referenced by the given mail.

        For each URL the row is moved through RUNNING → COMPLETED/FAILED.
        On unrecoverable authentication errors the loop aborts early so
        the rest of the queue is not exhausted against a broken key.

        Args:
            mail_id: Database id of the ``Mail`` whose URLs should be scanned.
            vt_client: VirusTotal client used to request URL reports.
        """
        canonical_urls_stmt = (
        select(CanonicalUrl)
        .join(OccurrenceUrl, OccurrenceUrl.canonical_id == CanonicalUrl.id)
        .where(
                OccurrenceUrl.mail_id == mail_id
            )
        )
        canonical_urls = db.session.scalars(canonical_urls_stmt).unique().all()
    
        for canonical_url in canonical_urls:
            canonical_url.scan_status = ScanStatus.RUNNING
            db.session.flush()

            try:
                report: VTReportSummary = vt_client.get_url_report(canonical_url.canonical)
                canonical_url.scan_status = ScanStatus.COMPLETED
                canonical_url.malicious = report.malicious
                canonical_url.suspicious = report.suspicious
                canonical_url.harmless = report.harmless
                canonical_url.undetected = report.undetected
                canonical_url.verdict = report.verdict
                canonical_url.last_analysis_id = report.last_analysis_id
                canonical_url.checked_at = report.checked_at

            except VTApiError as e:
                if e.code in ("WrongCredentialsError", "AuthenticationRequiredError"):
                    logger.error("Virustotal: Wrong API key! - stop scanning")
                    break
                canonical_url.scan_status = ScanStatus.FAILED
                logger.error(f"ID: {canonical_url.id} Error: {e}")
            except VTMaxRetriesException:
                canonical_url.scan_status = ScanStatus.FAILED
                logger.error(f"ID: {canonical_url.id} Max retries reached")

        db.session.commit()


    def scan_files(self, mail_id: int, vt_client: VTClient) -> None:
        """Scans every canonical attachment referenced by the given mail.

        Each file row is moved through RUNNING → COMPLETED/FAILED.
        VirusTotal returns ``None`` for hashes it has never seen, in
        which case the file is marked COMPLETED with no verdict change
        but its ``checked_at`` timestamp is updated.

        Args:
            mail_id: Database id of the ``Mail`` whose attachments should
                be scanned.
            vt_client: VirusTotal client used to request file reports.
        """
        canonical_files_stmt = (
        select(CanonicalFile)
        .join(OccurrenceFile, OccurrenceFile.canonical_id == CanonicalFile.id)
        .where(
                OccurrenceFile.mail_id == mail_id
            )
        )
        canonical_files = db.session.scalars(canonical_files_stmt).unique().all()

        for canonical_file in canonical_files:
            canonical_file.scan_status = ScanStatus.RUNNING
            db.session.flush()

            try:
                report: Optional[VTReportSummary] = vt_client.get_file_report(canonical_file.sha256)
                if report:
                    canonical_file.scan_status = ScanStatus.COMPLETED
                    canonical_file.malicious = report.malicious
                    canonical_file.suspicious = report.suspicious
                    canonical_file.harmless = report.harmless
                    canonical_file.undetected = report.undetected
                    canonical_file.verdict = report.verdict
                    canonical_file.last_analysis_id = report.last_analysis_id
                    canonical_file.checked_at = report.checked_at
                else:
                    canonical_file.scan_status = ScanStatus.COMPLETED
                    canonical_file.checked_at = datetime.now(timezone.utc)

            except Exception as e:
                canonical_file.scan_status = ScanStatus.FAILED
                logger.error(f"ID: {canonical_file.id} Error: {e}")

        db.session.commit()

