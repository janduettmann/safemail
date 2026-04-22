from typing import Optional
from sqlalchemy import select
from datetime import datetime, timezone
import logging

from app.enums import ScanStatus, Verdict
from app.exceptions import VTApiError, VTMaxRetriesException
from app.models import Mail, CanonicalUrl, CanonicalFile, OccurrenceFile, OccurrenceUrl
from app.schemas import VTReportSummary
from app.services.vt_client import VTClient
from app.extensions import db

logger = logging.getLogger(__name__)

class MailScanService:

    VERDICT_PRIORITY = {
        Verdict.MALICIOUS: 3,
        Verdict.SUSPICIOUS: 2,
        Verdict.BENIGN: 1,
        Verdict.UNKNOWN: 0,
    }

    def scan_mail(self, mail_id: int, vt_client: VTClient) -> None:
        mail = db.session.get(Mail, mail_id)
        if mail is None:
            return

        mail.scan_status = ScanStatus.RUNNING
        db.session.commit()

        self.scan_urls(mail_id, vt_client)
        self.scan_files(mail_id, vt_client)
        self.aggregate_mail_verdict(mail)
        db.session.commit()

    def aggregate_mail_verdict(self, mail: Mail) -> None:
        """Aggregate child CanonicalUrl/CanonicalFile results onto the Mail row.

        Picks the child with the most severe verdict (MALICIOUS > SUSPICIOUS >
        BENIGN > UNKNOWN) and writes its stats back to the Mail so the UI badge
        can render a single summary per mail.

        Args:
            mail: The Mail ORM instance to update.
        """
        urls_stmt = (
            select(CanonicalUrl)
            .join(OccurrenceUrl, OccurrenceUrl.canonical_id == CanonicalUrl.id)
            .where(OccurrenceUrl.mail_id == mail.id)
        )
        files_stmt = (
            select(CanonicalFile)
            .join(OccurrenceFile, OccurrenceFile.canonical_id == CanonicalFile.id)
            .where(OccurrenceFile.mail_id == mail.id)
        )
        children = (
            list(db.session.scalars(urls_stmt).unique().all())
            + list(db.session.scalars(files_stmt).unique().all())
        )

        if not children:
            mail.scan_status = ScanStatus.COMPLETED
            mail.verdict = Verdict.UNKNOWN
            mail.worst_verdict = 0
            mail.total_engines = 0
            return

        statuses = {c.scan_status for c in children}
        if ScanStatus.COMPLETED in statuses:
            mail.scan_status = ScanStatus.COMPLETED
        else:
            mail.scan_status = ScanStatus.FAILED

        worst_child = max(children, key=lambda c: self.VERDICT_PRIORITY[c.verdict])
        mail.verdict = worst_child.verdict
        mail.worst_verdict = worst_child.malicious
        mail.total_engines = (
            worst_child.malicious
            + worst_child.suspicious
            + worst_child.harmless
            + worst_child.undetected
        )

    def scan_urls(self, mail_id: int, vt_client: VTClient) -> None:
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

