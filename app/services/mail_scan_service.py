from typing import Optional
from sqlalchemy import select
from datetime import datetime, timezone
import logging

from app.enums import ScanStatus
from app.exceptions import VTApiError, VTMaxRetriesException
from app.models import CanonicalUrl, CanonicalFile, OccurrenceFile, OccurrenceUrl
from app.schemas import VTReportSummary
from app.services.vt_client import VTClient
from app.extensions import db

logger = logging.getLogger(__name__)

class MailScanService:

    def scan_mail(self, mail_id: int, vt_client: VTClient) -> None:
        self.scan_urls(mail_id, vt_client)
        self.scan_files(mail_id, vt_client)

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

