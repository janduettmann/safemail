import base64
import time
from datetime import datetime, timezone
from typing import Mapping, Any, Optional
import requests
from requests import JSONDecodeError, RequestException, Response
import os
import logging

from app.schemas import VTReportSummary
from app.enums import Verdict
from app.exceptions import MissingAnalysisIdException, VTMaxRetriesException, VTApiError

logger = logging.getLogger(__name__)

class VTClient:
    """A Service for communicating with the Virustotal API.

    Attributes:
        api_key: Virustotal API key.
        timeout_s: Request timeout in seconds
        max_retries: Maximum retries for transient errors (e.g., timeouts, HTTP(429).
    """
    def __init__(self, timeout_s: int = 10, max_retries: int = 5) -> None:
        self.api_key = os.environ["VT_API_KEY"]
        self.timeout_s = timeout_s
        self.max_retries = max_retries

    def get_url_report(self, canonical_url: str) -> VTReportSummary:
        """This method gets a Virustotal Url-Report.

        Args:
            vt_url_id: The BASE64 of the canonized URL.

        Returns:
            Returns a VTReportSummary (e.g. HTTP(200, 404) or None.

        Raises:
            PermissionError: Throws a PermissionError if the Virustotal API key is wrong.
            RuntimeError: Throws a RuntimeError if the rate limit from Virustotal is reached.
        """
        headers = {
            "accept": "application/json",
            "x-apikey": f"{self.api_key}"
        }
        vt_url_id: str = self._get_vt_url_id(canonical_url)
        url: str = f"https://www.virustotal.com/api/v3/urls/{vt_url_id}"

        response: Response = self._request_with_retry("GET", url, headers=headers)

        if response.status_code == 200:
            report = response.json()
            stats: Mapping[str, Any] = (report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) or {})
            return self._create_vt_report_summary(stats, vt_url_id)

        else: # If the status_code is 404
            analysis_id: str = self.submit_url(canonical_url)
            analysis_response: Response = self.get_analysis(analysis_id)

            stats = (analysis_response.json().get("data", {}).get("stats", {}) or {})
            return self._create_vt_report_summary(stats, analysis_id)



    def _get_vt_url_id(self, canonical_url: str) -> str:
        return base64.urlsafe_b64encode(canonical_url.encode()).decode().strip("=")

    def submit_url(self, canonical_url: str) -> str:
        """Sends a POST request to Virustotal with an url to get a Analysis id.

        Args:
            normalized: A base domain name like youtube.com instead of youtube.com/watch...

        Returns:
            Returns the analysis id.

        Raises:
            PermissionError: Throws a PermissionError if the Virustotal API key is wrong.
            RuntimeError: Throws a RuntimeError if the rate limit from Virustotal is reached.
        """
        url = "https://www.virustotal.com/api/v3/urls"
        payload = { "url": f"{canonical_url}" }
        headers = {
            "accept": "application/json",
            "x-apikey": f"{self.api_key}",
            "content-type": "application/x-www-form-urlencoded"
        }

        response: Response = self._request_with_retry("POST", url, headers=headers, payload=payload)

        if response.status_code == 200:
            analysis_id: str = response.json().get("data", {}).get("id")

            if analysis_id:
                return analysis_id

        raise MissingAnalysisIdException

    def get_analysis(self, analysis_id: str) -> Response:
        """This methode tries to get a analysis based in a analysis id.

        Args:
            analysis_id: Unique Idenifier of an analysis.

        Returns:
            Returns a VTReportSummary or None.

        Raises:
            ValueError: Throws a ValueError if the analysis id is invalid.
            PermissionError: Throws a PermissionError if the Virustotal API key is wrong.
            RuntimeError: Throws a RuntimeError if rate limit of Virustotal is reached.
        """
        url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        headers = {
        "accept": "application/json",
        "x-apikey": f"{self.api_key}"
        }

        response: Response = self._request_with_retry("GET", url, headers=headers)

        return response

    def get_file_report(self, sha256_hash: str) -> Optional[VTReportSummary]:
        """This methode tries to get a file report based on a sha256 hash:

        Args:
            sha256_hash: A sha256 representation of a file.

        Returns:
            Returns a VTReportSummary or None

        Raises:
            ValueError: Throws a ValueError if the file hash is invalid.
            PermissionError: Throws a PermissionError if the API key is wrong.
            RuntimeError: Throws a RuntimeError if rate limit of Virustotal is reached.
        """
        url: str = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
        headers: dict[str, str] = {
            "accept": "application/json",
            "x-apikey": f"{self.api_key}"
        }

        response: Response = self._request_with_retry("GET", url, headers=headers)

        if response.status_code == 404:
            return None

        stats: Mapping[str, Any] = (response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) or {})
        return self._create_vt_report_summary(stats, sha256_hash)

    def _reach_verdict(self, stats: Mapping[str, Any]) -> Verdict:
        """Reaches a verdict based on the stats.

        Args:
            stats: Analysis stats from Virustotal.

        Returns:
            Returns a Verdict.
        """
        malicious: int = int(stats.get("malicious", 0) or 0)
        suspicious: int = int(stats.get("suspicious", 0) or 0)
        harmless: int = int(stats.get("harmless", 0) or 0)

        malicious_ratio: float = malicious / (malicious + suspicious + harmless + 1e-6)
        suspicious_ratio: float = suspicious / (malicious + suspicious + harmless + 1e-6)

        if malicious_ratio > 0.15:
            return Verdict.MALICIOUS
        if suspicious_ratio > 0.15 or malicious_ratio > 0.05:
            return Verdict.SUSPICIOUS
        if harmless > 0:
            return Verdict.BENIGN
        return Verdict.UNKNOWN

    def _create_vt_report_summary(self, stats, last_analysis_id: str) -> VTReportSummary:
        """Creates a Summary of the report from the API request.

        Args:
            stats (dict[str, int]): Result of the AV scanner (e.g. harmless: 70, malicious: 10 etc)
            last_analysis_id: Id of the Virustotal report.

        Returns:
            VTReportSummary: Summary of the report.
        """
        verdict: Verdict = self._reach_verdict(stats)
        return VTReportSummary(
            last_analysis_id=last_analysis_id,
            verdict=verdict,
            malicious=int(stats.get("malicious", 0) or 0),
            suspicious=int(stats.get("suspicious", 0) or 0),
            harmless=int(stats.get("harmless", 0) or 0),
            undetected=int(stats.get("undetected", 0) or 0),
            checked_at=datetime.now(timezone.utc)
        )


    def _request_with_retry(self, method: str, url: str, headers: dict[str, str], payload = None) -> Response:
        """Tries to request the Virustotal endpoint.

        Args:
            payload (bytes|None): Attachment or URL which should be scanned.
            method: HTTP methode (e.g. GET or POST).
            url: URL of the Virustotal endpoint.
            headers: Header informaion for the request.

        Returns:
            Response: Response from the request.

        Raises:
            ValueError: If an unsupported HTML method is provided (e.g. PUT).
            VTApiError: If an error occured during the request (e.g. HTTP 400, 429 etc).
        """
        backoff_s = 1.0

        for attempt in range(self.max_retries):
            try:
                match method:
                    case "GET":
                        response = requests.get(url, headers=headers, timeout=self.timeout_s)
                    case "POST":
                        response = requests.post(url, data=payload, headers=headers, timeout=self.timeout_s)
                    case _:
                        raise ValueError(f"Unsupported methode: {method}")

                if response.status_code == 200:
                    logger.info("Virustotal: Successful response (HTTP 200)")
                    return response

                if response.status_code >= 400:
                    try:
                        error_body = response.json().get("error", {})

                    except (ValueError, JSONDecodeError):
                        error_body = {}

                    code = error_body.get("code", "UnknownError")
                    message = error_body.get("message", "")
                    status_code = response.status_code

                    match response.status_code:
                        case 400 | 401 | 403:
                            logger.error(f"Virustotal: {message} (HTTP {status_code})")
                            raise VTApiError(
                                code = code,
                                message = message,
                                status_code = status_code
                            )

                        case 404:
                            logger.error(f"Virustotal: {message} (HTTP 404)")
                            return response

                        case 429:
                            if code == "QuotaExceededError":
                                raise VTApiError(
                                    code = code,
                                    message = message,
                                    status_code = status_code
                                )
                            logger.error(f"Virustotal: {message} (HTTP 429)")
                            time.sleep(backoff_s)
                            backoff_s = min(backoff_s * 2, 30.0)
                            continue

                        case 503 | 504:
                            logger.error(f"Virustotal: {message} (HTTP {status_code})")
                            time.sleep(backoff_s)
                            backoff_s = min(backoff_s * 2, 30.0)
                            continue

            except RequestException as re:
                if attempt == self.max_retries - 1:
                    logger.error(f"Failed to connect! Error: {re}")
                    raise
                time.sleep(backoff_s)
                backoff_s = min(backoff_s * 2, 30.0)
                continue

        raise VTMaxRetriesException
