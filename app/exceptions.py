
class VTMaxRetriesException(Exception):
    """Raised when the maximum number of VirusTotal API retries is exceeded."""
    pass

class MissingAnalysisIdException(Exception):
    """Raised when a VirusTotal submission response does not contain an analysis ID."""
    pass

class MissingSecretException(Exception):
    """Raised when a required secret (e.g. API key) is not configured."""
    pass

class VTApiError(Exception):
    """Raised when the VirusTotal API returns a non-retryable error.

    Attributes:
        code: VirusTotal error code (e.g. 'WrongCredentialsError').
        message: Human-readable error description.
        status_code: HTTP status code of the response.
    """
    def __init__(self, code: str, message: str, status_code: int) -> None:
        self.code = code
        self.message = message
        self.status_code = status_code
        super().__init__(f"{code}: {message}")
