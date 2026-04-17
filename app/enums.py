from enum import Enum

class Verdict(str, Enum):
    """Safety verdict for a scanned URL or file."""
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"

class ScanStatus(str, Enum):
    """Lifecycle state of a VirusTotal scan job."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class SyncStatus(str, Enum):
    """Lifecycle state of an IMAP mail sync operation."""
    SYNCED = "synced"
    FAILED_HOST = "failed_host"
    FAILED_AUTH = "failed_auth"
    FAILED_TIMEOUT = "failed_timeout"
    RUNNING = "running"
