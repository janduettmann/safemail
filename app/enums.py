from enum import Enum

class Verdict(str, Enum):
    """Safety verdict for a scanned URL or file."""
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"

    @property
    def severity(self) -> int:
        return _SEVERITY[self]

_SEVERITY = {
    Verdict.UNKNOWN: 0,
    Verdict.BENIGN: 1,
    Verdict.SUSPICIOUS: 2,
    Verdict.MALICIOUS: 3
}

class ScanStatus(str, Enum):
    """Lifecycle state of a VirusTotal scan job."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class SyncStatus(str, Enum):
    """Lifecycle state of an IMAP mail sync operation."""
    SYNCED = "synced"
    RUNNING = "running"
    FAILED = "failed"

class ConnectionStatus(str, Enum):
    """Connection state of an Mail Account."""
    OK = "ok"
    HOST_UNREACHABLE = "host_unreachable"
    AUTH_FAILED = "auth_failed"
    TIMEOUT = "timeout"
    NEVER_CONNECTED = "never_connected"
    UNKNOWN_ERROR = "unknown_error"
