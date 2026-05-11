from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from collections import defaultdict

from app.scan_queue import ScanQueue
from app.enums import SyncStatus

db = SQLAlchemy()
login_manager = LoginManager()
user_keys: dict[int, bytes] = {}
scan_queue: ScanQueue = ScanQueue()
# Tracks sync state per (folder_id, page) tuple across background threads.
page_sync_status: dict[tuple[int, int], SyncStatus] = {}
# Caches the IMAP UIDs belonging to each (folder_id, page) tuple.
# Populated by the background sync thread before ingestion, so polling
# queries can filter mails by UID instead of using OFFSET-based pagination.
page_uids: defaultdict[tuple[int, int], set[int]] = defaultdict(set)

