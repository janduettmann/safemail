from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

from app.scan_queue import ScanQueue

db = SQLAlchemy()
login_manager = LoginManager()
user_keys: dict[int, bytes] = {}
scan_queue: ScanQueue = ScanQueue()

