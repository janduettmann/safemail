from queue import Queue
import threading
import time
from typing import Optional

class ScanQueue:

    def __init__(self) -> None:
        self.queue: Queue[int] = Queue()
        self.total: int = 0
        self.completed: int = 0
        self.lock = threading.Lock()
        self.finished_at: Optional[float] = None

    def add(self, mail_id: int) -> None:
        with self.lock:
            self.finished_at = None
            if self.completed == self.total:
                self.total = 0
                self.completed = 0
            self.queue.put(mail_id)
            self.total += 1

    def complete(self) -> None:
        with self.lock:
            self.completed += 1
            if self.completed == self.total:
                self.finished_at = time.time()

    def is_visible(self) -> bool:
        with self.lock:
            if self.finished_at:
                return self.total > 0 and time.time() - self.finished_at < 1.0
            return self.total > 0 and self.completed < self.total 

