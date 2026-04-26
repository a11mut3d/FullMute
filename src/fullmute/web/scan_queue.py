
import threading
import asyncio
import time
import gc
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from collections import deque
from enum import Enum

from fullmute.utils.logger import setup_logger
from fullmute.web.database import get_scan, update_scan_status, get_user_settings

logger = setup_logger()


class ScanStatus(Enum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanQueueItem:
    def __init__(self, scan_id: int, user_id: int, target_ids: List[int],
                 test_default_credentials: bool = True, search_exploits: bool = False,
                 port_scan_enabled: bool = False, port_scan_with_cves: bool = False,
                 port_scan_with_exploits: bool = False, max_duration_hours: int = 24):
        self.scan_id = scan_id
        self.user_id = user_id
        self.target_ids = target_ids
        self.test_default_credentials = test_default_credentials
        self.search_exploits = search_exploits
        self.port_scan_enabled = port_scan_enabled
        self.port_scan_with_cves = port_scan_with_cves
        self.port_scan_with_exploits = port_scan_with_exploits
        self.status = ScanStatus.PENDING
        self.created_at = datetime.now()
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.max_duration = timedelta(hours=max_duration_hours)
        self.thread: Optional[threading.Thread] = None
        self.thread_id: Optional[int] = None
        
    def is_expired(self) -> bool:
        if self.started_at and self.status == ScanStatus.RUNNING:
            return datetime.now() - self.started_at > self.max_duration
        return False
    
    def get_duration(self) -> float:
        """Get scan duration in seconds"""
        if self.started_at:
            end_time = self.completed_at or datetime.now()
            return (end_time - self.started_at).total_seconds()
        return 0.0


class UserScanQueue:
    def __init__(self, user_id: int, max_concurrent: int = 3):
        self.user_id = user_id
        self.max_concurrent = max_concurrent
        self.queue: deque[ScanQueueItem] = deque()
        self.running: Dict[int, ScanQueueItem] = {}  
        self.lock = threading.RLock()  
        self._shutdown = False
        self._last_cleanup = time.time()
        self._cleanup_interval = 300  

    def add_scan(self, scan_id: int, target_ids: List[int], test_default_credentials: bool = True, 
                 search_exploits: bool = False, port_scan_enabled: bool = False, 
                 port_scan_with_cves: bool = False, port_scan_with_exploits: bool = False) -> ScanQueueItem:
        with self.lock:
            item = ScanQueueItem(
                scan_id, self.user_id, target_ids, 
                test_default_credentials, 
                search_exploits,
                port_scan_enabled,
                port_scan_with_cves,
                port_scan_with_exploits
            )
            item.status = ScanStatus.QUEUED
            self.queue.append(item)
            logger.info(f"Added scan {scan_id} to queue for user {self.user_id}")

            
            self._cleanup_expired_scans()

            
            self._try_start_scans()

            return item

    def _cleanup_expired_scans(self):
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
            
        with self.lock:
            expired_scans = []
            
            
            for scan_id, item in list(self.running.items()):
                if item.is_expired():
                    expired_scans.append(scan_id)
                    logger.warning(f"Scan {scan_id} expired (duration: {item.get_duration():.1f}s), marking as failed")
                    item.status = ScanStatus.FAILED
                    item.completed_at = datetime.now()
                    update_scan_status(scan_id, 'failed', progress=0)
            
            
            for scan_id in expired_scans:
                del self.running[scan_id]
            
            if expired_scans:
                logger.info(f"Cleaned up {len(expired_scans)} expired scans")
                self._try_start_scans()
            
            self._last_cleanup = now

    def _try_start_scans(self):
        if self._shutdown:
            return

        available_slots = self.max_concurrent - len(self.running)

        while available_slots > 0 and self.queue:
            item = self.queue.popleft()

            
            scan_data = get_scan(item.scan_id)
            if scan_data and scan_data.get('status') == 'cancelled':
                item.status = ScanStatus.CANCELLED
                item.completed_at = datetime.now()
                logger.info(f"Scan {item.scan_id} was cancelled while in queue")
                continue

            
            item.status = ScanStatus.RUNNING
            item.started_at = datetime.now()
            self.running[item.scan_id] = item

            logger.info(f"Starting scan {item.scan_id} for user {self.user_id} (slot {len(self.running)}/{self.max_concurrent})")

            
            from fullmute.web.scanner import run_scan_sync

            
            thread = threading.Thread(
                target=run_scan_sync,
                args=(
                    item.scan_id, 
                    self.user_id, 
                    item.target_ids, 
                    item.test_default_credentials,
                    item.search_exploits,
                    item.port_scan_enabled,
                    item.port_scan_with_cves,
                    item.port_scan_with_exploits
                ),
                daemon=True,  
                name=f"scan-{item.scan_id}-user-{item.user_id}"
            )
            thread.start()
            item.thread = thread
            item.thread_id = thread.ident
            logger.info(f"Scan thread {thread.ident} started for scan {item.scan_id}")

            available_slots -= 1

    def complete_scan(self, scan_id: int, status: ScanStatus):
        with self.lock:
            if scan_id in self.running:
                item = self.running.pop(scan_id)
                item.status = status
                item.completed_at = datetime.now()
                duration = item.get_duration()
                logger.info(f"Scan {scan_id} completed with status {status} (duration: {duration:.1f}s)")

                
                self._try_start_scans()

    def cancel_scan(self, scan_id: int) -> bool:
        with self.lock:
            
            for i, item in enumerate(self.queue):
                if item.scan_id == scan_id:
                    self.queue.remove(item)
                    item.status = ScanStatus.CANCELLED
                    item.completed_at = datetime.now()
                    logger.info(f"Cancelled queued scan {scan_id}")
                    update_scan_status(scan_id, 'cancelled')
                    return True

            
            if scan_id in self.running:
                update_scan_status(scan_id, 'cancelled')
                logger.info(f"Marked running scan {scan_id} for cancellation")
                
                item = self.running.pop(scan_id)
                item.status = ScanStatus.CANCELLED
                item.completed_at = datetime.now()
                
                from fullmute.web.scanner import active_scans
                if scan_id in active_scans:
                    active_scans[scan_id]['status'] = 'cancelled'
                
                self._try_start_scans()
                return True

            return False

    def get_queue_status(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "user_id": self.user_id,
                "max_concurrent": self.max_concurrent,
                "queued": len(self.queue),
                "running": len(self.running),
                "queue_items": [
                    {
                        "scan_id": item.scan_id,
                        "status": item.status.value,
                        "position": i + 1
                    }
                    for i, item in enumerate(self.queue)
                ],
                "running_items": [
                    {
                        "scan_id": item.scan_id,
                        "status": item.status.value,
                        "started_at": item.started_at.isoformat() if item.started_at else None
                    }
                    for item in self.running.values()
                ]
            }


class ScanQueueManager:
    _instance: Optional['ScanQueueManager'] = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        
        self.user_queues: Dict[int, UserScanQueue] = {}
        self.global_lock = threading.Lock()
        self._shutdown = False
        
        logger.info("ScanQueueManager initialized")

    def get_user_queue(self, user_id: int) -> UserScanQueue:
        with self.global_lock:
            if user_id not in self.user_queues:
                
                import yaml
                from pathlib import Path
                config_path = Path(__file__).resolve().parents[2].parent / "config.yaml"
                max_concurrent = 3  
                
                try:
                    if config_path.exists():
                        with open(config_path, 'r') as f:
                            config = yaml.safe_load(f)
                            max_concurrent = config.get('scanner', {}).get('max_concurrent', 3)
                except Exception as e:
                    logger.warning(f"Could not load max_concurrent from config: {e}")

                self.user_queues[user_id] = UserScanQueue(user_id, max_concurrent)
                logger.info(f"Created new queue for user {user_id} with max_concurrent={max_concurrent} (from global config)")

            return self.user_queues[user_id]

    def add_scan(self, scan_id: int, user_id: int, target_ids: List[int], 
                 test_default_credentials: bool = True, search_exploits: bool = False,
                 port_scan_enabled: bool = False, port_scan_with_cves: bool = False,
                 port_scan_with_exploits: bool = False) -> ScanQueueItem:
        """Add a scan to user's queue"""
        user_queue = self.get_user_queue(user_id)
        return user_queue.add_scan(
            scan_id, 
            target_ids, 
            test_default_credentials, 
            search_exploits,
            port_scan_enabled,
            port_scan_with_cves,
            port_scan_with_exploits
        )

    def complete_scan(self, scan_id: int, user_id: int, status: ScanStatus):
        if user_id in self.user_queues:
            self.user_queues[user_id].complete_scan(scan_id, status)

    def cancel_scan(self, scan_id: int, user_id: int) -> bool:
        if user_id in self.user_queues:
            return self.user_queues[user_id].cancel_scan(scan_id)
        return False

    def get_user_queue_status(self, user_id: int) -> Dict[str, Any]:
        if user_id in self.user_queues:
            return self.user_queues[user_id].get_queue_status()
        return {"error": "User queue not found"}

    def get_all_queues_status(self) -> Dict[str, Any]:
        with self.global_lock:
            return {
                "total_users": len(self.user_queues),
                "total_queued": sum(len(q.queue) for q in self.user_queues.values()),
                "total_running": sum(len(q.running) for q in self.user_queues.values()),
                "user_queues": {
                    user_id: queue.get_queue_status()
                    for user_id, queue in self.user_queues.items()
                }
            }



scan_queue_manager: Optional[ScanQueueManager] = None


def get_scan_queue_manager() -> ScanQueueManager:
    global scan_queue_manager
    if scan_queue_manager is None:
        scan_queue_manager = ScanQueueManager()
    return scan_queue_manager


def init_scan_queue_manager() -> ScanQueueManager:
    global scan_queue_manager
    scan_queue_manager = ScanQueueManager()
    return scan_queue_manager
