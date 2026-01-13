import psutil
import time
import threading
from fullmute.utils.logger import setup_logger

logger = setup_logger()

class Monitor:
    def __init__(self, interval=10):
        self.interval = interval
        self.running = False
        self.thread = None

    def log_metrics(self):
        while self.running:
            try:
                memory_info = psutil.virtual_memory()
                cpu_percent = psutil.cpu_percent(interval=1)
                disk_usage = psutil.disk_usage('/')

                logger.info(
                    f"CPU: {cpu_percent}% | "
                    f"Memory: {memory_info.percent}% | "
                    f"Disk: {disk_usage.percent}%"
                )

                time.sleep(self.interval)
            except Exception as e:
                logger.error(f"Error in monitor: {e}")
                time.sleep(self.interval)

    def start(self):
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self.log_metrics, daemon=True)
            self.thread.start()
            logger.info("Monitor started")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        logger.info("Monitor stopped")
