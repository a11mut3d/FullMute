import asyncio
from datetime import datetime
from typing import Dict, List, Optional
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from fullmute.web.database import get_scan_configs, create_scan, get_targets, update_scan_status
from fullmute.web.config import config
from fullmute.utils.logger import setup_logger

logger = setup_logger()


class ScanScheduler:
    
    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self._job_map: Dict[int, str] = {}  
    
    def start(self):
        self.scheduler.start()
        logger.info("Scan scheduler started")
    
    def shutdown(self):
        self.scheduler.shutdown()
        logger.info("Scan scheduler stopped")
    
    def add_scheduled_scan(self, config_id: int, schedule_type: str, schedule_value: str):
        trigger = self._create_trigger(schedule_type, schedule_value)
        
        if trigger:
            job = self.scheduler.add_job(
                self._run_scheduled_scan,
                trigger=trigger,
                args=[config_id],
                id=f"scan_{config_id}",
                replace_existing=True,
                misfire_grace_time=3600  
            )
            self._job_map[config_id] = job.id
            logger.info(f"Added scheduled scan for config {config_id} ({schedule_type}: {schedule_value})")
    
    def remove_scheduled_scan(self, config_id: int):
        job_id = f"scan_{config_id}"
        try:
            self.scheduler.remove_job(job_id)
            if config_id in self._job_map:
                del self._job_map[config_id]
            logger.info(f"Removed scheduled scan for config {config_id}")
        except Exception as e:
            logger.warning(f"Failed to remove scheduled scan: {e}")
    
    def _create_trigger(self, schedule_type: str, schedule_value: str):
        if schedule_type == "daily":
            hour = int(schedule_value) if schedule_value.isdigit() else 0
            return CronTrigger(hour=hour, minute=0)
        
        elif schedule_type == "weekly":
            
            parts = schedule_value.split(',')
            if len(parts) == 2:
                day_of_week = int(parts[0])  
                hour = int(parts[1])
                return CronTrigger(day_of_week=day_of_week, hour=hour, minute=0)
        
        elif schedule_type == "monthly":
            
            parts = schedule_value.split(',')
            if len(parts) == 2:
                day = int(parts[0])
                hour = int(parts[1])
                return CronTrigger(day=day, hour=hour, minute=0)
        
        logger.warning(f"Unknown schedule type: {schedule_type}")
        return None
    
    async def _run_scheduled_scan(self, config_id: int):
        try:
            logger.info(f"Running scheduled scan for config {config_id}")
            
            
            configs = get_scan_configs()
            config_item = next((c for c in configs if c['id'] == config_id), None)
            
            if not config_item:
                logger.error(f"Scan config {config_id} not found")
                return
            
            
            target_ids = []
            for group_id in config_item['target_group_ids']:
                targets = get_targets(group_id=group_id)
                target_ids.extend([t['id'] for t in targets])
            
            if not target_ids:
                logger.warning(f"No targets for scheduled scan {config_id}")
                return
            
            
            scan_id = create_scan(
                config_id=config_id,
                target_ids=target_ids,
                user_id=config_item.get('created_by')
            )
            
            logger.info(f"Scheduled scan {scan_id} created for config {config_id}")
            
        except Exception as e:
            logger.error(f"Error running scheduled scan: {e}")
    
    def load_all_scheduled_scans(self):
        try:
            configs = get_scan_configs()
        except Exception as e:
            
            logger.debug(f"Could not load scheduled scans: {e}")
            return
        
        for config_item in configs:
            if (config_item['is_active'] and 
                config_item['schedule_type'] and 
                config_item['schedule_value']):
                
                self.add_scheduled_scan(
                    config_id=config_item['id'],
                    schedule_type=config_item['schedule_type'],
                    schedule_value=config_item['schedule_value']
                )



scheduler = ScanScheduler()


def init_scheduler():
    scheduler.start()
    scheduler.load_all_scheduled_scans()
    
    
    scheduler.scheduler.add_job(
        cleanup_expired_users,
        trigger=CronTrigger(hour=3, minute=0),  
        id="cleanup_expired_users",
        replace_existing=True,
        misfire_grace_time=3600
    )
    logger.info("Added daily cleanup job for expired users")
    
    return scheduler


def cleanup_expired_users():
    try:
        from fullmute.web.expiration_scheduler import cleanup_expired_users as cleanup_func
        
        result = cleanup_func()
        logger.info(f"Expired users cleanup: {result}")
        
    except Exception as e:
        logger.error(f"Error in expired users cleanup: {e}")
