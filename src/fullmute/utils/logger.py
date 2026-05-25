import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

import os

def setup_logger(name="fullmute", level="INFO", file_path=None, max_mb=50, backups=5):
    logger = logging.getLogger(name)

    logger.handlers.clear()

    # Allow overriding log level with environment variable FULLMUTE_LOG_LEVEL
    env_level = os.getenv('FULLMUTE_LOG_LEVEL')
    resolved_level = (env_level or level or 'INFO').upper()
    logger.setLevel(getattr(logging, resolved_level))

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    if file_path:
        log_file = Path(file_path)
        log_file.parent.mkdir(parents=True, exist_ok=True)

        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_mb * 1024 * 1024,
            backupCount=backups,
            encoding='utf-8'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger
