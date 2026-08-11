import sys
from loguru import logger
from .paths import DATA_DIR

logger.remove()

# Console Logger
logger.add(
    sys.stderr,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
    level="INFO"
)

# File Logger (Rotates daily, keeps 7 days, compresses old logs)
log_file = DATA_DIR / "error_panel.log"
logger.add(
    str(log_file),
    rotation="00:00",
    retention="7 days",
    compression="zip",
    level="DEBUG",
    encoding="utf-8"
)
