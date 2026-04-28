import logging
import sqlite3
import time
from datetime import datetime, timedelta
from database import DATABASE_PATH

logger = logging.getLogger("waf_cron")

def _get_conn():
    """Get a direct DB connection for background tasks (not a FastAPI Depends generator)."""
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def cleanup_old_logs():
    """Deletes detection logs older than configured retention days."""
    conn = None
    try:
        conn = _get_conn()
        cursor = conn.cursor()
        
        # Read retention days from options or default to 30
        cursor.execute("SELECT value FROM options WHERE key = 'log_retention_days'")
        row = cursor.fetchone()
        retention_days = int(row["value"]) if row else 30
        
        cutoff = datetime.utcnow() - timedelta(days=retention_days)
        cursor.execute("DELETE FROM detect_logs WHERE created_at < ?", (cutoff.strftime("%Y-%m-%d %H:%M:%S"),))
        
        # Clean expired CAPTCHA/Auth sessions
        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("DELETE FROM captcha_sessions WHERE expires_at < ?", (now_str,))
        cursor.execute("DELETE FROM auth_challenges WHERE expires_at < ?", (now_str,))
        
        conn.commit()
        logger.info(f"Cron: Cleaned up logs older than {retention_days} days and expired sessions.")
    except Exception as e:
        logger.error(f"Cron cleanup failed: {e}")
    finally:
        if conn:
            conn.close()

def compute_statistics():
    """Computes daily aggregation stats for dashboard."""
    conn = None
    try:
        conn = _get_conn()
        cursor = conn.cursor()
        today = datetime.utcnow().strftime("%Y-%m-%d 00:00:00")
        
        for stat_type in ["total-req", "total-denied"]:
            cursor.execute("SELECT id FROM system_statistics WHERE type = ? AND created_at >= ?", (stat_type, today))
            if not cursor.fetchone():
                cursor.execute("INSERT INTO system_statistics (type, value, value_type, created_at) VALUES (?, 0, 'count', ?)", (stat_type, today))
                
        conn.commit()
    except Exception as e:
        logger.error(f"Cron stats compute failed: {e}")
    finally:
        if conn:
            conn.close()

_scheduler = None

def start_scheduler():
    """Initializes and starts the APScheduler background tasks."""
    global _scheduler
    try:
        from apscheduler.schedulers.background import BackgroundScheduler  # type: ignore
        _scheduler = BackgroundScheduler()
        _scheduler.add_job(cleanup_old_logs, 'cron', hour=2, minute=0)
        _scheduler.add_job(compute_statistics, 'interval', minutes=5)
        _scheduler.start()
        logger.info("Background Cron Scheduler started.")
    except ImportError:
        logger.warning("apscheduler not installed — background tasks disabled. pip install apscheduler")

def stop_scheduler():
    global _scheduler
    if _scheduler:
        _scheduler.shutdown()
