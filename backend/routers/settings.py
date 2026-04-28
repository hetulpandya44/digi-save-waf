from fastapi import APIRouter, Depends, HTTPException  # type: ignore
import sqlite3
import time
import sys
import os
import socket
from typing import Dict

from database import get_db  # type: ignore
from routers.auth import get_current_user, hash_password  # type: ignore
from config import VERSION, APP_NAME, ALLOWED_SETTINGS_KEYS

router = APIRouter(prefix="/api/settings", tags=["settings"])


def _validate_setting(key: str, value: str) -> str:
    normalized = value.strip() if isinstance(value, str) else str(value)
    if key == "log_retention_days":
        try:
            days = int(normalized)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="log_retention_days must be an integer") from exc
        if days < 1 or days > 3650:
            raise HTTPException(status_code=400, detail="log_retention_days must be between 1 and 3650")
        return str(days)
    return normalized

@router.get("")
async def get_settings(conn: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM options")
    settings = {row["key"]: row["value"] for row in cursor.fetchall()}
    # Don't expose internal keys like jwt_secret_key
    settings.pop("jwt_secret_key", None)
    settings.pop("secret_key", None)
    settings["auth_gate_password_configured"] = bool(settings.get("auth_gate_password"))
    settings.pop("auth_gate_password", None)
    return settings

@router.put("")
async def update_settings(payload: Dict[str, str], conn: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = conn.cursor()
    updated_keys = []
    for key, value in payload.items():
        if key not in ALLOWED_SETTINGS_KEYS:
            raise HTTPException(status_code=400, detail=f"Setting '{key}' is not allowed")
        normalized_value = _validate_setting(key, value)
        if key == "auth_gate_password":
            if not normalized_value:
                continue
            normalized_value = hash_password(normalized_value)
        cursor.execute("""
            INSERT INTO options (key, value) 
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """, (key, normalized_value))
        updated_keys.append(key)
    conn.commit()
    return {"message": "Settings updated successfully", "updated_keys": updated_keys}

START_TIME = time.time()

@router.get("/sysinfo")
async def get_sysinfo(user: dict = Depends(get_current_user)):
    """Get system info like uptime, version, and environment details."""
    uptime_seconds = int(time.time() - START_TIME)
    
    waf_status = "offline"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)
            if s.connect_ex(("127.0.0.1", 8085)) == 0:
                waf_status = "online"
    except:
        pass
    
    return {
        "version": VERSION,
        "app_name": APP_NAME,
        "python_version": sys.version.split(' ')[0],
        "uptime": f"{uptime_seconds // 3600}h {(uptime_seconds % 3600) // 60}m {uptime_seconds % 60}s",
        "os": os.name,
        "waf_proxy": waf_status
    }
