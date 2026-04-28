import json
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import sqlite3
import logging

from database import get_db
from routers.auth import get_current_user

router = APIRouter(prefix="/api", tags=["Websites"])
logger = logging.getLogger("WAF_Manager.websites")


class WebsiteCreate(BaseModel):
    comment: str = ""
    server_names: List[str] = []
    ports: List[int] = [80]
    upstreams: List[str] = []
    cert_filename: str = ""
    key_filename: str = ""
    is_enabled: bool = True
    captcha_enabled: bool = False
    auth_enabled: bool = False
    dynamic_enabled: bool = False
    detection_mode: str = "balance"


class WebsiteUpdate(BaseModel):
    comment: Optional[str] = None
    server_names: Optional[List[str]] = None
    ports: Optional[List[int]] = None
    upstreams: Optional[List[str]] = None
    cert_filename: Optional[str] = None
    key_filename: Optional[str] = None
    is_enabled: Optional[bool] = None
    captcha_enabled: Optional[bool] = None
    auth_enabled: Optional[bool] = None
    dynamic_enabled: Optional[bool] = None
    detection_mode: Optional[str] = None


def website_to_dict(w):
    return {
        "id": w["id"],
        "comment": w["comment"],
        "server_names": json.loads(w["server_names"]) if w["server_names"] else [],
        "ports": json.loads(w["ports"]) if w["ports"] else [],
        "upstreams": json.loads(w["upstreams"]) if w["upstreams"] else [],
        "cert_filename": w["cert_filename"],
        "key_filename": w["key_filename"],
        "is_enabled": bool(w["is_enabled"]),
        "captcha_enabled": bool(w["captcha_enabled"]) if "captcha_enabled" in w.keys() else False,
        "auth_enabled": bool(w["auth_enabled"]) if "auth_enabled" in w.keys() else False,
        "dynamic_enabled": bool(w["dynamic_enabled"]) if "dynamic_enabled" in w.keys() else False,
        "detection_mode": w["detection_mode"] if "detection_mode" in w.keys() else "balance",
        "created_at": str(w["created_at"]),
        "updated_at": str(w["updated_at"])
    }


def notify_waf_site_cache_refresh():
    try:
        import httpx

        httpx.post("http://127.0.0.1:8085/internal/cache/invalidate", timeout=2.0)
    except Exception as exc:
        logger.warning(f"Could not notify WAF cache refresh: {exc}")


@router.get("/websites")
def get_websites(db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM websites ORDER BY id DESC")
    websites = cursor.fetchall()
    return {
        "code": 0,
        "data": [website_to_dict(w) for w in websites],
        "total": len(websites)
    }


@router.get("/websites/{website_id}")
def get_website(website_id: int, db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM websites WHERE id = ?", (website_id,))
    website = cursor.fetchone()
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")
    return {"code": 0, "data": website_to_dict(website)}


@router.post("/websites")
def create_website(req: WebsiteCreate, db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    cursor.execute(
        """INSERT INTO websites 
        (comment, server_names, ports, upstreams, cert_filename, key_filename, is_enabled,
         captcha_enabled, auth_enabled, dynamic_enabled, detection_mode) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            req.comment,
            json.dumps(req.server_names),
            json.dumps(req.ports),
            json.dumps(req.upstreams),
            req.cert_filename,
            req.key_filename,
            1 if req.is_enabled else 0,
            1 if req.captcha_enabled else 0,
            1 if req.auth_enabled else 0,
            1 if req.dynamic_enabled else 0,
            req.detection_mode
        )
    )
    db.commit()
    website_id = cursor.lastrowid
    notify_waf_site_cache_refresh()
    
    cursor.execute("SELECT * FROM websites WHERE id = ?", (website_id,))
    website = cursor.fetchone()
    
    return {"code": 0, "data": website_to_dict(website), "msg": "Website created successfully"}


@router.put("/websites/{website_id}")
def update_website(website_id: int, req: WebsiteUpdate, db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM websites WHERE id = ?", (website_id,))
    website = cursor.fetchone()
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")

    updates = []
    params = []
    
    if req.comment is not None:
        updates.append("comment = ?")
        params.append(req.comment)
    if req.server_names is not None:
        updates.append("server_names = ?")
        params.append(json.dumps(req.server_names))
    if req.ports is not None:
        updates.append("ports = ?")
        params.append(json.dumps(req.ports))
    if req.upstreams is not None:
        updates.append("upstreams = ?")
        params.append(json.dumps(req.upstreams))
    if req.cert_filename is not None:
        updates.append("cert_filename = ?")
        params.append(req.cert_filename)
    if req.key_filename is not None:
        updates.append("key_filename = ?")
        params.append(req.key_filename)
    if req.is_enabled is not None:
        updates.append("is_enabled = ?")
        params.append(1 if req.is_enabled else 0)
    if req.captcha_enabled is not None:
        updates.append("captcha_enabled = ?")
        params.append(1 if req.captcha_enabled else 0)
    if req.auth_enabled is not None:
        updates.append("auth_enabled = ?")
        params.append(1 if req.auth_enabled else 0)
    if req.dynamic_enabled is not None:
        updates.append("dynamic_enabled = ?")
        params.append(1 if req.dynamic_enabled else 0)
    if req.detection_mode is not None:
        updates.append("detection_mode = ?")
        params.append(req.detection_mode)

    if updates:
        updates.append("updated_at = CURRENT_TIMESTAMP")
        query = f"UPDATE websites SET {', '.join(updates)} WHERE id = ?"
        params.append(website_id)
        cursor.execute(query, tuple(params))
        db.commit()
        notify_waf_site_cache_refresh()

    cursor.execute("SELECT * FROM websites WHERE id = ?", (website_id,))
    updated_website = cursor.fetchone()
    
    return {"code": 0, "data": website_to_dict(updated_website), "msg": "Website updated successfully"}


@router.delete("/websites/{website_id}")
def delete_website(website_id: int, db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    cursor.execute("SELECT id FROM websites WHERE id = ?", (website_id,))
    if not cursor.fetchone():
        raise HTTPException(status_code=404, detail="Website not found")
        
    cursor.execute("DELETE FROM websites WHERE id = ?", (website_id,))
    db.commit()
    notify_waf_site_cache_refresh()
    return {"code": 0, "msg": "Website deleted successfully"}


@router.post("/websites/{website_id}/test")
async def test_website_upstream(website_id: int, db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    """Test connectivity to all upstreams configured for a website."""
    import httpx
    cursor = db.cursor()
    cursor.execute("SELECT * FROM websites WHERE id = ?", (website_id,))
    website = cursor.fetchone()
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")
    
    upstreams = json.loads(website["upstreams"]) if website["upstreams"] else []
    results = []
    
    async with httpx.AsyncClient(timeout=5.0, verify=True) as client:
        for upstream in upstreams:
            url = upstream if upstream.startswith("http") else f"http://{upstream}"
            try:
                resp = await client.get(url, follow_redirects=True)
                results.append({
                    "upstream": upstream,
                    "status": "online",
                    "http_code": resp.status_code,
                    "latency_ms": int(resp.elapsed.total_seconds() * 1000)
                })
            except httpx.TimeoutException:
                results.append({"upstream": upstream, "status": "timeout", "http_code": 0, "latency_ms": 5000})
            except Exception as e:
                results.append({"upstream": upstream, "status": "error", "http_code": 0, "latency_ms": 0, "error": str(e)})
    
    return {"code": 0, "data": results}
