import ipaddress
import sqlite3
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from database import get_db
from routers.auth import get_current_user

router = APIRouter(prefix="/api/ip_acl", tags=["IP ACL"])


class IpAclCreate(BaseModel):
    ip_cidr: str
    action: str = "block"   # 'block' | 'allow'
    note: str = ""
    is_enabled: bool = True


class IpAclUpdate(BaseModel):
    action: Optional[str] = None
    note: Optional[str] = None
    is_enabled: Optional[bool] = None


def _validate_ip_cidr(ip_cidr: str):
    """Raise HTTPException if the IP/CIDR is not valid."""
    try:
        ipaddress.ip_network(ip_cidr, strict=False)
    except ValueError:
        try:
            ipaddress.ip_address(ip_cidr)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid IP or CIDR: {ip_cidr}")


def _row_to_dict(row) -> dict:
    return {
        "id": row["id"],
        "ip_cidr": row["ip_cidr"],
        "action": row["action"],
        "note": row["note"],
        "is_enabled": bool(row["is_enabled"]),
        "created_at": str(row["created_at"]),
    }


@router.get("/")
def list_acl_rules(db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    """List all IP ACL rules (blocklist + allowlist)."""
    cursor = db.cursor()
    cursor.execute("SELECT * FROM ip_acl ORDER BY id DESC")
    rows = cursor.fetchall()
    return {
        "code": 0,
        "data": [_row_to_dict(r) for r in rows],
        "total": len(rows)
    }


@router.post("/")
def create_acl_rule(req: IpAclCreate, db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    """Add an IP or CIDR range to the blocklist or allowlist."""
    _validate_ip_cidr(req.ip_cidr)
    if req.action not in ("block", "allow"):
        raise HTTPException(status_code=400, detail="Action must be 'block' or 'allow'.")
    
    cursor = db.cursor()
    # Check for duplicate
    cursor.execute("SELECT id FROM ip_acl WHERE ip_cidr = ?", (req.ip_cidr,))
    if cursor.fetchone():
        raise HTTPException(status_code=409, detail=f"Rule for {req.ip_cidr} already exists.")
    
    cursor.execute(
        "INSERT INTO ip_acl (ip_cidr, action, note, is_enabled) VALUES (?, ?, ?, ?)",
        (req.ip_cidr, req.action, req.note, 1 if req.is_enabled else 0)
    )
    db.commit()
    rule_id = cursor.lastrowid
    cursor.execute("SELECT * FROM ip_acl WHERE id = ?", (rule_id,))
    return {"code": 0, "data": _row_to_dict(cursor.fetchone()), "msg": "ACL rule created."}


@router.put("/{rule_id}")
def update_acl_rule(rule_id: int, req: IpAclUpdate, db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    """Update an existing ACL rule (action, note, enabled state)."""
    cursor = db.cursor()
    cursor.execute("SELECT * FROM ip_acl WHERE id = ?", (rule_id,))
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Rule not found.")
    
    updates, params = [], []
    if req.action is not None:
        if req.action not in ("block", "allow"):
            raise HTTPException(status_code=400, detail="Action must be 'block' or 'allow'.")
        updates.append("action = ?"); params.append(req.action)
    if req.note is not None:
        updates.append("note = ?"); params.append(req.note)
    if req.is_enabled is not None:
        updates.append("is_enabled = ?"); params.append(1 if req.is_enabled else 0)
    
    if updates:
        params.append(rule_id)
        cursor.execute(f"UPDATE ip_acl SET {', '.join(updates)} WHERE id = ?", tuple(params))
        db.commit()
    
    cursor.execute("SELECT * FROM ip_acl WHERE id = ?", (rule_id,))
    return {"code": 0, "data": _row_to_dict(cursor.fetchone()), "msg": "Rule updated."}


@router.delete("/{rule_id}")
def delete_acl_rule(rule_id: int, db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    """Remove an ACL rule."""
    cursor = db.cursor()
    cursor.execute("SELECT id FROM ip_acl WHERE id = ?", (rule_id,))
    if not cursor.fetchone():
        raise HTTPException(status_code=404, detail="Rule not found.")
    cursor.execute("DELETE FROM ip_acl WHERE id = ?", (rule_id,))
    db.commit()
    return {"code": 0, "msg": "Rule deleted."}
