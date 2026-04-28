from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
import sqlite3

from database import get_db
from routers.auth import get_current_user
from detection.engine import get_all_module_info

router = APIRouter(prefix="/api", tags=["Policy Rules"])

SUPPORTED_POLICY_MODULES = get_all_module_info()
SUPPORTED_POLICY_MODULE_MAP = {module["key"]: module for module in SUPPORTED_POLICY_MODULES}
LEGACY_MODULE_KEY_MAP = {
    "m_sqli": "sqli",
    "m_xss": "xss",
    "m_cmd_injection": "rce",
    "m_path_traversal": "path_traversal",
    "m_ssrf": "ssrf",
    "m_ssti": "ssti",
    "m_scanner": "scanner",
    "m_sensitive_info": "sensitive",
    "m_xxe": "xxe",
}
MODE_ALIASES = {
    "balance": "default",
    "default": "default",
    "disable": "disabled",
    "disabled": "disabled",
    "strict": "strict",
}


# --- Policy Rules ---

class PolicyRuleCreate(BaseModel):
    name: str
    pattern: str = ""
    pattern_type: str = "regex"
    target: str = "url"
    action: str = "deny"
    risk_level: str = "medium"
    description: str = ""
    is_enabled: bool = True


class PolicyRuleUpdate(BaseModel):
    name: Optional[str] = None
    pattern: Optional[str] = None
    pattern_type: Optional[str] = None
    target: Optional[str] = None
    action: Optional[str] = None
    risk_level: Optional[str] = None
    description: Optional[str] = None
    is_enabled: Optional[bool] = None


def rule_to_dict(r):
    return {
        "id": r["id"],
        "name": r["name"],
        "pattern": r["pattern"],
        "pattern_type": r["pattern_type"],
        "target": r["target"],
        "action": r["action"],
        "risk_level": r["risk_level"],
        "description": r["description"],
        "is_enabled": bool(r["is_enabled"]),
        "created_at": str(r["created_at"]),
        "updated_at": str(r["updated_at"])
    }


@router.get("/policy-rules")
def get_policy_rules(db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM policy_rules ORDER BY id DESC")
    rules = cursor.fetchall()
    return {"code": 0, "data": [rule_to_dict(r) for r in rules], "total": len(rules)}


@router.get("/policy-rules/{rule_id}")
def get_policy_rule(rule_id: int, db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM policy_rules WHERE id = ?", (rule_id,))
    rule = cursor.fetchone()
    if not rule:
        raise HTTPException(status_code=404, detail="Policy rule not found")
    return {"code": 0, "data": rule_to_dict(rule)}


@router.post("/policy-rules")
def create_policy_rule(req: PolicyRuleCreate, db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    cursor.execute(
        """INSERT INTO policy_rules 
        (name, pattern, pattern_type, target, action, risk_level, description, is_enabled) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            req.name, req.pattern, req.pattern_type, req.target, req.action, 
            req.risk_level, req.description, 1 if req.is_enabled else 0
        )
    )
    db.commit()
    rule_id = cursor.lastrowid
    
    cursor.execute("SELECT * FROM policy_rules WHERE id = ?", (rule_id,))
    rule = cursor.fetchone()
    
    return {"code": 0, "data": rule_to_dict(rule), "msg": "Rule created"}


@router.put("/policy-rules/{rule_id}")
def update_policy_rule(rule_id: int, req: PolicyRuleUpdate, db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    cursor.execute("SELECT id FROM policy_rules WHERE id = ?", (rule_id,))
    if not cursor.fetchone():
        raise HTTPException(status_code=404, detail="Policy rule not found")

    updates = []
    params = []
    
    for field in ["name", "pattern", "pattern_type", "target", "action", "risk_level", "description"]:
        val = getattr(req, field)
        if val is not None:
            updates.append(f"{field} = ?")
            params.append(val)
            
    if req.is_enabled is not None:
        updates.append("is_enabled = ?")
        params.append(1 if req.is_enabled else 0)

    if updates:
        updates.append("updated_at = CURRENT_TIMESTAMP")
        query = f"UPDATE policy_rules SET {', '.join(updates)} WHERE id = ?"
        params.append(rule_id)
        cursor.execute(query, tuple(params))
        db.commit()

    cursor.execute("SELECT * FROM policy_rules WHERE id = ?", (rule_id,))
    updated_rule = cursor.fetchone()
    
    return {"code": 0, "data": rule_to_dict(updated_rule), "msg": "Rule updated"}


@router.put("/policy-rules/{rule_id}/toggle")
def toggle_policy_rule(rule_id: int, db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    cursor.execute("SELECT is_enabled FROM policy_rules WHERE id = ?", (rule_id,))
    rule = cursor.fetchone()
    if not rule:
        raise HTTPException(status_code=404, detail="Policy rule not found")
        
    new_state = 0 if rule["is_enabled"] else 1
    cursor.execute("UPDATE policy_rules SET is_enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (new_state, rule_id))
    db.commit()
    
    cursor.execute("SELECT * FROM policy_rules WHERE id = ?", (rule_id,))
    updated_rule = cursor.fetchone()
    
    return {"code": 0, "data": rule_to_dict(updated_rule), "msg": f"Rule {'enabled' if new_state else 'disabled'}"}


@router.delete("/policy-rules/{rule_id}")
def delete_policy_rule(rule_id: int, db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    cursor.execute("SELECT id FROM policy_rules WHERE id = ?", (rule_id,))
    if not cursor.fetchone():
        raise HTTPException(status_code=404, detail="Policy rule not found")
        
    cursor.execute("DELETE FROM policy_rules WHERE id = ?", (rule_id,))
    db.commit()
    return {"code": 0, "msg": "Rule deleted"}


# --- Policy Groups (Detection Modules) ---

class PolicyGroupUpdate(BaseModel):
    mode: str  # strict, default, disable


def _normalize_module_key(module: str) -> str:
    return LEGACY_MODULE_KEY_MAP.get(module, module)


def _normalize_mode(mode: Optional[str]) -> str:
    if not mode:
        return "default"
    return MODE_ALIASES.get(mode.lower(), mode.lower())


def _default_group_state(module_info: dict) -> dict:
    return {
        "module": module_info["key"],
        "mode": "default",
        "high_risk_action": "deny",
        "medium_risk_action": "continue",
        "low_risk_action": "continue",
        "state": "enabled",
        "description": module_info["description"],
        "created_at": "",
        "updated_at": "",
    }


def group_to_dict(g, module_info: dict):
    row = dict(g) if g else _default_group_state(module_info)
    mode = _normalize_mode(row.get("mode"))
    state = "disabled" if mode == "disabled" else row.get("state", "enabled")

    return {
        "id": row.get("id", 0),
        "module": module_info["key"],
        "module_name": module_info["name"],
        "mode": mode,
        "high_risk_action": row.get("high_risk_action", "deny"),
        "medium_risk_action": row.get("medium_risk_action", "continue"),
        "low_risk_action": row.get("low_risk_action", "continue"),
        "state": state,
        "description": row.get("description") or module_info["description"],
        "created_at": str(row.get("created_at", "")),
        "updated_at": str(row.get("updated_at", "")),
    }


@router.get("/policy-groups")
def get_policy_groups(db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM policy_groups ORDER BY module")
    rows = cursor.fetchall()

    groups_by_key = {}
    for row in rows:
        normalized_key = _normalize_module_key(row["module"])
        if normalized_key not in SUPPORTED_POLICY_MODULE_MAP:
            continue
        if normalized_key not in groups_by_key or row["module"] == normalized_key:
            groups_by_key[normalized_key] = row

    data = [group_to_dict(groups_by_key.get(module["key"]), module) for module in SUPPORTED_POLICY_MODULES]
    return {"code": 0, "data": data, "total": len(data)}


@router.put("/policy-groups/{module}")
def update_policy_group(module: str, req: PolicyGroupUpdate, db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    normalized_module = _normalize_module_key(module)
    if normalized_module not in SUPPORTED_POLICY_MODULE_MAP:
        raise HTTPException(status_code=404, detail="Policy group not found")

    normalized_mode = _normalize_mode(req.mode)
    if normalized_mode not in {"strict", "default", "disabled"}:
        raise HTTPException(status_code=400, detail="Mode must be one of: strict, default, disabled")

    cursor = db.cursor()
    cursor.execute("SELECT id FROM policy_groups WHERE module = ?", (normalized_module,))
    if not cursor.fetchone():
        module_info = SUPPORTED_POLICY_MODULE_MAP[normalized_module]
        cursor.execute(
            """
            INSERT INTO policy_groups
            (module, mode, high_risk_action, medium_risk_action, low_risk_action, state, description)
            VALUES (?, 'default', 'deny', 'continue', 'continue', 'enabled', ?)
            """,
            (normalized_module, module_info["description"]),
        )

    if normalized_mode == "strict":
        updates = ("enabled", "deny", "deny", "deny")
    elif normalized_mode == "default":
        updates = ("enabled", "deny", "continue", "continue")
    else:
        updates = ("disabled", "continue", "continue", "continue")
        
    cursor.execute(
        """UPDATE policy_groups 
           SET mode = ?, state = ?, high_risk_action = ?, medium_risk_action = ?, low_risk_action = ?, updated_at = CURRENT_TIMESTAMP
           WHERE module = ?""",
        (normalized_mode, updates[0], updates[1], updates[2], updates[3], normalized_module)
    )
    db.commit()
    
    cursor.execute("SELECT * FROM policy_groups WHERE module = ?", (normalized_module,))
    updated_group = cursor.fetchone()
    
    return {
        "code": 0,
        "data": group_to_dict(updated_group, SUPPORTED_POLICY_MODULE_MAP[normalized_module]),
        "msg": f"Module '{normalized_module}' set to {normalized_mode} mode",
    }

# --- IP Access Control (ACL) ---

class IPAclCreate(BaseModel):
    ip_cidr: str
    action: str = "block"
    note: str = ""
    is_enabled: bool = True

def acl_to_dict(a):
    return {
        "id": a["id"],
        "ip_cidr": a["ip_cidr"],
        "action": a["action"],
        "note": a["note"],
        "is_enabled": bool(a["is_enabled"]),
        "created_at": str(a["created_at"])
    }

@router.get("/ip-acl")
def get_ip_acls(db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM ip_acl ORDER BY id DESC")
    acls = cursor.fetchall()
    return {"code": 0, "data": [acl_to_dict(a) for a in acls], "total": len(acls)}

@router.post("/ip-acl")
def create_ip_acl(req: IPAclCreate, db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO ip_acl (ip_cidr, action, note, is_enabled) VALUES (?, ?, ?, ?)",
        (req.ip_cidr, req.action, req.note, 1 if req.is_enabled else 0)
    )
    db.commit()
    acl_id = cursor.lastrowid
    cursor.execute("SELECT * FROM ip_acl WHERE id = ?", (acl_id,))
    return {"code": 0, "data": acl_to_dict(cursor.fetchone()), "msg": "ACL created"}

@router.put("/ip-acl/{acl_id}/toggle")
def toggle_ip_acl(acl_id: int, db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    cursor.execute("SELECT is_enabled FROM ip_acl WHERE id = ?", (acl_id,))
    acl = cursor.fetchone()
    if not acl:
        raise HTTPException(status_code=404, detail="ACL not found")
    new_state = 0 if acl["is_enabled"] else 1
    cursor.execute("UPDATE ip_acl SET is_enabled = ? WHERE id = ?", (new_state, acl_id))
    db.commit()
    cursor.execute("SELECT * FROM ip_acl WHERE id = ?", (acl_id,))
    return {"code": 0, "data": acl_to_dict(cursor.fetchone()), "msg": f"ACL {'enabled' if new_state else 'disabled'}"}

@router.delete("/ip-acl/{acl_id}")
def delete_ip_acl(acl_id: int, db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    cursor.execute("SELECT id FROM ip_acl WHERE id = ?", (acl_id,))
    if not cursor.fetchone():
        raise HTTPException(status_code=404, detail="ACL not found")
        
    cursor.execute("DELETE FROM ip_acl WHERE id = ?", (acl_id,))
    db.commit()
    return {"code": 0, "msg": "ACL deleted"}
