import csv
import io
from typing import Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
import sqlite3

from database import get_db
from models import ATTACK_TYPES, RISK_LEVELS
from routers.auth import get_current_user

router = APIRouter(prefix="/api", tags=["Detection Logs"])

MODULE_LABELS = {
    "sqli": "SQL Injection",
    "xss": "Cross-Site Scripting (XSS)",
    "rce": "Command Injection / RCE",
    "path_traversal": "Path Traversal",
    "ssrf": "Server-Side Request Forgery",
    "xxe": "XML External Entity (XXE)",
    "ssti": "Template Injection (SSTI)",
    "scanner": "Bot / Scanner Detection",
    "sensitive": "Sensitive File Access",
    "crlf": "CRLF Injection",
    "ldap": "LDAP Injection",
    "xpath": "XPath Injection",
}


def _resolve_module_label(rule_id: str) -> str:
    if rule_id.startswith("rule_"):
        return "Custom Policy Rule"
    if rule_id == "ip_acl_block":
        return "IP Access Control"
    if rule_id == "mass_package":
        return "Oversized Request"
    if rule_id.startswith("m_"):
        return MODULE_LABELS.get(rule_id[2:], "Detection Engine")
    return "Detection Engine"


def log_to_dict(log):
    attack_type_str = ATTACK_TYPES.get(log["attack_type"], "Unknown")
    risk_level_str = RISK_LEVELS.get(log["risk_level"], "Unknown")
    protocol_str = "https" if log["protocol"] == 2 else "http"
    port_suffix = "" if log["dst_port"] in (80, 443) else f":{log['dst_port']}"
    website_url = f"{protocol_str}://{log['host']}{port_suffix}{log['url_path']}"

    module = _resolve_module_label(log["rule_id"])

    return {
        "id": log["id"],
        "event_id": log["event_id"],
        "site_uuid": log["site_uuid"],
        "src_ip": log["src_ip"],
        "socket_ip": log["socket_ip"],
        "protocol": log["protocol"],
        "host": log["host"],
        "url_path": log["url_path"],
        "dst_port": log["dst_port"],
        "country": log["country"],
        "province": log["province"],
        "city": log["city"],
        "attack_type": log["attack_type"],
        "attack_type_str": attack_type_str,
        "risk_level": log["risk_level"],
        "risk_level_str": risk_level_str,
        "action": log["action"],
        "action_str": "Blocked" if log["action"] == 1 else "Passed",
        "rule_id": log["rule_id"],
        "module": module,
        "website": website_url,
        "timestamp": log["timestamp"],
        "created_at": str(log["created_at"]),
        # Detail fields
        "src_port": log["src_port"],
        "dst_ip": log["dst_ip"],
        "method": log["method"],
        "query_string": log["query_string"],
        "status_code": log["status_code"],
        "req_header": log["req_header"],
        "req_body": log["req_body"],
        "rsp_header": log["rsp_header"],
        "rsp_body": log["rsp_body"],
        "payload": log["payload"],
        "location": log["location"],
        "decode_path": log["decode_path"]
    }


@router.get("/detect-logs")
def get_detect_log_list(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    attack_type: Optional[int] = None,
    risk_level: Optional[int] = None,
    action: Optional[int] = None,
    src_ip: Optional[str] = None,
    host: Optional[str] = None,
    keyword: Optional[str] = None,
    db: sqlite3.Connection = Depends(get_db),
    user: dict = Depends(get_current_user)
):
    cursor = db.cursor()
    
    where_clauses = []
    params = []
    
    if attack_type is not None:
        where_clauses.append("attack_type = ?")
        params.append(attack_type)
    if risk_level is not None:
        where_clauses.append("risk_level = ?")
        params.append(risk_level)
    if action is not None:
        where_clauses.append("action = ?")
        params.append(action)
    if src_ip:
        where_clauses.append("src_ip LIKE ?")
        params.append(f"%{src_ip}%")
    if host:
        where_clauses.append("host LIKE ?")
        params.append(f"%{host}%")
    if keyword:
        where_clauses.append("(url_path LIKE ? OR src_ip LIKE ? OR host LIKE ? OR payload LIKE ?)")
        kw = f"%{keyword}%"
        params.extend([kw, kw, kw, kw])
        
    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)
        
    # Get total count
    count_query = f"SELECT COUNT(*) as c FROM detect_logs {where_sql}"
    cursor.execute(count_query, tuple(params))
    total = cursor.fetchone()["c"]
    
    # Get paginated data
    offset = (page - 1) * page_size
    data_query = f"SELECT * FROM detect_logs {where_sql} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([page_size, offset])
    
    cursor.execute(data_query, tuple(params))
    logs = cursor.fetchall()

    return {
        "code": 0,
        "data": [log_to_dict(log) for log in logs],
        "total": total,
        "page": page,
        "page_size": page_size
    }


@router.get("/detect-logs/{event_id}")
def get_detect_log_detail(event_id: str, db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM detect_logs WHERE event_id = ?", (event_id,))
    log = cursor.fetchone()
    
    if not log:
        raise HTTPException(status_code=404, detail="Detection log not found")
        
    return {"code": 0, "data": log_to_dict(log)}


@router.get("/detect-logs/export/csv")
def export_detect_logs_csv(
    days: int = Query(7, ge=1, le=90, description="Export logs from last N days"),
    db: sqlite3.Connection = Depends(get_db),
    user: dict = Depends(get_current_user)
):
    """Export detection logs as a CSV file for forensic analysis."""
    cursor = db.cursor()
    since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        SELECT event_id, created_at, src_ip, country, method, host, url_path, 
               attack_type, risk_level, action, rule_id, payload
        FROM detect_logs 
        WHERE created_at >= ?
        ORDER BY timestamp DESC
    """, (since,))
    rows = cursor.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Event ID", "Timestamp", "Source IP", "Country", "Method", "Host", "URL Path", "Attack Type", "Risk Level", "Action", "Rule ID", "Payload"])
    
    for row in rows:
        writer.writerow([
            row["event_id"],
            row["created_at"],
            row["src_ip"],
            row["country"],
            row["method"],
            row["host"],
            row["url_path"],
            ATTACK_TYPES.get(row["attack_type"], "Unknown"),
            RISK_LEVELS.get(row["risk_level"], "Unknown"),
            "Blocked" if row["action"] == 1 else "Passed",
            row["rule_id"],
            row["payload"]
        ])
    
    output.seek(0)
    filename = f"digisave_waf_logs_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.delete("/detect-logs")
def clear_all_logs(db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    """Clear all detection logs (admin action)."""
    cursor = db.cursor()
    cursor.execute("DELETE FROM detect_logs")
    db.commit()
    return {"code": 0, "msg": "All detection logs cleared."}
