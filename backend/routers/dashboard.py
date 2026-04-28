import math
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
import sqlite3

from database import get_db
from routers.auth import get_current_user

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/counts")
def get_dashboard_counts(db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0).strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute(
        "SELECT value FROM system_statistics WHERE type = 'total-req' AND created_at >= ? ORDER BY created_at DESC LIMIT 1",
        (today_start,)
    )
    req_row = cursor.fetchone()
    total_req = req_row["value"] if req_row else 0

    cursor.execute(
        "SELECT value FROM system_statistics WHERE type = 'total-denied' AND created_at >= ? ORDER BY created_at DESC LIMIT 1",
        (today_start,)
    )
    denied_row = cursor.fetchone()
    total_denied = denied_row["value"] if denied_row else 0

    cursor.execute("SELECT count(*) as c FROM websites")
    total_sites = cursor.fetchone()["c"]

    cursor.execute("SELECT count(*) as c FROM websites WHERE is_enabled = 1")
    active_sites = cursor.fetchone()["c"]

    cursor.execute("SELECT count(*) as c FROM detect_logs")
    total_attacks = cursor.fetchone()["c"]

    cursor.execute("SELECT count(*) as c FROM detect_logs WHERE action = 1")
    blocked_attacks = cursor.fetchone()["c"]

    return {
        "code": 0,
        "data": {
            "requested": total_req,
            "intercepted": total_denied,
            "total_sites": total_sites,
            "active_sites": active_sites,
            "total_attacks": total_attacks,
            "blocked_attacks": blocked_attacks
        }
    }


@router.get("/sites")
def get_dashboard_sites(db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    cursor.execute("SELECT count(*) as c FROM websites")
    total = cursor.fetchone()["c"]
    
    cursor.execute("SELECT count(*) as c FROM websites WHERE is_enabled = 1")
    active = cursor.fetchone()["c"]
    
    return {
        "code": 0,
        "data": {"normal": active, "abnormal": total - active, "total": total}
    }


@router.get("/qps")
def get_dashboard_qps(db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    cursor.execute(
        "SELECT created_at, value FROM system_statistics WHERE type = 'req' ORDER BY created_at DESC LIMIT 75"
    )
    statistics = cursor.fetchall()

    nodes = []
    for stat in reversed(statistics):
        # sqlite created_at is string 'YYYY-MM-DD HH:MM:SS'
        # ensure it's formatted as string correctly
        nodes.append({
            "label": str(stat["created_at"]),
            "value": math.ceil(stat["value"] / 5)
        })

    return {"code": 0, "data": {"nodes": nodes, "total": len(nodes)}}


@router.get("/requests")
def get_dashboard_requests(db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    cursor.execute(
        "SELECT created_at, value FROM system_statistics WHERE type = 'total-req' ORDER BY created_at DESC LIMIT 30"
    )
    statistics = cursor.fetchall()
    
    stats_map = {str(r["created_at"]).split(' ')[0]: r["value"] for r in statistics}

    nodes = []
    now = datetime.utcnow()

    for i in range(30, 0, -1):
        day = (now - timedelta(days=i - 1)).strftime("%Y-%m-%d")
        nodes.append({"label": day, "value": stats_map.get(day, 0)})

    return {"code": 0, "data": {"nodes": nodes, "total": len(nodes)}}


@router.get("/intercepts")
def get_dashboard_intercepts(db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    cursor.execute(
        "SELECT created_at, value FROM system_statistics WHERE type = 'total-denied' ORDER BY created_at DESC LIMIT 30"
    )
    statistics = cursor.fetchall()
    
    stats_map = {str(r["created_at"]).split(' ')[0]: r["value"] for r in statistics}

    nodes = []
    now = datetime.utcnow()

    for i in range(30, 0, -1):
        day = (now - timedelta(days=i - 1)).strftime("%Y-%m-%d")
        nodes.append({"label": day, "value": stats_map.get(day, 0)})

    return {"code": 0, "data": {"nodes": nodes, "total": len(nodes)}}


@router.get("/attack_types")
def get_attack_type_distribution(db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    from models import ATTACK_TYPES
    
    cursor.execute(
        "SELECT attack_type, count(id) as c FROM detect_logs GROUP BY attack_type ORDER BY c DESC LIMIT 10"
    )
    results = cursor.fetchall()

    data = []
    for row in results:
        data.append({
            "type": ATTACK_TYPES.get(row["attack_type"], "Unknown"),
            "count": row["c"]
        })

    return {"code": 0, "data": data}


@router.get("/top_ips")
def get_top_attacker_ips(db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    cursor.execute("""
        SELECT src_ip, country, count(id) as c 
        FROM detect_logs 
        WHERE action = 1 
        GROUP BY src_ip, country 
        ORDER BY c DESC 
        LIMIT 10
    """)
    results = cursor.fetchall()

    data = []
    for row in results:
        data.append({"ip": row["src_ip"], "country": row["country"], "count": row["c"]})

    return {"code": 0, "data": data}


@router.get("/risk_distribution")
def get_risk_distribution(db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    from models import RISK_LEVELS
    
    cursor.execute(
        "SELECT risk_level, count(id) as c FROM detect_logs GROUP BY risk_level"
    )
    results = cursor.fetchall()

    data = []
    for row in results:
        data.append({
            "level": RISK_LEVELS.get(row["risk_level"], "Unknown"),
            "count": row["c"]
        })

    return {"code": 0, "data": data}

@router.get("/top_targeted_sites")
def get_top_targeted_sites(db: sqlite3.Connection = Depends(get_db), user: dict = Depends(get_current_user)):
    cursor = db.cursor()
    cursor.execute("""
        SELECT site_uuid, count(id) as c 
        FROM detect_logs 
        WHERE action = 1 
        GROUP BY site_uuid 
        ORDER BY c DESC 
        LIMIT 5
    """)
    results = cursor.fetchall()
    
    data = []
    for row in results:
        # Try to resolve site friendly name if possible
        site_id = row["site_uuid"].replace("site_", "").split("_")[0]
        site_name, ports = row["site_uuid"], ""
        try:
            cursor.execute("SELECT comment, ports FROM websites WHERE id = ?", (site_id,))
            srow = cursor.fetchone()
            if srow:
                site_name = srow["comment"] if srow["comment"] else f"Site #{site_id}"
                ports = srow["ports"]
        except Exception:
            pass
            
        data.append({
            "site_id": row["site_uuid"],
            "site_name": site_name,
            "ports": ports,
            "count": row["c"]
        })

    return {"code": 0, "data": data}
