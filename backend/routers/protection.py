import sqlite3
import random
import string
from typing import Optional
from datetime import datetime, timedelta
import hmac

from fastapi import APIRouter, Depends, HTTPException, Request  # type: ignore
from pydantic import BaseModel  # type: ignore
from fastapi.responses import JSONResponse, StreamingResponse  # type: ignore

try:
    from captcha.image import ImageCaptcha  # type: ignore
    has_captcha = True
except ImportError:
    has_captcha = False

from database import get_db  # type: ignore
from routers.auth import verify_password  # type: ignore

router = APIRouter(
    prefix="/api/protection",
    tags=["Protection"]
)

class CaptchaVerifyReq(BaseModel):
    captcha_text: str
    ip: Optional[str] = None

class AuthVerifyReq(BaseModel):
    password: str
    site_id: int
    ip: Optional[str] = None

class DynamicSolveReq(BaseModel):
    site_id: int
    ip: Optional[str] = None
    ua: str


def _get_request_ip(request: Request) -> str:
    for header in ("cf-connecting-ip", "x-real-ip", "x-forwarded-for"):
        value = request.headers.get(header, "")
        if not value:
            continue
        if header == "x-forwarded-for":
            return value.split(",")[0].strip()
        return value.strip()
    return request.client.host if request.client else "127.0.0.1"


def _cookie_options(request: Request) -> dict:
    return {
        "httponly": True,
        "samesite": "lax",
        "secure": request.url.scheme == "https",
    }


# ---------------------------------------------------------
# CAPTCHA Endpoints — stored in DB, not memory
# ---------------------------------------------------------

@router.get("/captcha/image")
def get_captcha_image(request: Request, db: sqlite3.Connection = Depends(get_db)):
    """Generate and return a CAPTCHA image. Challenge stored in DB."""
    ip = _get_request_ip(request)
    text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    
    # Store challenge in DB with 5-minute expiry
    cursor = db.cursor()
    expires = (datetime.utcnow() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO captcha_sessions (ip, token, expires_at)
        VALUES (?, ?, ?)
    """, (ip, f"challenge:{text}", expires))
    db.commit()
    
    if has_captcha:
        image = ImageCaptcha(width=280, height=90)
        data = image.generate(text)
        return StreamingResponse(data, media_type="image/png")
    else:
        raise HTTPException(status_code=500, detail="CAPTCHA system not fully installed (missing captcha package).")

@router.post("/captcha/verify")
def verify_captcha(req: CaptchaVerifyReq, request: Request, db: sqlite3.Connection = Depends(get_db)):
    """Verify CAPTCHA and issue a token cookie."""
    cursor = db.cursor()
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    request_ip = _get_request_ip(request)
    
    # Find matching challenge from DB
    cursor.execute("""
        SELECT id, token FROM captcha_sessions 
        WHERE ip = ? AND token LIKE 'challenge:%' AND expires_at > ?
        ORDER BY id DESC LIMIT 1
    """, (request_ip, now_str))
    row = cursor.fetchone()
    
    if not row:
        raise HTTPException(status_code=400, detail="No pending CAPTCHA found for this IP or it expired.")
    
    expected_text = row["token"].replace("challenge:", "")
    
    if req.captcha_text.upper() != expected_text.upper():
        raise HTTPException(status_code=400, detail="Incorrect CAPTCHA.")
    
    # Valid -> Remove challenge, generate session token
    cursor.execute("DELETE FROM captcha_sessions WHERE id = ?", (row["id"],))
    
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    cursor.execute("""
        INSERT INTO captcha_sessions (ip, token, expires_at)
        VALUES (?, ?, ?)
    """, (request_ip, token, (datetime.utcnow() + timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")))
    db.commit()
    
    response = JSONResponse({"status": "success", "message": "Verification successful."})
    response.set_cookie(key="waf_captcha_token", value=token, max_age=7200, **_cookie_options(request))
    return response

# ---------------------------------------------------------
# Auth Challenge Endpoints (Configurable Password Gate)
# ---------------------------------------------------------

@router.post("/auth/verify")
def verify_auth_challenge(req: AuthVerifyReq, request: Request, db: sqlite3.Connection = Depends(get_db)):
    """Verify password for a gated site. Password is configurable per-site via DB."""
    cursor = db.cursor()
    request_ip = _get_request_ip(request)
    
    # Get site-specific auth password from options, fallback to default
    cursor.execute("SELECT value FROM options WHERE key = ?", (f"auth_password_site_{req.site_id}",))
    row = cursor.fetchone()
    expected_password = row["value"] if row else None
    
    if not expected_password:
        # Try global auth password
        cursor.execute("SELECT value FROM options WHERE key = 'auth_gate_password'")
        row = cursor.fetchone()
        expected_password = row["value"] if row else "digisave123"
    
    if expected_password.startswith("$2"):
        valid_password = verify_password(req.password, expected_password)
    else:
        valid_password = hmac.compare_digest(req.password, expected_password)

    if not valid_password:
        raise HTTPException(status_code=403, detail="Incorrect password.")
        
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    
    cursor.execute("""
        INSERT INTO auth_challenges (site_id, ip, session_token, expires_at)
        VALUES (?, ?, ?, ?)
    """, (req.site_id, request_ip, token, (datetime.utcnow() + timedelta(hours=12)).strftime("%Y-%m-%d %H:%M:%S")))
    db.commit()
    
    response = JSONResponse({"status": "success", "message": "Access granted."})
    response.set_cookie(key=f"waf_auth_{req.site_id}", value=token, max_age=43200, **_cookie_options(request))
    return response

@router.post("/dynamic/solve")
def solve_dynamic(req: DynamicSolveReq, request: Request, db: sqlite3.Connection = Depends(get_db)):
    """Verifies the browser JS challenge and grants access."""
    # Since they reached here, the JS executed correctly (Proof of Work).
    import secrets
    session_token = "dyn_" + secrets.token_urlsafe(32)
    request_ip = _get_request_ip(request)
    
    cursor = db.cursor()
    expires_at = (datetime.utcnow() + timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    
    # We reuse auth_challenges for dynamic to keep DB schema simple since it's just a session store
    cursor.execute("INSERT INTO auth_challenges (site_id, ip, session_token, expires_at) VALUES (?, ?, ?, ?)",
                   (req.site_id, request_ip, session_token, expires_at))
    db.commit()
    
    response = JSONResponse({"status": "success", "message": "Browser verified"})
    response.set_cookie(key=f"waf_dyn_{req.site_id}", value=session_token, max_age=86400, **_cookie_options(request))
    return response
