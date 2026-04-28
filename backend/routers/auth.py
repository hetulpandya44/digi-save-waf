import base64
import io
import re
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
import bcrypt
import secrets
from jose import JWTError, jwt  # type: ignore
from pydantic import BaseModel  # type: ignore
import os
import sqlite3
import pyotp  # type: ignore
import logging
from collections import defaultdict
import time

from database import get_db  # type: ignore
from config import VERSION, APP_NAME

logger = logging.getLogger("WAF_Manager.auth")

router = APIRouter(prefix="/api", tags=["Authentication"])

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login", auto_error=False)

# -------------------------------------------------------------------
# Brute-force protection: track failed login attempts per IP
# -------------------------------------------------------------------
_login_attempts = defaultdict(list)  # ip -> [timestamp, ...]
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 300  # 5 minutes


def _is_login_locked(ip: str) -> bool:
    """Check if IP is locked out due to too many failed login attempts."""
    now = time.time()
    # Clean old attempts
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < LOGIN_LOCKOUT_SECONDS]
    return len(_login_attempts[ip]) >= MAX_LOGIN_ATTEMPTS


def _record_failed_login(ip: str):
    _login_attempts[ip].append(time.time())


def _clear_login_attempts(ip: str):
    _login_attempts.pop(ip, None)


# -------------------------------------------------------------------
# Secret Key: auto-generate and persist on first run
# -------------------------------------------------------------------
def _get_secret_key() -> str:
    """Get JWT secret key. Priority: env var > DB > auto-generate."""
    env_key = os.environ.get("SECRET_KEY")
    if env_key and env_key != "digisave-secret-key-change-in-production-2024":
        return env_key

    # Try loading from DB
    try:
        from database import DATABASE_PATH
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM options WHERE key = 'jwt_secret_key'")
        row = cursor.fetchone()
        if row and row["value"]:
            conn.close()
            return row["value"]
        # Generate new random key and store
        new_key = secrets.token_urlsafe(48)
        cursor.execute("""
            INSERT INTO options (key, value) VALUES ('jwt_secret_key', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """, (new_key,))
        conn.commit()
        conn.close()
        logger.info("Generated new JWT secret key and saved to database.")
        return new_key
    except Exception:
        # Fallback during first startup before DB init
        return secrets.token_urlsafe(48)


_SECRET_KEY: Optional[str] = None


def get_secret_key() -> str:
    global _SECRET_KEY
    if _SECRET_KEY:
        return _SECRET_KEY
    _SECRET_KEY = _get_secret_key()
    return _SECRET_KEY


# -------------------------------------------------------------------
# Password hashing with bcrypt
# -------------------------------------------------------------------
def hash_password(plain_password: str) -> str:
    """Hash a password using bcrypt with auto-generated salt."""
    return bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its bcrypt hash, with SHA-256 fallback for migration."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except (ValueError, Exception):
        # Fallback: check legacy SHA-256 hash for migration from old passwords
        import hashlib
        if hashlib.sha256(plain_password.encode()).hexdigest() == hashed_password:
            return True
        return False


# -------------------------------------------------------------------
# Models
# -------------------------------------------------------------------
class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str


class UserResponse(BaseModel):
    id: int
    username: str
    comment: str
    is_enabled: bool
    tfa_enabled: bool
    last_login_time: Optional[str] = None
    created_at: str


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, get_secret_key(), algorithm=ALGORITHM)


def get_current_user(token: Optional[str] = Depends(oauth2_scheme), db: sqlite3.Connection = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, get_secret_key(), algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if user is None or not user["is_enabled"]:
        raise HTTPException(status_code=401, detail="User not found or disabled")
    return dict(user)


# -------------------------------------------------------------------
# Login with brute-force protection
# -------------------------------------------------------------------
@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, request: Request, db: sqlite3.Connection = Depends(get_db)):
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Brute-force check
    if _is_login_locked(client_ip):
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed login attempts. Try again in {LOGIN_LOCKOUT_SECONDS // 60} minutes."
        )

    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (req.username,))
    user = cursor.fetchone()

    if not user or not verify_password(req.password, user["password_hash"]):
        _record_failed_login(client_ip)
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    if not user["is_enabled"]:
        raise HTTPException(status_code=403, detail="Account disabled")

    if user["tfa_enabled"]:
        if not req.totp_code:
            raise HTTPException(status_code=401, detail="MFA code required")
        totp = pyotp.TOTP(user["tfa_secret"])
        if not totp.verify(req.totp_code):
            _record_failed_login(client_ip)
            raise HTTPException(status_code=401, detail="Invalid MFA code")

    # Successful login — clear attempts, migrate legacy hash if needed
    _clear_login_attempts(client_ip)

    # Auto-migrate SHA-256 hash to bcrypt on successful login
    if not user["password_hash"].startswith("$2"):
        new_hash = hash_password(req.password)
        cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user["id"]))

    cursor.execute(
        "UPDATE users SET last_login_time = ? WHERE id = ?",
        (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), user["id"])
    )
    db.commit()

    token = create_access_token({"sub": user["username"]})
    return TokenResponse(access_token=token, username=user["username"])


@router.post("/logout")
def logout():
    return {"msg": "ok", "code": 0}


@router.get("/user")
def get_user(current_user: dict = Depends(get_current_user)):
    return {
        "code": 0,
        "data": {
            "id": current_user["id"],
            "username": current_user["username"],
            "comment": current_user["comment"],
            "is_enabled": bool(current_user["is_enabled"]),
            "tfa_enabled": bool(current_user["tfa_enabled"]),
            "last_login_time": current_user["last_login_time"],
            "created_at": current_user["created_at"]
        }
    }


# -------------------------------------------------------------------
# MFA endpoints
# -------------------------------------------------------------------
class MFAEnableReq(BaseModel):
    code: str


def _build_qr_data_url(provisioning_uri: str) -> Optional[str]:
    try:
        import qrcode  # type: ignore

        qr = qrcode.QRCode(box_size=8, border=2)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)

        image = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
        return f"data:image/png;base64,{encoded}"
    except Exception as exc:
        logger.warning(f"Could not generate local MFA QR image: {exc}")
        return None

@router.get("/mfa/setup")
def mfa_setup(current_user: dict = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    if current_user["tfa_enabled"]:
        raise HTTPException(400, "MFA already enabled")

    secret = current_user["tfa_secret"]
    if not secret:
        secret = pyotp.random_base32()
        cursor = db.cursor()
        cursor.execute("UPDATE users SET tfa_secret = ? WHERE id = ?", (secret, current_user["id"]))
        db.commit()

    provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user["username"],
        issuer_name=APP_NAME
    )

    return {
        "code": 0,
        "secret": secret,
        "uri": provisioning_uri,
        "qr_data_url": _build_qr_data_url(provisioning_uri),
    }

@router.post("/mfa/enable")
def mfa_enable(req: MFAEnableReq, current_user: dict = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    if current_user["tfa_enabled"]:
        raise HTTPException(400, "MFA already enabled")

    secret = current_user["tfa_secret"]
    if not secret:
        raise HTTPException(400, "Please setup MFA first")

    totp = pyotp.TOTP(secret)
    if not totp.verify(req.code):
        raise HTTPException(400, "Invalid code")

    cursor = db.cursor()
    cursor.execute("UPDATE users SET tfa_enabled = 1 WHERE id = ?", (current_user["id"],))
    db.commit()

    return {"code": 0, "msg": "MFA enabled successfully"}

@router.post("/mfa/disable")
def mfa_disable(req: MFAEnableReq, current_user: dict = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    if not current_user["tfa_enabled"]:
        raise HTTPException(400, "MFA is not enabled")

    totp = pyotp.TOTP(current_user["tfa_secret"])
    if not totp.verify(req.code):
        raise HTTPException(400, "Invalid code")

    cursor = db.cursor()
    cursor.execute("UPDATE users SET tfa_enabled = 0, tfa_secret = '' WHERE id = ?", (current_user["id"],))
    db.commit()

    return {"code": 0, "msg": "MFA disabled successfully"}


# -------------------------------------------------------------------
# Password change with bcrypt
# -------------------------------------------------------------------
class ChangePasswordReq(BaseModel):
    old_password: str
    new_password: str


class ChangeUsernameReq(BaseModel):
    current_password: str
    new_username: str


@router.post("/change-password")
def change_password(req: ChangePasswordReq, current_user: dict = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    if not verify_password(req.old_password, current_user["password_hash"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(req.new_password) < 6:
        raise HTTPException(status_code=400, detail="New password must be at least 6 characters")

    new_hash = hash_password(req.new_password)
    cursor = db.cursor()
    cursor.execute("UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (new_hash, current_user["id"]))
    db.commit()
    return {"code": 0, "msg": "Password changed successfully"}


@router.post("/change-username")
def change_username(req: ChangeUsernameReq, current_user: dict = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    if not verify_password(req.current_password, current_user["password_hash"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    new_username = req.new_username.strip()
    if len(new_username) < 3 or len(new_username) > 50:
        raise HTTPException(status_code=400, detail="Username must be between 3 and 50 characters")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", new_username):
        raise HTTPException(
            status_code=400,
            detail="Username may contain only letters, numbers, dot, underscore, and hyphen",
        )
    if new_username == current_user["username"]:
        raise HTTPException(status_code=400, detail="New username must be different")

    cursor = db.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ? AND id != ?", (new_username, current_user["id"]))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="That username is already in use")

    cursor.execute(
        "UPDATE users SET username = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (new_username, current_user["id"]),
    )
    db.commit()

    token = create_access_token({"sub": new_username})
    return {
        "code": 0,
        "msg": "Username changed successfully",
        "username": new_username,
        "access_token": token,
    }


# -------------------------------------------------------------------
# Info endpoints
# -------------------------------------------------------------------
@router.get("/version")
def get_version():
    return {"code": 0, "data": {"version": VERSION, "name": APP_NAME}}


@router.get("/ping")
def ping():
    return {"message": "pong"}
