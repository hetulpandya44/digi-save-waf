import asyncio
import os
import sys
import json
import subprocess
import uvicorn  # type: ignore
import traceback
import signal
import logging
from contextlib import asynccontextmanager
from typing import List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request  # type: ignore
from fastapi.staticfiles import StaticFiles  # type: ignore
from fastapi.responses import FileResponse, JSONResponse  # type: ignore
from fastapi.middleware.cors import CORSMiddleware  # type: ignore
from starlette.middleware.base import BaseHTTPMiddleware # type: ignore

class JSONLogFormatter(logging.Formatter):
    def format(self, record):
        log_obj = {
            "time": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "module": record.module,
            "message": record.getMessage()
        }
        return json.dumps(log_obj)

logger = logging.getLogger("WAF_Manager")
handler = logging.StreamHandler()
handler.setFormatter(JSONLogFormatter())
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Add backend dir to path so routers can import from database etc.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import init_db  # type: ignore
from seed_data import seed_database  # type: ignore
from cron import start_scheduler, stop_scheduler
from config import VERSION, APP_NAME
from routers import auth, dashboard, websites, detect_logs, policy_rules, settings, protection, ssl_certs, ip_acl  # type: ignore

# -------------------------------------------------------------------
# WebSocket Connection Manager (Live Threat Feed)
# -------------------------------------------------------------------
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in list(self.active_connections):
            try:
                await connection.send_text(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()

# -------------------------------------------------------------------
# WAF Engine subprocess reference
# -------------------------------------------------------------------
waf_process: subprocess.Popen | None = None


# -------------------------------------------------------------------
# Lifespan (replaces deprecated @app.on_event)
# -------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    global waf_process
    # Startup
    init_db()
    seed_database()

    engine_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "waf_engine.py")
    if os.path.exists(engine_path):
        print("Starting WAF Engine Proxy on port 8085...")
        waf_process = subprocess.Popen(
            [sys.executable, engine_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    # Start background tasks during startup
    asyncio.create_task(_monitor_waf_process())
    start_scheduler()

    yield  # Application runs here

    # Shutdown
    stop_scheduler()
    if waf_process and waf_process.poll() is None:
        logger.info("Stopping WAF Engine Proxy...")
        waf_process.terminate()
        try:
            waf_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            waf_process.kill()


async def _monitor_waf_process():
    """Continuously monitor and auto-restart the WAF proxy if it dies."""
    global waf_process
    engine_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "waf_engine.py")
    while True:
        await asyncio.sleep(10)
        if waf_process and waf_process.poll() is not None:
            logger.warning("WAF Engine process died! Auto-restarting...")
            try:
                waf_process = subprocess.Popen(
                    [sys.executable, engine_path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                logger.info(f"WAF Engine restarted with PID {waf_process.pid}")
            except Exception as e:
                logger.error(f"Failed to restart WAF engine: {e}")


# -------------------------------------------------------------------
# Application
# -------------------------------------------------------------------
app = FastAPI(
    title=APP_NAME,
    description="Digi Save - Web Application Firewall Management API",
    version=VERSION,
    lifespan=lifespan,
)

# Error handling middleware
class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            response = await call_next(request)
            return response
        except Exception as exc:
            logger.error(f"Failed to process request {request.url.path}: {traceback.format_exc()}")
            return JSONResponse(
                status_code=500,
                content={"code": 500, "message": "Internal Server Error"}
            )

app.add_middleware(ErrorHandlingMiddleware)

# CORS — locked to management UI origin by default
ALLOWED_ORIGINS = os.environ.get("CORS_ORIGINS", "http://localhost:8005").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routers
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(websites.router)
app.include_router(detect_logs.router)
app.include_router(policy_rules.router)
app.include_router(settings.router)
app.include_router(protection.router)
app.include_router(ssl_certs.router)
app.include_router(ip_acl.router)

# Serve frontend static files
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
if os.path.exists(FRONTEND_DIR):
    app.mount("/css", StaticFiles(directory=os.path.join(FRONTEND_DIR, "css")), name="css")
    app.mount("/js", StaticFiles(directory=os.path.join(FRONTEND_DIR, "js")), name="js")
    if os.path.exists(os.path.join(FRONTEND_DIR, "assets")):
        app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIR, "assets")), name="assets")


# -------------------------------------------------------------------
# Frontend page routes
# -------------------------------------------------------------------
@app.get("/")
@app.get("/login")
async def serve_login():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

@app.get("/dashboard")
async def serve_dashboard():
    return FileResponse(os.path.join(FRONTEND_DIR, "dashboard.html"))

@app.get("/sites")
async def serve_sites():
    return FileResponse(os.path.join(FRONTEND_DIR, "sites.html"))

@app.get("/logs")
async def serve_logs():
    return FileResponse(os.path.join(FRONTEND_DIR, "logs.html"))

@app.get("/rules")
async def serve_rules():
    return FileResponse(os.path.join(FRONTEND_DIR, "rules.html"))

@app.get("/settings")
async def serve_settings():
    return FileResponse(os.path.join(FRONTEND_DIR, "settings.html"))

@app.get("/ip_acl")
async def serve_ip_acl():
    return FileResponse(os.path.join(FRONTEND_DIR, "ip_acl.html"))


# -------------------------------------------------------------------
# WebSocket endpoint for live threat feed
# -------------------------------------------------------------------
@app.websocket("/ws/dashboard")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive; we only broadcast outward
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# -------------------------------------------------------------------
# Internal route: WAF engine pushes attack events here
# -------------------------------------------------------------------
@app.post("/internal/notify_attack")
async def notify_attack(payload: dict):
    """Called by the WAF proxy engine to push live attack events to all UI clients."""
    await manager.broadcast(json.dumps(payload))
    return {"status": "ok"}

@app.get("/api/open/health")
async def health_check():
    """Health check endpoint for Docker / Load Balancers."""
    waf_status = "running" if waf_process and waf_process.poll() is None else "stopped"
    return {"status": "healthy", "version": VERSION, "waf_engine": waf_status}


# -------------------------------------------------------------------
# Entry point
# -------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("  Digi Save WAF - Web Application Firewall & Management")
    print("  Management API: http://localhost:8005")
    print("  WAF Proxy Node: http://localhost:8085")
    print("  API docs at http://localhost:8005/docs")
    print("  Default login: admin / admin123")
    print("=" * 60)
    uvicorn.run("main:app", host="0.0.0.0", port=8005, reload=False)
