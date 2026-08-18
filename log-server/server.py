import os
import secrets
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from dotenv import load_dotenv

from database import init_db, register_device, add_log_entry, add_log_entries, get_devices, get_device, get_logs, get_stats, get_categories, get_log_by_id

load_dotenv()

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PASSWORD = os.environ.get("ADMIN_PASSWORD", "xigua-admin")
COOKIE_NAME = "xigua_admin_session"
SESSION_SECRET = os.environ.get("SESSION_SECRET", "change-me-in-production")

app = FastAPI(title="XIGUASecurity Log Collector")
app.mount("/static", StaticFiles(directory=os.path.join(APP_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(APP_DIR, "templates"))

init_db()

sessions: set = set()


def get_password() -> str:
    return DEFAULT_PASSWORD


def is_authenticated(request: Request) -> bool:
    token = request.cookies.get(COOKIE_NAME)
    if token and token in sessions:
        return True
    return False


def require_auth(request: Request):
    if not is_authenticated(request):
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"}, detail="Not authenticated")


class LogEntryPayload(BaseModel):
    timestamp: str
    category: Optional[str] = None
    function: Optional[str] = None
    summary: str
    details: Optional[dict] = None
    file_path: Optional[str] = None
    threat_name: Optional[str] = None
    action: Optional[str] = None
    result: Optional[str] = None


class BatchLogPayload(BaseModel):
    device_name: str = Field(..., min_length=1, max_length=128)
    entries: List[LogEntryPayload]


class RegisterPayload(BaseModel):
    device_name: str = Field(..., min_length=1, max_length=128)


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    require_auth(request)
    stats = get_stats()
    devices = get_devices()
    return templates.TemplateResponse(request, "dashboard.html", {
        "stats": stats,
        "devices": devices,
    })


@app.get("/threats", response_class=HTMLResponse)
async def threats_page(request: Request):
    require_auth(request)
    devices = get_devices()
    return templates.TemplateResponse(request, "threats.html", {
        "devices": devices,
    })


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: Optional[str] = None):
    return templates.TemplateResponse(request, "login.html", {
        "error": error,
    })


@app.post("/login")
async def login_post(request: Request, password: str = Form(...)):
    if password == get_password():
        token = secrets.token_urlsafe(32)
        sessions.add(token)
        response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(COOKIE_NAME, token, httponly=True, max_age=86400, samesite="lax")
        return response
    return RedirectResponse(url="/login?error=1", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/logout")
async def logout(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    if token:
        sessions.discard(token)
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(COOKIE_NAME)
    return response


@app.get("/device/{device_name}", response_class=HTMLResponse)
async def device_detail(request: Request, device_name: str):
    require_auth(request)
    device = get_device(device_name)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    logs = get_logs(device_name=device_name, limit=500)
    categories = get_categories()
    edr_count = len(get_logs(device_name=device_name, category="edr", limit=10000))
    timeline_count = len(get_logs(device_name=device_name, category="timeline", limit=10000))
    return templates.TemplateResponse(request, "device.html", {
        "device": device,
        "logs": logs,
        "categories": categories,
        "edr_count": edr_count,
        "timeline_count": timeline_count,
    })


@app.get("/device/{device_name}/timeline", response_class=HTMLResponse)
async def device_timeline(request: Request, device_name: str):
    require_auth(request)
    device = get_device(device_name)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return templates.TemplateResponse(request, "timeline.html", {
        "device": device,
    })


@app.get("/device/{device_name}/edr", response_class=HTMLResponse)
async def device_edr(request: Request, device_name: str):
    require_auth(request)
    device = get_device(device_name)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return templates.TemplateResponse(request, "edr.html", {
        "device": device,
    })


@app.get("/device/{device_name}/edr/{log_id}", response_class=HTMLResponse)
async def edr_detail(request: Request, device_name: str, log_id: int):
    require_auth(request)
    device = get_device(device_name)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    log = get_log_by_id(log_id)
    if not log or log.device_name != device_name:
        raise HTTPException(status_code=404, detail="EDR record not found")
    return templates.TemplateResponse(request, "edr-detail.html", {
        "device": device,
        "log": log,
    })


@app.get("/api/edr/{log_id}")
async def api_edr_detail(log_id: int, request: Request):
    require_auth(request)
    log = get_log_by_id(log_id)
    if not log:
        raise HTTPException(status_code=404, detail="EDR record not found")
    return {
        "id": log.id,
        "timestamp": log.timestamp,
        "summary": log.summary,
        "details": log.details,
    }


@app.get("/api/devices")
async def api_devices(request: Request):
    require_auth(request)
    return {"devices": [d.__dict__ for d in get_devices()]}


@app.get("/api/devices/{device_name}/logs")
async def api_device_logs(device_name: str, request: Request, category: Optional[str] = None, keyword: Optional[str] = None, limit: int = 1000):
    require_auth(request)
    logs = get_logs(device_name=device_name, category=category, keyword=keyword, limit=limit)
    return {
        "logs": [
            {
                "id": log.id,
                "timestamp": log.timestamp,
                "category": log.category,
                "function": log.function,
                "summary": log.summary,
                "details": log.details,
                "file_path": log.file_path,
                "threat_name": log.threat_name,
                "action": log.action,
                "result": log.result,
            }
            for log in logs
        ]
    }


@app.get("/api/timeline")
async def api_timeline(request: Request, device_name: Optional[str] = None, keyword: Optional[str] = None, limit: int = 1000):
    require_auth(request)
    logs = get_logs(category="timeline", device_name=device_name, keyword=keyword, limit=limit)
    return {
        "logs": [
            {
                "id": log.id,
                "timestamp": log.timestamp,
                "category": log.category,
                "function": log.function,
                "summary": log.summary,
                "details": log.details,
                "action": log.action,
                "result": log.result,
            }
            for log in logs
        ]
    }


@app.get("/api/edr")
async def api_edr(request: Request, device_name: Optional[str] = None, keyword: Optional[str] = None, limit: int = 1000):
    require_auth(request)
    logs = get_logs(category="edr", device_name=device_name, keyword=keyword, limit=limit)
    return {
        "logs": [
            {
                "id": log.id,
                "timestamp": log.timestamp,
                "category": log.category,
                "function": log.function,
                "summary": log.summary,
                "details": log.details,
                "action": log.action,
                "result": log.result,
            }
            for log in logs
        ]
    }
@app.get("/api/threats")
async def api_threats(request: Request, device_name: Optional[str] = None, keyword: Optional[str] = None, limit: int = 1000):
    require_auth(request)
    logs = get_logs(category="threat", device_name=device_name, keyword=keyword, limit=limit)
    return {
        "logs": [
            {
                "id": log.id,
                "timestamp": log.timestamp,
                "summary": log.summary,
                "details": log.details,
                "device_name": log.device_name,
            }
            for log in logs
        ]
    }

@app.post("/api/register")
async def api_register(payload: RegisterPayload):
    device_name = register_device(payload.device_name)
    return {"device_name": device_name, "status": "ok"}


@app.post("/api/log")
async def api_log(device_name: str = Form(...), payload: str = Form(...)):
    try:
        import json
        entry = json.loads(payload)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {e}")
    add_log_entry(device_name, entry)
    return {"status": "ok"}


@app.post("/api/logs/batch")
async def api_logs_batch(payload: BatchLogPayload):
    device_name = register_device(payload.device_name)
    entries = [e.model_dump() for e in payload.entries]
    count = add_log_entries(device_name, entries)
    return {"status": "ok", "received": count}


@app.post("/api/heartbeat")
async def api_heartbeat(payload: RegisterPayload):
    device_name = register_device(payload.device_name)
    return {"status": "ok", "device_name": device_name}


@app.get("/api/stats")
async def api_stats(request: Request):
    require_auth(request)
    return get_stats()


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == status.HTTP_303_SEE_OTHER and exc.headers and "Location" in exc.headers:
        return RedirectResponse(url=exc.headers["Location"], status_code=exc.status_code)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8052)
