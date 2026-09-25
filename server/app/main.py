from __future__ import annotations
import asyncio
import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Depends, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import select, func, desc
from sqlalchemy.orm import Session

from .db import Base, engine, get_db
from .models import Endpoint, SecurityEvent, Incident, EnrollmentToken

APP_VERSION = "1.0.0"
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DOWNLOAD_DIR = Path(os.getenv("DOWNLOAD_DIR", "/var/lib/cybersecurity-ops/downloads"))
BOOTSTRAP_TOKEN = os.getenv("BOOTSTRAP_TOKEN", "")

app = FastAPI(title="Linux Cybersecurity Operations Center", version=APP_VERSION)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

class Hub:
    def __init__(self):
        self.clients: set[WebSocket] = set()
        self.lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self.lock:
            self.clients.add(ws)

    async def disconnect(self, ws: WebSocket):
        async with self.lock:
            self.clients.discard(ws)

    async def publish(self, payload: dict):
        async with self.lock:
            clients = list(self.clients)
        dead = []
        for ws in clients:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(ws)

hub = Hub()

def sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()

def endpoint_by_token(db: Session, token: str | None):
    if not token:
        raise HTTPException(401, "Missing agent token")
    ep = db.scalar(select(Endpoint).where(Endpoint.token_hash == sha(token)))
    if not ep:
        raise HTTPException(401, "Invalid agent token")
    return ep

class Enroll(BaseModel):
    enrollment_token: str
    hostname: str
    platform: str
    architecture: str = ""
    os_version: str = ""
    username: str = ""
    agent_version: str = "1.0.0"

class Heartbeat(BaseModel):
    username: str = ""
    ip_address: str = ""
    os_version: str = ""
    architecture: str = ""
    agent_version: str = "1.0.0"
    telemetry: dict[str, Any] = Field(default_factory=dict)

class EventIn(BaseModel):
    event_type: str
    severity: str = "INFO"
    title: str
    details: str = ""
    data: dict[str, Any] = Field(default_factory=dict)

@app.on_event("startup")
async def startup():
    Base.metadata.create_all(engine)
    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)

@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")

@app.get("/api/health")
def health(db: Session = Depends(get_db)):
    db.execute(select(func.count(Endpoint.id))).scalar()
    return {"ok": True, "version": APP_VERSION, "database": "ok", "event_ingestor": "ok"}

@app.get("/api/dashboard")
def dashboard(db: Session = Depends(get_db)):
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=90)
    total = db.scalar(select(func.count(Endpoint.id))) or 0
    online = db.scalar(select(func.count(Endpoint.id)).where(Endpoint.last_seen >= cutoff)) or 0
    alerts = db.scalar(
        select(func.count(SecurityEvent.id)).where(
            SecurityEvent.created_at >= now - timedelta(hours=24),
            SecurityEvent.severity.in_(["MEDIUM", "HIGH", "CRITICAL"]),
        )
    ) or 0
    incidents = db.scalar(select(func.count(Incident.id)).where(Incident.status != "CLOSED")) or 0
    critical = db.scalar(
        select(func.count(Incident.id)).where(
            Incident.status != "CLOSED",
            Incident.severity == "CRITICAL",
        )
    ) or 0
    minute = db.scalar(
        select(func.count(SecurityEvent.id)).where(
            SecurityEvent.created_at >= now - timedelta(minutes=1)
        )
    ) or 0
    return {
        "endpoints": total,
        "online": online,
        "alerts": alerts,
        "incidents": incidents,
        "critical": critical,
        "events_min": minute,
    }

@app.get("/api/endpoints")
def endpoints(db: Session = Depends(get_db)):
    rows = db.scalars(select(Endpoint).order_by(Endpoint.hostname)).all()
    now = datetime.utcnow()
    out = []
    for e in rows:
        state = e.state if (now - e.last_seen).total_seconds() <= 90 else "OFFLINE"
        out.append({
            "id": e.id,
            "agent_id": e.agent_id,
            "hostname": e.hostname,
            "platform": e.platform,
            "architecture": e.architecture,
            "os_version": e.os_version,
            "username": e.username,
            "ip_address": e.ip_address,
            "agent_version": e.agent_version,
            "risk": e.risk,
            "state": state,
            "last_seen": e.last_seen.isoformat() + "Z",
        })
    return out

@app.get("/api/events")
def events(limit: int = 50, db: Session = Depends(get_db)):
    rows = db.execute(
        select(SecurityEvent, Endpoint.hostname)
        .outerjoin(Endpoint, SecurityEvent.endpoint_id == Endpoint.id)
        .order_by(desc(SecurityEvent.created_at))
        .limit(min(limit, 200))
    ).all()
    return [{
        "id": ev.id,
        "time": ev.created_at.isoformat() + "Z",
        "endpoint": host or "unknown",
        "type": ev.event_type,
        "severity": ev.severity,
        "title": ev.title,
        "details": ev.details,
    } for ev, host in rows]

@app.get("/api/incidents")
def incidents(limit: int = 30, db: Session = Depends(get_db)):
    rows = db.execute(
        select(Incident, Endpoint.hostname)
        .outerjoin(Endpoint, Incident.endpoint_id == Endpoint.id)
        .order_by(desc(Incident.opened_at))
        .limit(min(limit, 100))
    ).all()
    return [{
        "id": inc.id,
        "time": inc.opened_at.isoformat() + "Z",
        "endpoint": host or "unknown",
        "severity": inc.severity,
        "status": inc.status,
        "detection": inc.detection,
        "summary": inc.summary,
    } for inc, host in rows]

@app.get("/api/downloads")
def downloads():
    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
    return [
        {"name": p.name, "size": p.stat().st_size, "url": f"/downloads/{p.name}"}
        for p in sorted(DOWNLOAD_DIR.iterdir())
        if p.is_file()
    ]

@app.get("/downloads/{name}")
def download(name: str):
    target = (DOWNLOAD_DIR / name).resolve()
    if DOWNLOAD_DIR.resolve() not in target.parents:
        raise HTTPException(400, "Invalid path")
    if not target.is_file():
        raise HTTPException(404, "Not found")
    return FileResponse(target, filename=target.name)

@app.post("/api/admin/enrollment-token")
def new_enrollment_token(
    label: str = "",
    x_bootstrap_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    if not BOOTSTRAP_TOKEN or x_bootstrap_token != BOOTSTRAP_TOKEN:
        raise HTTPException(403, "Forbidden")
    raw = secrets.token_urlsafe(32)
    db.add(EnrollmentToken(token_hash=sha(raw), label=label, used=False))
    db.commit()
    return {"token": raw, "label": label}

@app.post("/api/agent/enroll")
async def enroll(payload: Enroll, request: Request, db: Session = Depends(get_db)):
    token = db.scalar(
        select(EnrollmentToken).where(
            EnrollmentToken.token_hash == sha(payload.enrollment_token),
            EnrollmentToken.used == False,
        )
    )
    if not token:
        raise HTTPException(403, "Invalid or already used enrollment token")

    agent_id = secrets.token_hex(16)
    agent_token = secrets.token_urlsafe(40)
    ep = Endpoint(
        agent_id=agent_id,
        token_hash=sha(agent_token),
        hostname=payload.hostname,
        platform=payload.platform,
        architecture=payload.architecture,
        os_version=payload.os_version,
        username=payload.username,
        ip_address=request.client.host if request.client else "",
        agent_version=payload.agent_version,
        last_seen=datetime.utcnow(),
        risk="LOW",
        state="ONLINE",
    )
    token.used = True
    db.add(ep)
    db.commit()
    db.refresh(ep)
    await hub.publish({"kind": "endpoint", "action": "enrolled", "endpoint": payload.hostname})
    return {"agent_id": agent_id, "agent_token": agent_token}

@app.post("/api/agent/heartbeat")
async def heartbeat(
    payload: Heartbeat,
    request: Request,
    x_agent_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    ep = endpoint_by_token(db, x_agent_token)
    ep.last_seen = datetime.utcnow()
    ep.state = "ONLINE"
    ep.username = payload.username or ep.username
    ep.os_version = payload.os_version or ep.os_version
    ep.architecture = payload.architecture or ep.architecture
    ep.agent_version = payload.agent_version or ep.agent_version
    ep.ip_address = payload.ip_address or (request.client.host if request.client else ep.ip_address)
    db.commit()
    await hub.publish({"kind": "heartbeat", "endpoint": ep.hostname, "time": ep.last_seen.isoformat() + "Z"})
    return {"ok": True}

@app.post("/api/agent/events")
async def ingest(
    events: list[EventIn],
    x_agent_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    ep = endpoint_by_token(db, x_agent_token)
    ep.last_seen = datetime.utcnow()
    created = []
    for e in events[:500]:
        sev = e.severity.upper()
        row = SecurityEvent(
            endpoint_id=ep.id,
            event_type=e.event_type.upper(),
            severity=sev,
            title=e.title,
            details=e.details,
            data_json=json.dumps(e.data),
        )
        db.add(row)
        created.append(row)
        if sev in {"HIGH", "CRITICAL"}:
            db.add(Incident(
                endpoint_id=ep.id,
                severity=sev,
                status="OPEN",
                detection=e.title,
                summary=e.details,
            ))
            if sev == "CRITICAL":
                ep.risk = "CRITICAL"
            elif ep.risk != "CRITICAL":
                ep.risk = "HIGH"
    db.commit()
    for e in created[-25:]:
        await hub.publish({
            "kind": "event",
            "endpoint": ep.hostname,
            "type": e.event_type,
            "severity": e.severity,
            "title": e.title,
            "time": e.created_at.isoformat() + "Z",
        })
    return {"accepted": len(created)}

@app.websocket("/ws/events")
async def websocket_events(ws: WebSocket):
    await hub.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        await hub.disconnect(ws)
