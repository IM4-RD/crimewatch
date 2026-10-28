"""
CrimeWatch API v2.0 — FastAPI Backend
======================================
Standalone server, separate from any database server.
MySQL runs on its own host.

Run:
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""

from contextlib import asynccontextmanager
# pyrefly: ignore [missing-import]
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Request, Query
# pyrefly: ignore [missing-import]
from fastapi.middleware.cors import CORSMiddleware
# pyrefly: ignore [missing-import]
from sqlalchemy.orm import Session
# pyrefly: ignore [missing-import]
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone, timedelta
import uuid, os, hashlib
# pyrefly: ignore [missing-import]
import aiofiles

from config import get_settings
from models import (
    init_db, get_db, User, Report, MediaFile,
    OfficerNote, StatusHistory, AuditLog, RefreshToken
)
from auth import (
    hash_password, verify_password,
    create_access_token, create_refresh_token,
    get_current_user, get_optional_user, require_role
)
from encryption import (
    load_private_key, get_public_key_pem,
    generate_rsa_keypair, save_keypair, server_decrypt
)

settings = get_settings()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Init DB tables
    init_db()

    # Generate RSA keys if missing
    priv = settings.PRIVATE_KEY_PATH
    pub  = settings.PUBLIC_KEY_PATH
    if not os.path.exists(priv) or not os.path.exists(pub):
        os.makedirs(os.path.dirname(priv), exist_ok=True)
        private_key, _ = generate_rsa_keypair(2048)
        save_keypair(private_key, priv, pub)
        print("[OK] RSA key pair generated")

    # Init media storage dir
    os.makedirs(settings.MEDIA_DIR, exist_ok=True)
    print(f"[OK] {settings.APP_NAME} v{settings.VERSION} started")

    yield

app = FastAPI(title=settings.APP_NAME, version=settings.VERSION, docs_url="/api/docs", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── STARTUP ──────────────────────────────────────────────────

# ── HELPERS ──────────────────────────────────────────────────
def audit(
    db: Session,
    action: str,
    user_id: Optional[str] = None,
    resource: Optional[str] = None,
    resource_id: Optional[str] = None,
    request: Optional[Request] = None
) -> None:
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    if request is not None:
        client = request.client
        if client is not None:
            ip_address = client.host
        user_agent = request.headers.get("user-agent")

    entry = AuditLog(
        user_id=user_id, action=action,
        resource=resource, resource_id=resource_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(entry)
    db.commit()

def fmt_report(r: Report, include_payload: bool = False) -> dict[str, Any]:
    d: dict[str, Any] = {
        "id":             r.id,
        "client_id":      r.client_id,
        "severity":       r.severity,
        "incident_type":  r.incident_type,
        "status":         r.status,
        "is_anonymous":   r.is_anonymous,
        "latitude":       r.latitude,
        "longitude":      r.longitude,
        "location_label": r.location_label,
        "submitted_by":   r.submitted_by,
        "assigned_officer": r.assigned_officer,
        "client_created_at": r.client_created_at.isoformat(),
        "received_at":    r.received_at.isoformat(),
        "updated_at":     r.updated_at.isoformat(),
        "media_count":    len(r.media_files),
    }
    if include_payload:
        d["encrypted_payload"] = r.encrypted_payload
        d["encryption_iv"]     = r.encryption_iv
        d["encryption_tag"]    = r.encryption_tag
        d["wrapped_key"]       = r.wrapped_key
    return d

# ── PYDANTIC SCHEMAS ─────────────────────────────────────────
class LoginReq(BaseModel):
    email: str
    password: str

class RegisterReq(BaseModel):
    email: str
    name: str
    password: str
    public_key: Optional[str] = None

class ReportCreate(BaseModel):
    client_id:         str
    encrypted_payload: str
    encryption_iv:     str
    encryption_tag:    str
    wrapped_key:       str
    severity:          str
    incident_type:     str
    is_anonymous:      bool = True
    latitude:          Optional[float] = None
    longitude:         Optional[float] = None
    location_label:    Optional[str]   = None
    client_created_at: str

class BulkSyncReq(BaseModel):
    reports: List[ReportCreate]

class StatusUpdate(BaseModel):
    status: str
    note:   Optional[str] = None
    assign_to: Optional[str] = None

class NoteCreate(BaseModel):
    note: str

# ── HEALTH ───────────────────────────────────────────────────
@app.get("/api/health")
def health(db: Session = Depends(get_db)):
    try:
        db.execute(__import__("sqlalchemy").text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    return {
        "status":  "ok" if db_ok else "degraded",
        "version": settings.VERSION,
        "db":      "connected" if db_ok else "error",
        "env":     settings.APP_ENV,
    }

# ── ENCRYPTION KEY EXCHANGE ──────────────────────────────────
@app.get("/api/keys/public")
def get_public_key() -> dict[str, Any]:
    """Return server RSA public key so clients can wrap their AES key."""
    try:
        pem = get_public_key_pem(settings.PUBLIC_KEY_PATH)
        return {"public_key": pem, "algorithm": "RSA-OAEP", "key_size": 2048}
    except FileNotFoundError:
        raise HTTPException(500, "Server key not initialized")

# ── AUTH ─────────────────────────────────────────────────────
@app.post("/api/auth/register", status_code=201)
def register(req: RegisterReq, db: Session = Depends(get_db)) -> dict[str, Any]:
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(400, "Email already registered")
    user = User(
        email=req.email, name=req.name,
        password_hash=hash_password(req.password),
        public_key=req.public_key, role="public"
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_access_token(user.id, user.role)
    return {"token": token, "user": {"id": user.id, "name": user.name, "role": user.role, "email": user.email}}

@app.post("/api/auth/login")
def login(req: LoginReq, request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    user = db.query(User).filter(User.email == req.email, User.is_active == True).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(401, "Invalid credentials")
    user.last_login_at = datetime.now(timezone.utc)
    raw_rt, hashed_rt = create_refresh_token()
    rt = RefreshToken(
        user_id=user.id,
        token_hash=hashed_rt,
        device_info=request.headers.get("user-agent", "")[:255],
        expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=30),
    )
    db.add(rt)
    db.commit()
    audit(db, "login", user.id, request=request)
    token = create_access_token(user.id, user.role)
    return {
        "token":         token,
        "refresh_token": raw_rt,
        "user": {"id": user.id, "name": user.name, "role": user.role, "email": user.email}
    }

@app.post("/api/auth/logout")
def logout(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict[str, str]:
    db.query(RefreshToken).filter(RefreshToken.user_id == user.id, RefreshToken.revoked == False).update({"revoked": True})
    db.commit()
    return {"message": "Logged out"}

@app.get("/api/auth/me")
def me(user: User = Depends(get_current_user)) -> dict[str, Any]:
    return {"id": user.id, "name": user.name, "role": user.role, "email": user.email}

@app.put("/api/auth/public-key")
def update_public_key(data: Dict[str, Any], user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict[str, str]:
    user.public_key = data.get("public_key")
    db.commit()
    return {"message": "Public key updated"}

# ── REPORTS ──────────────────────────────────────────────────
@app.post("/api/reports", status_code=201)
def create_report(
    req: ReportCreate,
    request: Request,
    user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db)
) -> dict[str, Any]:
    if db.query(Report).filter(Report.client_id == req.client_id).first():
        raise HTTPException(409, "Report already exists (duplicate client_id)")

    report = Report(
        client_id         = req.client_id,
        encrypted_payload = req.encrypted_payload,
        encryption_iv     = req.encryption_iv,
        encryption_tag    = req.encryption_tag,
        wrapped_key       = req.wrapped_key,
        severity          = req.severity,
        incident_type     = req.incident_type,
        is_anonymous      = req.is_anonymous,
        latitude          = req.latitude,
        longitude         = req.longitude,
        location_label    = req.location_label,
        submitted_by      = user.id if user else None,
        client_created_at = datetime.fromisoformat(req.client_created_at.replace("Z", "+00:00")),
        status            = "received",
    )
    db.add(report)
    db.flush()

    history = StatusHistory(report_id=report.id, new_status="received", changed_by=user.id if user else None)
    db.add(history)
    db.commit()
    db.refresh(report)
    audit(db, "report.create", user.id if user else None, "report", report.id, request)
    return {"id": report.id, "client_id": report.client_id, "status": "received", "received_at": report.received_at.isoformat()}

@app.post("/api/reports/bulk-sync")
def bulk_sync(
    req: BulkSyncReq,
    request: Request,
    user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db)
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for r in req.reports:
        existing = db.query(Report).filter(Report.client_id == r.client_id).first()
        if existing:
            results.append({"client_id": r.client_id, "server_id": existing.id, "status": "already_synced"})
            continue
        report = Report(
            client_id=r.client_id, encrypted_payload=r.encrypted_payload,
            encryption_iv=r.encryption_iv, encryption_tag=r.encryption_tag,
            wrapped_key=r.wrapped_key, severity=r.severity, incident_type=r.incident_type,
            is_anonymous=r.is_anonymous, latitude=r.latitude, longitude=r.longitude,
            location_label=r.location_label, submitted_by=user.id if user else None,
            client_created_at=datetime.fromisoformat(r.client_created_at.replace("Z", "+00:00")),
            status="received",
        )
        db.add(report)
        db.flush()
        db.add(StatusHistory(report_id=report.id, new_status="received"))
        results.append({"client_id": r.client_id, "server_id": report.id, "status": "synced"})
    db.commit()
    synced = sum(1 for r in results if r["status"] == "synced")
    audit(db, "report.bulk_sync", user.id if user else None, request=request)
    return {"results": results, "synced": synced, "total": len(results)}

@app.get("/api/reports")
def list_reports(
    status: Optional[str]  = Query(None),
    severity: Optional[str] = Query(None),
    incident_type: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> dict[str, Any]:
    q = db.query(Report)
    if user.role == "public":
        q = q.filter(Report.submitted_by == user.id)
    if status:
        q = q.filter(Report.status == status)
    if severity:
        q = q.filter(Report.severity == severity)
    if incident_type:
        q = q.filter(Report.incident_type == incident_type)
    total  = q.count()
    reports = q.order_by(Report.received_at.desc()).offset((page - 1) * limit).limit(limit).all()
    return {"reports": [fmt_report(r) for r in reports], "total": total, "page": page, "limit": limit}

@app.get("/api/reports/{report_id}")
def get_report(
    report_id: str,
    decrypt: bool = Query(False),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> dict[str, Any]:
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(404, "Report not found")
    if user.role == "public" and report.submitted_by != user.id:
        raise HTTPException(403, "Access denied")

    result = fmt_report(report, include_payload=True)

    # Decrypt only if explicitly requested by officer/admin
    if decrypt and user.role in ("officer", "admin"):
        try:
            priv = load_private_key(settings.PRIVATE_KEY_PATH)
            plaintext = server_decrypt(
                report.encrypted_payload, report.encryption_iv,
                report.encryption_tag, report.wrapped_key, priv
            )
            result["decrypted"] = plaintext
            audit(db, "report.decrypt", user.id, "report", report_id)
        except Exception as e:
            result["decrypt_error"] = str(e)

    return result

@app.patch("/api/reports/{report_id}/status")
def update_status(
    report_id: str,
    req: StatusUpdate,
    request: Request,
    user: User = Depends(require_role("officer", "admin")),
    db: Session = Depends(get_db)
) -> dict[str, Any]:
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(404, "Report not found")

    valid = {"received", "reviewing", "investigating", "resolved", "closed"}
    if req.status not in valid:
        raise HTTPException(400, f"Invalid status. Must be one of: {valid}")

    old = report.status
    report.status = req.status
    if req.assign_to:
        report.assigned_officer = req.assign_to

    db.add(StatusHistory(report_id=report.id, changed_by=user.id, old_status=old, new_status=req.status, note=req.note))

    if req.note:
        db.add(OfficerNote(report_id=report.id, officer_id=user.id, note=req.note))

    db.commit()
    db.refresh(report)  # Refresh report from DB after commit
    audit(db, "report.status_update", user.id, "report", report_id, request)
    return fmt_report(report)

@app.post("/api/reports/{report_id}/media", status_code=201)
async def upload_media(
    report_id: str,
    file: UploadFile = File(...),
    user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db)
) -> dict[str, Any]:
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(404, "Report not found")

    allowed = {"image/jpeg", "image/png", "image/webp", "video/mp4", "video/quicktime"}
    if file.content_type not in allowed:
        raise HTTPException(400, f"File type {file.content_type} not allowed")

    filename = file.filename or ""
    ext      = os.path.splitext(filename)[1].lower()
    fname    = f"{uuid.uuid4()}{ext}"
    fpath    = os.path.join(settings.MEDIA_DIR, report_id)
    os.makedirs(fpath, exist_ok=True)
    full_path = os.path.join(fpath, fname)

    content = await file.read()
    if len(content) > settings.MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, f"File exceeds {settings.MAX_UPLOAD_MB}MB limit")

    checksum = hashlib.sha256(content).hexdigest()
    async with aiofiles.open(full_path, "wb") as f:
        await f.write(content)

    mf = MediaFile(
        report_id=report_id, original_name=filename,
        stored_name=fname, mime_type=file.content_type,
        file_size_bytes=len(content), storage_path=full_path,
        checksum_sha256=checksum
    )
    db.add(mf)
    db.commit()
    return {"id": mf.id, "filename": fname, "size": len(content), "checksum": checksum}

@app.get("/api/reports/{report_id}/history")
def get_history(report_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(404, "Not found")
    if user.role == "public" and report.submitted_by != user.id:
        raise HTTPException(403, "Access denied")
    return [{"old": h.old_status, "new": h.new_status, "note": h.note, "at": h.changed_at.isoformat()} for h in report.status_history]

# ── STATS ─────────────────────────────────────────────────────
@app.get("/api/stats")
def stats(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    q = db.query(Report)
    if user.role == "public":
        q = q.filter(Report.submitted_by == user.id)
    reports = q.all()
    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for r in reports:
        by_status[r.status]        = by_status.get(r.status, 0) + 1
        by_severity[r.severity]    = by_severity.get(r.severity, 0) + 1
        by_type[r.incident_type]   = by_type.get(r.incident_type, 0) + 1
    return {"total": len(reports), "by_status": by_status, "by_severity": by_severity, "by_type": by_type}

# ── USERS (admin) ─────────────────────────────────────────────
@app.get("/api/users")
def list_users(user: User = Depends(require_role("admin")), db: Session = Depends(get_db)) -> dict[str, Any]:
    users = db.query(User).all()
    return {"users": [{"id": u.id, "email": u.email, "name": u.name, "role": u.role, "is_active": u.is_active} for u in users]}

@app.get("/api/users/officers")
def list_officers(user: User = Depends(require_role("officer", "admin")), db: Session = Depends(get_db)) -> dict[str, Any]:
    officers = db.query(User).filter(User.role.in_(["officer", "admin"]), User.is_active == True).all()
    return {"officers": [{"id": u.id, "email": u.email, "name": u.name, "role": u.role} for u in officers]}

@app.patch("/api/users/{user_id}/role")
def update_role(user_id: str, data: Dict[str, Any], request: Request, admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)) -> dict[str, Any]:
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(404, "User not found")
    valid_roles = {"public", "officer", "admin"}
    if data.get("role") not in valid_roles:
        raise HTTPException(400, "Invalid role")
    u.role = data["role"]
    db.commit()
    audit(db, "user.role_update", admin.id, "user", user_id, request)
    return {"id": u.id, "role": u.role}

if __name__ == "__main__":
    # pyrefly: ignore [missing-import]
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=settings.PORT, reload=settings.DEBUG)
