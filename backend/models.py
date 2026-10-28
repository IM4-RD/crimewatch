from typing import Optional, List
from datetime import datetime
# pyrefly: ignore [missing-import]
from sqlalchemy import create_engine, String, Float, Boolean, Text, DateTime, Integer, ForeignKey, BigInteger, text
# pyrefly: ignore [missing-import]
from sqlalchemy.ext.declarative import declarative_base
# pyrefly: ignore [missing-import]
from sqlalchemy.orm import sessionmaker, relationship, Mapped, mapped_column
# pyrefly: ignore [missing-import]
from sqlalchemy.sql import func
from config import get_settings
import uuid

settings = get_settings()

# SQLite for development, MySQL for production
if settings.APP_ENV == "development":
    engine = create_engine("sqlite:///./crimewatch_dev.db", connect_args={"check_same_thread": False})
else:
    engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True, pool_recycle=3600)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def new_id():
    return str(uuid.uuid4())

def repair_sqlite_audit_log_table() -> None:
    """Repair audit_log schema in SQLite dev DB if the id column was created as non-INTEGER."""
    if "sqlite" not in str(engine.url).lower():
        return

    with engine.connect() as conn:
        result = conn.execute(text("PRAGMA table_info('audit_log')"))
        rows = result.fetchall()
        if not rows:
            return

        id_column = next((row for row in rows if row[1] == "id"), None)
        if id_column is None or id_column[2].upper() == "INTEGER":
            return

        conn.execute(text("ALTER TABLE audit_log RENAME TO audit_log_old"))
        conn.execute(text(
            """
            CREATE TABLE audit_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id VARCHAR(36) NULL,
              action VARCHAR(100) NOT NULL,
              resource VARCHAR(100) NULL,
              resource_id VARCHAR(128) NULL,
              ip_address VARCHAR(45) NULL,
              user_agent VARCHAR(512) NULL,
              created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        ))
        conn.execute(text(
            """
            INSERT INTO audit_log (user_id, action, resource, resource_id, ip_address, user_agent, created_at)
            SELECT user_id, action, resource, resource_id, ip_address, user_agent, created_at
            FROM audit_log_old
            """
        ))
        conn.execute(text("DROP TABLE audit_log_old"))

# ── MODELS ───────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36),  primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20),  nullable=False, default="public")
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    public_key: Mapped[Optional[str]] = mapped_column(Text,        nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean,     default=True)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime,    nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime,    server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime,    server_default=func.now(), onupdate=func.now())
    reports: Mapped[List["Report"]] = relationship("Report", foreign_keys="Report.submitted_by", back_populates="submitter")

class Report(Base):
    __tablename__ = "reports"
    id: Mapped[str] = mapped_column(String(36),   primary_key=True, default=new_id)
    client_id: Mapped[str] = mapped_column(String(128),  unique=True, nullable=False, index=True)
    encrypted_payload: Mapped[str] = mapped_column(Text,         nullable=False)
    encryption_iv: Mapped[str] = mapped_column(String(64),   nullable=False)
    encryption_tag: Mapped[str] = mapped_column(String(64),   nullable=False)
    wrapped_key: Mapped[str] = mapped_column(Text,         nullable=False)
    severity: Mapped[str] = mapped_column(String(20),   nullable=False, default="medium")
    incident_type: Mapped[str] = mapped_column(String(100),  nullable=False)
    status: Mapped[str] = mapped_column(String(30),   nullable=False, default="received")
    is_anonymous: Mapped[bool] = mapped_column(Boolean,      default=True)
    latitude: Mapped[Optional[float]] = mapped_column(Float,        nullable=True)
    longitude: Mapped[Optional[float]] = mapped_column(Float,        nullable=True)
    location_label: Mapped[Optional[str]] = mapped_column(String(255),  nullable=True)
    submitted_by: Mapped[Optional[str]] = mapped_column(String(36),   ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    assigned_officer: Mapped[Optional[str]] = mapped_column(String(36),   ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    client_created_at: Mapped[datetime] = mapped_column(DateTime,     nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime,     server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime,     server_default=func.now(), onupdate=func.now())
    submitter: Mapped[Optional["User"]] = relationship("User", foreign_keys=[submitted_by], back_populates="reports")
    media_files: Mapped[List["MediaFile"]] = relationship("MediaFile", back_populates="report", cascade="all, delete-orphan")
    officer_notes: Mapped[List["OfficerNote"]] = relationship("OfficerNote", back_populates="report", cascade="all, delete-orphan")
    status_history: Mapped[List["StatusHistory"]] = relationship("StatusHistory", back_populates="report", cascade="all, delete-orphan")

class MediaFile(Base):
    __tablename__ = "media_files"
    id: Mapped[str] = mapped_column(String(36),  primary_key=True, default=new_id)
    report_id: Mapped[str] = mapped_column(String(36),  ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True)
    original_name: Mapped[str] = mapped_column(String(255), nullable=False)
    stored_name: Mapped[str] = mapped_column(String(255), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(100), nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(Integer,     default=0)
    storage_path: Mapped[str] = mapped_column(String(512), nullable=False)
    file_key_enc: Mapped[Optional[str]] = mapped_column(Text,        nullable=True)
    checksum_sha256: Mapped[Optional[str]] = mapped_column(String(64),  nullable=True)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime,    server_default=func.now())
    report: Mapped["Report"] = relationship("Report", back_populates="media_files")

class OfficerNote(Base):
    __tablename__ = "officer_notes"
    id: Mapped[str] = mapped_column(String(36),  primary_key=True, default=new_id)
    report_id: Mapped[str] = mapped_column(String(36),  ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True)
    officer_id: Mapped[str] = mapped_column(String(36),  ForeignKey("users.id",   ondelete="CASCADE"), nullable=False)
    note: Mapped[str] = mapped_column(Text,        nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime,    server_default=func.now())
    report: Mapped["Report"] = relationship("Report", back_populates="officer_notes")
    officer: Mapped["User"] = relationship("User")

class StatusHistory(Base):
    __tablename__ = "status_history"
    id: Mapped[str] = mapped_column(String(36),  primary_key=True, default=new_id)
    report_id: Mapped[str] = mapped_column(String(36),  ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True)
    changed_by: Mapped[Optional[str]] = mapped_column(String(36),  nullable=True)
    old_status: Mapped[Optional[str]] = mapped_column(String(50),  nullable=True)
    new_status: Mapped[str] = mapped_column(String(50),  nullable=False)
    note: Mapped[Optional[str]] = mapped_column(Text,        nullable=True)
    changed_at: Mapped[datetime] = mapped_column(DateTime,    server_default=func.now())
    report: Mapped["Report"] = relationship("Report", back_populates="status_history")

class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = {"sqlite_autoincrement": True}
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), index=True)

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id: Mapped[str] = mapped_column(String(36),  primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(String(36),  ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    device_info: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime,    nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean,     default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime,    server_default=func.now())

def init_db():
    """Create all tables and seed default users if database is empty."""
    Base.metadata.create_all(bind=engine)
    repair_sqlite_audit_log_table()
    
    # Seed default users only if none exist yet
    db = SessionLocal()
    if db.query(User).count() == 0:
        from auth import hash_password
        
        seed_users = [
            {
                "email": "public@crimewatch.ke",
                "name": "Public User",
                "role": "public",
                "password": "public123"
            },
            {
                "email": "officer@crimewatch.ke",
                "name": "Officer Kamau",
                "role": "officer",
                "password": "officer123"
            },
            {
                "email": "admin@crimewatch.ke",
                "name": "Admin Imran",
                "role": "admin",
                "password": "admin123"
            }
        ]
        
        for user_data in seed_users:
            user = User(
                email=user_data["email"],
                name=user_data["name"],
                role=user_data["role"],
                password_hash=hash_password(user_data["password"]),
                is_active=True
            )
            db.add(user)
        
        db.commit()
        print("[OK] Seeded default users: public, officer, admin")
    
    db.close()
