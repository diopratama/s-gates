from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Optional
import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt
from jwt.exceptions import InvalidTokenError
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db
from app.models import AuditRecord, NotificationEvent, User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login", auto_error=False)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"), hashed_password.encode("utf-8")
        )
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta
        or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token.",
            )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials.",
        )

    user = db.query(User).filter(User.email == email).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found or inactive.",
        )
    return user


def require_roles(*allowed_roles: str):
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Role '{current_user.role}' is not authorized to perform this action. "
                    f"Required role(s): {', '.join(allowed_roles)}"
                ),
            )
        return current_user

    return role_checker


def record_audit_event(
    db: Session,
    actor_email: str,
    actor_role: str,
    event_type: str,
    summary: str,
    assessment_code: Optional[str] = None,
    sgates_app_id: Optional[str] = None,
    previous_state: str = "",
    new_state: str = "",
    sha256_file_hash: str = "",
    metadata_json: Optional[dict] = None,
) -> AuditRecord:
    """Create a database-backed SHA-256 chain record (tamper-evident, not WORM)."""
    if db.get_bind().dialect.name == "postgresql":
        # Serialize chain-head reads/writes across API workers.
        db.execute(text("SELECT pg_advisory_xact_lock(731904218)"))

    last_record = db.query(AuditRecord).order_by(AuditRecord.id.desc()).first()
    prev_sig = last_record.immutable_signature if last_record else "GENESIS-SGATES-2026"
    created_at = datetime.now(timezone.utc)
    created_at_signed = created_at.isoformat(timespec="microseconds")
    signed_metadata = dict(metadata_json or {})
    signed_metadata["_chain_version"] = 2
    signed_metadata["_chain_created_at"] = created_at_signed
    payload_str = json.dumps(
        {
            "prev_sig": prev_sig,
            "actor_email": actor_email,
            "actor_role": actor_role,
            "event_type": event_type,
            "assessment_code": assessment_code,
            "sgates_app_id": sgates_app_id,
            "previous_state": previous_state,
            "new_state": new_state,
            "sha256_file_hash": sha256_file_hash,
            "summary": summary,
            "metadata_json": signed_metadata,
            "created_at": created_at_signed,
        },
        sort_keys=True,
    )
    signature = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
    audit = AuditRecord(
        assessment_code=assessment_code,
        sgates_app_id=sgates_app_id,
        actor_email=actor_email,
        actor_role=actor_role,
        event_type=event_type,
        previous_state=previous_state,
        new_state=new_state,
        sha256_file_hash=sha256_file_hash,
        summary=summary,
        metadata_json=signed_metadata,
        immutable_signature=signature,
        created_at=created_at,
    )
    db.add(audit)
    return audit


def emit_notification(
    db: Session,
    event_type: str,
    assessment_code: str,
    application_name: str,
    message: str,
    recipient_role: str = "ALL",
) -> NotificationEvent:
    """Emit notification event for S-Gates workflow transitions (PRD Section 36)."""
    notif = NotificationEvent(
        event_type=event_type,
        assessment_code=assessment_code,
        application_name=application_name,
        recipient_role=recipient_role,
        channel="In-App",
        message=message,
    )
    db.add(notif)
    return notif
