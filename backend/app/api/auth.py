from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db
from app.models import User
from app.schemas import LoginRequest, RoleSwitchRequest, TokenResponse, UserOut
from app.security import (
    create_access_token,
    get_current_user,
    record_audit_event,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["Authentication & RBAC"])

ROLE_EMAIL_MAP = {
    "CITIZEN_DEVELOPER": "citizen.dev@sgates.local",
    "IT_REVIEWER": "it.reviewer@sgates.local",
    "SECURITY_REVIEWER": "sec.reviewer@sgates.local",
    "ADMIN": "admin@sgates.local",
}


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = (
        db.query(User)
        .filter(User.email == payload.email.strip().lower())
        .first()
    )
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    token = create_access_token({"sub": user.email, "role": user.role})
    return TokenResponse(access_token=token, user=UserOut.model_validate(user))


@router.post("/switch-role", response_model=TokenResponse)
def switch_role(payload: RoleSwitchRequest, db: Session = Depends(get_db)):
    """Development-only role switcher for isolated demo environments."""
    if not settings.ENABLE_DEMO_ROLE_SWITCHER or settings.APP_ENV.lower() not in {"development", "test"}:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found.")
    target_email = ROLE_EMAIL_MAP.get(payload.role.upper())
    if not target_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported role '{payload.role}'. Choose from: {', '.join(ROLE_EMAIL_MAP.keys())}",
        )
    user = db.query(User).filter(User.email == target_email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target persona account not found.",
        )

    token = create_access_token({"sub": user.email, "role": user.role})
    return TokenResponse(access_token=token, user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)):
    return UserOut.model_validate(current_user)


@router.get("/personas")
def list_personas(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not settings.ENABLE_DEMO_ROLE_SWITCHER:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found.")
    users = db.query(User).order_by(User.id.asc()).all()
    return [UserOut.model_validate(u) for u in users]
