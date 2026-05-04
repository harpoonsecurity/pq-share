import json
import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..db import get_session
from ..email_send import send_email
from ..models import EmailChallenge, User
from ..security import (
    SESSION_COOKIE,
    b64url,
    b64url_decode,
    create_session,
    deterministic_salt_for_unknown,
    get_user_from_session_id,
    hash_auth_secret,
    normalize_email,
    random_token,
    revoke_session,
    verify_auth_secret,
)


log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])


async def current_user(
    db: AsyncSession = Depends(get_session),
    pq_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> User:
    user = await get_user_from_session_id(db, pq_session)
    if user is None:
        raise HTTPException(status_code=401, detail="not authenticated")
    return user


class KdfParams(BaseModel):
    m: int = Field(..., ge=8 * 1024, le=1024 * 1024, description="memory cost in KiB")
    t: int = Field(..., ge=1, le=10)
    p: int = Field(..., ge=1, le=4)


class PublicKeys(BaseModel):
    x25519: str
    ml_kem_768: str
    ed25519: str
    ml_dsa_65: str


class SignupRequest(BaseModel):
    email: EmailStr
    kdf_salt: str
    recovery_salt: str
    kdf_params: KdfParams
    auth_secret: str
    public_keys: PublicKeys
    wrapped_priv_password: str
    wrapped_priv_recovery: str


class SignupResponse(BaseModel):
    user_id: int
    confirmation_required: bool = True


class LoginChallengeResponse(BaseModel):
    kdf_salt: str
    kdf_params: KdfParams


def _decode_b64(value: str, *, field: str, expected_len: int | None = None) -> bytes:
    try:
        raw = b64url_decode(value)
    except Exception:
        raise HTTPException(status_code=400, detail=f"{field}: invalid base64url")
    if expected_len is not None and len(raw) != expected_len:
        raise HTTPException(
            status_code=400,
            detail=f"{field}: expected {expected_len} bytes, got {len(raw)}",
        )
    return raw


@router.post("/signup", response_model=SignupResponse)
async def signup(
    body: SignupRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> SignupResponse:
    email = normalize_email(body.email)

    existing = await session.scalar(select(User).where(User.email == email))
    if existing is not None:
        raise HTTPException(status_code=409, detail="email already registered")

    kdf_salt = _decode_b64(body.kdf_salt, field="kdf_salt", expected_len=16)
    recovery_salt = _decode_b64(body.recovery_salt, field="recovery_salt", expected_len=16)
    auth_secret = _decode_b64(body.auth_secret, field="auth_secret", expected_len=32)
    pub_x25519 = _decode_b64(body.public_keys.x25519, field="public_keys.x25519", expected_len=32)
    pub_mlkem = _decode_b64(body.public_keys.ml_kem_768, field="public_keys.ml_kem_768", expected_len=1184)
    pub_ed25519 = _decode_b64(body.public_keys.ed25519, field="public_keys.ed25519", expected_len=32)
    pub_mldsa = _decode_b64(body.public_keys.ml_dsa_65, field="public_keys.ml_dsa_65", expected_len=1952)
    wrapped_pwd = _decode_b64(body.wrapped_priv_password, field="wrapped_priv_password")
    wrapped_rec = _decode_b64(body.wrapped_priv_recovery, field="wrapped_priv_recovery")

    user = User(
        email=email,
        password_hash=hash_auth_secret(auth_secret),
        confirmed=False,
        pub_x25519=pub_x25519,
        pub_mlkem768=pub_mlkem,
        pub_ed25519=pub_ed25519,
        pub_mldsa65=pub_mldsa,
        kdf_salt=kdf_salt,
        recovery_salt=recovery_salt,
        kdf_params=json.dumps(body.kdf_params.model_dump()),
        wrapped_priv_password=wrapped_pwd,
        wrapped_priv_recovery=wrapped_rec,
    )
    session.add(user)
    await session.flush()

    token = random_token(32)
    challenge = EmailChallenge(
        user_id=user.id,
        token=token,
        purpose="signup",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    session.add(challenge)
    await session.commit()

    confirm_url = f"{settings.base_url}/confirm?token={token}"
    body_text = (
        f"Welcome to pq-share.\n\n"
        f"Please confirm your email by visiting:\n{confirm_url}\n\n"
        f"This link expires in 24 hours.\n\n"
        f"If you did not request an account, you can ignore this email.\n"
    )
    try:
        send_email(to=email, subject="Confirm your pq-share account", body=body_text)
    except Exception as exc:
        log.error("failed to send confirm email user_id=%s err=%s", user.id, exc)

    return SignupResponse(user_id=user.id)


class ConfirmResponse(BaseModel):
    ok: bool
    email: str | None = None


@router.get("/confirm", response_model=ConfirmResponse)
async def confirm_email(token: str, session: AsyncSession = Depends(get_session)) -> ConfirmResponse:
    chal = await session.scalar(select(EmailChallenge).where(EmailChallenge.token == token))
    if chal is None or chal.used:
        raise HTTPException(status_code=400, detail="invalid or used token")
    if chal.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="token expired")
    if chal.purpose != "signup":
        raise HTTPException(status_code=400, detail="wrong token purpose")

    user = await session.get(User, chal.user_id)
    if user is None:
        raise HTTPException(status_code=400, detail="user not found")

    user.confirmed = True
    chal.used = True
    await session.commit()
    return ConfirmResponse(ok=True, email=user.email)


@router.get("/login-challenge", response_model=LoginChallengeResponse)
async def login_challenge(
    email: str, session: AsyncSession = Depends(get_session)
) -> LoginChallengeResponse:
    """Return the per-user KDF salt and params so the browser can derive auth_secret.

    For unknown emails, return a stable HMAC-derived salt to prevent enumeration.
    """
    norm = normalize_email(email)
    user = await session.scalar(select(User).where(User.email == norm))
    if user is not None and user.kdf_salt is not None and user.kdf_params is not None:
        return LoginChallengeResponse(
            kdf_salt=b64url(user.kdf_salt),
            kdf_params=KdfParams(**json.loads(user.kdf_params)),
        )

    return LoginChallengeResponse(
        kdf_salt=b64url(deterministic_salt_for_unknown(norm)),
        kdf_params=KdfParams(m=64 * 1024, t=3, p=1),
    )


class LoginRequest(BaseModel):
    email: EmailStr
    auth_secret: str


class LoginResponse(BaseModel):
    user_id: int
    email: str
    public_keys: PublicKeys
    wrapped_priv_password: str


@router.post("/login", response_model=LoginResponse)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_session),
) -> LoginResponse:
    email = normalize_email(body.email)
    user = await db.scalar(select(User).where(User.email == email))

    auth_secret_bytes = _decode_b64(body.auth_secret, field="auth_secret", expected_len=32)

    if user is None or not verify_auth_secret(user.password_hash, auth_secret_bytes):
        raise HTTPException(status_code=401, detail="invalid credentials")
    if not user.confirmed:
        raise HTTPException(status_code=403, detail="email not confirmed; check your inbox")

    sid = await create_session(db, user.id)
    await db.commit()

    response.set_cookie(
        SESSION_COOKIE,
        sid,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        max_age=settings.session_ttl_hours * 3600,
        path="/",
    )

    return LoginResponse(
        user_id=user.id,
        email=user.email,
        public_keys=PublicKeys(
            x25519=b64url(user.pub_x25519),
            ml_kem_768=b64url(user.pub_mlkem768),
            ed25519=b64url(user.pub_ed25519),
            ml_dsa_65=b64url(user.pub_mldsa65),
        ),
        wrapped_priv_password=b64url(user.wrapped_priv_password),
    )


class MeResponse(BaseModel):
    user_id: int
    email: str
    confirmed: bool
    public_keys: PublicKeys


@router.get("/me", response_model=MeResponse)
async def me(user: User = Depends(current_user)) -> MeResponse:
    return MeResponse(
        user_id=user.id,
        email=user.email,
        confirmed=user.confirmed,
        public_keys=PublicKeys(
            x25519=b64url(user.pub_x25519),
            ml_kem_768=b64url(user.pub_mlkem768),
            ed25519=b64url(user.pub_ed25519),
            ml_dsa_65=b64url(user.pub_mldsa65),
        ),
    )


@router.post("/logout")
async def logout(
    response: Response,
    db: AsyncSession = Depends(get_session),
    pq_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> dict[str, bool]:
    if pq_session:
        await revoke_session(db, pq_session)
        await db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}
