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
    # Phase 3b additions; optional so legacy clients (pre-upgrade) still validate.
    secp384r1:  str | None = None
    ecdsa_p384: str | None = None
    ml_kem_1024: str | None = None
    ml_dsa_87:  str | None = None


# Expected byte lengths for each pubkey field. Used by signup and upgrade.
_PUBKEY_LENS: dict[str, int] = {
    "x25519":      32,
    "ml_kem_768":  1184,
    "ed25519":     32,
    "ml_dsa_65":   1952,
    "secp384r1":   49,    # P-384 compressed
    "ecdsa_p384":  49,    # P-384 compressed (separate keypair from ECDH key)
    "ml_kem_1024": 1568,
    "ml_dsa_87":   2592,
}


class SignupRequest(BaseModel):
    email: EmailStr
    kdf_salt: str
    recovery_salt: str
    kdf_params: KdfParams
    auth_secret: str
    public_keys: PublicKeys
    wrapped_priv_password: str
    wrapped_priv_recovery: str
    # Optional for back-compat with very old clients; new clients always send it
    # so subsequent bundle upgrades can re-wrap the recovery bundle automatically.
    wrapped_recovery_key: str | None = None


class SignupResponse(BaseModel):
    user_id: int
    confirmation_required: bool = True


class LoginChallengeResponse(BaseModel):
    kdf_salt: str
    kdf_params: KdfParams


def _public_keys_for(user: User) -> PublicKeys:
    """Serialize all 8 pubkeys; Phase 3b fields surface as None until upgrade."""
    return PublicKeys(
        x25519=b64url(user.pub_x25519),
        ml_kem_768=b64url(user.pub_mlkem768),
        ed25519=b64url(user.pub_ed25519),
        ml_dsa_65=b64url(user.pub_mldsa65),
        secp384r1=b64url(user.pub_secp384r1) if user.pub_secp384r1 else None,
        ecdsa_p384=b64url(user.pub_ecdsap384) if user.pub_ecdsap384 else None,
        ml_kem_1024=b64url(user.pub_mlkem1024) if user.pub_mlkem1024 else None,
        ml_dsa_87=b64url(user.pub_mldsa87) if user.pub_mldsa87 else None,
    )


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
    pub_x25519     = _decode_b64(body.public_keys.x25519,     field="public_keys.x25519",     expected_len=_PUBKEY_LENS["x25519"])
    pub_mlkem      = _decode_b64(body.public_keys.ml_kem_768, field="public_keys.ml_kem_768", expected_len=_PUBKEY_LENS["ml_kem_768"])
    pub_ed25519    = _decode_b64(body.public_keys.ed25519,    field="public_keys.ed25519",    expected_len=_PUBKEY_LENS["ed25519"])
    pub_mldsa      = _decode_b64(body.public_keys.ml_dsa_65,  field="public_keys.ml_dsa_65",  expected_len=_PUBKEY_LENS["ml_dsa_65"])
    # Phase 3b pubkeys are required for new signups (existing accounts upgrade via /upgrade-keys).
    if not all([body.public_keys.secp384r1, body.public_keys.ecdsa_p384, body.public_keys.ml_kem_1024, body.public_keys.ml_dsa_87]):
        raise HTTPException(status_code=400, detail="public_keys: all 8 algorithms required for new signups")
    pub_secp384r1  = _decode_b64(body.public_keys.secp384r1,   field="public_keys.secp384r1",   expected_len=_PUBKEY_LENS["secp384r1"])
    pub_ecdsap384  = _decode_b64(body.public_keys.ecdsa_p384,  field="public_keys.ecdsa_p384",  expected_len=_PUBKEY_LENS["ecdsa_p384"])
    pub_mlkem1024  = _decode_b64(body.public_keys.ml_kem_1024, field="public_keys.ml_kem_1024", expected_len=_PUBKEY_LENS["ml_kem_1024"])
    pub_mldsa87    = _decode_b64(body.public_keys.ml_dsa_87,   field="public_keys.ml_dsa_87",   expected_len=_PUBKEY_LENS["ml_dsa_87"])
    wrapped_pwd = _decode_b64(body.wrapped_priv_password, field="wrapped_priv_password")
    wrapped_rec = _decode_b64(body.wrapped_priv_recovery, field="wrapped_priv_recovery")
    wrapped_rec_key = (
        _decode_b64(body.wrapped_recovery_key, field="wrapped_recovery_key")
        if body.wrapped_recovery_key else None
    )

    user = User(
        email=email,
        password_hash=hash_auth_secret(auth_secret),
        confirmed=False,
        pub_x25519=pub_x25519,
        pub_mlkem768=pub_mlkem,
        pub_ed25519=pub_ed25519,
        pub_mldsa65=pub_mldsa,
        pub_secp384r1=pub_secp384r1,
        pub_ecdsap384=pub_ecdsap384,
        pub_mlkem1024=pub_mlkem1024,
        pub_mldsa87=pub_mldsa87,
        kdf_salt=kdf_salt,
        recovery_salt=recovery_salt,
        kdf_params=json.dumps(body.kdf_params.model_dump()),
        wrapped_priv_password=wrapped_pwd,
        wrapped_priv_recovery=wrapped_rec,
        wrapped_recovery_key=wrapped_rec_key,
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
    wrapped_recovery_key: str | None = None


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
        public_keys=_public_keys_for(user),
        wrapped_priv_password=b64url(user.wrapped_priv_password),
        wrapped_recovery_key=b64url(user.wrapped_recovery_key) if user.wrapped_recovery_key else None,
    )


class MeResponse(BaseModel):
    user_id: int
    email: str
    confirmed: bool
    public_keys: PublicKeys
    # Surfaced so the client can show the retroactive recovery-rewrap banner
    # to legacy accounts (those without wrapped_recovery_key set).
    wrapped_recovery_key: str | None = None
    recovery_salt: str | None = None
    kdf_params: KdfParams | None = None


@router.get("/me", response_model=MeResponse)
async def me(user: User = Depends(current_user)) -> MeResponse:
    return MeResponse(
        user_id=user.id,
        email=user.email,
        confirmed=user.confirmed,
        public_keys=_public_keys_for(user),
        wrapped_recovery_key=b64url(user.wrapped_recovery_key) if user.wrapped_recovery_key else None,
        recovery_salt=b64url(user.recovery_salt) if user.recovery_salt else None,
        kdf_params=KdfParams(**json.loads(user.kdf_params)) if user.kdf_params else None,
    )


# ---------------------------------------------------------------------------
# Key-set upgrade for existing users (Phase 3b).
#
# Pre-Phase-3b accounts have only the original 4 keypairs (x25519, ml_kem_768,
# ed25519, ml_dsa_65) and a v1 wrapped private bundle. The frontend detects
# this on login, generates the missing 4 keypairs locally, re-packs the
# bundle as v2, re-wraps under the same password & recovery keys, and posts
# here. This call atomically updates the user's pubkeys and both wrapped
# bundles.
# ---------------------------------------------------------------------------

class UpgradeKeysRequest(BaseModel):
    secp384r1:   str
    ecdsa_p384:  str
    ml_kem_1024: str
    ml_dsa_87:   str
    wrapped_priv_password: str
    # If the client has access to the recoveryKey (via the stored
    # wrapped_recovery_key, unwrappable with wrapKey), it should re-wrap the
    # v2 bundle under recoveryKey and send it here. Pre-wrapped_recovery_key
    # accounts will omit this and remain on a v1 recovery bundle until they
    # re-key recovery via /set-recovery-key.
    wrapped_priv_recovery: str | None = None
    # Pre-wrapped_recovery_key accounts can also include this field to
    # establish the wrapped recovery key for the first time.
    wrapped_recovery_key: str | None = None


class UpgradeKeysResponse(BaseModel):
    ok: bool


@router.post("/upgrade-keys", response_model=UpgradeKeysResponse)
async def upgrade_keys(
    body: UpgradeKeysRequest,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> UpgradeKeysResponse:
    if user.pub_secp384r1 is not None:
        raise HTTPException(status_code=409, detail="keys already upgraded")
    user.pub_secp384r1 = _decode_b64(body.secp384r1,   field="secp384r1",   expected_len=_PUBKEY_LENS["secp384r1"])
    user.pub_ecdsap384 = _decode_b64(body.ecdsa_p384,  field="ecdsa_p384",  expected_len=_PUBKEY_LENS["ecdsa_p384"])
    user.pub_mlkem1024 = _decode_b64(body.ml_kem_1024, field="ml_kem_1024", expected_len=_PUBKEY_LENS["ml_kem_1024"])
    user.pub_mldsa87   = _decode_b64(body.ml_dsa_87,   field="ml_dsa_87",   expected_len=_PUBKEY_LENS["ml_dsa_87"])
    user.wrapped_priv_password = _decode_b64(body.wrapped_priv_password, field="wrapped_priv_password")
    if body.wrapped_priv_recovery is not None:
        user.wrapped_priv_recovery = _decode_b64(body.wrapped_priv_recovery, field="wrapped_priv_recovery")
    if body.wrapped_recovery_key is not None:
        user.wrapped_recovery_key = _decode_b64(body.wrapped_recovery_key, field="wrapped_recovery_key")
    await db.commit()
    return UpgradeKeysResponse(ok=True)


# ---------------------------------------------------------------------------
# Retroactive recovery-key wrapping for accounts that signed up before
# wrapped_recovery_key existed. The user re-enters their recovery code on the
# dashboard; the client derives recoveryKey, re-wraps the current bundle under
# it, AND wraps recoveryKey under wrapKey, posting both atomically here.
# ---------------------------------------------------------------------------

class SetRecoveryKeyRequest(BaseModel):
    wrapped_priv_recovery: str   # current bundle, freshly re-wrapped under recoveryKey
    wrapped_recovery_key: str    # recoveryKey itself, wrapped under wrapKey


class SetRecoveryKeyResponse(BaseModel):
    ok: bool


@router.post("/set-recovery-key", response_model=SetRecoveryKeyResponse)
async def set_recovery_key(
    body: SetRecoveryKeyRequest,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> SetRecoveryKeyResponse:
    user.wrapped_priv_recovery = _decode_b64(body.wrapped_priv_recovery, field="wrapped_priv_recovery")
    user.wrapped_recovery_key  = _decode_b64(body.wrapped_recovery_key,  field="wrapped_recovery_key")
    await db.commit()
    return SetRecoveryKeyResponse(ok=True)


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
