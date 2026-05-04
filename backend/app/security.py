import hashlib
import hmac
import secrets
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .models import Session as SessionModel
from .models import User


_hasher = PasswordHasher(time_cost=2, memory_cost=64 * 1024, parallelism=1, hash_len=32)


def hash_auth_secret(auth_secret: bytes) -> str:
    return _hasher.hash(auth_secret)


def verify_auth_secret(stored_hash: str, auth_secret: bytes) -> bool:
    try:
        return _hasher.verify(stored_hash, auth_secret)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


SESSION_COOKIE = "pq_session"


async def create_session(db: AsyncSession, user_id: int) -> str:
    sid = random_token(32)
    db.add(
        SessionModel(
            id=sid,
            user_id=user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=settings.session_ttl_hours),
        )
    )
    await db.flush()
    return sid


async def get_user_from_session_id(db: AsyncSession, sid: str | None) -> User | None:
    if not sid:
        return None
    s = await db.get(SessionModel, sid)
    if s is None:
        return None
    if s.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        return None
    return await db.get(User, s.user_id)


async def revoke_session(db: AsyncSession, sid: str) -> None:
    s = await db.get(SessionModel, sid)
    if s is not None:
        await db.delete(s)


def b64url(b: bytes) -> str:
    return urlsafe_b64encode(b).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return urlsafe_b64decode(s + pad)


def random_token(n: int = 32) -> str:
    return b64url(secrets.token_bytes(n))


def deterministic_salt_for_unknown(email: str) -> bytes:
    """Stable random-looking salt for emails that don't exist; prevents enumeration."""
    pepper = settings.session_secret.encode()
    return hmac.new(pepper, email.lower().encode(), hashlib.sha256).digest()[:16]


def normalize_email(email: str) -> str:
    return email.strip().lower()
