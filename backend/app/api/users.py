from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..models import User
from ..security import b64url, normalize_email
from .auth import PublicKeys, _public_keys_for, current_user


router = APIRouter(prefix="/api/users", tags=["users"])


class UserLookupResponse(BaseModel):
    user_id: int
    email: str
    public_keys: PublicKeys


@router.get("/lookup", response_model=UserLookupResponse)
async def lookup(
    email: EmailStr,
    _me: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> UserLookupResponse:
    norm = normalize_email(email)
    user = await db.scalar(select(User).where(User.email == norm))
    if user is None or not user.confirmed:
        raise HTTPException(status_code=404, detail="no such confirmed user")
    return UserLookupResponse(
        user_id=user.id,
        email=user.email,
        public_keys=_public_keys_for(user),
    )
