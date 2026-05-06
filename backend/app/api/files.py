import json
import logging
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..db import get_session
from ..email_send import send_email
from ..models import File as FileModel
from ..models import FileRecipient, User
from ..security import b64url, b64url_decode, normalize_email
from ..suites import CryptoSuite
from .auth import PublicKeys, current_user


log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/files", tags=["files"])


MAX_BLOB_BYTES = 100 * 1024 * 1024  # 100 MiB

# (ephemeral_slot_len, kem_ciphertext_slot_len). 0 means the slot must be empty
# under that KEX. The "ephemeral_x25519_pub" wire field is reused for secp384r1
# compressed pubkeys (49 bytes), and "kem_ciphertext" is reused for ML-KEM-1024
# ciphertexts (1568 bytes).
_KEX_LENS: dict[str, tuple[int, int]] = {
    "X25519":          (32, 0),
    "X25519MLKEM768":  (32, 1088),
    "ML-KEM-768":      (0,  1088),
    "secp384r1":       (49, 0),
    "ML-KEM-1024":     (0,  1568),
}
# (sig_ed25519_slot_len, sig_mldsa65_slot_len). The classical-sig slot carries
# either Ed25519 (64B) or ECDSA-P384 raw R||S (96B); the PQ-sig slot carries
# either ML-DSA-65 (3309B) or ML-DSA-87 (4627B).
_SIG_LENS: dict[str, tuple[int, int]] = {
    "Ed25519":           (64, 0),
    "Ed25519+ML-DSA-65": (64, 3309),
    "ML-DSA-65":         (0,  3309),
    "ECDSA-P384":        (96, 0),
    "ML-DSA-87":         (0,  4627),
}

# Legacy default lengths when no suite is supplied.
_LEGACY_KEX_LENS = (32, 1088)        # hybrid X25519+ML-KEM-768
_LEGACY_SIG_LENS = (64, 3309)        # Ed25519+ML-DSA-65


def _decode(value: str, *, field: str, expected_len: int | None = None) -> bytes:
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


def _decode_exact(value: str, field: str, expected_len: int) -> bytes:
    """Decode a field that must be exactly `expected_len` bytes (0 means empty)."""
    raw = _decode(value, field=field)
    if len(raw) != expected_len:
        raise HTTPException(
            status_code=400,
            detail=f"{field}: expected {expected_len} bytes, got {len(raw)}",
        )
    return raw


def _new_file_id() -> str:
    return secrets.token_hex(32)


def _suite_view(suite_json: str | None) -> dict | None:
    """Re-validate stored suite JSON and return it with derived fields, or None."""
    if not suite_json:
        return None
    try:
        return CryptoSuite.model_validate_json(suite_json).with_derived()
    except Exception as exc:
        log.warning("stored suite_json failed re-validation: %s", exc)
        return None


class UploadRecipient(BaseModel):
    email: str
    ephemeral_x25519_pub: str
    kem_ciphertext: str
    wrapped_key: str


class UploadMeta(BaseModel):
    filename_enc: str
    metadata_json: str
    sig_ed25519: str
    sig_mldsa65: str
    recipients: list[UploadRecipient]
    suite: CryptoSuite | None = None


class UploadResponse(BaseModel):
    file_id: str
    recipient_count: int


@router.post("", response_model=UploadResponse)
async def upload(
    blob: UploadFile = File(...),
    meta: str = Form(...),
    sender: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> UploadResponse:
    try:
        meta_obj = UploadMeta.model_validate_json(meta)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"meta: {exc}")
    if not meta_obj.recipients:
        raise HTTPException(status_code=400, detail="recipients: at least one required")

    filename_enc = _decode(meta_obj.filename_enc, field="filename_enc")

    # Determine the exact byte count this suite expects for each wire-format slot.
    # No suite supplied = legacy client = original hybrid+dual lengths.
    if meta_obj.suite is not None:
        eph_len, kem_ct_len = _KEX_LENS.get(meta_obj.suite.kex, _LEGACY_KEX_LENS)
        sig_ed_len, sig_mldsa_len = _SIG_LENS.get(meta_obj.suite.sig, _LEGACY_SIG_LENS)
    else:
        eph_len, kem_ct_len = _LEGACY_KEX_LENS
        sig_ed_len, sig_mldsa_len = _LEGACY_SIG_LENS

    sig_ed = _decode_exact(meta_obj.sig_ed25519, "sig_ed25519", sig_ed_len)
    sig_mldsa = _decode_exact(meta_obj.sig_mldsa65, "sig_mldsa65", sig_mldsa_len)

    resolved: list[tuple[User, UploadRecipient, bytes, bytes, bytes]] = []
    seen_ids: set[int] = set()
    for r in meta_obj.recipients:
        norm = normalize_email(r.email)
        recipient = await db.scalar(select(User).where(User.email == norm))
        if recipient is None or not recipient.confirmed:
            raise HTTPException(status_code=400, detail=f"unknown or unconfirmed recipient: {r.email}")
        if recipient.id in seen_ids:
            raise HTTPException(status_code=400, detail=f"duplicate recipient: {r.email}")
        seen_ids.add(recipient.id)
        eph = _decode_exact(r.ephemeral_x25519_pub, f"recipient[{r.email}].ephemeral_x25519_pub", eph_len)
        kem_ct = _decode_exact(r.kem_ciphertext, f"recipient[{r.email}].kem_ciphertext", kem_ct_len)
        wrapped = _decode(r.wrapped_key, field=f"recipient[{r.email}].wrapped_key")
        resolved.append((recipient, r, eph, kem_ct, wrapped))

    file_id = _new_file_id()
    blob_path = settings.blob_dir / file_id
    written = 0
    chunk_size = 1024 * 1024
    with blob_path.open("wb") as fh:
        while True:
            chunk = await blob.read(chunk_size)
            if not chunk:
                break
            written += len(chunk)
            if written > MAX_BLOB_BYTES:
                fh.close()
                blob_path.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail=f"blob exceeds {MAX_BLOB_BYTES} bytes")
            fh.write(chunk)

    file_row = FileModel(
        id=file_id,
        sender_id=sender.id,
        blob_path=str(blob_path),
        filename_enc=filename_enc,
        size_ciphertext=written,
        metadata_json=meta_obj.metadata_json,
        sig_ed25519=sig_ed,
        sig_mldsa65=sig_mldsa,
        suite_json=meta_obj.suite.model_dump_json() if meta_obj.suite else None,
    )
    db.add(file_row)

    now = datetime.now(timezone.utc)
    for recipient, _, eph, kem_ct, wrapped in resolved:
        db.add(
            FileRecipient(
                file_id=file_id,
                recipient_id=recipient.id,
                ephemeral_x25519_pub=eph,
                kem_ciphertext=kem_ct,
                wrapped_key=wrapped,
                notified_at=now,
            )
        )

    await db.commit()

    inbox_url = f"{settings.base_url}/#/inbox"
    for recipient, _, _, _, _ in resolved:
        body = (
            f"{sender.email} has shared an encrypted file with you on pq-share.\n\n"
            f"Sign in to download it: {inbox_url}\n\n"
            f"Files are end-to-end encrypted; only you can decrypt this with your password.\n"
        )
        try:
            send_email(to=recipient.email, subject=f"{sender.email} sent you a file", body=body)
        except Exception as exc:
            log.error("notify failed file_id=%s recipient=%s err=%s", file_id, recipient.email, exc)

    return UploadResponse(file_id=file_id, recipient_count=len(resolved))


class InboxItem(BaseModel):
    file_id: str
    sender_email: str
    ciphertext_size: int
    created_at: datetime
    downloaded_at: datetime | None
    suite: dict | None = None


@router.get("/inbox", response_model=list[InboxItem])
async def inbox(
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> list[InboxItem]:
    stmt = (
        select(FileModel, FileRecipient, User)
        .join(FileRecipient, FileRecipient.file_id == FileModel.id)
        .join(User, User.id == FileModel.sender_id)
        .where(FileRecipient.recipient_id == user.id)
        .order_by(FileModel.created_at.desc())
    )
    rows = (await db.execute(stmt)).all()
    return [
        InboxItem(
            file_id=f.id,
            sender_email=sender.email,
            ciphertext_size=f.size_ciphertext,
            created_at=f.created_at,
            downloaded_at=fr.downloaded_at,
            suite=_suite_view(f.suite_json),
        )
        for f, fr, sender in rows
    ]


class SentRecipient(BaseModel):
    email: str
    downloaded_at: datetime | None


class SentItem(BaseModel):
    file_id: str
    ciphertext_size: int
    created_at: datetime
    recipients: list[SentRecipient]
    suite: dict | None = None


@router.get("/sent", response_model=list[SentItem])
async def sent(
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> list[SentItem]:
    files = (
        await db.scalars(
            select(FileModel)
            .where(FileModel.sender_id == user.id)
            .order_by(FileModel.created_at.desc())
        )
    ).all()
    out: list[SentItem] = []
    for f in files:
        rows = (
            await db.execute(
                select(FileRecipient, User)
                .join(User, User.id == FileRecipient.recipient_id)
                .where(FileRecipient.file_id == f.id)
            )
        ).all()
        out.append(
            SentItem(
                file_id=f.id,
                ciphertext_size=f.size_ciphertext,
                created_at=f.created_at,
                recipients=[SentRecipient(email=u.email, downloaded_at=fr.downloaded_at) for fr, u in rows],
                suite=_suite_view(f.suite_json),
            )
        )
    return out


class FileMetaResponse(BaseModel):
    file_id: str
    sender_email: str
    sender_public_keys: PublicKeys
    filename_enc: str
    metadata_json: str
    sig_ed25519: str
    sig_mldsa65: str
    ephemeral_x25519_pub: str
    kem_ciphertext: str
    wrapped_key: str
    ciphertext_size: int
    created_at: datetime
    suite: dict | None = None


async def _file_for_recipient(
    file_id: str, user: User, db: AsyncSession
) -> tuple[FileModel, FileRecipient, User]:
    row = (
        await db.execute(
            select(FileModel, FileRecipient, User)
            .join(FileRecipient, FileRecipient.file_id == FileModel.id)
            .join(User, User.id == FileModel.sender_id)
            .where(FileModel.id == file_id, FileRecipient.recipient_id == user.id)
        )
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="not found")
    return row[0], row[1], row[2]


@router.get("/{file_id}/meta", response_model=FileMetaResponse)
async def file_meta(
    file_id: str,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> FileMetaResponse:
    f, fr, sender = await _file_for_recipient(file_id, user, db)
    return FileMetaResponse(
        file_id=f.id,
        sender_email=sender.email,
        sender_public_keys=PublicKeys(
            x25519=b64url(sender.pub_x25519),
            ml_kem_768=b64url(sender.pub_mlkem768),
            ed25519=b64url(sender.pub_ed25519),
            ml_dsa_65=b64url(sender.pub_mldsa65),
        ),
        filename_enc=b64url(f.filename_enc),
        metadata_json=f.metadata_json,
        sig_ed25519=b64url(f.sig_ed25519),
        sig_mldsa65=b64url(f.sig_mldsa65),
        ephemeral_x25519_pub=b64url(fr.ephemeral_x25519_pub),
        kem_ciphertext=b64url(fr.kem_ciphertext),
        wrapped_key=b64url(fr.wrapped_key),
        ciphertext_size=f.size_ciphertext,
        created_at=f.created_at,
        suite=_suite_view(f.suite_json),
    )


@router.get("/{file_id}/blob")
async def file_blob(
    file_id: str,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> FileResponse:
    f = await db.get(FileModel, file_id)
    if f is None:
        raise HTTPException(status_code=404, detail="not found")
    if f.sender_id != user.id:
        fr = (
            await db.execute(
                select(FileRecipient).where(
                    FileRecipient.file_id == file_id,
                    FileRecipient.recipient_id == user.id,
                )
            )
        ).scalar_one_or_none()
        if fr is None:
            raise HTTPException(status_code=404, detail="not found")
    return FileResponse(
        f.blob_path,
        media_type="application/octet-stream",
        filename=f"{file_id}.bin",
    )


@router.post("/{file_id}/downloaded")
async def mark_downloaded(
    file_id: str,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> dict[str, bool]:
    fr = (
        await db.execute(
            select(FileRecipient).where(
                FileRecipient.file_id == file_id,
                FileRecipient.recipient_id == user.id,
            )
        )
    ).scalar_one_or_none()
    if fr is None:
        raise HTTPException(status_code=404, detail="not found")
    fr.downloaded_at = datetime.now(timezone.utc)
    await db.commit()
    return {"ok": True}
