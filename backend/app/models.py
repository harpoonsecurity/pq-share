from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, LargeBinary, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    pub_x25519: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    pub_mlkem768: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    pub_ed25519: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    pub_mldsa65: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # Phase 3b additions: keypair set for NIST 800-52 R2 / PQC-only / CNSA 2.0 suites.
    pub_secp384r1: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    pub_ecdsap384: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    pub_mlkem1024: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    pub_mldsa87: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    kdf_salt: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    recovery_salt: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    kdf_params: Mapped[str | None] = mapped_column(Text, nullable=True)

    # The encrypted private-key bundle. Named "blob" not "password" because
    # this column holds AEAD ciphertext, not the password itself — a CodeQL
    # heuristic flagged the older name `wrapped_priv_password` as a clear-text
    # password storage smell despite the value being already-encrypted.
    wrapped_priv_blob: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    wrapped_priv_recovery: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # AES-GCM(wrapKey, recoveryKey). Lets the client re-wrap the recovery
    # bundle on subsequent logins without ever asking for the recovery code
    # again. Nullable: legacy accounts predate this column.
    wrapped_recovery_key: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)


class EmailChallenge(Base):
    __tablename__ = "email_challenges"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    purpose: Mapped[str] = mapped_column(String(32))
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)


class File(Base):
    __tablename__ = "files"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    blob_path: Mapped[str] = mapped_column(String(512))
    filename_enc: Mapped[bytes] = mapped_column(LargeBinary)
    size_ciphertext: Mapped[int] = mapped_column(Integer)
    metadata_json: Mapped[str] = mapped_column(Text)
    sig_ed25519: Mapped[bytes] = mapped_column(LargeBinary)
    sig_mldsa65: Mapped[bytes] = mapped_column(LargeBinary)
    suite_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class FileRecipient(Base):
    __tablename__ = "file_recipients"

    id: Mapped[int] = mapped_column(primary_key=True)
    file_id: Mapped[str] = mapped_column(ForeignKey("files.id"), index=True)
    recipient_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    ephemeral_x25519_pub: Mapped[bytes] = mapped_column(LargeBinary)
    kem_ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    wrapped_key: Mapped[bytes] = mapped_column(LargeBinary)
    notified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    downloaded_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Group(Base):
    __tablename__ = "groups"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class GroupMember(Base):
    __tablename__ = "group_members"

    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
