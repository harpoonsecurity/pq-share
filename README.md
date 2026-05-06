# pq-share

End-to-end encrypted file sharing where every send picks its own cipher
suite. Classical curves, hybrid post-quantum, pure ML-KEM, CNSA 2.0 — all
of it, live, in the same browser tab.

- **Live demo:** <https://pq-share.theqissilent.app/>
- **User guide:** <https://theqissilent.app/guides/pq-share.html>
- **Project home:** <https://theqissilent.app/>

## What it is

pq-share is a browser-based file-sharing application. You sign up with an
email and a password; the browser generates eight long-term keypairs
locally; from then on, every file you send is end-to-end encrypted to the
recipient under whatever cipher suite you choose for that send.

Most "PQ-ready" demos pin one specific algorithm choice. pq-share lets
you pick a different combination per send, then shows you what changes:
the byte sizes on the wire, which primitives are exercised, where in the
modern cryptographic landscape your choice sits. Send the same file once
under classical X25519 and once under CNSA 2.0 ML-KEM-1024 + ML-DSA-87,
and watch the substance shift.

## Cryptography

Each account carries eight keypairs:

| Use | Algorithm | Tier | Spec |
| --- | --- | --- | --- |
| KEX | X25519 | classical | RFC 7748 |
| KEX | secp384r1 | classical | FIPS 186-5 §6 |
| KEX | ML-KEM-768 | post-quantum | FIPS 203 |
| KEX | ML-KEM-1024 | CNSA 2.0 | FIPS 203 |
| Sig | Ed25519 | classical | RFC 8032 |
| Sig | ECDSA-P384 | classical | FIPS 186-5 |
| Sig | ML-DSA-65 | post-quantum | FIPS 204 |
| Sig | ML-DSA-87 | CNSA 2.0 | FIPS 204 |

Symmetric: AES-128-GCM and AES-256-GCM (WebCrypto). Hash / HKDF: SHA-256,
SHA-384, SHA-512, SHA3-512. Password KDF: Argon2id.

The picker exposes five posture presets: **Custom**, **NIST SP 800-52
R2**, **FIPS 140-3 hybrid**, **PQC-only**, and **CNSA 2.0**. Each preset
locks all five primitive categories to a specific combination; Custom
mode lets you mix freely (within TLS-version constraints).

Implemented in the browser via:

- [`@noble/curves`](https://github.com/paulmillr/noble-curves) — X25519, P-384, Ed25519
- [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) — ML-KEM, ML-DSA
- [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) — SHA-2, SHA-3, HKDF
- [`hash-wasm`](https://github.com/Daninet/hash-wasm) — Argon2id
- Browser-native `SubtleCrypto` for AES-GCM

## Threat model (summary)

The full threat-model section is in the
[user guide](https://theqissilent.app/guides/pq-share.html#threat).
In brief:

**Protected:** file contents, filenames, your private keys, message
authenticity (signed under your long-term keys), per-send forward secrecy
at the KEM layer. The server holds AEAD ciphertext only and could not
decrypt your files if a court asked it to.

**Not protected:** the metadata trail (the server sees who sent to whom,
when, and what suite); the browser itself (anything running JS in the
same origin can exfiltrate keys); long-term password compromise (the
wrapped private bundle is encrypted under a deterministic
password-derived key — no forward secrecy on the bundle).

If you lose **both** your password and your recovery code, your files
are unrecoverable. The recovery code is shown once, at signup. Save it.

## Architecture

```
backend/                                FastAPI + async SQLAlchemy + aiosqlite
  app/
    api/auth.py        signup / login / unlock / key upgrade endpoints
    api/files.py       upload + inbox + sent + meta + blob
    api/users.py       recipient lookup
    suites.py          CryptoSuite Pydantic schema (preset locks, TLS-version validators)
    models.py          SQLAlchemy models (User, File, Session, ...)
    db.py              connection + idempotent ALTER TABLE migrations
    config.py          env-driven settings
    email_send.py      SMTP notifications (STARTTLS)
    security.py        b64url, password hashing, ...

frontend/                               vanilla JS, no build step (esm.sh import map)
  index.html           single SPA entry point with hash routing
  app.js               router, signup/login/unlock, send & decrypt flows
  crypto.js            primitive layer: 8 keypair types, bundle pack/unpack
  suite_ops.js         suite-aware dispatch table (getOps(suite))
  picker.js            cipher picker UI (state, presets, mutual exclusivity, render)
  api.js               fetch helpers
  style.css            shared design tokens + view-suite picker styles

data/                                   per-deployment runtime state (gitignored)
  pqshare.db           SQLite database
  blobs/               encrypted file blobs (one per upload)
```

The crypto layer dispatches on a `CryptoSuite` object that arrives with
each upload's metadata. Storing the suite per file lets recipients
decrypt under whatever combination the sender chose, and makes legacy
uploads (predating the picker) decrypt under a built-in `LEGACY_SUITE`
fallback.

## Build & run

### Prerequisites

- Python 3.12+
- Node not required (no build step for the frontend)

### Backend

```bash
cd backend

# Create venv & install dependencies
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env to set:
#   PQSHARE_BASE_URL          (e.g., http://localhost:8000)
#   PQSHARE_SESSION_SECRET    (long random string)
#   PQSHARE_SMTP_*            (Gmail App Password works)

# Run
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

The application is now available at <http://localhost:8000>. Sign up,
confirm via email, log in, and start sending files.

### Frontend

The frontend is served as static files by FastAPI from the `frontend/`
directory (mounted at `/static`, with `index.html` as the SPA entry).
There is no build step — the import map in `index.html` resolves
`@noble/*` and `hash-wasm` directly from
[esm.sh](https://esm.sh) at runtime.

To iterate on frontend code, edit files under `frontend/` and reload the
browser; FastAPI doesn't cache static files.

### Production deployment notes

- **Reverse proxy** the backend with nginx or similar; terminate TLS at
  the proxy.
- **Set `client_max_body_size`** on the proxy to at least 100 MiB
  (matches the backend's `MAX_BLOB_BYTES`).
- **Persist `data/`** — the SQLite database and blob directory hold all
  user state.
- **Run the service under a dedicated system user** (the live deployment
  uses a `pqshare` system account with `ReadWritePaths=` scoped to
  `data/` only, via systemd's `ProtectSystem=strict`).
- **Service file** (example):
  ```ini
  [Service]
  User=pqshare
  Group=pqshare
  WorkingDirectory=/path/to/pq-share/backend
  EnvironmentFile=/path/to/pq-share/backend/.env
  ExecStart=/path/to/pq-share/backend/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
  Restart=on-failure
  NoNewPrivileges=true
  PrivateTmp=true
  ProtectSystem=strict
  ProtectHome=read-only
  ReadWritePaths=/path/to/pq-share/data
  ```

### Database migrations

`db.py` contains a `_PENDING_COLUMNS` list. On startup, `init_db()`
inspects each declared column and runs a one-shot `ALTER TABLE ... ADD
COLUMN` if it's missing. New nullable columns can be added by appending
to that list — no separate migration tool required.

## Project status

v0.2 — every primitive in the picker except ChaCha20-Poly1305 and
AES-256-GCM-SIV is wired end-to-end. Both of those need a JS lib (they
aren't in WebCrypto). See the
[known limitations](https://theqissilent.app/guides/pq-share.html#limits)
section of the user guide for the rest.

## Acknowledgements

pq-share is part of [the q is silent](https://theqissilent.app/) — a
growing collection of small, working applications that make
cryptography tangible.

## License

The MIT License (MIT)

Copyright (c) 2026 Jim Walker (<https://www.linkedin.com/in/jimwalker80/>)

See [`LICENSE`](LICENSE) file.
