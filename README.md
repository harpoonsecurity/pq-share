# pq-share

Browser-based hybrid post-quantum file-sharing demo.

This repo exists primarily as the **subject under test for a CI/CD pipeline** that demonstrates how SAST tools (Semgrep, CodeQL) detect weak cryptography. The application itself uses hybrid PQ crypto where it matters; the SAST workflows in `.github/workflows/` will scan for and flag any classical-only or otherwise weak primitives that get introduced.

## Crypto stack

- **Key encapsulation:** X25519 + ML-KEM-768 (hybrid)
- **Digital signatures:** Ed25519 + ML-DSA-65 (dual)
- **Symmetric:** AES-256-GCM for file and filename
- **Password-based key derivation:** Argon2id (via hash-wasm)
- **HKDF:** SHA-512 with context binding to all public values

## Stack

- **Backend:** FastAPI + async SQLAlchemy + aiosqlite + pydantic-settings
- **Frontend:** Vanilla JS via `esm.sh` import map (no build step) using `@noble/curves`, `@noble/post-quantum`
- **Email:** smtplib + STARTTLS (Gmail App Password recommended)

## Running locally

1. Copy `backend/.env.example` to `backend/.env` and fill in real SMTP credentials.
2. Create a Python venv and install deps:
   ```
   cd backend
   python3 -m venv .venv
   .venv/bin/pip install -r requirements.txt
   ```
3. Start the server:
   ```
   .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```
4. Open http://localhost:8000.

## Status

- Phase C (auth foundation): done
- Phase A (file sharing): done
- Phase B (PQ-TLS proxy): not started
- Groups, notification refinements: pending
