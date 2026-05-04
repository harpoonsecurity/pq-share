import { postJson, getJson } from "/static/api.js";
import {
  DEFAULT_KDF_PARAMS,
  aesGcmOpen,
  aesGcmSeal,
  b64url,
  b64urlDecode,
  buildSigningTranscript,
  bytesToRecoveryCode,
  deriveMaster,
  deriveSubKey,
  dualSign,
  dualVerify,
  generateKeypairs,
  generateRecoveryCodeBytes,
  hybridDecapsulate,
  hybridEncapsulate,
  openFileKey,
  packPrivateBundle,
  randomFileKey,
  sealFileKey,
  unpackPrivateBundle,
} from "/static/crypto.js";

// ---------- App state (in-memory, lost on reload) ----------

const appState = {
  user: null,            // { id, email }
  publicKeys: null,      // { x25519, ml_kem_768, ed25519, ml_dsa_65 } as Uint8Array
  privateKeys: null,     // { x25519Priv, ed25519Priv, mlkemPriv, mldsaPriv } as Uint8Array
};

const SS = {
  EMAIL: "pqshare:email",
  WRAPPED_BLOB: "pqshare:wrappedPriv",
  RECOVERY_CODE: "pqshare:lastRecoveryCode",
  RECOVERY_EMAIL: "pqshare:lastRecoveryEmail",
};

// ---------- Router ----------

const VIEWS = ["home", "signup", "recovery", "confirm", "login", "unlock", "dashboard", "send", "inbox", "sent"];

function show(view) {
  for (const v of VIEWS) {
    document.getElementById(`view-${v}`).classList.toggle("hidden", v !== view);
  }
}

async function route() {
  const hash = location.hash.replace(/^#/, "") || "/";
  if (hash.startsWith("/signup")) return show("signup");
  if (hash.startsWith("/login")) return show("login");
  if (hash.startsWith("/recovery")) return show("recovery");

  // The remaining routes need an unlocked session.
  if (!appState.privateKeys) {
    await maybeAutoUnlockOrHome();
    return;
  }
  if (hash.startsWith("/send")) return renderSend();
  if (hash.startsWith("/inbox")) return renderInbox();
  if (hash.startsWith("/sent")) return renderSent();
  return renderDashboard();
}

window.addEventListener("hashchange", route);

async function maybeAutoUnlockOrHome() {
  // If we have a session cookie, /me returns 200 and we can hydrate.
  try {
    const me = await getJson("/api/auth/me");
    appState.user = { id: me.user_id, email: me.email };
    appState.publicKeys = decodePublicKeys(me.public_keys);
    if (sessionStorage.getItem(SS.WRAPPED_BLOB)) {
      sessionStorage.setItem(SS.EMAIL, me.email);
      return show("unlock");
    }
    // Logged in on server but no wrapped blob in this tab → can't unwrap, force re-login.
    return show("login");
  } catch (err) {
    // 401 expected when not logged in — fall through to home.
    show("home");
  }
}

function decodePublicKeys(pks) {
  return {
    x25519: b64urlDecode(pks.x25519),
    ml_kem_768: b64urlDecode(pks.ml_kem_768),
    ed25519: b64urlDecode(pks.ed25519),
    ml_dsa_65: b64urlDecode(pks.ml_dsa_65),
  };
}

// ---------- Email confirm flow (?token=...) ----------

async function maybeHandleConfirm() {
  const url = new URL(location.href);
  if (url.pathname !== "/confirm") return false;
  show("confirm");
  const status = document.getElementById("confirm-status");
  const token = url.searchParams.get("token");
  if (!token) {
    status.textContent = "Missing token.";
    status.className = "error";
    return true;
  }
  try {
    const res = await getJson(`/api/auth/confirm?token=${encodeURIComponent(token)}`);
    status.textContent = `Email ${res.email} confirmed. You can now log in.`;
    const a = document.createElement("a");
    a.href = "#/login";
    a.textContent = "Continue to log in →";
    a.style.display = "inline-block";
    a.style.marginTop = "0.75rem";
    status.parentElement.appendChild(a);
  } catch (err) {
    status.textContent = `Confirmation failed: ${err.message}`;
    status.className = "error";
  }
  return true;
}

// ---------- Progress helpers ----------

function makeProgress(containerId) {
  const container = document.getElementById(containerId);
  container.classList.remove("hidden");
  container.innerHTML = "";
  return {
    step(label) {
      const el = document.createElement("span");
      el.className = "step active";
      el.textContent = label;
      container.appendChild(el);
      return () => { el.classList.remove("active"); el.classList.add("done"); };
    },
    error(msg) {
      const el = document.createElement("div");
      el.className = "error";
      el.textContent = msg;
      container.appendChild(el);
    },
    reset() { container.innerHTML = ""; container.classList.add("hidden"); },
  };
}

// ---------- Signup ----------

document.getElementById("signup-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const email = form.email.value.trim().toLowerCase();
  const password = form.password.value;
  const password2 = form.password2.value;
  if (password !== password2) { alert("Passwords do not match"); return; }

  const submitBtn = form.querySelector("button[type=submit]");
  submitBtn.disabled = true;
  const p = makeProgress("signup-progress");

  try {
    const kdfSalt = crypto.getRandomValues(new Uint8Array(16));
    const recoverySalt = crypto.getRandomValues(new Uint8Array(16));
    const recoveryBytes = generateRecoveryCodeBytes(24);
    const recoveryCode = bytesToRecoveryCode(recoveryBytes);

    let done = p.step("Deriving password key (Argon2id)…");
    const master = await deriveMaster(password, kdfSalt, DEFAULT_KDF_PARAMS);
    const wrapKey = deriveSubKey(master, "pqshare:wrap-v1");
    const authSecret = deriveSubKey(master, "pqshare:auth-v1");
    done();

    done = p.step("Deriving recovery key (Argon2id)…");
    const recoveryMaster = await deriveMaster(
      bytesToHexString(recoveryBytes), recoverySalt, DEFAULT_KDF_PARAMS
    );
    const recoveryKey = deriveSubKey(recoveryMaster, "pqshare:recovery-v1");
    done();

    done = p.step("Generating keypairs (X25519, Ed25519, ML-KEM-768, ML-DSA-65)…");
    const keys = generateKeypairs();
    done();

    done = p.step("Wrapping private keys…");
    const bundle = packPrivateBundle(keys);
    const wrappedPwd = await aesGcmSeal(wrapKey, bundle);
    const wrappedRec = await aesGcmSeal(recoveryKey, bundle);
    done();

    done = p.step("Uploading to server…");
    await postJson("/api/auth/signup", {
      email,
      kdf_salt: b64url(kdfSalt),
      recovery_salt: b64url(recoverySalt),
      kdf_params: DEFAULT_KDF_PARAMS,
      auth_secret: b64url(authSecret),
      public_keys: {
        x25519: b64url(keys.classical.x25519.pub),
        ml_kem_768: b64url(keys.pq.ml_kem_768.pub),
        ed25519: b64url(keys.classical.ed25519.pub),
        ml_dsa_65: b64url(keys.pq.ml_dsa_65.pub),
      },
      wrapped_priv_password: b64url(wrappedPwd),
      wrapped_priv_recovery: b64url(wrappedRec),
    });
    done();

    document.getElementById("recovery-code").textContent = recoveryCode;
    sessionStorage.setItem(SS.RECOVERY_CODE, recoveryCode);
    sessionStorage.setItem(SS.RECOVERY_EMAIL, email);
    location.hash = "#/recovery";
  } catch (err) {
    p.error(`Error: ${err.message}`);
  } finally {
    submitBtn.disabled = false;
  }
});

// Recovery view: download button.
document.getElementById("download-recovery").addEventListener("click", () => {
  const code = document.getElementById("recovery-code").textContent;
  const email = sessionStorage.getItem(SS.RECOVERY_EMAIL) || "";
  const blob = new Blob(
    [
      `pq-share recovery code\n`,
      `account: ${email}\n`,
      `generated: ${new Date().toISOString()}\n\n`,
      `${code}\n\n`,
      `Keep this code somewhere safe. If you lose your password, this is the only way\n`,
      `to recover access to files that have been shared with you.\n`,
    ],
    { type: "text/plain" }
  );
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `pqshare-recovery-${email || "account"}.txt`;
  document.body.appendChild(a);
  a.click();
  a.remove();
});

function bytesToHexString(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------- Login ----------

document.getElementById("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const email = form.email.value.trim().toLowerCase();
  const password = form.password.value;
  const submitBtn = form.querySelector("button[type=submit]");
  submitBtn.disabled = true;
  const p = makeProgress("login-progress");

  try {
    let done = p.step("Fetching login challenge…");
    const chal = await getJson(`/api/auth/login-challenge?email=${encodeURIComponent(email)}`);
    const kdfSalt = b64urlDecode(chal.kdf_salt);
    done();

    done = p.step("Deriving keys (Argon2id)…");
    const master = await deriveMaster(password, kdfSalt, chal.kdf_params);
    const wrapKey = deriveSubKey(master, "pqshare:wrap-v1");
    const authSecret = deriveSubKey(master, "pqshare:auth-v1");
    done();

    done = p.step("Authenticating…");
    const resp = await postJson("/api/auth/login", {
      email,
      auth_secret: b64url(authSecret),
    });
    done();

    done = p.step("Unwrapping private keys…");
    const wrappedBlob = b64urlDecode(resp.wrapped_priv_password);
    let bundle;
    try {
      bundle = await aesGcmOpen(wrapKey, wrappedBlob);
    } catch (e) {
      throw new Error("Could not decrypt private keys — wrong password?");
    }
    const priv = unpackPrivateBundle(bundle);
    done();

    appState.user = { id: resp.user_id, email: resp.email };
    appState.publicKeys = decodePublicKeys(resp.public_keys);
    appState.privateKeys = priv;

    sessionStorage.setItem(SS.EMAIL, resp.email);
    sessionStorage.setItem(SS.WRAPPED_BLOB, resp.wrapped_priv_password);

    p.reset();
    form.reset();
    location.hash = "#/";
    renderDashboard();
  } catch (err) {
    p.error(`Login failed: ${err.message}`);
  } finally {
    submitBtn.disabled = false;
  }
});

// ---------- Unlock (re-derive private keys after a reload) ----------

document.getElementById("unlock-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = event.currentTarget.password.value;
  const submitBtn = event.currentTarget.querySelector("button[type=submit]");
  submitBtn.disabled = true;
  const p = makeProgress("unlock-progress");

  try {
    const email = sessionStorage.getItem(SS.EMAIL);
    const wrappedB64 = sessionStorage.getItem(SS.WRAPPED_BLOB);
    if (!email || !wrappedB64) throw new Error("Missing session data — please log in again.");

    let done = p.step("Fetching login challenge…");
    const chal = await getJson(`/api/auth/login-challenge?email=${encodeURIComponent(email)}`);
    const kdfSalt = b64urlDecode(chal.kdf_salt);
    done();

    done = p.step("Deriving wrap key (Argon2id)…");
    const master = await deriveMaster(password, kdfSalt, chal.kdf_params);
    const wrapKey = deriveSubKey(master, "pqshare:wrap-v1");
    done();

    done = p.step("Unwrapping private keys…");
    let bundle;
    try {
      bundle = await aesGcmOpen(wrapKey, b64urlDecode(wrappedB64));
    } catch (e) {
      throw new Error("Could not decrypt private keys — wrong password?");
    }
    appState.privateKeys = unpackPrivateBundle(bundle);
    done();

    p.reset();
    event.currentTarget.reset();
    renderDashboard();
  } catch (err) {
    p.error(`Unlock failed: ${err.message}`);
  } finally {
    submitBtn.disabled = false;
  }
});

document.getElementById("unlock-cancel").addEventListener("click", async () => {
  await doLogout();
});

// ---------- Dashboard ----------

async function fingerprint(bytes) {
  const h = await crypto.subtle.digest("SHA-256", bytes);
  const arr = new Uint8Array(h);
  return Array.from(arr.subarray(0, 8), (b) => b.toString(16).padStart(2, "0")).join(":");
}

async function renderDashboard() {
  show("dashboard");
  document.getElementById("dash-email").textContent = appState.user.email;
  const tbody = document.querySelector("#dash-fingerprints tbody");
  tbody.innerHTML = "";
  const rows = [
    ["Ed25519 (sig)", appState.publicKeys.ed25519],
    ["ML-DSA-65 (sig)", appState.publicKeys.ml_dsa_65],
    ["X25519 (kem)", appState.publicKeys.x25519],
    ["ML-KEM-768 (kem)", appState.publicKeys.ml_kem_768],
  ];
  for (const [label, bytes] of rows) {
    const tr = document.createElement("tr");
    const fp = await fingerprint(bytes);
    tr.innerHTML = `<th>${label}</th><td>${fp}</td>`;
    tbody.appendChild(tr);
  }
}

document.getElementById("logout-btn").addEventListener("click", () => doLogout());

async function doLogout() {
  try {
    await postJson("/api/auth/logout", {});
  } catch (_) { /* ignore */ }
  sessionStorage.removeItem(SS.WRAPPED_BLOB);
  sessionStorage.removeItem(SS.EMAIL);
  appState.user = null;
  appState.publicKeys = null;
  appState.privateKeys = null;
  location.hash = "#/";
  show("home");
}

// ---------- Send a file ----------

function parseRecipients(raw) {
  return Array.from(new Set(
    raw
      .split(/[\s,;]+/)
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  ));
}

function decodeRecipientPubs(pubs) {
  return {
    x25519: b64urlDecode(pubs.x25519),
    ml_kem_768: b64urlDecode(pubs.ml_kem_768),
    ed25519: b64urlDecode(pubs.ed25519),
    ml_dsa_65: b64urlDecode(pubs.ml_dsa_65),
  };
}

function renderSend() {
  show("send");
  document.getElementById("send-form").reset();
  document.getElementById("send-progress").classList.add("hidden");
}

document.getElementById("send-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!appState.privateKeys) { alert("Locked — please unlock first."); return; }
  const form = event.currentTarget;
  const fileInput = form.file;
  const file = fileInput.files[0];
  if (!file) return;
  const emails = parseRecipients(form.recipients.value);
  if (emails.length === 0) { alert("Add at least one recipient email."); return; }

  const submitBtn = form.querySelector("button[type=submit]");
  submitBtn.disabled = true;
  const p = makeProgress("send-progress");

  try {
    let done = p.step(`Looking up ${emails.length} recipient${emails.length === 1 ? "" : "s"}…`);
    const recipients = [];
    for (const email of emails) {
      try {
        const r = await getJson(`/api/users/lookup?email=${encodeURIComponent(email)}`);
        recipients.push({ email: r.email, pubs: decodeRecipientPubs(r.public_keys) });
      } catch (e) {
        throw new Error(`recipient ${email}: ${e.message}`);
      }
    }
    done();

    done = p.step(`Encrypting (${file.size.toLocaleString()} bytes)…`);
    const fileBytes = new Uint8Array(await file.arrayBuffer());
    const fileKey = randomFileKey();
    const ciphertext = await aesGcmSeal(fileKey, fileBytes);
    const filenameEnc = await aesGcmSeal(fileKey, new TextEncoder().encode(file.name));
    done();

    done = p.step("Signing (Ed25519 + ML-DSA-65)…");
    const metadata = {
      v: 1,
      mime: file.type || "application/octet-stream",
      plain_size: fileBytes.length,
      created: new Date().toISOString(),
    };
    const metadataJson = JSON.stringify(metadata);
    const transcript = await buildSigningTranscript(ciphertext, metadataJson);
    const sigs = dualSign(transcript, appState.privateKeys.ed25519Priv, appState.privateKeys.mldsaPriv);
    done();

    done = p.step(`Wrapping file key for ${recipients.length} recipient${recipients.length === 1 ? "" : "s"} (X25519 + ML-KEM-768)…`);
    const wrapped = [];
    for (const r of recipients) {
      const { ephemeralX25519Pub, kemCiphertext, wrapKey } = hybridEncapsulate(r.pubs);
      const wrappedKey = await sealFileKey(wrapKey, fileKey);
      wrapped.push({
        email: r.email,
        ephemeral_x25519_pub: b64url(ephemeralX25519Pub),
        kem_ciphertext: b64url(kemCiphertext),
        wrapped_key: b64url(wrappedKey),
      });
    }
    done();

    done = p.step("Uploading…");
    const meta = {
      filename_enc: b64url(filenameEnc),
      metadata_json: metadataJson,
      sig_ed25519: b64url(sigs.ed),
      sig_mldsa65: b64url(sigs.mldsa),
      recipients: wrapped,
    };
    const fd = new FormData();
    fd.append("blob", new Blob([ciphertext], { type: "application/octet-stream" }), "blob");
    fd.append("meta", JSON.stringify(meta));
    const res = await fetch("/api/files", { method: "POST", body: fd, credentials: "same-origin" });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(text || res.statusText);
    }
    const result = await res.json();
    done();

    p.step(`Sent. file_id=${result.file_id.slice(0, 16)}…`);
    setTimeout(() => { location.hash = "#/sent"; }, 800);
  } catch (err) {
    p.error(`Send failed: ${err.message}`);
  } finally {
    submitBtn.disabled = false;
  }
});

// ---------- Inbox ----------

function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MiB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GiB`;
}

function fmtDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString();
}

async function decryptFilenameFromMeta(meta) {
  const wrapKey = hybridDecapsulate({
    ephemeralX25519Pub: b64urlDecode(meta.ephemeral_x25519_pub),
    kemCiphertext: b64urlDecode(meta.kem_ciphertext),
    recipientPrivs: appState.privateKeys,
    recipientPubs: appState.publicKeys,
  });
  const fileKey = await openFileKey(wrapKey, b64urlDecode(meta.wrapped_key));
  const filenameBytes = await openFileKey(fileKey, b64urlDecode(meta.filename_enc));
  return { filename: new TextDecoder().decode(filenameBytes), fileKey, wrapKey };
}

async function renderInbox() {
  show("inbox");
  const tbody = document.querySelector("#inbox-table tbody");
  tbody.innerHTML = "";
  document.getElementById("inbox-empty").classList.add("hidden");

  let items;
  try {
    items = await getJson("/api/files/inbox");
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="5" class="error">${e.message}</td></tr>`;
    return;
  }

  if (items.length === 0) {
    document.getElementById("inbox-empty").classList.remove("hidden");
    return;
  }

  for (const it of items) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${it.sender_email}</td>
      <td class="filename">decrypting…</td>
      <td>${fmtBytes(it.ciphertext_size)}</td>
      <td>${fmtDate(it.created_at)}</td>
      <td><button class="dl">Download</button></td>
    `;
    tbody.appendChild(tr);
    const filenameCell = tr.querySelector(".filename");
    const dlBtn = tr.querySelector("button.dl");

    let cachedMeta = null;
    let cachedFilename = null;

    (async () => {
      try {
        const meta = await getJson(`/api/files/${it.file_id}/meta`);
        cachedMeta = meta;
        const { filename } = await decryptFilenameFromMeta(meta);
        cachedFilename = filename;
        filenameCell.textContent = filename;
      } catch (e) {
        filenameCell.textContent = `(decrypt error: ${e.message})`;
        filenameCell.classList.add("error");
      }
    })();

    dlBtn.addEventListener("click", async () => {
      dlBtn.disabled = true;
      try {
        await downloadFile(it.file_id, cachedMeta, cachedFilename);
        // Refresh status via re-render
        await renderInbox();
      } catch (e) {
        alert(`Download failed: ${e.message}`);
        dlBtn.disabled = false;
      }
    });
  }
}

async function downloadFile(fileId, knownMeta, knownFilename) {
  const meta = knownMeta || await getJson(`/api/files/${fileId}/meta`);
  const senderPubs = decodeRecipientPubs(meta.sender_public_keys);

  const blobRes = await fetch(`/api/files/${fileId}/blob`, { credentials: "same-origin" });
  if (!blobRes.ok) throw new Error(`blob ${blobRes.status}`);
  const ciphertext = new Uint8Array(await blobRes.arrayBuffer());

  const transcript = await buildSigningTranscript(ciphertext, meta.metadata_json);
  const sigs = { ed: b64urlDecode(meta.sig_ed25519), mldsa: b64urlDecode(meta.sig_mldsa65) };
  const ok = dualVerify(transcript, sigs, senderPubs.ed25519, senderPubs.ml_dsa_65);
  if (!ok) throw new Error("signature verification failed — refusing to decrypt");

  const wrapKey = hybridDecapsulate({
    ephemeralX25519Pub: b64urlDecode(meta.ephemeral_x25519_pub),
    kemCiphertext: b64urlDecode(meta.kem_ciphertext),
    recipientPrivs: appState.privateKeys,
    recipientPubs: appState.publicKeys,
  });
  const fileKey = await openFileKey(wrapKey, b64urlDecode(meta.wrapped_key));
  const plaintext = await openFileKey(fileKey, ciphertext);
  const filename = knownFilename || new TextDecoder().decode(
    await openFileKey(fileKey, b64urlDecode(meta.filename_enc))
  );

  const blob = new Blob([plaintext], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);

  await postJson(`/api/files/${fileId}/downloaded`, {});
}

// ---------- Sent ----------

async function renderSent() {
  show("sent");
  const tbody = document.querySelector("#sent-table tbody");
  tbody.innerHTML = "";
  document.getElementById("sent-empty").classList.add("hidden");

  let items;
  try {
    items = await getJson("/api/files/sent");
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="3" class="error">${e.message}</td></tr>`;
    return;
  }

  if (items.length === 0) {
    document.getElementById("sent-empty").classList.remove("hidden");
    return;
  }

  for (const it of items) {
    const tr = document.createElement("tr");
    const recipientList = it.recipients
      .map((r) => `${r.email}${r.downloaded_at ? " ✓" : ""}`)
      .join(", ");
    tr.innerHTML = `
      <td>${fmtDate(it.created_at)}</td>
      <td>${fmtBytes(it.ciphertext_size)}</td>
      <td>${recipientList}</td>
    `;
    tbody.appendChild(tr);
  }
}

// ---------- Boot ----------

(async () => {
  if (await maybeHandleConfirm()) return;
  await route();
})();
