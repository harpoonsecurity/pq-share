import { postJson, getJson } from "/static/api.js";
import { initPicker, showPicker, getSuite } from "/static/picker.js";
import { getOps, LEGACY_SUITE } from "/static/suite_ops.js";
import {
  DEFAULT_KDF_PARAMS,
  aesGcmOpen,
  aesGcmSeal,
  b64url,
  b64urlDecode,
  buildSigningTranscript,
  bytesToRecoveryCode,
  buildUpgradedBundle,
  deriveMaster,
  deriveSubKey,
  dualSign,
  dualVerify,
  generateExtendedKeypairs,
  generateKeypairs,
  generateRecoveryCodeBytes,
  hybridDecapsulate,
  hybridEncapsulate,
  openFileKey,
  packPrivateBundle,
  randomFileKey,
  recoveryCodeToBytes,
  sealFileKey,
  unpackPrivateBundle,
} from "/static/crypto.js";

// ---------- App state (in-memory, lost on reload) ----------

const appState = {
  user: null,            // { id, email }
  publicKeys: null,      // { x25519, ml_kem_768, ed25519, ml_dsa_65, ...3b... } as Uint8Array
  privateKeys: null,     // { x25519Priv, ed25519Priv, mlkemPriv, mldsaPriv, ...3b... } as Uint8Array
  wrapKey: null,         // 32-byte AES-GCM key derived from password; in-memory only
  meExtras: null,        // { recovery_salt, kdf_params } cached from /me for retroactive recovery setup
};

const SS = {
  EMAIL: "pqshare:email",
  WRAPPED_BLOB: "pqshare:wrappedPriv",
  WRAPPED_RECOVERY_KEY: "pqshare:wrappedRecoveryKey",
  RECOVERY_CODE: "pqshare:lastRecoveryCode",
  RECOVERY_EMAIL: "pqshare:lastRecoveryEmail",
};

// ---------- Router ----------

const VIEWS = ["home", "signup", "recovery", "confirm", "login", "unlock", "dashboard", "send", "suite", "inbox", "sent"];

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
  if (hash.startsWith("/suite")) return renderSuite();
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
    appState.meExtras = { recovery_salt: me.recovery_salt, kdf_params: me.kdf_params };
    if (me.wrapped_recovery_key) {
      sessionStorage.setItem(SS.WRAPPED_RECOVERY_KEY, me.wrapped_recovery_key);
    } else {
      sessionStorage.removeItem(SS.WRAPPED_RECOVERY_KEY);
    }
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
    x25519:      b64urlDecode(pks.x25519),
    ml_kem_768:  b64urlDecode(pks.ml_kem_768),
    ed25519:     b64urlDecode(pks.ed25519),
    ml_dsa_65:   b64urlDecode(pks.ml_dsa_65),
    secp384r1:   pks.secp384r1   ? b64urlDecode(pks.secp384r1)   : null,
    ecdsa_p384:  pks.ecdsa_p384  ? b64urlDecode(pks.ecdsa_p384)  : null,
    ml_kem_1024: pks.ml_kem_1024 ? b64urlDecode(pks.ml_kem_1024) : null,
    ml_dsa_87:   pks.ml_dsa_87   ? b64urlDecode(pks.ml_dsa_87)   : null,
  };
}

/** If the just-unlocked bundle is v1, generate the four Phase 3b keypairs,
 *  re-pack as v2, re-wrap under wrapKey (always) and recoveryKey (if we can
 *  derive it from a stored wrapped_recovery_key), and POST to /upgrade-keys.
 *  Returns the new {priv, pubs, wrappedPwd} or null. */
async function maybeUpgradeKeyset(priv, wrapKey, wrappedRecoveryKeyB64, progress) {
  if (priv.bundleVersion !== 1) return null;
  const done = progress.step("Upgrading keyset (Phase 3b: secp384r1, ECDSA-P384, ML-KEM-1024, ML-DSA-87)…");
  const ext = generateExtendedKeypairs();
  const bundleV2 = buildUpgradedBundle(priv, ext);
  const wrappedPwd = await aesGcmSeal(wrapKey, bundleV2);

  const body = {
    secp384r1:   b64url(ext.secp384r1.pub),
    ecdsa_p384:  b64url(ext.ecdsa_p384.pub),
    ml_kem_1024: b64url(ext.ml_kem_1024.pub),
    ml_dsa_87:   b64url(ext.ml_dsa_87.pub),
    wrapped_priv_blob: b64url(wrappedPwd),
  };
  // If the server has a wrapped_recovery_key for this user, we can unwrap
  // recoveryKey using wrapKey, then re-wrap the v2 bundle under recoveryKey.
  // No recovery code needed.
  if (wrappedRecoveryKeyB64) {
    const recoveryKey = await aesGcmOpen(wrapKey, b64urlDecode(wrappedRecoveryKeyB64));
    const wrappedRecV2 = await aesGcmSeal(recoveryKey, bundleV2);
    body.wrapped_priv_recovery = b64url(wrappedRecV2);
  }
  await postJson("/api/auth/upgrade-keys", body);
  done();

  const newPriv = {
    ...priv,
    bundleVersion: 2,
    secp384r1Priv: ext.secp384r1.priv,
    ecdsap384Priv: ext.ecdsa_p384.priv,
    mlkem1024Priv: ext.ml_kem_1024.priv,
    mldsa87Priv:   ext.ml_dsa_87.priv,
  };
  return { priv: newPriv, pubs: {
    secp384r1:   ext.secp384r1.pub,
    ecdsa_p384:  ext.ecdsa_p384.pub,
    ml_kem_1024: ext.ml_kem_1024.pub,
    ml_dsa_87:   ext.ml_dsa_87.pub,
  }, wrappedPwd };
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

    done = p.step("Generating 8 keypairs (X25519, secp384r1, ML-KEM-768, ML-KEM-1024, Ed25519, ECDSA-P384, ML-DSA-65, ML-DSA-87)…");
    const keys = generateKeypairs();
    done();

    done = p.step("Wrapping private keys…");
    const bundle = packPrivateBundle(keys);
    const wrappedPwd = await aesGcmSeal(wrapKey, bundle);
    const wrappedRec = await aesGcmSeal(recoveryKey, bundle);
    // Also wrap recoveryKey under wrapKey so future bundle upgrades can re-wrap
    // the recovery bundle without ever asking for the recovery code again.
    const wrappedRecKey = await aesGcmSeal(wrapKey, recoveryKey);
    done();

    done = p.step("Uploading to server…");
    await postJson("/api/auth/signup", {
      email,
      kdf_salt: b64url(kdfSalt),
      recovery_salt: b64url(recoverySalt),
      kdf_params: DEFAULT_KDF_PARAMS,
      auth_secret: b64url(authSecret),
      public_keys: {
        x25519:      b64url(keys.classical.x25519.pub),
        ml_kem_768:  b64url(keys.pq.ml_kem_768.pub),
        ed25519:     b64url(keys.classical.ed25519.pub),
        ml_dsa_65:   b64url(keys.pq.ml_dsa_65.pub),
        secp384r1:   b64url(keys.classical_p384.secp384r1.pub),
        ecdsa_p384:  b64url(keys.classical_p384.ecdsa_p384.pub),
        ml_kem_1024: b64url(keys.pq_l5.ml_kem_1024.pub),
        ml_dsa_87:   b64url(keys.pq_l5.ml_dsa_87.pub),
      },
      wrapped_priv_blob: b64url(wrappedPwd),
      wrapped_priv_recovery: b64url(wrappedRec),
      wrapped_recovery_key:  b64url(wrappedRecKey),
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
    const wrappedBlob = b64urlDecode(resp.wrapped_priv_blob);
    let bundle;
    try {
      bundle = await aesGcmOpen(wrapKey, wrappedBlob);
    } catch (e) {
      throw new Error("Could not decrypt private keys — wrong password?");
    }
    let priv = unpackPrivateBundle(bundle);
    done();

    let publicKeys = decodePublicKeys(resp.public_keys);
    let wrappedB64 = resp.wrapped_priv_blob;
    const wrappedRecoveryKeyB64 = resp.wrapped_recovery_key || null;

    const upgrade = await maybeUpgradeKeyset(priv, wrapKey, wrappedRecoveryKeyB64, p);
    if (upgrade) {
      priv = upgrade.priv;
      publicKeys = { ...publicKeys, ...upgrade.pubs };
      wrappedB64 = b64url(upgrade.wrappedPwd);
    }

    appState.user = { id: resp.user_id, email: resp.email };
    appState.publicKeys = publicKeys;
    appState.privateKeys = priv;
    appState.wrapKey = wrapKey;  // kept in memory for retroactive recovery setup
    appState.meExtras = null;    // fetched lazily by renderDashboard if banner needed

    sessionStorage.setItem(SS.EMAIL, resp.email);
    sessionStorage.setItem(SS.WRAPPED_BLOB, wrappedB64);
    if (wrappedRecoveryKeyB64) sessionStorage.setItem(SS.WRAPPED_RECOVERY_KEY, wrappedRecoveryKeyB64);
    else                       sessionStorage.removeItem(SS.WRAPPED_RECOVERY_KEY);

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
    let priv = unpackPrivateBundle(bundle);
    done();

    const wrappedRecoveryKeyB64 = sessionStorage.getItem(SS.WRAPPED_RECOVERY_KEY);
    const upgrade = await maybeUpgradeKeyset(priv, wrapKey, wrappedRecoveryKeyB64, p);
    if (upgrade) {
      priv = upgrade.priv;
      appState.publicKeys = { ...(appState.publicKeys || {}), ...upgrade.pubs };
      sessionStorage.setItem(SS.WRAPPED_BLOB, b64url(upgrade.wrappedPwd));
    }
    appState.privateKeys = priv;
    appState.wrapKey = wrapKey;

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
  await maybeShowRecoveryRewrapBanner();
  const tbody = document.querySelector("#dash-fingerprints tbody");
  tbody.innerHTML = "";
  const pks = appState.publicKeys;
  const rows = [
    ["Ed25519 (sig)",      pks.ed25519],
    ["ECDSA-P384 (sig)",   pks.ecdsa_p384],
    ["ML-DSA-65 (sig)",    pks.ml_dsa_65],
    ["ML-DSA-87 (sig)",    pks.ml_dsa_87],
    ["X25519 (kem)",       pks.x25519],
    ["secp384r1 (kem)",    pks.secp384r1],
    ["ML-KEM-768 (kem)",   pks.ml_kem_768],
    ["ML-KEM-1024 (kem)",  pks.ml_kem_1024],
  ].filter(([_, b]) => b);  // hide rows whose key isn't yet provisioned
  for (const [label, bytes] of rows) {
    const tr = document.createElement("tr");
    const fp = await fingerprint(bytes);
    tr.innerHTML = `<th>${label}</th><td>${fp}</td>`;
    tbody.appendChild(tr);
  }
}

document.getElementById("logout-btn").addEventListener("click", () => doLogout());

// ---------- Retroactive recovery-key wrap (legacy accounts) ----------

async function maybeShowRecoveryRewrapBanner() {
  const banner = document.getElementById("dash-recovery-banner");
  // Show only when: account is upgraded (has v2 keys) AND no wrapped_recovery_key exists.
  const upgraded = !!appState.publicKeys?.secp384r1;
  const haveWrappedRecKey = !!sessionStorage.getItem(SS.WRAPPED_RECOVERY_KEY);
  if (!upgraded || haveWrappedRecKey || sessionStorage.getItem("pqshare:recoveryRewrapDismissed") === "1") {
    banner.classList.add("hidden");
    return;
  }
  banner.classList.remove("hidden");

  // Lazy-fetch recovery_salt + kdf_params if we don't have them.
  if (!appState.meExtras || !appState.meExtras.recovery_salt) {
    try {
      const me = await getJson("/api/auth/me");
      appState.meExtras = { recovery_salt: me.recovery_salt, kdf_params: me.kdf_params };
    } catch (_) { /* ignore — submit will retry */ }
  }
}

document.getElementById("recovery-rewrap-dismiss").addEventListener("click", () => {
  sessionStorage.setItem("pqshare:recoveryRewrapDismissed", "1");
  document.getElementById("dash-recovery-banner").classList.add("hidden");
});

document.getElementById("recovery-rewrap-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!appState.wrapKey || !appState.privateKeys) {
    alert("Session locked — please log in again.");
    return;
  }
  if (!appState.meExtras || !appState.meExtras.recovery_salt || !appState.meExtras.kdf_params) {
    alert("Couldn't fetch your recovery salt; please reload and try again.");
    return;
  }
  const form = event.currentTarget;
  const code = form.recovery_code.value.trim();
  const submitBtn = form.querySelector("button[type=submit]");
  submitBtn.disabled = true;
  const p = makeProgress("recovery-rewrap-progress");

  try {
    let done = p.step("Parsing recovery code…");
    let recoveryBytes;
    try {
      recoveryBytes = recoveryCodeToBytes(code);
    } catch (e) {
      throw new Error(`Invalid recovery code: ${e.message}`);
    }
    if (recoveryBytes.length !== 24) throw new Error("Recovery code is the wrong length.");
    done();

    done = p.step("Deriving recovery key (Argon2id)…");
    const recoverySalt = b64urlDecode(appState.meExtras.recovery_salt);
    const recoveryMaster = await deriveMaster(
      Array.from(recoveryBytes, (b) => b.toString(16).padStart(2, "0")).join(""),
      recoverySalt,
      appState.meExtras.kdf_params,
    );
    const recoveryKey = deriveSubKey(recoveryMaster, "pqshare:recovery-v1");
    done();

    done = p.step("Re-wrapping bundle under recovery key…");
    const bundleV2 = packPrivateBundle({
      classical: {
        x25519:  { priv: appState.privateKeys.x25519Priv,  pub: new Uint8Array(0) },
        ed25519: { priv: appState.privateKeys.ed25519Priv, pub: new Uint8Array(0) },
      },
      pq: {
        ml_kem_768: { priv: appState.privateKeys.mlkemPriv, pub: new Uint8Array(0) },
        ml_dsa_65:  { priv: appState.privateKeys.mldsaPriv, pub: new Uint8Array(0) },
      },
      classical_p384: {
        secp384r1:  { priv: appState.privateKeys.secp384r1Priv, pub: new Uint8Array(0) },
        ecdsa_p384: { priv: appState.privateKeys.ecdsap384Priv, pub: new Uint8Array(0) },
      },
      pq_l5: {
        ml_kem_1024: { priv: appState.privateKeys.mlkem1024Priv, pub: new Uint8Array(0) },
        ml_dsa_87:   { priv: appState.privateKeys.mldsa87Priv,   pub: new Uint8Array(0) },
      },
    });
    const wrappedRec = await aesGcmSeal(recoveryKey, bundleV2);
    const wrappedRecKey = await aesGcmSeal(appState.wrapKey, recoveryKey);
    done();

    done = p.step("Saving…");
    await postJson("/api/auth/set-recovery-key", {
      wrapped_priv_recovery: b64url(wrappedRec),
      wrapped_recovery_key:  b64url(wrappedRecKey),
    });
    sessionStorage.setItem(SS.WRAPPED_RECOVERY_KEY, b64url(wrappedRecKey));
    done();

    p.reset();
    form.reset();
    document.getElementById("dash-recovery-banner").classList.add("hidden");
    alert("Recovery upgraded. Your recovery code now restores all eight keypairs.");
  } catch (err) {
    p.error(`Failed: ${err.message}`);
  } finally {
    submitBtn.disabled = false;
  }
});

async function doLogout() {
  try {
    await postJson("/api/auth/logout", {});
  } catch (_) { /* ignore */ }
  sessionStorage.removeItem(SS.WRAPPED_BLOB);
  sessionStorage.removeItem(SS.WRAPPED_RECOVERY_KEY);
  sessionStorage.removeItem(SS.EMAIL);
  appState.user = null;
  appState.publicKeys = null;
  appState.privateKeys = null;
  appState.wrapKey = null;
  appState.meExtras = null;
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
    x25519:      b64urlDecode(pubs.x25519),
    ml_kem_768:  b64urlDecode(pubs.ml_kem_768),
    ed25519:     b64urlDecode(pubs.ed25519),
    ml_dsa_65:   b64urlDecode(pubs.ml_dsa_65),
    secp384r1:   pubs.secp384r1   ? b64urlDecode(pubs.secp384r1)   : null,
    ecdsa_p384:  pubs.ecdsa_p384  ? b64urlDecode(pubs.ecdsa_p384)  : null,
    ml_kem_1024: pubs.ml_kem_1024 ? b64urlDecode(pubs.ml_kem_1024) : null,
    ml_dsa_87:   pubs.ml_dsa_87   ? b64urlDecode(pubs.ml_dsa_87)   : null,
  };
}

function renderSend() {
  show("send");
  document.getElementById("send-form").reset();
  document.getElementById("send-progress").classList.add("hidden");
  appState.draftSend = null;
}

function renderSuite() {
  if (!appState.draftSend) {
    location.hash = "#/send";
    return;
  }
  show("suite");
  document.getElementById("suite-progress").classList.add("hidden");
  showPicker({
    recipient: { email: appState.draftSend.emails[0], status: appState.draftSend.emails.length > 1 ? `+ ${appState.draftSend.emails.length - 1} more · keys verified on continue` : "key on file" },
    suite: appState.draftSend.suite,
  });
}

document.getElementById("send-form").addEventListener("submit", (event) => {
  event.preventDefault();
  if (!appState.privateKeys) { alert("Locked — please unlock first."); return; }
  const form = event.currentTarget;
  const file = form.file.files[0];
  if (!file) return;
  const emails = parseRecipients(form.recipients.value);
  if (emails.length === 0) { alert("Add at least one recipient email."); return; }

  appState.draftSend = { file, emails, suite: appState.draftSend?.suite };
  location.hash = "#/suite";
});

async function performShare(suiteIntent) {
  if (!appState.draftSend) { location.hash = "#/send"; return; }
  if (!appState.privateKeys) { alert("Locked — please unlock first."); return; }
  const { file, emails } = appState.draftSend;
  appState.draftSend.suite = suiteIntent;

  const shareBtn = document.getElementById("suite-share");
  const backBtn = document.getElementById("suite-back");
  shareBtn.disabled = true;
  backBtn.disabled = true;
  const p = makeProgress("suite-progress");

  try {
    const ops = getOps(suiteIntent);
    const requiredPubField = {
      "X25519":         "x25519",
      "X25519MLKEM768": "ml_kem_768",     // also needs x25519, but that's always present
      "ML-KEM-768":     "ml_kem_768",
      "secp384r1":      "secp384r1",
      "ML-KEM-1024":    "ml_kem_1024",
    }[suiteIntent.kex];
    const requiredSigField = {
      "Ed25519":            "ed25519",
      "Ed25519+ML-DSA-65":  "ml_dsa_65",
      "ML-DSA-65":          "ml_dsa_65",
      "ECDSA-P384":         "ecdsa_p384",
      "ML-DSA-87":          "ml_dsa_87",
    }[suiteIntent.sig];
    if (!appState.publicKeys[requiredSigField]) {
      throw new Error(`Your account needs the Phase 3b key upgrade to sign with ${suiteIntent.sig}. Log out and log back in to trigger it.`);
    }

    let done = p.step(`Looking up ${emails.length} recipient${emails.length === 1 ? "" : "s"}…`);
    const recipients = [];
    for (const email of emails) {
      try {
        const r = await getJson(`/api/users/lookup?email=${encodeURIComponent(email)}`);
        const pubs = decodeRecipientPubs(r.public_keys);
        if (!pubs[requiredPubField]) {
          throw new Error(`recipient ${r.email} hasn't completed the Phase 3b key upgrade yet (needs ${requiredPubField}). Ask them to log in once, then retry, or pick a suite that uses only Phase 3a keys.`);
        }
        recipients.push({ email: r.email, pubs });
      } catch (e) {
        throw new Error(`${e.message}`);
      }
    }
    done();

    done = p.step(`Encrypting (${file.size.toLocaleString()} bytes, ${suiteIntent.sym})…`);
    const fileBytes = new Uint8Array(await file.arrayBuffer());
    const fileKey = randomFileKey(ops.aead.keyLen);
    const ciphertext = await ops.aead.seal(fileKey, fileBytes);
    const filenameEnc = await ops.aead.seal(fileKey, new TextEncoder().encode(file.name));
    done();

    done = p.step(`Signing (${suiteIntent.sig}, transcript ${suiteIntent.hash})…`);
    const metadata = {
      v: 1,
      mime: file.type || "application/octet-stream",
      plain_size: fileBytes.length,
      created: new Date().toISOString(),
    };
    const metadataJson = JSON.stringify(metadata);
    const transcript = await buildSigningTranscript(ciphertext, metadataJson, ops.transcriptHash);
    const sigs = ops.sig.sign(transcript, appState.privateKeys);
    done();

    done = p.step(`Wrapping file key for ${recipients.length} recipient${recipients.length === 1 ? "" : "s"} (${suiteIntent.kex})…`);
    const wrapped = [];
    for (const r of recipients) {
      const { ephemeralX25519Pub, kemCiphertext, wrapKey } = ops.kem.encapsulate(r.pubs);
      const wrappedKey = await ops.aead.seal(wrapKey, fileKey);
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
      suite: {
        preset: suiteIntent.preset,
        tls:    suiteIntent.tls,
        rng:    suiteIntent.rng,
        kex:    suiteIntent.kex,
        hash:   suiteIntent.hash,
        sym:    suiteIntent.sym,
        sig:    suiteIntent.sig,
      },
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
    appState.draftSend = null;
    setTimeout(() => { location.hash = "#/sent"; }, 800);
  } catch (err) {
    p.error(`Send failed: ${err.message}`);
  } finally {
    shareBtn.disabled = false;
    backBtn.disabled = false;
  }
}

initPicker({
  onBack: () => { location.hash = "#/send"; },
  onShare: (suiteIntent) => performShare(suiteIntent),
});

// ---------- Inbox ----------

function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MiB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GiB`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

const POSTURE_NAME = { classical: "Classical", hybrid: "Hybrid PQC", pqc: "PQC-only", cnsa: "CNSA 2.0" };

/** Render a small inline pill describing the file's cipher suite. Files
 *  predating the picker arrive with suite == null — those are shown as a
 *  hybrid pill labeled "(legacy)" since the LEGACY_SUITE primitives are known. */
function suiteBadgeHtml(suite) {
  if (!suite) {
    const tip = "Legacy upload (predates the cipher picker): X25519+ML-KEM-768 hybrid · Ed25519+ML-DSA-65 dual sig · SHA-512 HKDF · AES-256-GCM · SHA-256 transcript";
    return `<span class="suite-pill" data-tier="hybrid" title="${escapeHtml(tip)}">Hybrid (legacy)</span>`;
  }
  const tier = suite.posture_tier || "hybrid";
  const label = POSTURE_NAME[tier] || tier;
  const detail = `KEX ${suite.kex} · SIG ${suite.sig} · HASH ${suite.hash} · AEAD ${suite.sym} · RNG ${suite.rng} · TLS ${suite.tls} · +${suite.overhead_bytes}B`;
  return `<span class="suite-pill" data-tier="${escapeHtml(tier)}" title="${escapeHtml(detail)}">${escapeHtml(label)}</span>`;
}

function fmtDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString();
}

function suiteForMeta(meta) {
  // New uploads carry their suite; legacy uploads (suite missing) used the
  // historical hardcoded combination.
  return meta.suite || LEGACY_SUITE;
}

async function decryptFilenameFromMeta(meta) {
  const suite = suiteForMeta(meta);
  const ops = getOps(suite);
  const wrapKey = ops.kem.decapsulate({
    ephemeralX25519Pub: b64urlDecode(meta.ephemeral_x25519_pub),
    kemCiphertext: b64urlDecode(meta.kem_ciphertext),
    recipientPrivs: appState.privateKeys,
    recipientPubs: appState.publicKeys,
  });
  const fileKey = await ops.aead.open(wrapKey, b64urlDecode(meta.wrapped_key));
  const filenameBytes = await ops.aead.open(fileKey, b64urlDecode(meta.filename_enc));
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
    tbody.innerHTML = `<tr><td colspan="6" class="error">${e.message}</td></tr>`;
    return;
  }

  if (items.length === 0) {
    document.getElementById("inbox-empty").classList.remove("hidden");
    return;
  }

  for (const it of items) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(it.sender_email)}</td>
      <td class="filename">decrypting…</td>
      <td>${fmtBytes(it.ciphertext_size)}</td>
      <td>${suiteBadgeHtml(it.suite)}</td>
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
  const suite = suiteForMeta(meta);
  const ops = getOps(suite);
  const senderPubs = decodeRecipientPubs(meta.sender_public_keys);

  const blobRes = await fetch(`/api/files/${fileId}/blob`, { credentials: "same-origin" });
  if (!blobRes.ok) throw new Error(`blob ${blobRes.status}`);
  const ciphertext = new Uint8Array(await blobRes.arrayBuffer());

  // Legacy (no suite) uploads used SHA-256 for the transcript; new uploads use suite.hash.
  const transcriptHash = meta.suite ? suite.hash : "SHA-256";
  const transcript = await buildSigningTranscript(ciphertext, meta.metadata_json, transcriptHash);
  const sigs = { ed: b64urlDecode(meta.sig_ed25519), mldsa: b64urlDecode(meta.sig_mldsa65) };
  const ok = ops.sig.verify(transcript, sigs, senderPubs);
  if (!ok) throw new Error("signature verification failed — refusing to decrypt");

  const wrapKey = ops.kem.decapsulate({
    ephemeralX25519Pub: b64urlDecode(meta.ephemeral_x25519_pub),
    kemCiphertext: b64urlDecode(meta.kem_ciphertext),
    recipientPrivs: appState.privateKeys,
    recipientPubs: appState.publicKeys,
  });
  const fileKey = await ops.aead.open(wrapKey, b64urlDecode(meta.wrapped_key));
  const plaintext = await ops.aead.open(fileKey, ciphertext);
  const filename = knownFilename || new TextDecoder().decode(
    await ops.aead.open(fileKey, b64urlDecode(meta.filename_enc))
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
    tbody.innerHTML = `<tr><td colspan="4" class="error">${e.message}</td></tr>`;
    return;
  }

  if (items.length === 0) {
    document.getElementById("sent-empty").classList.remove("hidden");
    return;
  }

  for (const it of items) {
    const tr = document.createElement("tr");
    const recipientList = it.recipients
      .map((r) => `${escapeHtml(r.email)}${r.downloaded_at ? " ✓" : ""}`)
      .join(", ");
    tr.innerHTML = `
      <td>${fmtDate(it.created_at)}</td>
      <td>${fmtBytes(it.ciphertext_size)}</td>
      <td>${suiteBadgeHtml(it.suite)}</td>
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
