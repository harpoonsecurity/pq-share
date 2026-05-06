// Cipher suite picker — UI-only state, mutual exclusivity rules, and rendering.
// The selected suite is captured as `suite_intent` metadata on upload; the
// underlying crypto remains hardcoded (X25519+ML-KEM-768 KEM, Ed25519+ML-DSA-65 sigs,
// AES-256-GCM, SHA-512 HKDF) until the algorithm abstraction layer lands.

const TIER = {
  // RNG
  "HMAC-DRBG-SHA256":   "hybrid",
  "AES-CTR-DRBG-256":   "hybrid",
  "HMAC-DRBG-SHA512":   "pqc",
  // KEX
  "X25519":             "classical",
  "secp384r1":          "classical",
  "X25519MLKEM768":     "hybrid",
  "ML-KEM-768":         "pqc",
  "ML-KEM-1024":        "cnsa",
  // Hash
  "SHA-256":            "classical",
  "SHA-384":            "hybrid",
  "SHA-512":            "hybrid",
  "SHA3-512":           "pqc",
  // Symmetric
  "AES-128-GCM":        "classical",
  "AES-256-GCM":        "hybrid",
  "ChaCha20-Poly1305":  "hybrid",
  "AES-256-GCM-SIV":    "pqc",
  // Signature
  "Ed25519":            "classical",
  "ECDSA-P384":         "classical",
  "Ed25519+ML-DSA-65":  "hybrid",
  "ML-DSA-65":          "pqc",
  "ML-DSA-87":          "cnsa",
};

const CATEGORIES = [
  {
    key: "rng",
    title: "Random number generator",
    purpose: "How nonces, IVs, and ephemeral keys are generated",
    options: ["HMAC-DRBG-SHA256", "AES-CTR-DRBG-256", "HMAC-DRBG-SHA512"],
    role: "DRBG",
  },
  {
    key: "kex",
    title: "Key exchange (TLS & envelope KEM)",
    purpose: "How session keys are agreed",
    options: ["X25519", "secp384r1", "X25519MLKEM768", "ML-KEM-768", "ML-KEM-1024"],
    role: "KEX",
    tls12Disallowed: ["X25519MLKEM768", "ML-KEM-768", "ML-KEM-1024"],
  },
  {
    key: "hash",
    title: "Hash & HKDF",
    purpose: "How key material is derived and content is bound",
    options: ["SHA-256", "SHA-384", "SHA-512", "SHA3-512"],
    role: "HASH",
  },
  {
    key: "sym",
    title: "Symmetric encryption",
    purpose: "How file bytes & TLS records are sealed",
    options: ["AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305", "AES-256-GCM-SIV"],
    role: "AEAD",
  },
  {
    key: "sig",
    title: "Digital signature",
    purpose: "How sender identity is proven on the envelope",
    options: ["Ed25519", "ECDSA-P384", "Ed25519+ML-DSA-65", "ML-DSA-65", "ML-DSA-87"],
    role: "SIG",
    tls12Disallowed: ["Ed25519+ML-DSA-65", "ML-DSA-65", "ML-DSA-87"],
  },
];

// Microcopy keyed by primitive name. Only the most informative cases are
// listed; defaults fall back to the category's neutral blurb.
const MICROCOPY = {
  "X25519":             { warn: "Classical ECDH is breakable by a sufficiently large quantum computer. Captured traffic can be decrypted retroactively." },
  "secp256r1":          { warn: "P-256 ECDH offers ~128 bits of classical security; Shor's algorithm reduces this to zero post-quantum." },
  "secp384r1":          { warn: "Classical-only — store-now-decrypt-later applies. P-384 buys you margin against classical attacks but not quantum." },
  "X25519MLKEM768":     { ok: "Hybrid: classically and quantum-secure. The IETF default for TLS 1.3 PQ migration." },
  "ML-KEM-768":         { ok: "Pure post-quantum. Loses classical hedge — fine if you trust ML-KEM, but no fallback if it's later broken." },
  "ML-KEM-1024":        { ok: "NIST level 5 ML-KEM. Required by CNSA 2.0 for national-security systems." },
  "AES-128-GCM":        { warn: "AES-128 has Grover-reduced effective security of 64 bits against a quantum adversary. Acceptable for short-lived secrets, not archival." },
  "AES-256-GCM":        { ok: "256-bit AEAD with implicit nonce derivation per RFC 5116. The current safe default." },
  "ChaCha20-Poly1305":  { ok: "Constant-time on platforms without AES hardware. Often faster on ARM mobile." },
  "AES-256-GCM-SIV":    { ok: "Nonce-misuse resistant. Trades some throughput for safer key reuse semantics." },
  "SHA-256":            { warn: "Unbroken, but pairs poorly with AES-256: 128-bit collision margin caps the suite's effective security." },
  "SHA-384":            { ok: "Pairs cleanly with AES-256 for a uniform 192-bit security margin." },
  "SHA-512":            { ok: "256-bit collision resistance — the right hash for AES-256 + ML-KEM-1024 uniformity." },
  "SHA3-512":           { ok: "Keccak-based; structurally different from SHA-2 — useful as a hedge." },
  "Ed25519":            { warn: "Classical EdDSA. Forgeable in polynomial time once large quantum computers exist." },
  "ECDSA-P256":         { warn: "ECDSA on 256-bit curves: forgeable by Shor's algorithm in polynomial time post-quantum." },
  "ECDSA-P384":         { warn: "Larger curve, but still classical — vulnerable to Shor." },
  "Ed25519+ML-DSA-65":  { ok: "Dual signatures: recipient verifies both — fails closed if either is broken." },
  "ML-DSA-65":          { ok: "Pure post-quantum signature, NIST level 3." },
  "ML-DSA-87":          { ok: "ML-DSA level 5. CNSA 2.0 mandated." },
  "AES-CTR-DRBG-256":   { ok: "FIPS 140-3 approved DRBG seeded from getrandom(2)." },
  "HMAC-DRBG-SHA256":   { ok: "FIPS 140-3 approved DRBG. Standard fallback when AES hardware is unavailable." },
  "HMAC-DRBG-SHA512":   { ok: "FIPS-approved with a larger internal state — overkill for most uses but harmless." },
};

// What the dispatch can execute today. ChaCha20 and AES-GCM-SIV still need a
// JS lib; everything else works once both sender and recipient have upgraded
// keys (the upgrade runs automatically at login for legacy accounts).
const SUPPORTED = {
  rng:  new Set(["HMAC-DRBG-SHA256", "AES-CTR-DRBG-256", "HMAC-DRBG-SHA512"]),
  kex:  new Set(["X25519", "secp384r1", "X25519MLKEM768", "ML-KEM-768", "ML-KEM-1024"]),
  hash: new Set(["SHA-256", "SHA-384", "SHA-512", "SHA3-512"]),
  sym:  new Set(["AES-128-GCM", "AES-256-GCM"]),
  sig:  new Set(["Ed25519", "ECDSA-P384", "Ed25519+ML-DSA-65", "ML-DSA-65", "ML-DSA-87"]),
};
const UNSUPPORTED_REASON = {
  "ChaCha20-Poly1305": "Not in WebCrypto — needs additional JS lib.",
  "AES-256-GCM-SIV":   "Not in WebCrypto — needs additional JS lib.",
};

const PRESETS = [
  { id: "custom",            label: "Custom",                tier: "hybrid",    suite: null },
  { id: "nist-800-52",       label: "NIST SP 800-52 R2",     tier: "classical",
    suite: { rng: "AES-CTR-DRBG-256", kex: "secp384r1",      hash: "SHA-384", sym: "AES-256-GCM", sig: "ECDSA-P384",        tls: "1.2" } },
  { id: "fips-140-3-hybrid", label: "FIPS 140-3 hybrid",     tier: "hybrid",
    suite: { rng: "AES-CTR-DRBG-256", kex: "X25519MLKEM768", hash: "SHA-384", sym: "AES-256-GCM", sig: "Ed25519+ML-DSA-65", tls: "1.3" } },
  { id: "pqc-only",          label: "PQC-only",              tier: "pqc",
    suite: { rng: "HMAC-DRBG-SHA512", kex: "ML-KEM-768",     hash: "SHA3-512", sym: "AES-256-GCM", sig: "ML-DSA-65",        tls: "1.3" } },
  { id: "cnsa-2",            label: "CNSA 2.0",              tier: "cnsa",
    suite: { rng: "AES-CTR-DRBG-256", kex: "ML-KEM-1024",    hash: "SHA-512", sym: "AES-256-GCM", sig: "ML-DSA-87",         tls: "1.3" } },
];

// Rough byte overheads of the handshake key share + envelope material, in bytes.
// Sourced from RFC 8446, IANA codepoints, and FIPS 204/205 spec; close enough
// for the user-facing "+X bytes" indicator.
const HANDSHAKE_BYTES = {
  "X25519":         32, "secp384r1":     97, "X25519MLKEM768": 1216,
  "ML-KEM-768":   1184, "ML-KEM-1024": 1568,
};
const SIG_BYTES = {
  "Ed25519": 64, "ECDSA-P384": 96, "Ed25519+ML-DSA-65": 3373, "ML-DSA-65": 3309, "ML-DSA-87": 4627,
};

// ---------- State ----------

const DEFAULT = {
  preset: "custom",
  tls: "1.3",
  rng: "AES-CTR-DRBG-256",
  kex: "X25519MLKEM768",
  hash: "SHA-384",
  sym: "AES-256-GCM",
  sig: "Ed25519+ML-DSA-65",
};

let state = { ...DEFAULT };
let recipient = null; // { email, status }
let backHandler = () => { history.back(); };
let shareHandler = () => {};

// ---------- Selectors ----------

// Tier each non-custom preset establishes when applied.
const PRESET_TIER = {
  "nist-800-52":       "classical",
  "fips-140-3-hybrid": "hybrid",
  "pqc-only":          "pqc",
  "cnsa-2":            "cnsa",
};

function postureTier() {
  // If a non-custom preset is active, the user has made a regulatory claim;
  // honor it. Custom mode falls back to weakest-link aggregation.
  if (PRESET_TIER[state.preset]) return PRESET_TIER[state.preset];
  const order = { classical: 0, hybrid: 1, pqc: 2, cnsa: 3 };
  const tiers = ["rng", "kex", "hash", "sym", "sig"].map((k) => TIER[state[k]]);
  let weakest = "cnsa";
  for (const t of tiers) {
    if (order[t] < order[weakest]) weakest = t;
  }
  return weakest;
}

function postureName(tier) {
  return { classical: "Classical only", hybrid: "Hybrid PQC", pqc: "Post-quantum only", cnsa: "CNSA 2.0" }[tier];
}

function postureSub(tier) {
  return {
    classical: "No post-quantum protection · pre-2024 baseline",
    hybrid:    "Quantum-secure migration tier",
    pqc:       "Pure PQ — no classical hedge",
    cnsa:      "NSA Commercial National Security Algorithm Suite v2 · NIST level 5",
  }[tier];
}

function activePreset() {
  return PRESETS.find((p) => p.id === state.preset) || PRESETS[0];
}

function isLocked() {
  const p = activePreset();
  return !!p.suite;
}

function tlsDisallows(catKey, primitive) {
  if (state.tls !== "1.2") return false;
  const cat = CATEGORIES.find((c) => c.key === catKey);
  return cat.tls12Disallowed && cat.tls12Disallowed.includes(primitive);
}

function presetDisallows(catKey, primitive) {
  const p = activePreset();
  if (!p.suite) return false;
  return p.suite[catKey] !== primitive;
}

// Total handshake & envelope overhead estimates.
function overhead() {
  const handshake = (HANDSHAKE_BYTES[state.kex] || 0) + 64; // 64B = misc transcript
  const envelope = (SIG_BYTES[state.sig] || 0) + 96;        // 96B = AEAD tag + IV + framing
  const total = handshake + envelope;
  const fmt = (n) => n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`;
  return { handshake, envelope, total: fmt(total), totalBytes: total };
}

// ---------- Render ----------

function el(tag, props = {}, children = []) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") e.className = v;
    else if (k === "dataset") for (const [dk, dv] of Object.entries(v)) e.dataset[dk] = dv;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === "html") e.innerHTML = v;
    else if (k === "text") e.textContent = v;
    else e.setAttribute(k, v);
  }
  for (const c of children) {
    if (c == null) continue;
    e.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return e;
}

function presetExecutable(p) {
  if (!p.suite) return true; // "Custom" — always permitted; executability checked at share-time.
  for (const k of ["rng", "kex", "hash", "sym", "sig"]) {
    if (!SUPPORTED[k].has(p.suite[k])) return false;
  }
  return true;
}

function suiteExecutable() {
  for (const k of ["rng", "kex", "hash", "sym", "sig"]) {
    if (!SUPPORTED[k].has(state[k])) return false;
  }
  return true;
}

function renderPostureRow() {
  const row = document.getElementById("suite-posture-row");
  row.innerHTML = "";
  for (const p of PRESETS) {
    const ok = presetExecutable(p);
    const cls = ["posture-chip"];
    if (state.preset === p.id) cls.push("is-active");
    if (!ok) cls.push("is-locked-out");
    const props = {
      class: cls.join(" "),
      dataset: { tier: p.tier },
      type: "button",
      onclick: () => { if (ok) applyPreset(p.id); },
      text: p.label,
    };
    if (!ok) props.title = "Includes primitives not yet supported in this build (Phase 2B).";
    row.appendChild(el("button", props));
  }
}

function renderTlsToggle() {
  const wrap = document.getElementById("suite-tls-toggle");
  wrap.innerHTML = "";
  for (const v of ["1.2", "1.3"]) {
    const b = el("button", {
      class: state.tls === v ? "is-active" : "",
      type: "button",
      text: `TLS ${v}`,
      onclick: () => setTls(v),
    });
    if (isLocked() && activePreset().suite.tls !== v) b.disabled = true;
    wrap.appendChild(b);
  }
}

function renderCategories() {
  const root = document.getElementById("suite-categories");
  root.innerHTML = "";
  const locked = isLocked();
  const presetTier = activePreset().tier;

  for (const cat of CATEGORIES) {
    const selected = state[cat.key];
    const selectedTier = TIER[selected];
    const cardTier = locked ? presetTier : selectedTier;

    const head = el("div", { class: "cat-head" }, [
      el("span", { class: "cat-title", text: cat.title }),
      el("span", { class: "cat-purpose" }, [
        locked ? el("span", { class: "cat-lock", text: "🔒 preset-locked" }) : cat.purpose,
      ]),
    ]);

    const pillRow = el("div", { class: "pill-row" });
    for (const opt of cat.options) {
      const isSelected = opt === selected;
      const tlsBlocked = tlsDisallows(cat.key, opt);
      const presetBlocked = locked && presetDisallows(cat.key, opt);
      const v1Unsupported = !SUPPORTED[cat.key].has(opt);
      const lockedOut = tlsBlocked || presetBlocked || v1Unsupported;
      const optTier = TIER[opt];
      const wantsWarning = isSelected && optTier === "classical" && !locked;

      const classes = ["pill"];
      if (isSelected) classes.push("is-selected");
      if (lockedOut) classes.push("is-locked-out");
      if (wantsWarning) classes.push("is-warning");

      const props = {
        class: classes.join(" "),
        dataset: { tier: optTier },
        type: "button",
        text: opt,
        onclick: () => {
          if (lockedOut) return;
          select(cat.key, opt);
        },
      };
      if (v1Unsupported) props.title = UNSUPPORTED_REASON[opt] || "Not yet supported in this build.";
      pillRow.appendChild(el("button", props));
    }

    const mc = MICROCOPY[selected] || {};
    const microcopy = mc.warn
      ? el("div", { class: "cat-microcopy is-warn", text: `⚠ ${mc.warn}` })
      : el("div", { class: "cat-microcopy", text: mc.ok || cat.purpose });

    const card = el("div", {
      class: "cat-card",
      dataset: { tier: cardTier },
    }, [head, pillRow, microcopy]);

    root.appendChild(card);
  }
}

function renderRecipient() {
  const card = document.getElementById("suite-recipient");
  card.innerHTML = "";
  if (!recipient) {
    card.appendChild(el("div", { class: "recipient-meta" }, [
      el("div", { class: "recipient-name", text: "—" }),
      el("div", { class: "recipient-status", text: "no recipient set" }),
    ]));
    return;
  }
  const initials = (recipient.email.split("@")[0].slice(0, 2) || "??").toUpperCase();
  card.appendChild(el("div", { class: "recipient-avatar", text: initials }));
  card.appendChild(el("div", { class: "recipient-meta" }, [
    el("div", { class: "recipient-name", text: recipient.email }),
    el("div", { class: "recipient-status", text: recipient.status || "ready" }),
  ]));
}

function renderPostureBadge() {
  const tier = postureTier();
  const o = overhead();
  const badge = document.getElementById("suite-posture-badge");
  badge.dataset.tier = tier;
  badge.innerHTML = "";
  badge.appendChild(el("div", { class: "posture-dot" }));
  badge.appendChild(el("div", { class: "posture-text" }, [
    el("div", { class: "posture-name", text: postureName(tier) }),
    el("div", { class: "posture-sub", text: postureSub(tier) }),
    el("div", { class: "posture-overhead", text: `+${o.total} handshake + envelope` }),
  ]));
}

function renderChain() {
  const stack = document.getElementById("suite-chain");
  stack.innerHTML = "";
  stack.dataset.glow = postureTier();

  // Transport (TLS handshake)
  stack.appendChild(el("div", { class: "chain-group-label" }, [
    el("span", { text: "Transport · TLS " + state.tls }),
    el("span", { class: "mono", text: `+${overhead().handshake} B` }),
  ]));
  for (const k of ["rng", "kex", "hash", "sym"]) {
    const cat = CATEGORIES.find((c) => c.key === k);
    stack.appendChild(el("div", {
      class: "chain-row",
      dataset: { tier: TIER[state[k]] },
    }, [
      el("span", { class: "chain-row-name", text: state[k] }),
      el("span", { class: "chain-row-role", text: cat.role }),
    ]));
  }

  // Envelope
  stack.appendChild(el("div", { class: "chain-group-label" }, [
    el("span", { text: "Envelope · file → recipient" }),
    el("span", { class: "mono", text: `+${overhead().envelope} B` }),
  ]));
  for (const [k, role] of [["sym", "AEAD"], ["hash", "HKDF"], ["sig", "SIGN"]]) {
    stack.appendChild(el("div", {
      class: "chain-row",
      dataset: { tier: TIER[state[k]] },
    }, [
      el("span", { class: "chain-row-name", text: state[k] }),
      el("span", { class: "chain-row-role", text: role }),
    ]));
  }
}

function renderWarning() {
  const wrap = document.getElementById("suite-warning");
  wrap.innerHTML = "";
  if (postureTier() === "classical") {
    wrap.appendChild(el("div", { class: "warn-banner" }, [
      el("div", { class: "warn-banner-title", text: "⚠ Harvest-now, decrypt-later risk" }),
      document.createTextNode(
        "Captured traffic from this exchange becomes decryptable to any actor who later builds a cryptographically relevant quantum computer. Switch to Hybrid PQC for forward security."
      ),
    ]));
  }
}

function renderShareButton() {
  const btn = document.getElementById("suite-share");
  if (!suiteExecutable()) {
    btn.disabled = true;
    btn.textContent = "Selection not yet supported";
    btn.title = "One or more selected primitives are Phase 2B — pick supported alternatives.";
  } else {
    btn.disabled = false;
    btn.removeAttribute("title");
    btn.textContent = postureTier() === "classical" ? "Encrypt & share anyway" : "Encrypt & share";
  }
}

function renderAll() {
  renderPostureRow();
  renderTlsToggle();
  renderCategories();
  renderRecipient();
  renderPostureBadge();
  renderChain();
  renderWarning();
  renderShareButton();
}

// ---------- Mutators ----------

function select(catKey, primitive) {
  if (state[catKey] === primitive) return;
  state[catKey] = primitive;
  // Hand-edit always demotes to Custom unless the new selection still matches the active preset.
  const p = activePreset();
  if (p.suite && p.suite[catKey] !== primitive) state.preset = "custom";
  renderAll();
}

function setTls(version) {
  if (state.tls === version) return;
  state.tls = version;
  // Auto-correct any TLS 1.2-disallowed selections by falling back to a sane default.
  if (version === "1.2") {
    if (CATEGORIES[1].tls12Disallowed.includes(state.kex)) state.kex = "X25519";
    if (CATEGORIES[4].tls12Disallowed.includes(state.sig)) state.sig = "Ed25519";
    state.preset = "custom";
  }
  renderAll();
}

function applyPreset(id) {
  const p = PRESETS.find((x) => x.id === id);
  if (!p) return;
  state.preset = id;
  if (p.suite) {
    state.tls  = p.suite.tls;
    state.rng  = p.suite.rng;
    state.kex  = p.suite.kex;
    state.hash = p.suite.hash;
    state.sym  = p.suite.sym;
    state.sig  = p.suite.sig;
  }
  renderAll();
}

// ---------- Public API ----------

export function initPicker({ onBack, onShare }) {
  backHandler = onBack || backHandler;
  shareHandler = onShare || shareHandler;
  document.getElementById("suite-back").addEventListener("click", () => backHandler());
  document.getElementById("suite-share").addEventListener("click", () => shareHandler(getSuite()));
}

export function showPicker({ recipient: r, suite: prior }) {
  recipient = r || null;
  if (prior) state = { ...DEFAULT, ...prior };
  else state = { ...DEFAULT };
  renderAll();
}

export function getSuite() {
  return {
    preset: state.preset,
    tls: state.tls,
    rng: state.rng,
    kex: state.kex,
    hash: state.hash,
    sym: state.sym,
    sig: state.sig,
    posture_tier: postureTier(),
    overhead_bytes: overhead().totalBytes,
  };
}
