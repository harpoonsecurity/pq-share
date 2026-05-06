import { ed25519, x25519 } from "@noble/curves/ed25519";
import { p384 } from "@noble/curves/p384";
import { ml_kem768, ml_kem1024 } from "@noble/post-quantum/ml-kem";
import { ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256, sha384, sha512 } from "@noble/hashes/sha2";
import { sha3_512 } from "@noble/hashes/sha3";
import { argon2id } from "hash-wasm";

export { ed25519, x25519, p384, ml_kem768, ml_kem1024, ml_dsa65, ml_dsa87, sha256, sha384, sha512, sha3_512, hkdf };

// ---------- Encoding helpers ----------

export function b64url(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function b64urlDecode(s) {
  s = s.replaceAll("-", "+").replaceAll("_", "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const enc = new TextEncoder();
const dec = new TextDecoder();

export function concatBytes(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------- KDF ----------

export const DEFAULT_KDF_PARAMS = { m: 64 * 1024, t: 3, p: 1 };

/** Run Argon2id and return a 32-byte master key. `password` is a string, `salt` is Uint8Array(16). */
export async function deriveMaster(password, salt, params = DEFAULT_KDF_PARAMS) {
  const hex = await argon2id({
    password,
    salt,
    parallelism: params.p,
    iterations: params.t,
    memorySize: params.m,
    hashLength: 32,
    outputType: "hex",
  });
  return hexToBytes(hex);
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

/** Derive a 32-byte key from master via HKDF-SHA512 with a context label. */
export function deriveSubKey(master, label) {
  return hkdf(sha512, master, undefined, enc.encode(label), 32);
}

// ---------- AES-GCM (browser-native, key length determined by caller) ----------

/** Seal `plaintext` with AES-GCM using `key`. `key` length (16 or 32) selects AES-128 vs AES-256. */
export async function aesGcmSeal(key, plaintext) {
  const cryptoKey = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, plaintext)
  );
  return concatBytes(iv, ct);
}

export async function aesGcmOpen(key, sealed) {
  const iv = sealed.subarray(0, 12);
  const ct = sealed.subarray(12);
  const cryptoKey = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
  const pt = new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, ct)
  );
  return pt;
}

// ---------- Keypair generation ----------

/** Generate the four "Phase 3a" keypairs: X25519, Ed25519, ML-KEM-768, ML-DSA-65. */
function generateBaseKeypairs() {
  const x25519Priv = x25519.utils.randomPrivateKey();
  const ed25519Priv = ed25519.utils.randomPrivateKey();
  const mlkemKp = ml_kem768.keygen();
  const mldsaKp = ml_dsa65.keygen();
  return {
    x25519:    { priv: x25519Priv,         pub: x25519.getPublicKey(x25519Priv) },
    ed25519:   { priv: ed25519Priv,        pub: ed25519.getPublicKey(ed25519Priv) },
    ml_kem_768:{ priv: mlkemKp.secretKey,  pub: mlkemKp.publicKey },
    ml_dsa_65: { priv: mldsaKp.secretKey,  pub: mldsaKp.publicKey },
  };
}

/** Generate the "Phase 3b" keypairs: secp384r1 (ECDH), ECDSA-P384 (sig), ML-KEM-1024, ML-DSA-87. */
export function generateExtendedKeypairs() {
  const sec384Priv = p384.utils.randomPrivateKey();
  const ecdsa384Priv = p384.utils.randomPrivateKey();
  const mlkem1024Kp = ml_kem1024.keygen();
  const mldsa87Kp = ml_dsa87.keygen();
  return {
    secp384r1:   { priv: sec384Priv,             pub: p384.getPublicKey(sec384Priv,   true) }, // compressed (49B)
    ecdsa_p384:  { priv: ecdsa384Priv,           pub: p384.getPublicKey(ecdsa384Priv, true) },
    ml_kem_1024: { priv: mlkem1024Kp.secretKey,  pub: mlkem1024Kp.publicKey },
    ml_dsa_87:   { priv: mldsa87Kp.secretKey,    pub: mldsa87Kp.publicKey },
  };
}

/** Full 8-keypair set used by new signups. */
export function generateKeypairs() {
  const base = generateBaseKeypairs();
  const ext = generateExtendedKeypairs();
  return {
    classical: { x25519: base.x25519, ed25519: base.ed25519 },
    pq:        { ml_kem_768: base.ml_kem_768, ml_dsa_65: base.ml_dsa_65 },
    classical_p384: { secp384r1: ext.secp384r1, ecdsa_p384: ext.ecdsa_p384 },
    pq_l5:          { ml_kem_1024: ext.ml_kem_1024, ml_dsa_87: ext.ml_dsa_87 },
  };
}

// ---------- Private-key bundle (length-prefixed concat) ----------

// v1: 4 fields (x25519, ed25519, ml_kem_768, ml_dsa_65)
// v2: 8 fields (v1 fields + secp384r1, ecdsa_p384, ml_kem_1024, ml_dsa_87)
const BUNDLE_V1 = 1;
const BUNDLE_V2 = 2;
const BUNDLE_VERSION = BUNDLE_V2;

function u32be(n) {
  const b = new Uint8Array(4);
  b[0] = (n >>> 24) & 0xff;
  b[1] = (n >>> 16) & 0xff;
  b[2] = (n >>> 8) & 0xff;
  b[3] = n & 0xff;
  return b;
}

function readU32be(buf, offset) {
  return (buf[offset] << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3];
}

/** Pack a v2 (8-field) bundle. `keys` must include classical, pq, classical_p384, pq_l5. */
export function packPrivateBundle(keys) {
  const parts = [
    new Uint8Array([BUNDLE_V2]),
    u32be(keys.classical.x25519.priv.length),       keys.classical.x25519.priv,
    u32be(keys.classical.ed25519.priv.length),      keys.classical.ed25519.priv,
    u32be(keys.pq.ml_kem_768.priv.length),          keys.pq.ml_kem_768.priv,
    u32be(keys.pq.ml_dsa_65.priv.length),           keys.pq.ml_dsa_65.priv,
    u32be(keys.classical_p384.secp384r1.priv.length),  keys.classical_p384.secp384r1.priv,
    u32be(keys.classical_p384.ecdsa_p384.priv.length), keys.classical_p384.ecdsa_p384.priv,
    u32be(keys.pq_l5.ml_kem_1024.priv.length),      keys.pq_l5.ml_kem_1024.priv,
    u32be(keys.pq_l5.ml_dsa_87.priv.length),        keys.pq_l5.ml_dsa_87.priv,
  ];
  return concatBytes(...parts);
}

export function unpackPrivateBundle(buf) {
  const v = buf[0];
  if (v !== BUNDLE_V1 && v !== BUNDLE_V2) {
    throw new Error(`unknown bundle version ${v}`);
  }
  let off = 1;
  const readField = () => {
    const len = readU32be(buf, off);
    off += 4;
    const out = buf.slice(off, off + len);
    off += len;
    return out;
  };
  const result = {
    bundleVersion: v,
    x25519Priv:  readField(),
    ed25519Priv: readField(),
    mlkemPriv:   readField(),
    mldsaPriv:   readField(),
    secp384r1Priv:  null,
    ecdsap384Priv:  null,
    mlkem1024Priv:  null,
    mldsa87Priv:    null,
  };
  if (v === BUNDLE_V2) {
    result.secp384r1Priv = readField();
    result.ecdsap384Priv = readField();
    result.mlkem1024Priv = readField();
    result.mldsa87Priv   = readField();
  }
  return result;
}

/** Take a v1 unpacked bundle and a freshly-generated extended keyset; produce
 *  a v2 packed bundle plus the four new pubkeys for upload. */
export function buildUpgradedBundle(v1Priv, extendedKeys) {
  const fauxKeys = {
    classical: {
      x25519:  { priv: v1Priv.x25519Priv,  pub: x25519.getPublicKey(v1Priv.x25519Priv) },
      ed25519: { priv: v1Priv.ed25519Priv, pub: ed25519.getPublicKey(v1Priv.ed25519Priv) },
    },
    pq: {
      ml_kem_768: { priv: v1Priv.mlkemPriv, pub: new Uint8Array(0) },  // pubs unused for packing
      ml_dsa_65:  { priv: v1Priv.mldsaPriv, pub: new Uint8Array(0) },
    },
    classical_p384: extendedKeys,
    pq_l5: { ml_kem_1024: extendedKeys.ml_kem_1024, ml_dsa_87: extendedKeys.ml_dsa_87 },
  };
  // Re-shape: classical_p384 in fauxKeys should hold secp384r1 / ecdsa_p384.
  fauxKeys.classical_p384 = { secp384r1: extendedKeys.secp384r1, ecdsa_p384: extendedKeys.ecdsa_p384 };
  return packPrivateBundle(fauxKeys);
}

// ---------- Recovery code formatting ----------

const BASE32_ALPHABET = "abcdefghijkmnpqrstuvwxyz23456789";

export function bytesToRecoveryCode(bytes) {
  // Crockford-style base32 (no 0/1/l/o), grouped 4-4-4-... for readability.
  let bits = 0;
  let value = 0;
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out.match(/.{1,4}/g).join("-");
}

export function recoveryCodeToBytes(code) {
  const cleaned = code.toLowerCase().replace(/[^a-z0-9]/g, "");
  const inv = new Map();
  for (let i = 0; i < BASE32_ALPHABET.length; i++) inv.set(BASE32_ALPHABET[i], i);
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of cleaned) {
    const v = inv.get(ch);
    if (v === undefined) throw new Error(`invalid recovery code character: ${ch}`);
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export function generateRecoveryCodeBytes(length = 24) {
  return crypto.getRandomValues(new Uint8Array(length));
}

// ---------- Hybrid KEM (X25519 + ML-KEM-768) ----------

const HYBRID_KEM_INFO = enc.encode("pqshare:hybrid-kem-v1");

function hybridContext(ephX25519Pub, recipientX25519Pub, recipientMlkemPub, kemCt) {
  return concatBytes(
    HYBRID_KEM_INFO,
    new Uint8Array([0x00]),
    ephX25519Pub,
    recipientX25519Pub,
    recipientMlkemPub,
    kemCt,
  );
}

/** Returns {ephemeralX25519Pub, kemCiphertext, wrapKey} for the given recipient.
 *  Default args preserve legacy callers; new callers should pass hashFn and keyLen. */
export function hybridEncapsulate(recipientPubs, { hashFn = sha512, keyLen = 32 } = {}) {
  const rxPub = recipientPubs.x25519;
  const rkPub = recipientPubs.ml_kem_768;
  const ephPriv = x25519.utils.randomPrivateKey();
  const ephPub = x25519.getPublicKey(ephPriv);
  const ss1 = x25519.getSharedSecret(ephPriv, rxPub);

  const { cipherText, sharedSecret: ss2 } = ml_kem768.encapsulate(rkPub);

  const ikm = concatBytes(ss1, ss2);
  const info = hybridContext(ephPub, rxPub, rkPub, cipherText);
  const wrapKey = hkdf(hashFn, ikm, undefined, info, keyLen);
  return { ephemeralX25519Pub: ephPub, kemCiphertext: cipherText, wrapKey };
}

/** Reconstructs wrapKey from the recipient's view of an upload. */
export function hybridDecapsulate({ ephemeralX25519Pub, kemCiphertext, recipientPrivs, recipientPubs }, { hashFn = sha512, keyLen = 32 } = {}) {
  const ss1 = x25519.getSharedSecret(recipientPrivs.x25519Priv, ephemeralX25519Pub);
  const ss2 = ml_kem768.decapsulate(kemCiphertext, recipientPrivs.mlkemPriv);
  const ikm = concatBytes(ss1, ss2);
  const info = hybridContext(ephemeralX25519Pub, recipientPubs.x25519, recipientPubs.ml_kem_768, kemCiphertext);
  return hkdf(hashFn, ikm, undefined, info, keyLen);
}

// ---------- Hash dispatch (used by signing transcript & HKDF) ----------

const HASH_FNS = {
  "SHA-256":  sha256,
  "SHA-384":  sha384,
  "SHA-512":  sha512,
  "SHA3-512": sha3_512,
};

export function hashFnFor(name) {
  const h = HASH_FNS[name];
  if (!h) throw new Error(`unsupported hash: ${name}`);
  return h;
}

/** Hash `data` (Uint8Array) with the named algorithm; returns Uint8Array. */
export function digest(name, data) {
  return hashFnFor(name)(data);
}

// ---------- Signature transcript ----------

/** Compute hash(ciphertext) || utf8(metadata_json). The hash is suite-determined. */
export async function buildSigningTranscript(ciphertext, metadataJson, hashName = "SHA-256") {
  const h = digest(hashName, ciphertext);
  return concatBytes(h, enc.encode(metadataJson));
}

// ---------- Signature primitives ----------

export function ed25519Sign(message, priv) { return ed25519.sign(message, priv); }
export function ed25519Verify(message, sig, pub) { return ed25519.verify(sig, message, pub); }

export function mldsa65Sign(message, priv) { return ml_dsa65.sign(priv, message); }
export function mldsa65Verify(message, sig, pub) { return ml_dsa65.verify(pub, message, sig); }

/** ECDSA-P384. The transcript is hashed first with `hashFn` (suite hash) before signing.
 *  Signature is raw R||S (96 bytes) for stable wire size. */
export function ecdsaP384Sign(message, priv, hashFn) {
  const h = hashFn(message);
  return p384.sign(h, priv).toCompactRawBytes();
}
export function ecdsaP384Verify(message, sig, pub, hashFn) {
  const h = hashFn(message);
  try { return p384.verify(sig, h, pub); }
  catch { return false; }
}

export function mldsa87Sign(message, priv) { return ml_dsa87.sign(priv, message); }
export function mldsa87Verify(message, sig, pub) { return ml_dsa87.verify(pub, message, sig); }

/** Dual signatures (Ed25519 + ML-DSA-65). Kept for callers that explicitly want both. */
export function dualSign(message, edPriv, mldsaPriv) {
  return { ed: ed25519Sign(message, edPriv), mldsa: mldsa65Sign(message, mldsaPriv) };
}

export function dualVerify(message, sigs, edPub, mldsaPub) {
  return ed25519Verify(message, sigs.ed, edPub) && mldsa65Verify(message, sigs.mldsa, mldsaPub);
}

// ---------- Single-algorithm KEM helpers (parameterized by HKDF hash) ----------

const X25519_KEM_INFO   = enc.encode("pqshare:x25519-kem-v1");
const MLKEM768_KEM_INFO = enc.encode("pqshare:mlkem768-kem-v1");

/** Classical-only KEX via X25519 ECDH. Returns wrapKey of length `keyLen`. */
export function x25519Encapsulate({ recipientX25519Pub, hashFn, keyLen }) {
  const ephPriv = x25519.utils.randomPrivateKey();
  const ephPub = x25519.getPublicKey(ephPriv);
  const ss = x25519.getSharedSecret(ephPriv, recipientX25519Pub);
  const info = concatBytes(X25519_KEM_INFO, new Uint8Array([0x00]), ephPub, recipientX25519Pub);
  const wrapKey = hkdf(hashFn, ss, undefined, info, keyLen);
  return { ephemeralX25519Pub: ephPub, wrapKey };
}

export function x25519Decapsulate({ ephemeralX25519Pub, recipientX25519Priv, recipientX25519Pub, hashFn, keyLen }) {
  const ss = x25519.getSharedSecret(recipientX25519Priv, ephemeralX25519Pub);
  const info = concatBytes(X25519_KEM_INFO, new Uint8Array([0x00]), ephemeralX25519Pub, recipientX25519Pub);
  return hkdf(hashFn, ss, undefined, info, keyLen);
}

/** Pure-PQ KEX via ML-KEM-768. Returns wrapKey of length `keyLen`. */
export function mlkem768Encapsulate({ recipientMlkemPub, hashFn, keyLen }) {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(recipientMlkemPub);
  const info = concatBytes(MLKEM768_KEM_INFO, new Uint8Array([0x00]), recipientMlkemPub, cipherText);
  const wrapKey = hkdf(hashFn, sharedSecret, undefined, info, keyLen);
  return { kemCiphertext: cipherText, wrapKey };
}

export function mlkem768Decapsulate({ kemCiphertext, recipientMlkemPriv, recipientMlkemPub, hashFn, keyLen }) {
  const ss = ml_kem768.decapsulate(kemCiphertext, recipientMlkemPriv);
  const info = concatBytes(MLKEM768_KEM_INFO, new Uint8Array([0x00]), recipientMlkemPub, kemCiphertext);
  return hkdf(hashFn, ss, undefined, info, keyLen);
}

// ---------- secp384r1 ECDH ----------

const SECP384R1_KEM_INFO  = enc.encode("pqshare:secp384r1-kem-v1");
const MLKEM1024_KEM_INFO  = enc.encode("pqshare:mlkem1024-kem-v1");

export function secp384r1Encapsulate({ recipientP384Pub, hashFn, keyLen }) {
  const ephPriv = p384.utils.randomPrivateKey();
  const ephPub = p384.getPublicKey(ephPriv, true); // compressed (49B)
  const sharedPoint = p384.getSharedSecret(ephPriv, recipientP384Pub, true);
  // Drop the leading SEC1 prefix byte to get the raw X coordinate (48B) — standard ECDH KDF input.
  const sharedX = sharedPoint.slice(1);
  const info = concatBytes(SECP384R1_KEM_INFO, new Uint8Array([0x00]), ephPub, recipientP384Pub);
  const wrapKey = hkdf(hashFn, sharedX, undefined, info, keyLen);
  return { ephemeralP384Pub: ephPub, wrapKey };
}

export function secp384r1Decapsulate({ ephemeralP384Pub, recipientP384Priv, recipientP384Pub, hashFn, keyLen }) {
  const sharedPoint = p384.getSharedSecret(recipientP384Priv, ephemeralP384Pub, true);
  const sharedX = sharedPoint.slice(1);
  const info = concatBytes(SECP384R1_KEM_INFO, new Uint8Array([0x00]), ephemeralP384Pub, recipientP384Pub);
  return hkdf(hashFn, sharedX, undefined, info, keyLen);
}

// ---------- ML-KEM-1024 ----------

export function mlkem1024Encapsulate({ recipientMlkemPub, hashFn, keyLen }) {
  const { cipherText, sharedSecret } = ml_kem1024.encapsulate(recipientMlkemPub);
  const info = concatBytes(MLKEM1024_KEM_INFO, new Uint8Array([0x00]), recipientMlkemPub, cipherText);
  const wrapKey = hkdf(hashFn, sharedSecret, undefined, info, keyLen);
  return { kemCiphertext: cipherText, wrapKey };
}

export function mlkem1024Decapsulate({ kemCiphertext, recipientMlkemPriv, recipientMlkemPub, hashFn, keyLen }) {
  const ss = ml_kem1024.decapsulate(kemCiphertext, recipientMlkemPriv);
  const info = concatBytes(MLKEM1024_KEM_INFO, new Uint8Array([0x00]), recipientMlkemPub, kemCiphertext);
  return hkdf(hashFn, ss, undefined, info, keyLen);
}

// ---------- File key sealing ----------

export function randomFileKey(byteLen = 32) {
  return crypto.getRandomValues(new Uint8Array(byteLen));
}

export const sealFileKey = aesGcmSeal;
export const openFileKey = aesGcmOpen;

