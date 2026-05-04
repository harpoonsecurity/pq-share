import { ed25519, x25519 } from "@noble/curves/ed25519";
import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256, sha512 } from "@noble/hashes/sha2";
import { argon2id } from "hash-wasm";

export { ed25519, x25519, ml_kem768, ml_dsa65, sha256, sha512 };

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

// ---------- AES-256-GCM (browser-native) ----------

export async function aesGcmSeal(key32, plaintext) {
  const cryptoKey = await crypto.subtle.importKey("raw", key32, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, plaintext)
  );
  return concatBytes(iv, ct);
}

export async function aesGcmOpen(key32, sealed) {
  const iv = sealed.subarray(0, 12);
  const ct = sealed.subarray(12);
  const cryptoKey = await crypto.subtle.importKey("raw", key32, "AES-GCM", false, ["decrypt"]);
  const pt = new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, ct)
  );
  return pt;
}

// ---------- Keypair generation ----------

export function generateKeypairs() {
  const x25519Priv = x25519.utils.randomPrivateKey();
  const x25519Pub = x25519.getPublicKey(x25519Priv);

  const ed25519Priv = ed25519.utils.randomPrivateKey();
  const ed25519Pub = ed25519.getPublicKey(ed25519Priv);

  const mlkemKp = ml_kem768.keygen();
  const mldsaKp = ml_dsa65.keygen();

  return {
    classical: {
      x25519: { priv: x25519Priv, pub: x25519Pub },
      ed25519: { priv: ed25519Priv, pub: ed25519Pub },
    },
    pq: {
      ml_kem_768: { priv: mlkemKp.secretKey, pub: mlkemKp.publicKey },
      ml_dsa_65: { priv: mldsaKp.secretKey, pub: mldsaKp.publicKey },
    },
  };
}

// ---------- Private-key bundle (length-prefixed concat) ----------

const BUNDLE_VERSION = 1;

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

export function packPrivateBundle(keys) {
  const parts = [
    new Uint8Array([BUNDLE_VERSION]),
    u32be(keys.classical.x25519.priv.length), keys.classical.x25519.priv,
    u32be(keys.classical.ed25519.priv.length), keys.classical.ed25519.priv,
    u32be(keys.pq.ml_kem_768.priv.length), keys.pq.ml_kem_768.priv,
    u32be(keys.pq.ml_dsa_65.priv.length), keys.pq.ml_dsa_65.priv,
  ];
  return concatBytes(...parts);
}

export function unpackPrivateBundle(buf) {
  if (buf[0] !== BUNDLE_VERSION) throw new Error(`unknown bundle version ${buf[0]}`);
  let off = 1;
  const readField = () => {
    const len = readU32be(buf, off);
    off += 4;
    const v = buf.slice(off, off + len);
    off += len;
    return v;
  };
  return {
    x25519Priv: readField(),
    ed25519Priv: readField(),
    mlkemPriv: readField(),
    mldsaPriv: readField(),
  };
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

/** Returns {ephemeralX25519Pub, kemCiphertext, wrapKey(32)} for the given recipient. */
export function hybridEncapsulate({ x25519: rxPub, ml_kem_768: rkPub }) {
  const ephPriv = x25519.utils.randomPrivateKey();
  const ephPub = x25519.getPublicKey(ephPriv);
  const ss1 = x25519.getSharedSecret(ephPriv, rxPub);

  const { cipherText, sharedSecret: ss2 } = ml_kem768.encapsulate(rkPub);

  const ikm = concatBytes(ss1, ss2);
  const info = hybridContext(ephPub, rxPub, rkPub, cipherText);
  const wrapKey = hkdf(sha512, ikm, undefined, info, 32);
  return { ephemeralX25519Pub: ephPub, kemCiphertext: cipherText, wrapKey };
}

/** Returns wrapKey(32) reconstructed from the recipient's view of an upload. */
export function hybridDecapsulate({ ephemeralX25519Pub, kemCiphertext, recipientPrivs, recipientPubs }) {
  const ss1 = x25519.getSharedSecret(recipientPrivs.x25519Priv, ephemeralX25519Pub);
  const ss2 = ml_kem768.decapsulate(kemCiphertext, recipientPrivs.mlkemPriv);
  const ikm = concatBytes(ss1, ss2);
  const info = hybridContext(ephemeralX25519Pub, recipientPubs.x25519, recipientPubs.ml_kem_768, kemCiphertext);
  return hkdf(sha512, ikm, undefined, info, 32);
}

// ---------- Dual signatures (Ed25519 + ML-DSA-65) ----------

/** Compute SHA-256(ciphertext) || utf8(metadata_json). This is what gets signed. */
export async function buildSigningTranscript(ciphertext, metadataJson) {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", ciphertext));
  return concatBytes(h, enc.encode(metadataJson));
}

export function dualSign(message, edPriv, mldsaPriv) {
  const ed = ed25519.sign(message, edPriv);
  const mldsa = ml_dsa65.sign(mldsaPriv, message);
  return { ed, mldsa };
}

export function dualVerify(message, sigs, edPub, mldsaPub) {
  const edOk = ed25519.verify(sigs.ed, message, edPub);
  const mldsaOk = ml_dsa65.verify(mldsaPub, message, sigs.mldsa);
  return edOk && mldsaOk;
}

// ---------- File key sealing ----------

export function randomFileKey() {
  return crypto.getRandomValues(new Uint8Array(32));
}

export const sealFileKey = aesGcmSeal;
export const openFileKey = aesGcmOpen;

