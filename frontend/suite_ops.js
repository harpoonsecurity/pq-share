// Suite-driven crypto dispatch.
//
// Given a CryptoSuite object (the picker's output), exposes:
//
//   ops.aead.keyLen                                    bytes of file key
//   ops.aead.seal(key, plaintext)      -> Uint8Array   AES-GCM seal
//   ops.aead.open(key, sealed)         -> Uint8Array   AES-GCM open
//   ops.kem.encapsulate(recipientPubs) -> { wrapKey, ephemeralX25519Pub?, kemCiphertext? }
//   ops.kem.decapsulate({ ephemeralX25519Pub, kemCiphertext, recipientPrivs, recipientPubs }) -> wrapKey
//   ops.kem.uses_x25519, ops.kem.uses_mlkem            wire-format hints (which fields populate)
//   ops.sig.sign(message, sender_keys)         -> { ed?, mldsa? }
//   ops.sig.verify(message, sigs, sender_pubs) -> bool
//   ops.sig.uses_ed25519, ops.sig.uses_mldsa65         wire-format hints
//   ops.transcriptHash                                  hash name passed to buildSigningTranscript()
//
// Subset notes for v1:
//   KEX:  X25519 | X25519MLKEM768 | ML-KEM-768   (others need new keypairs)
//   SIG:  Ed25519 | Ed25519+ML-DSA-65 | ML-DSA-65 (others need new keypairs)
//   AEAD: AES-128-GCM | AES-256-GCM             (ChaCha20 / GCM-SIV need new lib)
//   HASH: SHA-256 | SHA-384 | SHA-512 | SHA3-512  all supported

import {
  aesGcmSeal, aesGcmOpen,
  hashFnFor,
  hybridEncapsulate, hybridDecapsulate,
  x25519Encapsulate, x25519Decapsulate,
  mlkem768Encapsulate, mlkem768Decapsulate,
  secp384r1Encapsulate, secp384r1Decapsulate,
  mlkem1024Encapsulate, mlkem1024Decapsulate,
  ed25519Sign, ed25519Verify,
  mldsa65Sign, mldsa65Verify,
  ecdsaP384Sign, ecdsaP384Verify,
  mldsa87Sign, mldsa87Verify,
  dualSign, dualVerify,
} from "/static/crypto.js";

export const SUPPORTED_KEX  = new Set(["X25519", "secp384r1", "X25519MLKEM768", "ML-KEM-768", "ML-KEM-1024"]);
export const SUPPORTED_SIG  = new Set(["Ed25519", "ECDSA-P384", "Ed25519+ML-DSA-65", "ML-DSA-65", "ML-DSA-87"]);
export const SUPPORTED_SYM  = new Set(["AES-128-GCM", "AES-256-GCM"]);
export const SUPPORTED_HASH = new Set(["SHA-256", "SHA-384", "SHA-512", "SHA3-512"]);

export function isSuiteExecutable(suite) {
  return SUPPORTED_KEX.has(suite.kex)
      && SUPPORTED_SIG.has(suite.sig)
      && SUPPORTED_SYM.has(suite.sym)
      && SUPPORTED_HASH.has(suite.hash);
}

// ---------- AEAD ----------

function buildAead(symName) {
  if (symName === "AES-128-GCM") return { keyLen: 16, seal: aesGcmSeal, open: aesGcmOpen };
  if (symName === "AES-256-GCM") return { keyLen: 32, seal: aesGcmSeal, open: aesGcmOpen };
  throw new Error(`unsupported AEAD in v1 dispatch: ${symName}`);
}

// ---------- KEM ----------

function buildKem(kexName, hashName, keyLen) {
  const hashFn = hashFnFor(hashName);
  if (kexName === "X25519") {
    return {
      uses_x25519: true, uses_mlkem: false,
      encapsulate(recipientPubs) {
        const { ephemeralX25519Pub, wrapKey } = x25519Encapsulate({
          recipientX25519Pub: recipientPubs.x25519, hashFn, keyLen,
        });
        return { ephemeralX25519Pub, kemCiphertext: new Uint8Array(0), wrapKey };
      },
      decapsulate({ ephemeralX25519Pub, recipientPrivs, recipientPubs }) {
        return x25519Decapsulate({
          ephemeralX25519Pub,
          recipientX25519Priv: recipientPrivs.x25519Priv,
          recipientX25519Pub: recipientPubs.x25519,
          hashFn, keyLen,
        });
      },
    };
  }
  if (kexName === "X25519MLKEM768") {
    return {
      uses_x25519: true, uses_mlkem: true,
      encapsulate(recipientPubs) {
        return hybridEncapsulate(recipientPubs, { hashFn, keyLen });
      },
      decapsulate(args) {
        return hybridDecapsulate(args, { hashFn, keyLen });
      },
    };
  }
  if (kexName === "ML-KEM-768") {
    return {
      uses_x25519: false, uses_mlkem: true,
      encapsulate(recipientPubs) {
        const { kemCiphertext, wrapKey } = mlkem768Encapsulate({
          recipientMlkemPub: recipientPubs.ml_kem_768, hashFn, keyLen,
        });
        return { ephemeralX25519Pub: new Uint8Array(0), kemCiphertext, wrapKey };
      },
      decapsulate({ kemCiphertext, recipientPrivs, recipientPubs }) {
        return mlkem768Decapsulate({
          kemCiphertext,
          recipientMlkemPriv: recipientPrivs.mlkemPriv,
          recipientMlkemPub: recipientPubs.ml_kem_768,
          hashFn, keyLen,
        });
      },
    };
  }
  if (kexName === "secp384r1") {
    // Wire-format reuse: the "ephemeral_x25519_pub" slot carries a P-384 compressed pub (49B).
    return {
      uses_x25519: true, uses_mlkem: false,
      encapsulate(recipientPubs) {
        const { ephemeralP384Pub, wrapKey } = secp384r1Encapsulate({
          recipientP384Pub: recipientPubs.secp384r1, hashFn, keyLen,
        });
        return { ephemeralX25519Pub: ephemeralP384Pub, kemCiphertext: new Uint8Array(0), wrapKey };
      },
      decapsulate({ ephemeralX25519Pub, recipientPrivs, recipientPubs }) {
        return secp384r1Decapsulate({
          ephemeralP384Pub: ephemeralX25519Pub,
          recipientP384Priv: recipientPrivs.secp384r1Priv,
          recipientP384Pub: recipientPubs.secp384r1,
          hashFn, keyLen,
        });
      },
    };
  }
  if (kexName === "ML-KEM-1024") {
    return {
      uses_x25519: false, uses_mlkem: true,
      encapsulate(recipientPubs) {
        const { kemCiphertext, wrapKey } = mlkem1024Encapsulate({
          recipientMlkemPub: recipientPubs.ml_kem_1024, hashFn, keyLen,
        });
        return { ephemeralX25519Pub: new Uint8Array(0), kemCiphertext, wrapKey };
      },
      decapsulate({ kemCiphertext, recipientPrivs, recipientPubs }) {
        return mlkem1024Decapsulate({
          kemCiphertext,
          recipientMlkemPriv: recipientPrivs.mlkem1024Priv,
          recipientMlkemPub: recipientPubs.ml_kem_1024,
          hashFn, keyLen,
        });
      },
    };
  }
  throw new Error(`unsupported KEX: ${kexName}`);
}

// ---------- Signature ----------

function buildSig(sigName, hashName) {
  const hashFn = hashFnFor(hashName);
  if (sigName === "Ed25519") {
    return {
      uses_ed25519: true, uses_mldsa65: false,
      sign(message, { ed25519Priv }) {
        return { ed: ed25519Sign(message, ed25519Priv), mldsa: new Uint8Array(0) };
      },
      verify(message, sigs, sender_pubs) {
        return ed25519Verify(message, sigs.ed, sender_pubs.ed25519);
      },
    };
  }
  if (sigName === "Ed25519+ML-DSA-65") {
    return {
      uses_ed25519: true, uses_mldsa65: true,
      sign(message, { ed25519Priv, mldsaPriv }) {
        return dualSign(message, ed25519Priv, mldsaPriv);
      },
      verify(message, sigs, sender_pubs) {
        return dualVerify(message, sigs, sender_pubs.ed25519, sender_pubs.ml_dsa_65);
      },
    };
  }
  if (sigName === "ML-DSA-65") {
    return {
      uses_ed25519: false, uses_mldsa65: true,
      sign(message, { mldsaPriv }) {
        return { ed: new Uint8Array(0), mldsa: mldsa65Sign(message, mldsaPriv) };
      },
      verify(message, sigs, sender_pubs) {
        return mldsa65Verify(message, sigs.mldsa, sender_pubs.ml_dsa_65);
      },
    };
  }
  if (sigName === "ECDSA-P384") {
    // Wire-format reuse: sig_ed25519 slot carries the 96B raw R||S.
    return {
      uses_ed25519: true, uses_mldsa65: false,
      sign(message, { ecdsap384Priv }) {
        return { ed: ecdsaP384Sign(message, ecdsap384Priv, hashFn), mldsa: new Uint8Array(0) };
      },
      verify(message, sigs, sender_pubs) {
        return ecdsaP384Verify(message, sigs.ed, sender_pubs.ecdsa_p384, hashFn);
      },
    };
  }
  if (sigName === "ML-DSA-87") {
    return {
      uses_ed25519: false, uses_mldsa65: true,
      sign(message, { mldsa87Priv }) {
        return { ed: new Uint8Array(0), mldsa: mldsa87Sign(message, mldsa87Priv) };
      },
      verify(message, sigs, sender_pubs) {
        return mldsa87Verify(message, sigs.mldsa, sender_pubs.ml_dsa_87);
      },
    };
  }
  throw new Error(`unsupported signature: ${sigName}`);
}

// ---------- Public entry ----------

export function getOps(suite) {
  if (!isSuiteExecutable(suite)) {
    throw new Error(
      `suite contains primitives not yet implemented in this build (kex=${suite.kex}, sig=${suite.sig}, sym=${suite.sym}, hash=${suite.hash})`
    );
  }
  const aead = buildAead(suite.sym);
  const kem  = buildKem(suite.kex, suite.hash, aead.keyLen);
  const sig  = buildSig(suite.sig, suite.hash);
  return {
    aead,
    kem,
    sig,
    transcriptHash: suite.hash,
  };
}

/** Default suite used to decrypt legacy uploads that have no `suite` field stored. */
export const LEGACY_SUITE = {
  preset: "fips-140-3-hybrid",
  tls: "1.3",
  rng: "AES-CTR-DRBG-256",
  kex: "X25519MLKEM768",
  hash: "SHA-512",         // legacy hybridDecapsulate used SHA-512
  sym: "AES-256-GCM",
  sig: "Ed25519+ML-DSA-65",
};
