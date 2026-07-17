// File: digital_signature.js
// Author: Robert C. Broeckelmann Jr.
// Notes:
//
// Standalone Digital Signature tool with three panes:
//   #1 SLH-DSA (FIPS 205, post-quantum)      — @noble/post-quantum
//   #2 RSA (PKCS#1 v1.5 / PSS) + any hash     — node-forge (keygen) + pure-JS padding
//   #3 ECC (ECDSA over P-256/P-384/P-521/secp256k1, EdDSA) + any hash — @noble/curves
//
// The RSA and ECC panes deliberately DO NOT use the Web Crypto API: crypto.subtle
// only supports the SHA family, whereas these panes support a wide range of hash
// algorithms (SHA-2, SHA-3, RIPEMD-160, BLAKE2b, and the legacy/broken SHA-1 and
// MD5). Everything runs in the browser; no key material is ever persisted.
//
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var slh = require("@noble/post-quantum/slh-dsa.js");
var mldsa = require("@noble/post-quantum/ml-dsa.js");
var forge = require("node-forge");
var p256 = require("@noble/curves/p256").p256;
var p384 = require("@noble/curves/p384").p384;
var p521 = require("@noble/curves/p521").p521;
var secp256k1 = require("@noble/curves/secp256k1").secp256k1;
var schnorr = require("@noble/curves/secp256k1").schnorr;
var ed25519 = require("@noble/curves/ed25519").ed25519;
var ed448 = require("@noble/curves/ed448").ed448;
var bls12_381 = require("@noble/curves/bls12-381").bls12_381;
var nobleSha256 = require("@noble/hashes/sha256").sha256;
var nobleSha512 = require("@noble/hashes/sha512");
var nobleSha1 = require("@noble/hashes/sha1").sha1;
var nobleSha3 = require("@noble/hashes/sha3");
var nobleRipemd160 = require("@noble/hashes/ripemd160").ripemd160;
var nobleBlake2b = require("@noble/hashes/blake2b").blake2b;
var nobleBlake3 = require("@noble/hashes/blake3").blake3;
var log = bunyan.createLogger({ name: 'digital_signature',
                                level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

// ---------------------------------------------------------------------------
// SLH-DSA parameter sets (FIPS 205). Keyed by the label shown in the dropdown.
// ---------------------------------------------------------------------------
var PARAM_SETS = {
  'SLH-DSA-SHA2-128s': slh.slh_dsa_sha2_128s,
  'SLH-DSA-SHA2-128f': slh.slh_dsa_sha2_128f,
  'SLH-DSA-SHA2-192s': slh.slh_dsa_sha2_192s,
  'SLH-DSA-SHA2-192f': slh.slh_dsa_sha2_192f,
  'SLH-DSA-SHA2-256s': slh.slh_dsa_sha2_256s,
  'SLH-DSA-SHA2-256f': slh.slh_dsa_sha2_256f,
  'SLH-DSA-SHAKE-128s': slh.slh_dsa_shake_128s,
  'SLH-DSA-SHAKE-128f': slh.slh_dsa_shake_128f,
  'SLH-DSA-SHAKE-192s': slh.slh_dsa_shake_192s,
  'SLH-DSA-SHAKE-192f': slh.slh_dsa_shake_192f,
  'SLH-DSA-SHAKE-256s': slh.slh_dsa_shake_256s,
  'SLH-DSA-SHAKE-256f': slh.slh_dsa_shake_256f
};

// ---------------------------------------------------------------------------
// ML-DSA parameter sets (FIPS 204, formerly CRYSTALS-Dilithium).
// ---------------------------------------------------------------------------
var ML_PARAM_SETS = {
  'ML-DSA-44': mldsa.ml_dsa44,
  'ML-DSA-65': mldsa.ml_dsa65,
  'ML-DSA-87': mldsa.ml_dsa87
};

// ---------------------------------------------------------------------------
// Small DOM helpers
// ---------------------------------------------------------------------------
function val(id) {
  var el = document.getElementById(id);
  return el ? el.value : '';
}
function setVal(id, v) {
  var el = document.getElementById(id);
  if (el) el.value = v;
}

// ---------------------------------------------------------------------------
// Byte / base64 / hex helpers
// ---------------------------------------------------------------------------
function strBytes(s) { return new TextEncoder().encode(s); }

function bytesToB64(bytes) {
  var b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  var bin = '';
  for (var i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
  return btoa(bin);
}
function b64ToBytes(b64) {
  var bin = atob(String(b64).replace(/\s+/g, ''));
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function bytesToHex(bytes) {
  var s = '';
  for (var i = 0; i < bytes.length; i++) s += ('0' + bytes[i].toString(16)).slice(-2);
  return s;
}
function hexToBytes(hex) {
  var h = String(hex).replace(/\s+/g, '');
  var a = new Uint8Array(h.length >> 1);
  for (var i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16);
  return a;
}
function concatBytes() {
  var total = 0, i;
  for (i = 0; i < arguments.length; i++) total += arguments[i].length;
  var out = new Uint8Array(total), off = 0;
  for (i = 0; i < arguments.length; i++) { out.set(arguments[i], off); off += arguments[i].length; }
  return out;
}
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
function randomBytes(n) { var a = new Uint8Array(n); crypto.getRandomValues(a); return a; }

// PEM framing over raw bytes (used by SLH-DSA, whose keys are opaque bytes).
function rawToPem(bytes, label) {
  var b64 = bytesToB64(bytes);
  var lines = b64.match(/.{1,64}/g).join('\n');
  return '-----BEGIN ' + label + '-----\n' + lines + '\n-----END ' + label + '-----\n';
}
function pemToRaw(pem) {
  var b64 = String(pem).split(/\r?\n/)
    .filter(function (line) { return line.indexOf('-----') === -1; })
    .join('').replace(/\s+/g, '');
  return b64ToBytes(b64);
}

// ---------------------------------------------------------------------------
// Hash registry (shared by the RSA and ECC panes). `oid` is the DER-encoded
// DigestInfo prefix required by RSA PKCS#1 v1.5 (null => v1.5 not available for
// that hash — use PSS). `security` flags legacy/broken hashes for the UI.
// ---------------------------------------------------------------------------
function md5Digest(bytes) {
  var md = forge.md.md5.create();
  md.update(forge.util.binary.raw.encode(bytes));
  return forge.util.binary.raw.decode(md.digest().getBytes());
}
var HASHES = {
  'SHA-256':     { fn: nobleSha256,          oid: '3031300d060960864801650304020105000420' },
  'SHA-384':     { fn: nobleSha512.sha384,   oid: '3041300d060960864801650304020205000430' },
  'SHA-512':     { fn: nobleSha512.sha512,   oid: '3051300d060960864801650304020305000440' },
  'SHA3-256':    { fn: nobleSha3.sha3_256,   oid: '3031300d060960864801650304020805000420' },
  'SHA3-384':    { fn: nobleSha3.sha3_384,   oid: '3041300d060960864801650304020905000430' },
  'SHA3-512':    { fn: nobleSha3.sha3_512,   oid: '3051300d060960864801650304020a05000440' },
  'BLAKE2b-512': { fn: nobleBlake2b,         oid: null },
  'BLAKE3-256':  { fn: nobleBlake3,          oid: null },
  'RIPEMD-160':  { fn: nobleRipemd160,       oid: '3021300906052b2403020105000414' },
  'SHA-1':       { fn: nobleSha1,            oid: '3021300906052b0e03021a05000414' },
  'MD5':         { fn: md5Digest,            oid: '3020300c06082a864886f70d020505000410' }
};
function digestOf(hashName, bytes) {
  var h = HASHES[hashName];
  if (!h) throw new Error('Unknown hash: ' + hashName);
  return h.fn(bytes);
}

// ---------------------------------------------------------------------------
// ECC curves (pane #3). ECDSA curves take a selectable hash; EdDSA curves have
// their hash fixed by the scheme (Ed25519 -> SHA-512, Ed448 -> SHAKE256).
// ---------------------------------------------------------------------------
var CURVES = {
  'P-256':     { kind: 'ecdsa', curve: p256,      jwkCrv: 'P-256',     fieldBytes: 32 },
  'P-384':     { kind: 'ecdsa', curve: p384,      jwkCrv: 'P-384',     fieldBytes: 48 },
  'P-521':     { kind: 'ecdsa', curve: p521,      jwkCrv: 'P-521',     fieldBytes: 66 },
  'secp256k1': { kind: 'ecdsa', curve: secp256k1, jwkCrv: 'secp256k1', fieldBytes: 32 },
  'Ed25519':   { kind: 'eddsa', curve: ed25519,   jwkCrv: 'Ed25519' },
  'Ed448':     { kind: 'eddsa', curve: ed448,     jwkCrv: 'Ed448' },
  // Schnorr (BIP-340 over secp256k1) and BLS (BLS12-381) hash the message
  // themselves, so the Hash selection does not apply to them.
  'secp256k1-schnorr': { kind: 'schnorr', curve: schnorr },
  'bls12-381':         { kind: 'bls',     curve: bls12_381 }
};

// SLH-DSA / RSA key generation can block for a moment; defer so the "…" status
// paints first.
function defer(fn) { setTimeout(fn, 15); }

// ===========================================================================
// Pane #1 — SLH-DSA (post-quantum)
// ===========================================================================
function currentAlg() {
  var name = val('ds_param');
  var alg = PARAM_SETS[name];
  if (!alg) throw new Error('Unknown parameter set: ' + name);
  return alg;
}

function triggerDownload(filename, data, mime) {
  var blob = new Blob([data], { type: mime || 'application/octet-stream' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
}

function generateKeys() {
  var name = val('ds_param');
  setVal('ds_status', 'Generating ' + name + ' key pair…');
  defer(function () {
    try {
      var alg = currentAlg();
      var kp = alg.keygen();
      setVal('ds_private_key', rawToPem(kp.secretKey, 'SLH-DSA PRIVATE KEY'));
      setVal('ds_public_key', rawToPem(kp.publicKey, 'SLH-DSA PUBLIC KEY'));
      setVal('ds_status', 'Generated ' + name + ' key pair (public ' +
        kp.publicKey.length + ' B, secret ' + kp.secretKey.length + ' B).');
    } catch (e) {
      log.error('generateKeys: ' + e.message);
      setVal('ds_status', 'Key generation error: ' + e.message);
    }
  });
  return false;
}

// ---------------------------------------------------------------------------
// Keystore download helpers (shared by all three panes).
//
// Formats: PEM, DER, JWK, PKCS#12. An optional password encrypts the private
// material (encrypted PKCS#8 for PEM/DER, a PBES2 JWE for JWK, native for
// PKCS#12). Not every key type supports every format — unsupported combinations
// report a clear status message rather than emit a broken file.
//
// PBES2 (JWK password protection) uses the Web Crypto API. That is unrelated to
// the panes' deliberate avoidance of crypto.subtle for *signing* (which exists
// only to allow non-SHA hashes); PBES2 here is standard and hash-agnostic.
// ---------------------------------------------------------------------------
function b64u(bytes) {
  var b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  var bin = '';
  for (var i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function forgeBnB64u(bn) {
  var h = bn.toString(16); if (h.length % 2) h = '0' + h;
  return b64u(hexToBytes(h));
}
function derBytes(asn1) {
  return new Uint8Array(forge.util.binary.raw.decode(forge.asn1.toDer(asn1).getBytes()));
}
// A native BigInt (from @noble affine coords) as fixed-length big-endian bytes.
function bigToBytes(x, len) {
  var h = x.toString(16); while (h.length < len * 2) h = '0' + h;
  return hexToBytes(h);
}

// Password-protect a string as a compact PBES2 JWE (RFC 7518 §4.8), via subtle.
async function pbes2JweEncrypt(plaintext, password) {
  var alg = 'PBES2-HS256+A128KW', enc = 'A256GCM';
  var p2s = randomBytes(16), p2c = 100000;
  var pwKey = await crypto.subtle.importKey('raw', strBytes(password), 'PBKDF2', false, ['deriveKey']);
  var salt = concatBytes(strBytes(alg), new Uint8Array([0]), p2s);
  var wrapKey = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: salt, iterations: p2c, hash: 'SHA-256' },
    pwKey, { name: 'AES-KW', length: 128 }, false, ['wrapKey']);
  var cek = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  var wrapped = new Uint8Array(await crypto.subtle.wrapKey('raw', cek, wrapKey, 'AES-KW'));
  var ph = { alg: alg, enc: enc, p2s: b64u(p2s), p2c: p2c };
  var phB64 = b64u(strBytes(JSON.stringify(ph)));
  var iv = randomBytes(12);
  var full = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv, additionalData: strBytes(phB64), tagLength: 128 }, cek, strBytes(plaintext)));
  return [phB64, b64u(wrapped), b64u(iv), b64u(full.slice(0, full.length - 16)), b64u(full.slice(full.length - 16))].join('.');
}

// Emit a JWK set (public + private), optionally PBES2-encrypted, as a download.
async function downloadJwkSet(jwks, password, baseName, statusId) {
  var text = JSON.stringify({ keys: jwks }, null, 2);
  if (password) {
    triggerDownload(baseName + '.jwe', await pbes2JweEncrypt(text, password), 'application/jose');
    setVal(statusId, 'Downloaded PBES2-encrypted JWK set (' + baseName + '.jwe).');
  } else {
    triggerDownload(baseName + '.jwk.json', text, 'application/jwk+json');
    setVal(statusId, 'Downloaded JWK set (' + baseName + '.jwk.json).');
  }
}

// ---------------------------------------------------------------------------
// Pane #1 SLH-DSA download: PEM (raw, unencrypted) and JWK (+password) are
// supported; DER and PKCS#12 have no standard SLH-DSA representation.
// ---------------------------------------------------------------------------
async function downloadKeys() {
  var fmt = val('ds_slh_ks_format') || 'pem', pw = val('ds_slh_ks_password');
  var priv = val('ds_private_key'), pub = val('ds_public_key');
  if (!priv && !pub) { setVal('ds_status', 'Nothing to download — generate a key pair first.'); return false; }
  try {
    if (fmt === 'pem') {
      if (pw) { setVal('ds_status', 'Password protection for SLH-DSA is only available in JWK format. Choose JWK.'); return false; }
      triggerDownload('slh-dsa-keys.pem', pub + '\n' + priv, 'application/x-pem-file');
      setVal('ds_status', 'Downloaded key pair (slh-dsa-keys.pem).');
    } else if (fmt === 'jwk') {
      var alg = val('ds_param');
      var pubJwk = { kty: 'AKP', alg: alg, x: b64u(pemToRaw(pub)), use: 'sig' };
      var privJwk = { kty: 'AKP', alg: alg, x: b64u(pemToRaw(pub)), d: b64u(pemToRaw(priv)), use: 'sig' };
      await downloadJwkSet([pubJwk, privJwk], pw, 'slh-dsa-keys', 'ds_status');
    } else {
      setVal('ds_status', fmt.toUpperCase() + ' export is not supported for SLH-DSA keys. Use PEM or JWK.');
    }
  } catch (e) {
    log.error('downloadKeys: ' + e.message);
    setVal('ds_status', 'Download error: ' + e.message);
  }
  return false;
}

function sign() {
  var name = val('ds_param');
  setVal('ds_status', 'Signing with ' + name + '…');
  defer(function () {
    try {
      var alg = currentAlg();
      var sk = pemToRaw(val('ds_private_key'));
      var sig = alg.sign(sk, strBytes(val('ds_value')));
      setVal('ds_signature', bytesToB64(sig));
      setVal('ds_status', 'Signed (' + name + ') — signature is ' + sig.length + ' bytes.');
    } catch (e) {
      log.error('sign: ' + e.message);
      setVal('ds_status', 'Sign error: ' + e.message + ' (does the parameter set match the key pair?)');
    }
  });
  return false;
}

function validate() {
  var name = val('ds_param');
  setVal('ds_status', 'Validating signature with ' + name + '…');
  defer(function () {
    try {
      var alg = currentAlg();
      var ok = alg.verify(pemToRaw(val('ds_public_key')), strBytes(val('ds_value')), b64ToBytes(val('ds_signature')));
      setVal('ds_status', ok
        ? 'Signature VALID ✓ — the signature matches the value and public key.'
        : 'Signature INVALID ✗ — the signature does not verify.');
    } catch (e) {
      log.error('validate: ' + e.message);
      setVal('ds_status', 'Validation error: ' + e.message + ' (does the parameter set match the key pair?)');
    }
  });
  return false;
}

// ===========================================================================
// Pane #4 — ML-DSA (FIPS 204, post-quantum)
// ===========================================================================
function currentMldsaAlg() {
  var name = val('ds_ml_param');
  var alg = ML_PARAM_SETS[name];
  if (!alg) throw new Error('Unknown ML-DSA parameter set: ' + name);
  return alg;
}

function mldsaGenerateKeys() {
  var name = val('ds_ml_param');
  setVal('ds_ml_status', 'Generating ' + name + ' key pair…');
  defer(function () {
    try {
      var kp = currentMldsaAlg().keygen();
      setVal('ds_ml_private_key', rawToPem(kp.secretKey, 'ML-DSA PRIVATE KEY'));
      setVal('ds_ml_public_key', rawToPem(kp.publicKey, 'ML-DSA PUBLIC KEY'));
      setVal('ds_ml_status', 'Generated ' + name + ' key pair (public ' +
        kp.publicKey.length + ' B, secret ' + kp.secretKey.length + ' B).');
    } catch (e) {
      log.error('mldsaGenerateKeys: ' + e.message);
      setVal('ds_ml_status', 'Key generation error: ' + e.message);
    }
  });
  return false;
}

function mldsaSign() {
  var name = val('ds_ml_param');
  setVal('ds_ml_status', 'Signing with ' + name + '…');
  defer(function () {
    try {
      var sig = currentMldsaAlg().sign(pemToRaw(val('ds_ml_private_key')), strBytes(val('ds_ml_value')));
      setVal('ds_ml_signature', bytesToB64(sig));
      setVal('ds_ml_status', 'Signed (' + name + ') — signature is ' + sig.length + ' bytes.');
    } catch (e) {
      log.error('mldsaSign: ' + e.message);
      setVal('ds_ml_status', 'Sign error: ' + e.message + ' (does the parameter set match the key pair?)');
    }
  });
  return false;
}

function mldsaValidate() {
  var name = val('ds_ml_param');
  setVal('ds_ml_status', 'Validating signature with ' + name + '…');
  defer(function () {
    try {
      var ok = currentMldsaAlg().verify(pemToRaw(val('ds_ml_public_key')), strBytes(val('ds_ml_value')), b64ToBytes(val('ds_ml_signature')));
      setVal('ds_ml_status', ok
        ? 'Signature VALID ✓ — the signature matches the value and public key.'
        : 'Signature INVALID ✗ — the signature does not verify.');
    } catch (e) {
      log.error('mldsaValidate: ' + e.message);
      setVal('ds_ml_status', 'Validation error: ' + e.message + ' (does the parameter set match the key pair?)');
    }
  });
  return false;
}

// PEM (raw, unencrypted) and JWK (+password) supported; DER/PKCS#12 have no
// standard ML-DSA representation.
async function mldsaDownloadKeys() {
  var fmt = val('ds_ml_ks_format') || 'pem', pw = val('ds_ml_ks_password');
  var priv = val('ds_ml_private_key'), pub = val('ds_ml_public_key');
  if (!priv && !pub) { setVal('ds_ml_status', 'Nothing to download — generate a key pair first.'); return false; }
  try {
    if (fmt === 'pem') {
      if (pw) { setVal('ds_ml_status', 'Password protection for ML-DSA is only available in JWK format. Choose JWK.'); return false; }
      triggerDownload('ml-dsa-keys.pem', pub + '\n' + priv, 'application/x-pem-file');
      setVal('ds_ml_status', 'Downloaded key pair (ml-dsa-keys.pem).');
    } else if (fmt === 'jwk') {
      var alg = val('ds_ml_param');
      var pubJwk = { kty: 'AKP', alg: alg, x: b64u(pemToRaw(pub)), use: 'sig' };
      var privJwk = { kty: 'AKP', alg: alg, x: b64u(pemToRaw(pub)), d: b64u(pemToRaw(priv)), use: 'sig' };
      await downloadJwkSet([pubJwk, privJwk], pw, 'ml-dsa-keys', 'ds_ml_status');
    } else {
      setVal('ds_ml_status', fmt.toUpperCase() + ' export is not supported for ML-DSA keys. Use PEM or JWK.');
    }
  } catch (e) {
    log.error('mldsaDownloadKeys: ' + e.message);
    setVal('ds_ml_status', 'Download error: ' + e.message);
  }
  return false;
}

// ===========================================================================
// Pane #2 — RSA (PKCS#1 v1.5 / PSS) with a selectable hash (pure JS)
// ===========================================================================
// RSA primitives on native BigInt (this is a debugging tool, not a hardened
// constant-time implementation).
// BigInt constants written as BigInt(...) rather than 0n/1n literals: browserify's
// insert-module-globals lexes this file (it references `process`) with an esprima
// build that predates BigInt literals.
var _B0 = BigInt(0), _B1 = BigInt(1), _B8 = BigInt(8), _B255 = BigInt(255);
function forgeToBig(fbn) { return BigInt('0x' + fbn.toString(16)); }
function os2ip(bytes) { var x = _B0; for (var i = 0; i < bytes.length; i++) x = (x << _B8) | BigInt(bytes[i]); return x; }
function i2osp(x, len) { var o = new Uint8Array(len); for (var i = len - 1; i >= 0; i--) { o[i] = Number(x & _B255); x >>= _B8; } return o; }
function modpow(b, e, m) { var r = _B1; b %= m; while (e > _B0) { if (e & _B1) r = r * b % m; e >>= _B1; b = b * b % m; } return r; }

// EMSA-PKCS1-v1_5 (RFC 8017 §9.2): 0x00 01 FF..FF 00 || DigestInfo(hash) || H
function emsaPkcs1v15(msg, hashName, emLen) {
  var h = HASHES[hashName];
  if (!h.oid) throw new Error('PKCS#1 v1.5 has no DigestInfo OID for ' + hashName + '. Choose PSS padding instead.');
  var T = concatBytes(hexToBytes(h.oid), digestOf(hashName, msg));
  if (emLen < T.length + 11) throw new Error('Modulus too short for ' + hashName + '.');
  var psLen = emLen - T.length - 3;
  var em = new Uint8Array(emLen);
  em[0] = 0x00; em[1] = 0x01;
  for (var i = 0; i < psLen; i++) em[2 + i] = 0xff;
  em[2 + psLen] = 0x00;
  em.set(T, 3 + psLen);
  return em;
}

// MGF1 (RFC 8017 §B.2.1) using the same hash as the signature.
function mgf1(seed, len, hashName) {
  var t = new Uint8Array(0), counter = 0;
  while (t.length < len) {
    t = concatBytes(t, digestOf(hashName, concatBytes(seed, i2osp(BigInt(counter), 4))));
    counter++;
  }
  return t.slice(0, len);
}

// EMSA-PSS-ENCODE (RFC 8017 §9.1.1); salt length = digest length.
function emsaPssEncode(msg, hashName, emBits) {
  var mHash = digestOf(hashName, msg), hLen = mHash.length, sLen = hLen;
  var emLen = Math.ceil(emBits / 8);
  if (emLen < hLen + sLen + 2) throw new Error('Modulus too short for PSS with ' + hashName + '.');
  var salt = randomBytes(sLen);
  var H = digestOf(hashName, concatBytes(new Uint8Array(8), mHash, salt));
  var DB = concatBytes(new Uint8Array(emLen - sLen - hLen - 2), new Uint8Array([0x01]), salt);
  var dbMask = mgf1(H, emLen - hLen - 1, hashName);
  var maskedDB = DB.map(function (b, i) { return b ^ dbMask[i]; });
  maskedDB[0] &= (0xff >> (8 * emLen - emBits));
  return concatBytes(maskedDB, H, new Uint8Array([0xbc]));
}
function emsaPssVerify(msg, em, hashName, emBits) {
  var mHash = digestOf(hashName, msg), hLen = mHash.length, sLen = hLen;
  var emLen = Math.ceil(emBits / 8);
  if (em.length !== emLen || em[em.length - 1] !== 0xbc) return false;
  var maskedDB = em.slice(0, emLen - hLen - 1), H = em.slice(emLen - hLen - 1, emLen - 1);
  var DB = maskedDB.map(function (b, i) { return b ^ mgf1(H, emLen - hLen - 1, hashName)[i]; });
  DB[0] &= (0xff >> (8 * emLen - emBits));
  for (var i = 0; i < emLen - sLen - hLen - 2; i++) if (DB[i] !== 0) return false;
  if (DB[emLen - sLen - hLen - 2] !== 0x01) return false;
  var salt = DB.slice(DB.length - sLen);
  var H2 = digestOf(hashName, concatBytes(new Uint8Array(8), mHash, salt));
  return bytesEqual(H, H2);
}

function rsaPaddingLabel(p) { return p === 'pss' ? 'PSS' : 'PKCS#1 v1.5'; }

// Generate a 2048-bit RSA key pair with node-forge (pure JS); display as PEM.
function rsaGenerateKeys() {
  var bits = parseInt(val('ds_rsa_bits'), 10) || 2048;
  setVal('ds_rsa_status', 'Generating RSA ' + bits + '-bit key pair… (pure JS — larger sizes take longer)');
  defer(function () {
    try {
      var kp = forge.pki.rsa.generateKeyPair({ bits: bits, e: 0x10001 });
      setVal('ds_rsa_private_key', forge.pki.privateKeyToPem(kp.privateKey).trim() + '\n');
      setVal('ds_rsa_public_key', forge.pki.publicKeyToPem(kp.publicKey).trim() + '\n');
      setVal('ds_rsa_status', 'Generated RSA ' + bits + '-bit key pair.');
    } catch (e) {
      log.error('rsaGenerateKeys: ' + e.message);
      setVal('ds_rsa_status', 'Key generation error: ' + e.message);
    }
  });
  return false;
}

function rsaSelfSignedCert(privateKey, publicKey) {
  var cert = forge.pki.createCertificate();
  cert.publicKey = publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date(Date.UTC(2020, 0, 1));
  cert.validity.notAfter = new Date(Date.UTC(2035, 0, 1));
  var attrs = [{ name: 'commonName', value: 'digital-signature-tool' }];
  cert.setSubject(attrs); cert.setIssuer(attrs);
  cert.sign(privateKey, forge.md.sha256.create());
  return cert;
}

async function rsaDownloadKeys() {
  var fmt = val('ds_rsa_ks_format') || 'pem', pw = val('ds_rsa_ks_password');
  var privPem = val('ds_rsa_private_key'), pubPem = val('ds_rsa_public_key');
  if (!privPem.trim() || !pubPem.trim()) { setVal('ds_rsa_status', 'No key pair to export. Generate a key pair first.'); return false; }
  try {
    var key = forge.pki.privateKeyFromPem(privPem);
    var pub = forge.pki.publicKeyFromPem(pubPem);
    var pkcs8 = forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(key)); // PrivateKeyInfo

    if (fmt === 'pem') {
      var privBlock = pw
        ? forge.pki.encryptedPrivateKeyToPem(forge.pki.encryptPrivateKeyInfo(pkcs8, pw, { algorithm: 'aes256' }))
        : forge.pki.privateKeyInfoToPem(pkcs8);
      triggerDownload('rsa-keys.pem', privBlock.trim() + '\n' + forge.pki.publicKeyToPem(pub).trim() + '\n', 'application/x-pem-file');
      setVal('ds_rsa_status', pw ? 'Downloaded PEM (encrypted private key + public key).' : 'Downloaded PEM (private + public key).');
    } else if (fmt === 'der') {
      var privDer = pw ? derBytes(forge.pki.encryptPrivateKeyInfo(pkcs8, pw, { algorithm: 'aes256' })) : derBytes(pkcs8);
      triggerDownload('rsa-private.der', privDer, 'application/pkcs8');
      triggerDownload('rsa-public.der', derBytes(forge.pki.publicKeyToAsn1(pub)), 'application/octet-stream');
      setVal('ds_rsa_status', pw ? 'Downloaded DER (encrypted private + public), two files.' : 'Downloaded DER (private + public), two files.');
    } else if (fmt === 'jwk') {
      var pubJwk = { kty: 'RSA', n: forgeBnB64u(key.n), e: forgeBnB64u(key.e), use: 'sig' };
      var privJwk = { kty: 'RSA', n: forgeBnB64u(key.n), e: forgeBnB64u(key.e), d: forgeBnB64u(key.d),
        p: forgeBnB64u(key.p), q: forgeBnB64u(key.q), dp: forgeBnB64u(key.dP), dq: forgeBnB64u(key.dQ), qi: forgeBnB64u(key.qInv), use: 'sig' };
      await downloadJwkSet([pubJwk, privJwk], pw, 'rsa-keys', 'ds_rsa_status');
    } else if (fmt === 'pkcs12') {
      if (!pw) { setVal('ds_rsa_status', 'PKCS#12 requires a password. Enter one in the password field.'); return false; }
      var p12 = forge.pkcs12.toPkcs12Asn1(key, [rsaSelfSignedCert(key, pub)], pw, { algorithm: '3des' });
      triggerDownload('rsa-keys.p12', derBytes(p12), 'application/x-pkcs12');
      setVal('ds_rsa_status', 'Downloaded password-protected PKCS#12 (rsa-keys.p12).');
    } else {
      setVal('ds_rsa_status', 'Unknown keystore format: ' + fmt);
    }
  } catch (e) {
    log.error('rsaDownloadKeys: ' + e.message);
    setVal('ds_rsa_status', 'Download error: ' + e.message);
  }
  return false;
}

function rsaSign() {
  var padding = val('ds_rsa_padding'), hashName = val('ds_rsa_hash');
  setVal('ds_rsa_status', 'Signing with RSA ' + rsaPaddingLabel(padding) + ' / ' + hashName + '…');
  try {
    var key = forge.pki.privateKeyFromPem(val('ds_rsa_private_key'));
    var n = forgeToBig(key.n), d = forgeToBig(key.d);
    var modBits = n.toString(2).length, k = Math.ceil(modBits / 8);
    var msg = strBytes(val('ds_rsa_value'));
    var em = padding === 'pss' ? emsaPssEncode(msg, hashName, modBits - 1) : emsaPkcs1v15(msg, hashName, k);
    var sig = i2osp(modpow(os2ip(em), d, n), k);
    setVal('ds_rsa_signature', bytesToB64(sig));
    setVal('ds_rsa_status', 'Signed (RSA ' + rsaPaddingLabel(padding) + ' / ' + hashName + ') — ' + sig.length + ' bytes.');
  } catch (e) {
    log.error('rsaSign: ' + e.message);
    setVal('ds_rsa_status', 'Sign error: ' + e.message);
  }
  return false;
}

function rsaValidate() {
  var padding = val('ds_rsa_padding'), hashName = val('ds_rsa_hash');
  setVal('ds_rsa_status', 'Validating RSA ' + rsaPaddingLabel(padding) + ' / ' + hashName + '…');
  try {
    var key = forge.pki.publicKeyFromPem(val('ds_rsa_public_key'));
    var n = forgeToBig(key.n), e = forgeToBig(key.e);
    var modBits = n.toString(2).length, k = Math.ceil(modBits / 8);
    var msg = strBytes(val('ds_rsa_value'));
    var m = modpow(os2ip(b64ToBytes(val('ds_rsa_signature'))), e, n);
    var em = i2osp(m, k);
    var ok = padding === 'pss'
      ? emsaPssVerify(msg, em, hashName, modBits - 1)
      : bytesEqual(em, emsaPkcs1v15(msg, hashName, k));
    setVal('ds_rsa_status', ok
      ? 'Signature VALID ✓ — the signature matches the value and public key.'
      : 'Signature INVALID ✗ — the signature does not verify.');
  } catch (e) {
    log.error('rsaValidate: ' + e.message);
    setVal('ds_rsa_status', 'Validation error: ' + e.message);
  }
  return false;
}

// ===========================================================================
// Pane #3 — ECC (ECDSA / EdDSA) with a selectable hash (@noble/curves)
// ===========================================================================
function eccCurve() {
  var name = val('ds_ecc_curve');
  var c = CURVES[name];
  if (!c) throw new Error('Unknown curve: ' + name);
  return c;
}

function eccGenerateKeys() {
  var name = val('ds_ecc_curve');
  setVal('ds_ecc_status', 'Generating ' + name + ' key pair…');
  try {
    var c = eccCurve();
    var priv = c.curve.utils.randomPrivateKey();
    var pub = c.curve.getPublicKey(priv);
    setVal('ds_ecc_private_key', bytesToHex(priv));
    setVal('ds_ecc_public_key', bytesToHex(pub));
    setVal('ds_ecc_status', 'Generated ' + name + ' key pair (private ' + priv.length + ' B, public ' + pub.length + ' B).');
  } catch (e) {
    log.error('eccGenerateKeys: ' + e.message);
    setVal('ds_ecc_status', 'Key generation error: ' + e.message);
  }
  return false;
}

// Build a JWK pair for the current ECC keys (EC for ECDSA curves, OKP for EdDSA).
function eccJwkSet() {
  var c = eccCurve();
  var priv = hexToBytes(val('ds_ecc_private_key')), pubHex = val('ds_ecc_public_key');
  if (c.kind === 'eddsa') {
    var pub = hexToBytes(pubHex);
    return [
      { kty: 'OKP', crv: c.jwkCrv, x: b64u(pub), use: 'sig' },
      { kty: 'OKP', crv: c.jwkCrv, x: b64u(pub), d: b64u(priv), use: 'sig' }
    ];
  }
  var pt = c.curve.ProjectivePoint.fromHex(pubHex).toAffine();
  var x = b64u(bigToBytes(pt.x, c.fieldBytes)), y = b64u(bigToBytes(pt.y, c.fieldBytes));
  return [
    { kty: 'EC', crv: c.jwkCrv, x: x, y: y, use: 'sig' },
    { kty: 'EC', crv: c.jwkCrv, x: x, y: y, d: b64u(priv), use: 'sig' }
  ];
}

async function eccDownloadKeys() {
  var fmt = val('ds_ecc_ks_format') || 'jwk', pw = val('ds_ecc_ks_password');
  var priv = val('ds_ecc_private_key'), pub = val('ds_ecc_public_key');
  if (!priv && !pub) { setVal('ds_ecc_status', 'Nothing to download — generate a key pair first.'); return false; }
  try {
    var c = eccCurve();
    if (fmt === 'jwk' && (c.kind === 'schnorr' || c.kind === 'bls')) {
      setVal('ds_ecc_status', 'JWK is not defined for ' + val('ds_ecc_curve') + '. Copy the hex from the key fields.');
    } else if (fmt === 'jwk') {
      await downloadJwkSet(eccJwkSet(), pw, 'ecc-keys', 'ds_ecc_status');
    } else {
      setVal('ds_ecc_status', fmt.toUpperCase() + ' export is not supported for these raw ECC keys. Use JWK (or copy the hex from the key fields).');
    }
  } catch (e) {
    log.error('eccDownloadKeys: ' + e.message);
    setVal('ds_ecc_status', 'Download error: ' + e.message);
  }
  return false;
}

function eccSign() {
  var name = val('ds_ecc_curve'), hashName = val('ds_ecc_hash');
  setVal('ds_ecc_status', 'Signing with ' + name + '…');
  try {
    var c = eccCurve();
    var priv = hexToBytes(val('ds_ecc_private_key'));
    var msg = strBytes(val('ds_ecc_value'));
    var sig, detail;
    if (c.kind === 'ecdsa') {
      sig = c.curve.sign(digestOf(hashName, msg), priv).toCompactRawBytes();
      detail = name + ' / ' + hashName;
    } else {
      // EdDSA, Schnorr (BIP-340), and BLS all hash the message internally.
      sig = c.curve.sign(msg, priv);
      detail = name;
    }
    setVal('ds_ecc_signature', bytesToB64(sig));
    setVal('ds_ecc_status', 'Signed (' + detail + ') — signature is ' + sig.length + ' bytes.');
  } catch (e) {
    log.error('eccSign: ' + e.message);
    setVal('ds_ecc_status', 'Sign error: ' + e.message + ' (does the curve match the key pair?)');
  }
  return false;
}

function eccValidate() {
  var name = val('ds_ecc_curve'), hashName = val('ds_ecc_hash');
  setVal('ds_ecc_status', 'Validating signature with ' + name + '…');
  try {
    var c = eccCurve();
    var pub = hexToBytes(val('ds_ecc_public_key'));
    var sig = b64ToBytes(val('ds_ecc_signature'));
    var msg = strBytes(val('ds_ecc_value'));
    var ok = c.kind === 'ecdsa'
      ? c.curve.verify(sig, digestOf(hashName, msg), pub)
      : c.curve.verify(sig, msg, pub);
    setVal('ds_ecc_status', ok
      ? 'Signature VALID ✓ — the signature matches the value and public key.'
      : 'Signature INVALID ✗ — the signature does not verify.');
  } catch (e) {
    log.error('eccValidate: ' + e.message);
    setVal('ds_ecc_status', 'Validation error: ' + e.message + ' (does the curve/hash match the signature?)');
  }
  return false;
}

// ---------------------------------------------------------------------------
// Copy a field's contents to the clipboard.
// ---------------------------------------------------------------------------
function copyField(elementId) {
  var el = document.getElementById(elementId);
  if (!el) { log.error('copyField: element not found: ' + elementId); return false; }
  var text = el.value || '';
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(function (err) { log.error('copyField: ' + err); });
  } else {
    try { el.focus(); el.select(); document.execCommand('copy'); } catch (e) { log.error('copyField fallback: ' + e.message); }
  }
  return false;
}

// ---------------------------------------------------------------------------
// "Return to debugger" link — point back at whichever page sent us here.
// ---------------------------------------------------------------------------
function setReturnLink() {
  var allowed = { 'debugger.html': '/debugger.html', 'debugger2.html': '/debugger2.html' };
  var from = new URLSearchParams(window.location.search).get('from');
  var target = allowed[from] || '/debugger.html';
  var link = document.getElementById('return_link');
  if (link) link.setAttribute('href', target);
}

window.onload = function () {
  log.debug('Entering onload function.');
  setReturnLink();
  setVal('ds_value', 'Sign me with SLH-DSA!');
  setVal('ds_rsa_value', 'Sign me with RSA!');
  setVal('ds_ecc_value', 'Sign me with ECC!');
  setVal('ds_ml_value', 'Sign me with ML-DSA!');
};

module.exports = {
  generateKeys,
  downloadKeys,
  sign,
  validate,
  rsaGenerateKeys,
  rsaDownloadKeys,
  rsaSign,
  rsaValidate,
  eccGenerateKeys,
  eccDownloadKeys,
  eccSign,
  eccValidate,
  mldsaGenerateKeys,
  mldsaDownloadKeys,
  mldsaSign,
  mldsaValidate,
  copyField
};
