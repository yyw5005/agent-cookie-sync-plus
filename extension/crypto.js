// Cookie Sync Plus, sealed-export crypto.
//
// The sealed export envelope (the one format both the extension and the
// agent-side Python must agree on):
//
//   {
//     "format": "cookiesync-enc",
//     "v": 1,
//     "kdf": "pbkdf2-sha256",
//     "iterations": 210000,
//     "salt": "<base64, 16 bytes>",
//     "iv": "<base64, 12 bytes>",
//     "ciphertext": "<base64, AES-256-GCM of the UTF-8 JSON of the cookie array>"
//   }
//
// Key: PBKDF2-HMAC-SHA256(passphrase, salt, 210000) -> 32 bytes.
// A fresh random salt is used for every export, so the same cookies
// encrypt to different bytes each time. GCM gives authentication: a
// tampered or wrongly-keyed file fails to decrypt instead of producing
// garbage cookies.
//
// The passphrase lives in chrome.storage.local (this computer only) and
// is never part of any export. The sync folder then holds ciphertext only,
// so whoever moves the file (rclone, Syncthing, the bot's pull job) never
// sees a live session.

export const ENC_FORMAT = "cookiesync-enc";
export const ENC_VERSION = 1;
export const ENC_KDF = "pbkdf2-sha256";
export const ENC_ITERATIONS = 210000;

const te = new TextEncoder();
const td = new TextDecoder();

export function b64encode(bytes) {
  const bin = String.fromCharCode(...bytes);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64decode(s) {
  let t = String(s).replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4) t += "=";
  const bin = atob(t);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function deriveKey(passphrase, salt) {
  const base = await crypto.subtle.importKey(
    "raw",
    te.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: ENC_ITERATIONS, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// cookies: the shaped array (as written to cookies.json). Returns the envelope.
export async function encryptCookies(cookies, passphrase) {
  if (!passphrase) throw new Error("A passphrase is required to seal the export.");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt);
  const plain = te.encode(JSON.stringify(cookies));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
  return {
    format: ENC_FORMAT,
    v: ENC_VERSION,
    kdf: ENC_KDF,
    iterations: ENC_ITERATIONS,
    salt: b64encode(salt),
    iv: b64encode(iv),
    ciphertext: b64encode(ct)
  };
}

// The reverse, used by tests (the agent side decrypts in Python).
export async function decryptEnvelope(envelope, passphrase) {
  if (!envelope || envelope.format !== ENC_FORMAT) {
    throw new Error("Not a sealed export envelope.");
  }
  if (envelope.v !== ENC_VERSION || envelope.kdf !== ENC_KDF) {
    throw new Error("Unsupported envelope version or KDF.");
  }
  const key = await deriveKey(passphrase, b64decode(envelope.salt));
  let plain;
  try {
    plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64decode(envelope.iv) },
      key,
      b64decode(envelope.ciphertext)
    );
  } catch (_) {
    throw new Error("Decryption failed: wrong passphrase or a damaged file.");
  }
  return JSON.parse(td.decode(plain));
}

export function isEnvelope(obj) {
  return Boolean(obj && obj.format === ENC_FORMAT);
}
