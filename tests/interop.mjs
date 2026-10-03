// Cross-language interop test: the extension seals with WebCrypto, the
// agent unseals with Python (and back). This is the one format both sides
// must agree on, so it is tested live in both directions.
//
// Usage: node tests/interop.mjs <python-bin>
import { encryptCookies, decryptEnvelope } from "../extension/crypto.js";
import { execFileSync } from "node:child_process";
import { writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const PY = process.argv[2] || "python3";
const PASSPHRASE = "interop-test-passphrase-42";
const SAMPLE = [
  { name: "sessionid", value: "s3cr3tünïcödé", domain: ".example.com", path: "/", secure: true, httpOnly: true },
  { name: "prefs", value: "x=1", domain: "example.com", path: "/", secure: false, httpOnly: false },
];
const dir = tmpdir();

const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// --- direction 1: JS encrypt -> Python decrypt (the real production path) ---
const envelope = await encryptCookies(SAMPLE, PASSPHRASE);
const encPath = join(dir, "csp-interop-enc.json");
writeFileSync(encPath, JSON.stringify(envelope));
const pyDecrypt = `
import json, sys
sys.path.insert(0, ${JSON.stringify(join(new URL(".", import.meta.url).pathname, "..", "agent"))})
import importlib.util
spec = importlib.util.spec_from_file_location("ic", ${JSON.stringify(join(new URL(".", import.meta.url).pathname, "..", "agent", "inject-cookies.py"))})
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
env = json.load(open(${JSON.stringify(encPath)}))
print(json.dumps(m.decrypt_envelope(env, ${JSON.stringify(PASSPHRASE)}), ensure_ascii=False))
`;
const backInPython = JSON.parse(execFileSync(PY, ["-c", pyDecrypt], { encoding: "utf-8" }));
if (!eq(backInPython, SAMPLE)) {
  console.error("FAIL: JS -> Python roundtrip mismatch");
  process.exit(1);
}
console.log("ok: JS encrypt -> Python decrypt");

// --- direction 2: Python encrypt -> JS decrypt ---
const pyEncrypt = `
import json, os, base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
cookies = ${JSON.stringify(JSON.stringify(SAMPLE))}
salt, iv = os.urandom(16), os.urandom(12)
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=210000)
key = kdf.derive(${JSON.stringify(PASSPHRASE)}.encode())
ct = AESGCM(key).encrypt(iv, cookies.encode(), None)
b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
print(json.dumps({"format": "cookiesync-enc", "v": 1, "kdf": "pbkdf2-sha256",
  "iterations": 210000, "salt": b64(salt), "iv": b64(iv), "ciphertext": b64(ct)}))
`;
const pyEnvelope = JSON.parse(execFileSync(PY, ["-c", pyEncrypt], { encoding: "utf-8" }));
const backInJs = await decryptEnvelope(pyEnvelope, PASSPHRASE);
if (!eq(backInJs, SAMPLE)) {
  console.error("FAIL: Python -> JS roundtrip mismatch");
  process.exit(1);
}
console.log("ok: Python encrypt -> JS decrypt");

// --- wrong passphrase must fail loudly on both sides ---
let failed = false;
try { await decryptEnvelope(pyEnvelope, "wrong"); } catch (e) { failed = /wrong passphrase|Decryption failed/.test(e.message); }
if (!failed) { console.error("FAIL: JS accepted a wrong passphrase"); process.exit(1); }
console.log("ok: wrong passphrase rejected");

console.log("interop: all directions pass");
