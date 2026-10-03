#!/usr/bin/env python3
"""Inject synced Chrome cookies into the agent browser via CDP.

Requires Chrome with --remote-debugging-port. Connects with suppress_origin=True
(Chrome 130+ rejects CDP websockets that send an Origin header unless
--remote-allow-origins is set).

Reads cookies.json (plain) or cookies.enc.json (sealed with AES-256-GCM).
A sealed export needs the passphrase the extension used: pass it with
--passphrase, --passphrase-env (default AGENT_COOKIE_PASSPHRASE) or
--passphrase-file. Sealed exports need the `cryptography` package
(`pip install -r requirements.txt`).

After injecting, writes inject.meta.json next to the cookies file. Copy
that file back into the user's sync folder as agent-health.json and the
extension's settings page will show whether the bot is staying signed in.

Never prints cookie values.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from typing import Any

try:
    from websocket import create_connection
except ImportError:
    print("Install websocket-client in the venv first.", file=sys.stderr)
    sys.exit(2)

DEFAULT_COOKIES = os.environ.get("AGENT_COOKIES_PATH", os.path.expanduser("~/.agentcookiesync/cookies.json"))
ENC_FORMAT = "cookiesync-enc"
ENC_KDF = "pbkdf2-sha256"


def _b64decode(s: str) -> bytes:
    t = s.replace("-", "+").replace("_", "/")
    t += "=" * (-len(t) % 4)
    return base64.b64decode(t)


def decrypt_envelope(envelope: dict[str, Any], passphrase: str) -> list[dict[str, Any]]:
    """Decrypt a cookiesync-enc envelope. Raises ValueError on any problem."""
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    except ImportError:
        raise ValueError(
            "Sealed export needs the 'cryptography' package: pip install cryptography"
        )
    if not isinstance(envelope, dict) or envelope.get("format") != ENC_FORMAT:
        raise ValueError("Not a sealed export envelope.")
    if envelope.get("kdf") != ENC_KDF:
        raise ValueError("Unsupported envelope KDF: %r" % (envelope.get("kdf"),))
    if not passphrase:
        raise ValueError(
            "This export is sealed. Provide the passphrase via --passphrase, "
            "--passphrase-env or --passphrase-file."
        )
    try:
        iterations = int(envelope.get("iterations") or 0)
        salt = _b64decode(envelope["salt"])
        iv = _b64decode(envelope["iv"])
        ct = _b64decode(envelope["ciphertext"])
    except (KeyError, ValueError, TypeError) as e:
        raise ValueError("Damaged envelope: %s" % e)
    if iterations < 100000 or len(salt) != 16 or len(iv) != 12:
        raise ValueError("Damaged envelope: bad parameters.")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    key = kdf.derive(passphrase.encode("utf-8"))
    try:
        plain = AESGCM(key).decrypt(iv, ct, None)
    except Exception:
        raise ValueError("Decryption failed: wrong passphrase or a damaged file.")
    data = json.loads(plain.decode("utf-8"))
    if not isinstance(data, list):
        raise ValueError("Damaged envelope: payload is not a cookie list.")
    return data


def resolve_passphrase(args: argparse.Namespace) -> str:
    if args.passphrase:
        print("Warning: --passphrase is visible in the process list; prefer --passphrase-env.",
              file=sys.stderr)
        return args.passphrase
    env_name = args.passphrase_env or "AGENT_COOKIE_PASSPHRASE"
    if env_name and os.environ.get(env_name):
        return os.environ[env_name]
    if args.passphrase_file:
        with open(os.path.expanduser(args.passphrase_file), encoding="utf-8") as f:
            return f.read().strip()
    if args.prompt_passphrase:
        return getpass.getpass("Cookie export passphrase: ")
    return ""


def load_cookie_file(path: str, passphrase: str) -> tuple[list[dict[str, Any]], bool]:
    """Return (cookies, was_encrypted). Raises ValueError on any problem."""
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    if isinstance(raw, dict) and raw.get("format") == ENC_FORMAT:
        return decrypt_envelope(raw, passphrase), True
    if isinstance(raw, dict):
        raw = raw.get("cookies") or []
    if not isinstance(raw, list):
        raise ValueError("Cookie file does not hold a cookie list.")
    return raw, False


def discover_port() -> int | None:
    try:
        out = subprocess.check_output(["ps", "-eo", "args"], text=True, errors="ignore")
    except Exception:
        out = ""
    ports: list[int] = []
    for line in out.splitlines():
        if "remote-debugging-port=" not in line:
            continue
        if "chrome" not in line.lower() and "chromium" not in line.lower():
            continue
        m = re.search(r"--remote-debugging-port=(\d+)", line)
        if m:
            ports.append(int(m.group(1)))
    for p in sorted(set(ports), reverse=True):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{p}/json/version", timeout=1) as r:
                r.read(50)
            return p
        except Exception:
            continue
    for p in (9224, 9222, 9333):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{p}/json/version", timeout=1) as r:
                r.read(50)
            return p
        except Exception:
            continue
    return None


def map_same_site(value: str | None) -> str | None:
    s = (value or "").lower()
    if s in ("no_restriction", "none"):
        return "None"
    if s == "strict":
        return "Strict"
    if s == "lax":
        return "Lax"
    return None


def to_cdp(cookie: dict[str, Any]) -> dict[str, Any] | None:
    name = cookie.get("name")
    domain = cookie.get("domain")
    if not name or domain is None:
        return None
    item: dict[str, Any] = {
        "name": name,
        "value": cookie.get("value") or "",
        "domain": domain,
        "path": cookie.get("path") or "/",
        "secure": bool(cookie.get("secure")),
        "httpOnly": bool(cookie.get("httpOnly") or cookie.get("httponly")),
    }
    ss = map_same_site(cookie.get("sameSite") or cookie.get("samesite"))
    if ss:
        if ss == "None" and not item["secure"]:
            item["secure"] = True
        item["sameSite"] = ss
    exp = cookie.get("expires")
    if exp and not cookie.get("session"):
        try:
            expf = float(exp)
            if expf > time.time():
                item["expires"] = expf
        except (TypeError, ValueError):
            pass
    return item


def domain_match(domain: str, filters: set[str]) -> bool:
    d = domain.lstrip(".").lower()
    for f in filters:
        f = f.lstrip(".").lower()
        if d == f or d.endswith("." + f):
            return True
    return False


class Cdp:
    def __init__(self, ws_url: str):
        self.ws = create_connection(ws_url, timeout=120, suppress_origin=True)
        self._id = 0

    def call(self, method: str, params: dict | None = None, timeout: float = 120) -> dict:
        self._id += 1
        mid = self._id
        payload: dict[str, Any] = {"id": mid, "method": method}
        if params is not None:
            payload["params"] = params
        self.ws.send(json.dumps(payload))
        start = time.time()
        while time.time() - start < timeout:
            resp = json.loads(self.ws.recv())
            if resp.get("id") == mid:
                return resp
        raise TimeoutError(method)

    def close(self) -> None:
        try:
            self.ws.close()
        except Exception:
            pass


def main() -> int:
    ap = argparse.ArgumentParser(description="Inject synced cookies into agent Chrome via CDP")
    ap.add_argument("--cookies", default=DEFAULT_COOKIES)
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--domains", default="", help="Comma-separated domain filter")
    ap.add_argument("--chunk", type=int, default=100)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--meta", default="", help="Write inject.meta.json here (default next to cookies)")
    ap.add_argument("--passphrase", default="", help="Passphrase for a sealed export (visible in ps; prefer --passphrase-env)")
    ap.add_argument("--passphrase-env", default="AGENT_COOKIE_PASSPHRASE", help="Env var holding the passphrase (default AGENT_COOKIE_PASSPHRASE)")
    ap.add_argument("--passphrase-file", default="", help="File holding the passphrase")
    ap.add_argument("--prompt-passphrase", action="store_true", help="Ask for the passphrase interactively")
    args = ap.parse_args()

    passphrase = resolve_passphrase(args)
    try:
        raw, was_encrypted = load_cookie_file(args.cookies, passphrase)
    except ValueError as e:
        print("Cookie file error: %s" % e, file=sys.stderr)
        return 1
    except FileNotFoundError:
        print("Cookie file not found: %s" % args.cookies, file=sys.stderr)
        return 1

    filters = {d.strip() for d in args.domains.split(",") if d.strip()}
    batch = []
    for c in raw:
        item = to_cdp(c)
        if not item:
            continue
        if filters and not domain_match(item["domain"], filters):
            continue
        batch.append(item)

    domains = sorted({c["domain"].lstrip(".").lower() for c in batch})
    print(f"cookies={len(batch)} domains={len(domains)} encrypted={was_encrypted} dry_run={args.dry_run}")

    port = args.port or discover_port()
    if not port:
        if args.dry_run:
            # Dry run validates the file and the passphrase without a browser.
            print("dry-run ok: file parses%s" % (" and decrypts" if was_encrypted else ""))
            return 0
        print("No Chrome remote-debugging-port found.", file=sys.stderr)
        return 1
    print(f"port={port}")
    if args.dry_run:
        return 0

    with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=3) as r:
        version = json.loads(r.read())
    ws_url = version["webSocketDebuggerUrl"]
    try:
        cdp = Cdp(ws_url)
    except Exception as e:
        msg = str(e)
        print(
            "CDP websocket failed: %s. "
            "This script already uses suppress_origin=True; if you still see 403, "
            "restart Chrome with --remote-allow-origins=* "
            "(or --remote-allow-origins=http://127.0.0.1:%s)."
            % (msg, port),
            file=sys.stderr,
        )
        return 1
    ok = fail = 0
    per_domain: dict[str, dict[str, int]] = {}
    try:
        for i in range(0, len(batch), args.chunk):
            chunk = batch[i : i + args.chunk]
            resp = cdp.call("Storage.setCookies", {"cookies": chunk})
            if "error" in resp:
                for one in chunk:
                    r2 = cdp.call("Storage.setCookies", {"cookies": [one]})
                    d = one["domain"].lstrip(".").lower()
                    st = per_domain.setdefault(d, {"ok": 0, "fail": 0})
                    if "error" in r2:
                        fail += 1
                        st["fail"] += 1
                    else:
                        ok += 1
                        st["ok"] += 1
            else:
                ok += len(chunk)
                for one in chunk:
                    d = one["domain"].lstrip(".").lower()
                    per_domain.setdefault(d, {"ok": 0, "fail": 0})["ok"] += 1
    finally:
        cdp.close()

    meta_path = args.meta or os.path.join(os.path.dirname(os.path.abspath(args.cookies)), "inject.meta.json")
    meta = {
        "injected_at": datetime.now(timezone.utc).isoformat(),
        "ok": fail == 0,
        "attempted": len(batch),
        "succeeded": ok,
        "failed": fail,
        "port": port,
        "domain_count": len(domains),
        "domain_sample": domains[:25],
        "domains": per_domain,
        "encrypted": was_encrypted,
        "method": "cdp-Storage.setCookies",
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    try:
        os.chmod(meta_path, 0o600)
    except OSError:
        pass
    print(f"injected ok={ok} fail={fail} meta={meta_path}")
    print("To close the loop, copy inject.meta.json back to the user's sync folder as agent-health.json.")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
