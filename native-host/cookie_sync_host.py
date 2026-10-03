#!/usr/bin/env python3
"""Cookie Sync Plus native messaging host.

Chrome starts this program, sends one message on stdin and reads one reply
on stdout. It writes files to the sync folder:

  cookies.json        the cookies, for your agent to pull (plain mode)
  cookies.enc.json    the sealed export envelope (sealed mode)
  cookies.meta.json   when, how many, which rules applied, a domain sample
  export.log          append-only audit log of every export (JSON lines)

Commands (in the message's "cmd" field):
  poll_request   the agent dropped sync-request.flag; answer export:true once
  poll_health    return the agent's last inject.meta.json, copied back into
                 this folder as agent-health.json by the bot's sync job

It never prints a cookie value and never touches the network.
"""
from __future__ import annotations

import json
import os
import struct
import sys
import time
from datetime import datetime, timezone

ENC_FORMAT = "cookiesync-enc"
PLAIN_FORMAT = "cookiesync-plain"
EXPORT_LOG_MAX_LINES = 500


def sync_dir() -> str:
    override = os.environ.get("AGENT_COOKIE_SYNC_DIR")
    if override:
        return override
    local = os.environ.get("LOCALAPPDATA")
    if local:
        return os.path.join(local, "AgentCookieSync")
    return os.path.join(os.path.expanduser("~"), ".agentcookiesync")


def read_message():
    raw_len = sys.stdin.buffer.read(4)
    if not raw_len:
        return None
    (length,) = struct.unpack("<I", raw_len)
    data = sys.stdin.buffer.read(length)
    return json.loads(data.decode("utf-8"))


def send_message(msg: dict) -> None:
    encoded = json.dumps(msg).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("<I", len(encoded)))
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


def chmod_private(path: str) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def append_export_log(out_dir: str, entry: dict) -> None:
    log_path = os.path.join(out_dir, "export.log")
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        with open(log_path, encoding="utf-8") as f:
            lines = f.readlines()
        if len(lines) > EXPORT_LOG_MAX_LINES:
            with open(log_path, "w", encoding="utf-8") as f:
                f.writelines(lines[-EXPORT_LOG_MAX_LINES:])
    except OSError:
        pass
    chmod_private(log_path)


def handle_export(msg: dict, out_dir: str) -> dict:
    fmt = msg.get("format") or PLAIN_FORMAT
    sealed = fmt == ENC_FORMAT
    cookies_path = os.path.join(out_dir, "cookies.enc.json" if sealed else "cookies.json")
    stale_path = os.path.join(out_dir, "cookies.json" if sealed else "cookies.enc.json")
    meta_path = os.path.join(out_dir, "cookies.meta.json")
    exported_at = msg.get("exported_at") or datetime.now(timezone.utc).isoformat()

    if sealed:
        envelope = msg.get("payload")
        if not isinstance(envelope, dict) or envelope.get("format") != ENC_FORMAT:
            return {"ok": False, "error": "sealed export without a valid envelope"}
        body = envelope
        cookie_count = int(msg.get("cookie_count") or 0)
        domains: list[str] = []
    else:
        cookies = msg.get("cookies") or []
        body = cookies
        cookie_count = len(cookies)
        domains = sorted({(c.get("domain") or "").lstrip(".") for c in cookies if c.get("domain")})

    with open(cookies_path, "w", encoding="utf-8") as f:
        json.dump(body, f, ensure_ascii=False, separators=(",", ":"))
    # Switching modes must not leave the other format behind: a stale
    # plaintext file next to a sealed export would defeat the sealing.
    try:
        if os.path.exists(stale_path):
            os.remove(stale_path)
    except OSError:
        pass

    meta = {
        "exported_at": exported_at,
        "exported_at_unix": time.time(),
        "cookie_count": cookie_count,
        "source": "cookie-sync-plus",
        "format": fmt,
        "encrypted": sealed,
        "reason": msg.get("reason"),
        "total_in_chrome": msg.get("total_in_chrome"),
        "filter": msg.get("filter"),
        "out_dir": out_dir,
        "domain_sample": [] if sealed else domains[:25],
        "domain_count": None if sealed else len(domains),
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    chmod_private(cookies_path)
    chmod_private(meta_path)

    append_export_log(out_dir, {
        "at": exported_at,
        "reason": msg.get("reason"),
        "cookie_count": cookie_count,
        "sites": (msg.get("filter") or {}).get("sites"),
        "encrypted": sealed,
        "format": fmt,
    })
    return {"ok": True, "cookie_count": cookie_count, "path": cookies_path, "encrypted": sealed}


def handle_poll_request(out_dir: str) -> dict:
    flag = os.path.join(out_dir, "sync-request.flag")
    if os.path.exists(flag):
        try:
            os.remove(flag)
        except OSError:
            pass
        return {"ok": True, "export": True}
    return {"ok": True, "export": False}


def handle_poll_health(out_dir: str) -> dict:
    health_path = os.path.join(out_dir, "agent-health.json")
    health = None
    if os.path.exists(health_path):
        try:
            with open(health_path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                health = {
                    k: data.get(k)
                    for k in ("injected_at", "ok", "attempted", "succeeded", "failed",
                              "domain_count", "encrypted", "method")
                }
        except (OSError, ValueError):
            health = None
    return {"ok": True, "health": health}


def main() -> int:
    msg = read_message()
    if not msg:
        return 0
    out_dir = sync_dir()
    os.makedirs(out_dir, exist_ok=True)
    cmd = msg.get("cmd")
    if cmd == "poll_request":
        send_message(handle_poll_request(out_dir))
    elif cmd == "poll_health":
        send_message(handle_poll_health(out_dir))
    else:
        send_message(handle_export(msg, out_dir))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        try:
            send_message({"ok": False, "error": str(e)})
        except Exception:
            pass
        raise SystemExit(1)
