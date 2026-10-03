"""Tests for the Cookie Sync Plus native messaging host.

Spawns native-host/cookie_sync_host.py as Chrome would: one length-prefixed
JSON message on stdin, one length-prefixed reply on stdout. Uses
AGENT_COOKIE_SYNC_DIR so nothing touches the real home folder.
"""
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HOST = Path(__file__).resolve().parent.parent / "native-host" / "cookie_sync_host.py"
PY = sys.executable


def run_host(msg, sync_dir):
    payload = json.dumps(msg).encode("utf-8")
    frame = struct.pack("<I", len(payload)) + payload
    env = dict(os.environ, AGENT_COOKIE_SYNC_DIR=str(sync_dir))
    proc = subprocess.run(
        [PY, str(HOST)], input=frame, capture_output=True, env=env, timeout=30
    )
    assert proc.returncode == 0, proc.stderr.decode()
    out = proc.stdout
    assert len(out) >= 4
    (length,) = struct.unpack("<I", out[:4])
    return json.loads(out[4:4 + length].decode("utf-8"))


def sample_cookies():
    return [
        {"name": "sessionid", "value": "abc123", "domain": ".example.com",
         "path": "/", "secure": True, "httpOnly": True, "session": False},
        {"name": "_ga", "value": "GA1.2", "domain": ".example.com",
         "path": "/", "secure": False, "httpOnly": False, "session": False},
    ]


def sealed_envelope():
    return {
        "format": "cookiesync-enc", "v": 1, "kdf": "pbkdf2-sha256",
        "iterations": 210000,
        "salt": "AAAAAAAAAAAAAAAAAAAAAA",
        "iv": "AAAAAAAAAAAA",
        "ciphertext": "dGVzdA",
    }


def test_plain_export_writes_files_and_log(tmp_path):
    resp = run_host({
        "format": "cookiesync-plain", "reason": "click",
        "exported_at": "2026-10-04T00:00:00+00:00",
        "cookie_count": 2, "total_in_chrome": 10,
        "filter": {"sites": 1}, "cookies": sample_cookies(),
    }, tmp_path)
    assert resp["ok"] is True
    assert resp["encrypted"] is False
    cookies = json.loads((tmp_path / "cookies.json").read_text())
    assert cookies == sample_cookies()
    meta = json.loads((tmp_path / "cookies.meta.json").read_text())
    assert meta["cookie_count"] == 2
    assert meta["domain_sample"] == ["example.com"]
    assert meta["encrypted"] is False
    log_lines = (tmp_path / "export.log").read_text().strip().split("\n")
    entry = json.loads(log_lines[-1])
    assert entry["reason"] == "click" and entry["encrypted"] is False
    # 0600 permissions
    assert oct((tmp_path / "cookies.json").stat().st_mode & 0o777) == "0o600"


def test_sealed_export_removes_stale_plain_and_hides_domains(tmp_path):
    (tmp_path / "cookies.json").write_text('[{"name":"old"}]')
    resp = run_host({
        "format": "cookiesync-enc", "reason": "alarm",
        "exported_at": "2026-10-04T00:00:00+00:00",
        "cookie_count": 2, "total_in_chrome": 10,
        "filter": {"sites": 1}, "payload": sealed_envelope(),
    }, tmp_path)
    assert resp["ok"] is True and resp["encrypted"] is True
    assert (tmp_path / "cookies.enc.json").exists()
    assert not (tmp_path / "cookies.json").exists(), "stale plaintext must go"
    meta = json.loads((tmp_path / "cookies.meta.json").read_text())
    assert meta["encrypted"] is True
    assert meta["domain_sample"] == []
    assert meta["domain_count"] is None


def test_plain_export_removes_stale_sealed(tmp_path):
    (tmp_path / "cookies.enc.json").write_text('{"format":"cookiesync-enc"}')
    resp = run_host({
        "format": "cookiesync-plain", "reason": "click",
        "exported_at": "2026-10-04T00:00:00+00:00",
        "cookie_count": 1, "total_in_chrome": 5,
        "filter": {}, "cookies": sample_cookies()[:1],
    }, tmp_path)
    assert resp["ok"] is True
    assert not (tmp_path / "cookies.enc.json").exists()


def test_poll_request_flag(tmp_path):
    assert run_host({"cmd": "poll_request"}, tmp_path) == {"ok": True, "export": False}
    (tmp_path / "sync-request.flag").write_text("2026-10-04T00:00:00Z")
    assert run_host({"cmd": "poll_request"}, tmp_path) == {"ok": True, "export": True}
    assert not (tmp_path / "sync-request.flag").exists(), "flag is one-shot"


def test_poll_health(tmp_path):
    assert run_host({"cmd": "poll_health"}, tmp_path) == {"ok": True, "health": None}
    (tmp_path / "agent-health.json").write_text(json.dumps({
        "injected_at": "2026-10-04T01:00:00+00:00", "ok": True,
        "attempted": 40, "succeeded": 40, "failed": 0,
        "domain_count": 5, "encrypted": True, "method": "cdp-Storage.setCookies",
        "secret_field": "must not leak through",
    }))
    resp = run_host({"cmd": "poll_health"}, tmp_path)
    assert resp["ok"] is True
    assert resp["health"]["succeeded"] == 40
    assert resp["health"]["encrypted"] is True
    assert "secret_field" not in resp["health"], "host whitelists health fields"


def test_export_log_trims(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("cookie_sync_host", str(HOST))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.EXPORT_LOG_MAX_LINES = 10
    for i in range(25):
        mod.append_export_log(str(tmp_path), {"at": str(i), "reason": "alarm"})
    lines = (tmp_path / "export.log").read_text().strip().split("\n")
    assert len(lines) == 10
    assert json.loads(lines[0])["at"] == "15"
