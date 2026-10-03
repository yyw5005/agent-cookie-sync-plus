"""Tests for sealed-export decrypt/load in agent/inject-cookies.py.

Imports the script as a module (the filename has a hyphen, so importlib is
used) and exercises decrypt_envelope / load_cookie_file / resolve_passphrase
without needing a browser.
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

AGENT = Path(__file__).resolve().parent.parent / "agent" / "inject-cookies.py"


def load_module():
    spec = importlib.util.spec_from_file_location("inject_cookies", str(AGENT))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def mod():
    return load_module()


def make_envelope(cookies, passphrase, iterations=210000):
    """Build a cookiesync-enc envelope with the same format the extension uses."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64, os
    salt = os.urandom(16)
    iv = os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    key = kdf.derive(passphrase.encode("utf-8"))
    ct = AESGCM(key).encrypt(iv, json.dumps(cookies).encode("utf-8"), None)
    b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
    return {
        "format": "cookiesync-enc", "v": 1, "kdf": "pbkdf2-sha256",
        "iterations": iterations,
        "salt": b64(salt), "iv": b64(iv), "ciphertext": b64(ct),
    }


SAMPLE = [
    {"name": "sessionid", "value": "abc123", "domain": ".example.com", "path": "/"},
    {"name": "token", "value": "zz", "domain": "api.example.com", "path": "/"},
]
PASSPHRASE = "correct horse battery staple"


def test_decrypt_roundtrip(mod):
    env = make_envelope(SAMPLE, PASSPHRASE)
    assert mod.decrypt_envelope(env, PASSPHRASE) == SAMPLE


def test_decrypt_wrong_passphrase(mod):
    env = make_envelope(SAMPLE, PASSPHRASE)
    with pytest.raises(ValueError, match="wrong passphrase"):
        mod.decrypt_envelope(env, "nope")


def test_decrypt_missing_passphrase(mod):
    env = make_envelope(SAMPLE, PASSPHRASE)
    with pytest.raises(ValueError, match="Provide the passphrase"):
        mod.decrypt_envelope(env, "")


def test_decrypt_tampered_ciphertext(mod):
    env = make_envelope(SAMPLE, PASSPHRASE)
    env["ciphertext"] = env["ciphertext"][:-2] + ("AA" if not env["ciphertext"].endswith("AA") else "BB")
    with pytest.raises(ValueError, match="wrong passphrase or a damaged file"):
        mod.decrypt_envelope(env, PASSPHRASE)


def test_decrypt_rejects_weak_parameters(mod):
    env = make_envelope(SAMPLE, PASSPHRASE, iterations=1000)
    with pytest.raises(ValueError, match="bad parameters"):
        mod.decrypt_envelope(env, PASSPHRASE)


def test_load_plain_list(mod, tmp_path):
    p = tmp_path / "cookies.json"
    p.write_text(json.dumps(SAMPLE))
    cookies, enc = mod.load_cookie_file(str(p), "")
    assert cookies == SAMPLE and enc is False


def test_load_dict_with_cookies_key(mod, tmp_path):
    p = tmp_path / "cookies.json"
    p.write_text(json.dumps({"cookies": SAMPLE}))
    cookies, enc = mod.load_cookie_file(str(p), "")
    assert cookies == SAMPLE and enc is False


def test_load_sealed(mod, tmp_path):
    p = tmp_path / "cookies.enc.json"
    p.write_text(json.dumps(make_envelope(SAMPLE, PASSPHRASE)))
    cookies, enc = mod.load_cookie_file(str(p), PASSPHRASE)
    assert cookies == SAMPLE and enc is True


def test_resolve_passphrase_env(mod, monkeypatch):
    monkeypatch.setenv("AGENT_COOKIE_PASSPHRASE", "from-env")
    args = mod.argparse.Namespace(passphrase="", passphrase_env="AGENT_COOKIE_PASSPHRASE",
                                  passphrase_file="", prompt_passphrase=False)
    assert mod.resolve_passphrase(args) == "from-env"


def test_to_cdp_mapping(mod):
    item = mod.to_cdp({"name": "sid", "value": "v", "domain": ".example.com",
                       "path": "/", "secure": False, "httpOnly": True,
                       "sameSite": "no_restriction", "expires": 9999999999})
    assert item["sameSite"] == "None" and item["secure"] is True
    assert mod.to_cdp({"name": "", "domain": "x"}) is None
