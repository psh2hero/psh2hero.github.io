#!/usr/bin/env python3
"""Password-protect the GED pages.

Reads the plain pages from GED/_private/ (gitignored, never published) and
writes encrypted copies to GED/. Each published page holds only AES-256-GCM
ciphertext; the password is not stored anywhere in it. The browser derives the
key from the typed password (PBKDF2-SHA256) and decrypts the page in place.

Usage:
    python3 tools/protect_html.py            # prompts for the password
    GED_PASSWORD=... python3 tools/protect_html.py
"""
import base64
import getpass
import html
import json
import os
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "GED" / "_private"
OUT = ROOT / "GED"
ITERATIONS = 600_000

TEMPLATE = """<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>__TITLE__</title>
<style>
  :root { --bg: #f7f4ee; --card: #ffffff; --ink: #2b2723; --muted: #7a7168; --line: #e6dfd4; --accent: #c0563f; --bad: #b8402e; color-scheme: light; }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #1c1a18; --card: #26231f; --ink: #ece6dc; --muted: #a49a8e; --line: #3a352f; --accent: #e8826b; --bad: #e8826b; color-scheme: dark; }
  }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 16px;
    background: var(--bg); color: var(--ink); font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", "Apple SD Gothic Neo", "Noto Sans KR", sans-serif; }
  form { width: 100%; max-width: 340px; background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 28px 24px; }
  h1 { font-size: 1.15rem; margin: 0 0 4px; }
  p { margin: 0 0 18px; color: var(--muted); font-size: .9rem; }
  input { width: 100%; padding: 11px 12px; font: inherit; color: var(--ink); background: var(--bg); border: 1px solid var(--line); border-radius: 8px; }
  input:focus { outline: 2px solid var(--accent); outline-offset: -1px; }
  button { width: 100%; margin-top: 12px; padding: 11px; font: inherit; font-weight: 600; color: #fff; background: var(--accent); border: 0; border-radius: 8px; cursor: pointer; }
  button:disabled { opacity: .6; cursor: wait; }
  #err { min-height: 1.4em; margin: 10px 0 0; color: var(--bad); font-size: .85rem; }
</style>
</head>
<body>
<form id="f" autocomplete="off">
  <h1>__TITLE__</h1>
  <p>비밀번호를 입력하세요 · Enter password</p>
  <input id="pw" type="password" autofocus required aria-label="Password">
  <button id="go">Open</button>
  <div id="err" role="alert"></div>
</form>
<script id="payload" type="application/json">__PAYLOAD__</script>
<script>
(() => {
  const P = JSON.parse(document.getElementById('payload').textContent);
  const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const KEY = 'ged.pw';

  async function decrypt(pw) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: b64(P.salt), iterations: P.iter, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(P.iv) }, key, b64(P.ct));
    return new TextDecoder().decode(pt);
  }

  async function unlock(pw) {
    const page = await decrypt(pw);
    try { sessionStorage.setItem(KEY, pw); } catch {}
    document.open(); document.write(page); document.close();
  }

  const f = document.getElementById('f'), go = document.getElementById('go'), err = document.getElementById('err');
  f.addEventListener('submit', async e => {
    e.preventDefault();
    go.disabled = true; err.textContent = '';
    try { await unlock(document.getElementById('pw').value); }
    catch { err.textContent = '비밀번호가 틀렸습니다 · Wrong password'; go.disabled = false; }
  });

  // Same password for every GED page: skip the prompt within this tab session.
  let saved = null;
  try { saved = sessionStorage.getItem(KEY); } catch {}
  if (saved) unlock(saved).catch(() => { try { sessionStorage.removeItem(KEY); } catch {} });
})();
</script>
</body>
</html>
"""


def encrypt(data: bytes, password: str) -> dict:
    salt, iv = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(hashes.SHA256(), 32, salt, ITERATIONS).derive(password.encode())
    ct = AESGCM(key).encrypt(iv, data, None)  # ciphertext || tag, as WebCrypto expects
    b = lambda x: base64.b64encode(x).decode()
    return {"salt": b(salt), "iv": b(iv), "iter": ITERATIONS, "ct": b(ct)}


def main():
    sources = sorted(SRC.glob("*.html"))
    if not sources:
        sys.exit(f"No pages found in {SRC}")

    password = os.environ.get("GED_PASSWORD")
    if not password:
        password = getpass.getpass("Password: ")
        if password != getpass.getpass("Confirm:  "):
            sys.exit("Passwords do not match.")
    if not password:
        sys.exit("Empty password.")

    for src in sources:
        text = src.read_text(encoding="utf-8")
        m = re.search(r"<title>(.*?)</title>", text, re.S)
        title = html.escape(html.unescape(m.group(1).strip())) if m else src.stem
        payload = json.dumps(encrypt(text.encode("utf-8"), password))
        page = TEMPLATE.replace("__TITLE__", title).replace("__PAYLOAD__", payload)
        (OUT / src.name).write_text(page, encoding="utf-8")
        print(f"encrypted {src.relative_to(ROOT)} -> {(OUT / src.name).relative_to(ROOT)}")


if __name__ == "__main__":
    main()
