#!/usr/bin/env python3
"""
Tu dang nhap ADFS (asso.hust.edu.vn) bang tai khoan/mat khau, doi lay id_token,
roi doi id_token do thanh TokenBKNexus (qua Lab/LoginByAccessToken), va ghi
token do vao mot Gist bi mat cho ESP32 doc.

Bien moi truong can co (dat trong GitHub Actions Secrets, KHONG hardcode):
  HUST_USERNAME   - vd: huy.nq2517005@sis.hust.edu.vn (dung dung dinh dang
                    ma trang dang nhap doi hoi - xem placeholder tren form)
  HUST_PASSWORD   - mat khau tai khoan truong
  GH_TOKEN        - GitHub Personal Access Token, scope "gist", de ghi vao Gist
  GIST_ID         - id cua gist bi mat da tao san (chua 1 file, vd token.txt)
  GIST_FILENAME   - ten file trong gist can ghi (vd "token.txt")

Script KHONG retry nhieu lan khi sai mat khau hoac gap buoc xac thuc la
(MFA/CAPTCHA) - no dung lai va bao loi ngay, de tranh bi khoa tai khoan.
"""
import os
import re
import sys
import uuid
import html
import json
from urllib.parse import urlparse, parse_qs, urlencode

import requests

ADFS_BASE = "https://asso.hust.edu.vn"
CLIENT_ID = "https://ctsv.hust.edu.vn"
REDIRECT_URI = "https://ctsv.hust.edu.vn"
LOGIN_BY_TOKEN_URL = "https://ctsv.hust.edu.vn/bknexus/Lab/LoginByAccessToken"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36")


def fail(msg: str) -> "NoReturn":
    print(f"[FAIL] {msg}", file=sys.stderr)
    sys.exit(1)


def build_authorize_url() -> str:
    params = {
        "response_type": "id_token",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "state": str(uuid.uuid4()),
        "client-request-id": str(uuid.uuid4()),
        "x-client-SKU": "Js",
        "x-client-Ver": "1.0.16",
        "nonce": str(uuid.uuid4()),
    }
    return f"{ADFS_BASE}/adfs/oauth2/authorize?{urlencode(params)}"


def extract_form(html_text: str, form_id: str):
    """Lay action (da unescape) va cac input name/value cua 1 <form id=...>."""
    m = re.search(
        rf'<form[^>]*id="{form_id}"[^>]*action="([^"]+)"', html_text
    )
    if not m:
        return None, {}
    action = html.unescape(m.group(1))
    form_html_match = re.search(
        rf'<form[^>]*id="{form_id}".*?</form>', html_text, re.S
    )
    fields = {}
    if form_html_match:
        for name, value in re.findall(
            r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', form_html_match.group(0)
        ):
            fields[html.unescape(name)] = html.unescape(value)
    return action, fields


def main():
    username = os.environ.get("HUST_USERNAME", "")
    password = os.environ.get("HUST_PASSWORD", "")
    gh_token = os.environ.get("GH_TOKEN", "")
    gist_id = os.environ.get("GIST_ID", "")
    gist_filename = os.environ.get("GIST_FILENAME", "token.txt")

    if not all([username, password, gh_token, gist_id]):
        fail("Thieu bien moi truong (HUST_USERNAME / HUST_PASSWORD / GH_TOKEN / GIST_ID)")

    session = requests.Session()
    session.headers.update({"User-Agent": UA})

    # 1) GET trang dang nhap de ADFS sinh state/nonce/client-request-id va tra ve form
    authorize_url = build_authorize_url()
    r = session.get(authorize_url, timeout=20)
    if r.status_code != 200:
        fail(f"Khong mo duoc trang dang nhap ADFS (HTTP {r.status_code})")

    action, fields = extract_form(r.text, "loginForm")
    if not action:
        fail("Khong tim thay form dang nhap - giao dien ADFS co the da doi")

    # 2) POST tai khoan/mat khau
    payload = dict(fields)
    payload["UserName"] = username
    payload["Password"] = password
    payload.setdefault("AuthMethod", "FormsAuthentication")

    r2 = session.post(action, data=payload, timeout=20, allow_redirects=False)

    # Thanh cong: ADFS tra ve 302 voi Location chua #id_token=... trong fragment
    if r2.status_code in (301, 302, 303) and "Location" in r2.headers:
        location = r2.headers["Location"]
        fragment = urlparse(location).fragment
        if not fragment:
            fail(f"Redirect khong co fragment chua token: {location[:80]}...")
        qs = parse_qs(fragment)
        id_token = qs.get("id_token", [None])[0]
        if not id_token:
            fail("Redirect thanh cong nhung khong thay id_token trong fragment")
    elif r2.status_code == 200:
        # Khong redirect: hoac sai mat khau, hoac co buoc xac thuc bo sung (MFA/trang khac)
        err = re.search(r'id="errorText"[^>]*>([^<]*)</span>', r2.text)
        err_text = html.unescape(err.group(1)).strip() if err and err.group(1) else ""
        if err_text:
            fail(f"ADFS tu choi dang nhap: {err_text}")
        # Khong co loi ro rang nhung cung khong redirect -> co the la buoc MFA la
        # khong luong truoc duoc. Dung lai, KHONG doan mo, de tranh gui sai du lieu.
        fail("ADFS khong redirect va khong bao loi ro rang - co the da them buoc "
             "xac thuc moi (MFA/CAPTCHA). Dang nhap tay va kiem tra lai luong.")
    else:
        fail(f"Phan hoi khong mong doi tu ADFS (HTTP {r2.status_code})")

    # 3) Doi id_token lay TokenBKNexus
    r3 = requests.post(
        LOGIN_BY_TOKEN_URL,
        json={"AccessToken": id_token},
        headers={"Content-Type": "application/json", "User-Agent": UA,
                 "Origin": "https://ctsv.hust.edu.vn",
                 "Referer": "https://ctsv.hust.edu.vn/dat-ve"},
        timeout=20,
    )
    try:
        data = r3.json()
    except ValueError:
        fail(f"LoginByAccessToken tra ve khong phai JSON (HTTP {r3.status_code})")

    if data.get("RespCode") != 0 or not data.get("Token"):
        fail(f"LoginByAccessToken that bai: {data}")

    token_bknexus = data["Token"]
    print(f"[OK] Lay duoc TokenBKNexus moi, dai {len(token_bknexus)} ky tu")

    # 4) Ghi vao Gist cho ESP32 doc
    gist_resp = requests.patch(
        f"https://api.github.com/gists/{gist_id}",
        headers={
            "Authorization": f"Bearer {gh_token}",
            "Accept": "application/vnd.github+json",
        },
        json={"files": {gist_filename: {"content": token_bknexus}}},
        timeout=20,
    )
    if gist_resp.status_code != 200:
        fail(f"Khong ghi duoc vao Gist (HTTP {gist_resp.status_code}): {gist_resp.text[:200]}")

    print("[OK] Da cap nhat Gist. ESP32 se tu lay token trong vong vai phut.")


if __name__ == "__main__":
    main()
