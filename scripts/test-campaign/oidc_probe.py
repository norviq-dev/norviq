#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Phase-B OIDC/JWT adversarial probe. Forges malicious tokens and asserts the API rejects them (401),
while a valid HS256 break-glass token is accepted. Run with the .venv python (needs python-jose).

Env: API_BASE (default http://127.0.0.1:18081), SECRET (legacy HS256 secret), JWKS_PEM (optional path to
the Keycloak RSA public key PEM for the alg-confusion test)."""
from __future__ import annotations
import base64, hashlib, hmac, json, os, time, urllib.request

API = os.environ.get("API_BASE", "http://127.0.0.1:18081").rstrip("/")
SECRET = os.environ.get("SECRET", "identity-local-secret-7c1f")
JWKS_PEM = os.environ.get("JWKS_PEM", "")

def b64(b: bytes) -> bytes:
    return base64.urlsafe_b64encode(b).rstrip(b"=")

def jwt_unsigned(header: dict, payload: dict) -> str:
    h = b64(json.dumps(header, separators=(",", ":")).encode())
    p = b64(json.dumps(payload, separators=(",", ":")).encode())
    return (h + b"." + p).decode()

def hs(header: dict, payload: dict, secret: bytes) -> str:
    body = jwt_unsigned(header, payload).encode()
    sig = b64(hmac.new(secret, body, hashlib.sha256).digest())
    return body.decode() + "." + sig.decode()

def code_for(token: str) -> int:
    req = urllib.request.Request(API + "/api/v1/me", headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0

def main() -> int:
    now = int(time.time())
    admin = {"sub": "atk", "role": "admin", "namespace": "default", "iat": now, "exp": now + 3600}
    results = []

    # 1) alg:none (unsigned) -> reject
    t = jwt_unsigned({"alg": "none", "typ": "JWT"}, admin) + "."
    results.append(("alg:none", code_for(t), 401))

    # 2) off-allowlist alg HS512 with the real secret -> reject (only HS256 allowed in legacy)
    t = hs({"alg": "HS512", "typ": "JWT"}, admin, SECRET.encode())  # signed HS256 bytes but header lies HS512
    results.append(("alg:HS512 off-allowlist", code_for(t), 401))

    # 3) HS256 with WRONG secret -> reject
    t = hs({"alg": "HS256", "typ": "JWT"}, admin, b"not-the-secret")
    results.append(("HS256 wrong-secret", code_for(t), 401))

    # 4) alg-confusion: HS256 signed with the RSA PUBLIC key bytes -> reject (HS256 path uses api_secret_key)
    if JWKS_PEM and os.path.exists(JWKS_PEM):
        pub = open(JWKS_PEM, "rb").read()
        t = hs({"alg": "HS256", "typ": "JWT", "kid": "confuse"}, admin, pub)
        results.append(("alg-confusion HS256-with-RSpub", code_for(t), 401))

    # 5) expired HS256 (real secret) -> reject
    exp = dict(admin, exp=now - 10)
    t = hs({"alg": "HS256", "typ": "JWT"}, exp, SECRET.encode())
    results.append(("HS256 expired", code_for(t), 401))

    # 6) VALID HS256 break-glass (real secret) -> ACCEPT (legacy on)
    t = hs({"alg": "HS256", "typ": "JWT"}, admin, SECRET.encode())
    results.append(("HS256 valid break-glass", code_for(t), 200))

    ok = True
    print("== OIDC/JWT forge probes (expect reject=401, valid=200) ==")
    for name, got, want in results:
        verdict = "PASS" if got == want else "FAIL"
        if got != want:
            ok = False
        print(f"  [{verdict}] {name:34s} -> HTTP {got} (want {want})")
    return 0 if ok else 1

if __name__ == "__main__":
    raise SystemExit(main())
