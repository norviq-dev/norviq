#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Generate the dedicated fleet bundle signing keypair (RS256). The PRIVATE key goes ONLY to the hub;
# the PUBLIC key (trust root) is distributed to spokes. Local POC artifacts — gitignored, never committed.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PRIV="$HERE/fleet-signing-priv.pem"
PUB="$HERE/fleet-signing-pub.pem"
if [ -f "$PRIV" ] && [ -f "$PUB" ]; then echo "keys already exist"; exit 0; fi
"$HERE/../../.venv/bin/python" - "$PRIV" "$PUB" <<'PY'
import sys
import rsa
from jose.backends import RSAKey
priv_path, pub_path = sys.argv[1], sys.argv[2]
_, priv = rsa.newkeys(2048)
priv_pem = priv.save_pkcs1().decode()
open(priv_path, "w").write(priv_pem)
open(pub_path, "w").write(RSAKey(priv_pem, "RS256").public_key().to_pem().decode())
print("generated", priv_path, pub_path)
PY
