#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Generate a locked-down OPA capabilities.json: everything `opa capabilities --current` reports, MINUS the
builtins that let a policy escape the pure-decision sandbox (network egress / SSRF, OPA server env/config
disclosure, JWT decode/verify, dynamic-module compilation, and trace/print information disclosure).

This is engine-layer defense-in-depth for the same class of finding the API-layer reject in
`norviq/api/routers/policies.py` (`_FORBIDDEN_REGO_TOKENS`) closes: a `--capabilities` file passed to
`opa run --server` makes the OPA COMPILER itself reject these builtins (undefined function), so even a rego
payload that somehow reaches the OPA server without going through the API validator (e.g. a future code path,
a bug in the API check) still cannot call them. Keep the two lists in sync when either changes.

Regenerate after an OPA upgrade:
    python3 scripts/gen-opa-capabilities.py --opa-version-check

`--opa-version-check` refuses to write unless the binary is the version `opa.image` in helm/norviq/values.yaml
pins: the sidecar is what compiles and serves the policies, so its builtin set is the one to lock down. Without
it the script generates from whatever `opa` is first on PATH. Pass `--opa-bin` to point at the pinned binary.

Generated from: OPA v1.21.4 (the opa_linux_amd64_static release asset, sha256 2ab571f3...).
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VALUES_PATH = REPO_ROOT / "helm" / "norviq" / "values.yaml"
OUTPUT_PATHS = [
    REPO_ROOT / "helm" / "norviq" / "files" / "opa-capabilities.json",
    REPO_ROOT / "norviq" / "engine" / "opa-capabilities.json",
]

# Mirrors norviq/api/routers/policies.py::_FORBIDDEN_REGO_TOKENS (keep both lists in sync):
#   http.send          - arbitrary outbound HTTP (SSRF: internal services, cloud metadata endpoint)
#   opa.runtime        - dumps OPA server env vars / config (secret exfiltration)
#   net.*              - net.lookup_ip_addr / net.cidr_* (network/DNS reconnaissance)
#   io.*               - io.jwt.decode/verify/encode (token forging/inspection surface)
#   rego.parse_module  - compiles rego at eval time from attacker-controlled input (parser/sandbox escape)
#   trace              - trace() (internal evaluation state disclosure)
#   print              - print() (side-channel / log-based information disclosure; also a perf foot-gun)
_FORBIDDEN_EXACT = {"http.send", "opa.runtime", "rego.parse_module", "trace", "print"}
_FORBIDDEN_PREFIXES = ("net.", "io.")


def _is_forbidden(name: str) -> bool:
    return name in _FORBIDDEN_EXACT or name.startswith(_FORBIDDEN_PREFIXES)


def pinned_opa_version(values_text: str) -> str:
    """The x.y.z of `opa.image` in the chart's values.yaml. Read with a regex rather than a YAML parser so the
    script keeps running on a bare python3; the `opa:` block is top-level and `image` is one of its keys."""
    m = re.search(r'^opa:\n(?:[ \t]+.*\n|\n)*?[ \t]+image:\s*"?[^"\s]*/opa:v?(\d+\.\d+\.\d+)', values_text, re.M)
    if not m:
        raise ValueError("opa.image in helm/norviq/values.yaml names no openpolicyagent/opa:<x.y.z> tag")
    return m.group(1)


def generate(opa_bin: str) -> dict:
    raw = subprocess.run([opa_bin, "capabilities", "--current"], check=True, capture_output=True, text=True).stdout
    caps = json.loads(raw)
    before = len(caps.get("builtins", []))
    dropped = sorted(b["name"] for b in caps.get("builtins", []) if _is_forbidden(b["name"]))
    caps["builtins"] = [b for b in caps.get("builtins", []) if not _is_forbidden(b["name"])]
    after = len(caps["builtins"])
    print(f"opa capabilities: {before} builtins -> {after} kept, {before - after} dropped", file=sys.stderr)
    print("dropped:", ", ".join(dropped), file=sys.stderr)
    return caps


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--opa-bin", default="opa", help="path to the opa binary (default: opa on PATH)")
    parser.add_argument(
        "--opa-version-check",
        action="store_true",
        help="refuse to write unless the binary is the version opa.image in helm/norviq/values.yaml pins",
    )
    args = parser.parse_args()

    opa_bin = shutil.which(args.opa_bin)
    if not opa_bin:
        print(f"error: '{args.opa_bin}' not found on PATH", file=sys.stderr)
        return 1

    version_out = subprocess.run([opa_bin, "version"], check=True, capture_output=True, text=True).stdout
    m = re.search(r"Version:\s*(\S+)", version_out)
    version = m.group(1) if m else "unknown"
    print(f"generating from opa version {version}", file=sys.stderr)
    if args.opa_version_check:
        pinned = pinned_opa_version(VALUES_PATH.read_text(encoding="utf-8"))
        if version != pinned:
            print(f"error: opa {version} is not {pinned}, the version opa.image pins; nothing written", file=sys.stderr)
            return 1

    caps = generate(opa_bin)
    payload = json.dumps(caps, indent=2, sort_keys=True) + "\n"
    for out_path in OUTPUT_PATHS:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(payload, encoding="utf-8")
        print(f"wrote {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
