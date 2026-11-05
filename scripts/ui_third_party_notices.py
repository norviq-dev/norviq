# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Write ui/THIRD_PARTY_NOTICES.txt from ui/package-lock.json and an installed ui/node_modules.

The console image ships a Vite bundle, and the bundle carries none of its dependencies' licence
files. This collects them: for every package that can reach the bundle, the licence, NOTICE and
third-party-notice files at the top of the installed package, in full. Line endings are normalised to
LF and trailing whitespace is removed; nothing else is changed.

"Can reach the bundle" is every non-dev package in the lockfile, plus the dev packages whose code the
build compiles into its output anyway (bundled_dev_packages() below): each package named in an
@import of ui/src/index.css (tailwindcss's generated CSS carries its own licence banner, for one) and
the build-time emitters listed in BUILD_TIME_EMITTERS. Together that is a superset of what the bundle
contains (it also lists type-only and CLI-only packages), so nothing the bundle carries is left out.
tests/release/test_ui_licence_allowlist.py checks the licences of this same set.

Run after `npm ci` in ui/:

    python3 scripts/ui_third_party_notices.py            # rewrite the file
    python3 scripts/ui_third_party_notices.py --check    # exit 1 if the file is stale or missing

It exits 1 if a package has no licence file, rather than writing an entry with nothing in it.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_LEGAL = re.compile(r"^(licen[cs]e|copying|notice|thirdpartynotices)([.-].*)?$", re.IGNORECASE)
_RULE = "=" * 78

# Dev-only packages (devDependencies) that write code of their own into the built bundle, so their
# licence applies to what the console image ships even though the lockfile marks them `dev`. Keep this
# list in step with ui/vite.config.ts and the bundler Vite uses. Packages pulled in through an @import
# in ui/src/index.css are found by parsing that file and need no entry here.
BUILD_TIME_EMITTERS: tuple[str, ...] = (
    "vite",  # injects its module-preload helper and modulepreload polyfill into the entry chunk
    "rolldown",  # Vite 8's bundler: emits its runtime helpers (CommonJS interop, chunk loading)
    # Checked and NOT listed: @tailwindcss/vite only drives tailwindcss, whose CSS output is covered by
    # the @import "tailwindcss" in index.css; @vitejs/plugin-react only injects React Refresh in dev
    # builds, and the production JSX runtime comes from react (a runtime dependency).
)

# `@import "pkg"`, `@import 'pkg/file.css'`, `@import url("pkg")`, optionally followed by layer() etc.
_CSS_IMPORT = re.compile(r"""@import\s+(?:url\(\s*)?["']([^"']+)["']""")


def css_import_packages(css: str) -> list[str]:
    """npm package names named by the @import rules in a CSS source (relative and URL imports skipped)."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
    names = []
    for spec in _CSS_IMPORT.findall(css):
        if spec.startswith((".", "/", "~/")) or "://" in spec or spec.startswith("@/"):
            continue
        parts = spec.split("/")
        name = "/".join(parts[:2]) if spec.startswith("@") else parts[0]
        if name not in names:
            names.append(name)
    return names


def bundled_dev_packages(ui: Path, lock_packages: dict[str, dict]) -> dict[str, str]:
    """Lockfile key -> reason, for every dev-marked package whose code reaches the bundle.

    Resolved through the lockfile's top-level `node_modules/<name>` entry, which is what both
    `@import` resolution from ui/src and Vite's own imports load. A name the lockfile does not have is
    an error: a build input that cannot be checked must not be skipped.
    """
    wanted = {
        name: "@import in ui/src/index.css" for name in css_import_packages((ui / "src" / "index.css").read_text())
    }
    for name in BUILD_TIME_EMITTERS:
        wanted.setdefault(name, "build-time emitter")
    out = {}
    for name, reason in wanted.items():
        key = f"node_modules/{name}"
        if key not in lock_packages:
            raise LookupError(f"{name} ({reason}) has no {key} entry in ui/package-lock.json")
        out[key] = reason
    return out


def bundle_packages(ui: Path, lock_packages: dict[str, dict]) -> dict[str, dict]:
    """Lockfile key -> metadata for every package that can reach the bundle (see the module docstring)."""
    extra = bundled_dev_packages(ui, lock_packages)
    return {
        key: meta
        for key, meta in lock_packages.items()
        if key and (key in extra or not (meta.get("dev") or meta.get("devOptional")))
    }


def _packages(ui: Path) -> list[tuple[str, str, str, Path]]:
    lock = json.loads((ui / "package-lock.json").read_text())["packages"]
    out = []
    for key, meta in bundle_packages(ui, lock).items():
        name = key.rsplit("node_modules/", 1)[1]
        out.append((name, meta["version"], str(meta.get("license", "UNKNOWN")), ui / key))
    return sorted(out, key=lambda p: (p[0], p[1]))


def render(ui: Path) -> str:
    pkgs = _packages(ui)
    missing = []
    parts = [
        "Norviq console UI: third-party notices",
        "",
        "The console image (Dockerfile.ui) serves a JavaScript bundle built from ui/. The bundle",
        "includes code from the packages below. This file lists every non-dev package in",
        "ui/package-lock.json plus the dev packages the build compiles into the bundle (those named",
        "in an @import of ui/src/index.css, and the build-time emitters listed in the generator),",
        "which together are a superset of what the bundle contains, with the licence, NOTICE and",
        "third-party-notice files each package ships, reproduced in full (line endings normalised",
        "to LF, trailing whitespace removed).",
        "",
        "Generated by scripts/ui_third_party_notices.py. Do not edit by hand.",
        "",
        f"{len(pkgs)} packages:",
        "",
    ]
    parts += [f"  {name} {version} ({lic})" for name, version, lic, _ in pkgs]
    for name, version, lic, path in pkgs:
        files = sorted(f for f in path.iterdir() if f.is_file() and _LEGAL.match(f.name)) if path.is_dir() else []
        if not files:
            missing.append(f"{name}@{version}")
            continue
        for f in files:
            raw = f.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
            # Trailing spaces only: they carry no meaning in a licence and trip whitespace linters.
            text = "\n".join(line.rstrip() for line in raw.splitlines()).strip("\n")
            parts += ["", _RULE, f"{name} {version} ({lic}): {f.name}", _RULE, "", text]
    if missing:
        sys.exit("no licence file installed for: " + ", ".join(missing) + " (run `npm ci` in ui/ first)")
    return "\n".join(parts) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ui-dir", type=Path, default=ROOT / "ui")
    ap.add_argument("--out", type=Path, default=ROOT / "ui" / "THIRD_PARTY_NOTICES.txt")
    ap.add_argument("--check", action="store_true", help="fail if --out differs from what would be written")
    args = ap.parse_args()
    text = render(args.ui_dir)
    if args.check:
        current = args.out.read_text() if args.out.exists() else ""
        if current != text:
            print(f"{args.out} is stale: re-run scripts/ui_third_party_notices.py after `npm ci`", file=sys.stderr)
            return 1
        print(f"{args.out} is current")
        return 0
    args.out.write_text(text)
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
