# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Every code reference in docs/cli.md must name something that exists.

The page used to cite `file:line`. Measured against `prep/0.2.6` before this test existed: 135 line
citations, of which 51 pointed outside the symbol the sentence meant (as far as 563 lines away), four
cited only a blank line or a lone `)`, and 69 gave a bare basename (`policies.py:1140`) the page never
resolved. Nothing in CI reads prose, so every refactor of `norviq/api/routers/policies.py` moved the
code out from under the sentence and left the sentence in place — and one of those sentences
("`--target-type` is inert") had become false while still pointing at the line that proved it.

So the page names symbols instead, and this test resolves them:

  * `path::name` / `path::Class.method` — Python through `ast` (functions, classes, methods, nested
    functions, class attributes, module-level assignments; NOT imports, so an anchor cannot name the
    importing file instead of the defining one). TypeScript, Go and Rego through a definition grep;
    nginx through its `location` blocks. Any other file type fails until a resolver is written for it.
  * `file.yaml: a.b.c` / `file.toml: a.b.c` — a key path, walked through the parsed document.

A symbol anchor cannot drift by a line; it can only stop existing, and then this fails. That still
does not prove the sentence is TRUE — read the code when you change it — but it does prove the
reader is sent to the thing the sentence is about.
"""

from __future__ import annotations

import ast
import re
import tomllib
from functools import lru_cache
from pathlib import Path

import pytest
import yaml

_ROOT = Path(__file__).resolve().parents[1]

# Pages held to symbol anchors. Add a page here once its line citations are converted.
_ANCHORED_PAGES = ("docs/cli.md",)

# `policies.py:1140`, `norviq/cli/main.py:49-53`, `ui/nginx.conf:26-27,64-70`. The extension list is
# what keeps host:port (`norviq-api:8080`, `http://127.0.0.1:8080`) from matching.
_RAW_CITATION = re.compile(
    r"(?<![\w/.-])[\w./-]+\.(?:py|pyi|tsx?|jsx?|go|rego|ya?ml|toml|conf|json|sh|md|cfg|ini):\d+"
)
# The page once continued a citation with a bare `:1187,1197`; it named no file at all.
_BARE_CONTINUATION = re.compile(r"`:\d[\d,\-]*`")
# "called at line 48" — the same defect in prose.
_PROSE_LINE_REF = re.compile(r"\blines? \d+\b", re.IGNORECASE)

_BACKTICK_SPAN = re.compile(r"`([^`\n]+)`")
_CODE_ANCHOR = re.compile(r"^([\w.][\w./-]*)::(.+)$")
_KEY_ANCHOR = re.compile(r"^([\w.][\w./-]*\.(?:ya?ml|toml)): (\S.*)$")


def _raw_citations(text: str) -> list[str]:
    hits = [m.group(0) for m in _RAW_CITATION.finditer(text)]
    hits += [m.group(0) for m in _BARE_CONTINUATION.finditer(text)]
    hits += [m.group(0) for m in _PROSE_LINE_REF.finditer(text)]
    return hits


def _anchors(text: str) -> list[tuple[str, str, str]]:
    """(kind, path, target) for every backticked anchor on the page."""
    found = []
    for span in _BACKTICK_SPAN.findall(text):
        if m := _CODE_ANCHOR.match(span):
            found.append(("code", m.group(1), m.group(2).strip()))
        elif m := _KEY_ANCHOR.match(span):
            found.append(("key", m.group(1), m.group(2).strip()))
    return found


# --- resolvers ----------------------------------------------------------------------------------

@lru_cache(maxsize=None)
def _python_symbols(path: Path) -> frozenset[str]:
    """Dotted names DEFINED in a module. Imports are deliberately absent."""
    names: set[str] = set()

    def walk(body: list[ast.stmt], prefix: str, scope: str) -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(prefix + node.name)
                walk(node.body, f"{prefix}{node.name}.",
                     "class" if isinstance(node, ast.ClassDef) else "function")
                continue
            if scope != "function":  # a function's locals are not something a sentence can point at
                if isinstance(node, ast.Assign):
                    names.update(prefix + t.id for t in node.targets if isinstance(t, ast.Name))
                elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                    names.add(prefix + node.target.id)
            # Definitions under `if TYPE_CHECKING:`, `try:`, `with ...:` belong to the enclosing scope.
            for field in ("body", "orelse", "finalbody", "handlers"):
                for child in getattr(node, field, []) or []:
                    if isinstance(child, ast.ExceptHandler):
                        walk(child.body, prefix, scope)
                    elif isinstance(child, ast.stmt):
                        walk([child], prefix, scope)

    walk(ast.parse(path.read_text(encoding="utf-8")).body, "", "module")
    return frozenset(names)


def _ts_defines(src: str, name: str) -> bool:
    n = re.escape(name)
    return re.search(
        rf"^\s*(?:export\s+)?(?:default\s+)?(?:declare\s+)?(?:async\s+)?"
        rf"(?:function\*?|const|let|var|class|interface|type|enum)\s+{n}\b"
        rf"|^\s*(?:(?:public|private|protected|static|readonly|async)\s+)*{n}\s*(?:<[^>]*>)?\([^)]*\)\s*[:{{]",
        src, re.MULTILINE,
    ) is not None


def _go_defines(src: str, name: str) -> bool:
    n = re.escape(name)
    return re.search(
        rf"^func\s+(?:\([^)]*\)\s*)?{n}\s*[\[(]|^type\s+{n}\b|^(?:const|var)\s+{n}\b|^\t{n}\s+(?:\S+\s+)?=",
        src, re.MULTILINE,
    ) is not None


def _rego_defines(src: str, name: str) -> bool:
    n = re.escape(name)
    return re.search(rf"^(?:default\s+)?{n}\s*(?:\[|\{{|=|:=|if\b|contains\b|\()", src, re.MULTILINE) is not None


def _nginx_defines(src: str, target: str) -> bool:
    m = re.fullmatch(r"location\s+(\S+)", target)
    if not m:
        return False
    return re.search(rf"^\s*location\s+(?:[=~^*]+\s*)?{re.escape(m.group(1))}\s*\{{", src, re.MULTILINE) is not None


_GREP_RESOLVERS = {
    ".ts": _ts_defines, ".tsx": _ts_defines, ".js": _ts_defines, ".jsx": _ts_defines,
    ".go": _go_defines, ".rego": _rego_defines,
}


def _resolve(kind: str, rel: str, target: str) -> str | None:
    """None if the anchor resolves, else why not."""
    if rel.startswith(("/", "..")) or "/../" in rel:
        return "path must be repo-relative"
    path = _ROOT / rel
    if not path.is_file():
        return "no such file (anchors take the full repo-relative path, never a bare basename)"
    if kind == "key":
        return _resolve_key(path, target)
    if path.suffix == ".py":
        return None if target in _python_symbols(path) else "not defined in this module"
    src = path.read_text(encoding="utf-8")
    if path.suffix == ".conf":
        return None if _nginx_defines(src, target) else "no such nginx location block"
    grep = _GREP_RESOLVERS.get(path.suffix)
    if grep is None:
        return f"no resolver for {path.suffix or 'extensionless'} files — add one to this test"
    missing = [part for part in target.split(".") if not grep(src, part)]
    return f"no definition of {missing}" if missing else None


def _resolve_key(path: Path, dotted: str) -> str | None:
    if path.suffix == ".toml":
        docs = [tomllib.loads(path.read_text(encoding="utf-8"))]
    else:
        docs = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d is not None]
    for doc in docs:
        node = doc
        for key in dotted.split("."):
            if not isinstance(node, dict) or key not in node:
                break
            node = node[key]
        else:
            return None
    return "key path not present"


# --- the page ----------------------------------------------------------------------------------

@pytest.mark.parametrize("page", _ANCHORED_PAGES)
def test_no_raw_line_citations(page):
    hits = _raw_citations((_ROOT / page).read_text(encoding="utf-8"))
    assert not hits, (
        f"{page} cites line numbers, which nothing keeps fresh — name the symbol instead "
        f"(`path::function`, `path::Class.method`, `file.yaml: key.path`):\n  " + "\n  ".join(hits)
    )


@pytest.mark.parametrize("page", _ANCHORED_PAGES)
def test_every_anchor_resolves(page):
    anchors = _anchors((_ROOT / page).read_text(encoding="utf-8"))
    assert anchors, f"{page} has no anchors at all — the anchor pattern no longer matches the page's convention"
    broken = [f"`{rel}{'::' if kind == 'code' else ': '}{target}` — {why}"
              for kind, rel, target in sorted(set(anchors))
              if (why := _resolve(kind, rel, target)) is not None]
    assert not broken, f"{page} has anchors that resolve to nothing:\n  " + "\n  ".join(broken)


@pytest.mark.parametrize("page", _ANCHORED_PAGES)
def test_every_double_colon_span_is_a_well_formed_anchor(page):
    """A malformed anchor (`main.py ::cli`, `::cli`) would be skipped by the resolver, not failed by it."""
    spans = [s for s in _BACKTICK_SPAN.findall((_ROOT / page).read_text(encoding="utf-8")) if "::" in s]
    malformed = [s for s in spans if not _CODE_ANCHOR.match(s)]
    assert not malformed, f"{page} has `::` spans that are not `path::symbol`:\n  " + "\n  ".join(malformed)


# --- controls: the checks above must be able to fail ---------------------------------------------

@pytest.mark.parametrize("text", [
    "`policies.py:1140`",
    "(`norviq/cli/main.py:49-53`)",
    "`ui/nginx.conf:26-27,64-70`",
    "`pyproject.toml:67-68`",
    "echoed back at `:1187,1197`",
    "(`_load_dotenv`, called at line 48)",
])
def test_raw_citation_detector_flags(text):
    assert _raw_citations(text), text


@pytest.mark.parametrize("text", [
    "`http://127.0.0.1:8080`",
    "`norviq-api:8080`",
    "`kubectl -n norviq port-forward svc/norviq-ui 8080:80`",
    "the 64 KiB / 650-line / 25-regex-operation caps",
    "`norviq/cli/main.py::cli`",
])
def test_raw_citation_detector_passes(text):
    assert not _raw_citations(text), text


@pytest.mark.parametrize("kind,rel,target", [
    ("code", "norviq/cli/main.py", "policy_lsit"),             # typo
    ("code", "norviq/cli/main.py", "APIClient"),               # imported there, defined elsewhere
    ("code", "main.py", "cli"),                                # bare basename
    ("code", "norviq/nope.py", "x"),                           # no such file
    ("code", "norviq/api/routers/agents.py", "update_trust.frozen"),  # a local, not a symbol
    ("code", "norviq/cli/api_client.py", "APIClient.get_json"),       # no such method
    ("code", "norviq/config.py", "NorviqSettings.opa_mod"),          # no such attribute
    ("code", "ui/src/auth/session.ts", "setTokn"),
    ("code", "webhook/injector.go", "mintSidecarTokn"),
    ("code", "webhook/presets/strict.rego", "decison"),
    ("code", "ui/nginx.conf", "location /nope/"),
    ("code", "docs/cli.md", "anything"),                       # no resolver for the type
    ("key", "pyproject.toml", "project.scriptz.norviq"),
    ("key", "helm/norviq/values.yaml", "baselineClusterPolicy.enforcementMod"),
])
def test_resolver_rejects(kind, rel, target):
    assert _resolve(kind, rel, target) is not None, f"{rel} {target} should NOT resolve"


@pytest.mark.parametrize("kind,rel,target", [
    ("code", "norviq/cli/main.py", "policy_list"),
    ("code", "norviq/cli/api_client.py", "APIClient._fatal"),
    ("code", "norviq/config.py", "NorviqSettings.opa_mode"),
    ("code", "norviq/sidecar/http_fallback.py", "create_http_fallback.evaluate"),
    ("code", "ui/src/auth/session.ts", "setToken"),
    ("code", "webhook/injector.go", "mintSidecarToken"),
    ("code", "webhook/presets/strict.rego", "decision"),
    ("code", "ui/nginx.conf", "location /api/"),
    ("key", "pyproject.toml", "project.scripts.norviq"),
    ("key", "helm/norviq/values.yaml", "baselineClusterPolicy.enforcementMode"),
])
def test_resolver_accepts(kind, rel, target):
    assert _resolve(kind, rel, target) is None
