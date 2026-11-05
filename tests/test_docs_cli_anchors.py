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
    importing file instead of the defining one). TypeScript, Go and Rego through a definition grep,
    which can back a bare name only; nginx through its `location` blocks. Any other file type fails
    until a resolver is written for it.
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

# `policies.py:1140`, `norviq/cli/main.py:49-53`, `ui/nginx.conf:26-27,64-70`, `_helpers.tpl:20`,
# `Dockerfile.api:52`. The extension list is what keeps host:port (`norviq-api:8080`,
# `http://127.0.0.1:8080`) from matching, so it names the extensions instead of guessing: every text
# file type the repo tracks (fonts and images aside), and the extensionless build files by name.
_RAW_CITATION = re.compile(
    r"(?<![\w/.-])(?:"
    r"[\w./-]*\.(?:py|pyi|tsx?|jsx?|mjs|cjs|go|mod|sum|rego|ya?ml|toml|conf|json|sh|bash|md|cfg|ini|tpl|sql"
    r"|txt|css|html?|env|lock|cff|\w*ignore)(?:\.example)?"
    r"|(?:[\w./-]*/)?(?:Dockerfile|Containerfile|Makefile)(?:\.[\w-]+)?"
    r"):\d+"
)
# The page once continued a citation with a bare `:1187,1197`; it named no file at all.
_BARE_CONTINUATION = re.compile(r"`:\d[\d,\-]*`")
# "called at line 48" — the same defect in prose, including "line" and "48" on either side of a wrap.
_PROSE_LINE_REF = re.compile(r"\blines?\s+\d+\b", re.IGNORECASE)

_CODE_ANCHOR = re.compile(r"^([\w.][\w./-]*)::(\S.*)$")
_KEY_ANCHOR = re.compile(r"^([\w.][\w./-]*\.(?:ya?ml|toml)): (\S.*)$")
# Text that is only ever written as part of an anchor. Every occurrence in the page's prose (`_prose`)
# must sit inside a span `_anchors` returned — see `test_nothing_anchor_shaped_is_left_unchecked`.
_ANCHOR_SHAPED = re.compile(r"::|\.(?:ya?ml|toml):\s")


def _raw_citations(text: str) -> list[str]:
    hits = [m.group(0) for m in _RAW_CITATION.finditer(text)]
    hits += [m.group(0) for m in _BARE_CONTINUATION.finditer(text)]
    hits += [" ".join(m.group(0).split()) for m in _PROSE_LINE_REF.finditer(text)]
    return hits


# --- reading the page the way CommonMark does ----------------------------------------------------
#
# The first version of this test paired backticks one line at a time (`([^`\n]+)`). CommonMark lets a
# code span wrap a line, and after a span that did, every pairing on the next line was off by one: the
# two anchors written after a wrapped span on this page (`APIClient._request`, and the second of the
# three `reporter.py::_payload`) were never resolved, and a typo planted in either still gave a green
# run. So what is not prose (fenced code, HTML comments, blockquote markers) is blanked first, and a
# backtick string pairs with the next one of the same length across line breaks, but never across a
# blank line or into another block: a list item, a heading, a GFM table cell (CommonMark 0.31 §6.1,
# GFM §4.10). Checked against markdown-it-py 3.0.0 over the 67 tracked .md files when this was written:
# identical code spans on 65. The other two use constructs this reads as prose although GFM renders
# them as code or not at all (an indented code block inside a list item; table cells past the header's
# count) — so a `::` in one is checked or reported, never skipped.
#
# That is the general rule: the parser can be wrong about a construct no page here uses yet, but it can
# no longer be wrong quietly, because `test_nothing_anchor_shaped_is_left_unchecked` fails on any `::`
# it did not hand to the resolver.

_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
_HTML_COMMENT = re.compile(r"^ {0,3}<!--")
_QUOTE_MARKERS = re.compile(r"^(?: {0,3}> ?)+")
# A line that is a block by itself (ATX heading, thematic break): no span reaches past it.
_ONE_LINE_BLOCK = re.compile(r"^ {0,3}(?:#{1,6}(?:\s|$)|(?:[-*_][ \t]*){3,}$)")
# A line that opens a new block (a list item) even with no blank line before it.
_BLOCK_START = re.compile(r"^\s*(?:[-+*]|\d{1,9}[.)])(?:\s|$)")
# The row under a GFM table's header: pipes, dashes, colons.
_TABLE_DELIMITER = re.compile(r"^ {0,3}(?=[^|\n]*\|)(?=[^-\n]*-)[|:\- \t]+$")
_CELL_PIPE = re.compile(r"(?<!\\)\|")
_BACKTICK_RUN = re.compile(r"`+")


def _blank(line: str) -> str:
    return re.sub(r"[^\n]", " ", line)


def _prose(text: str) -> str:
    """`text` with fenced code, HTML comment blocks and blockquote markers blanked to spaces.

    Offsets and line numbers still match the page.
    """
    out, fence, comment, opened_at = [], None, False, 0
    for number, line in enumerate(text.splitlines(keepends=True), 1):
        if q := _QUOTE_MARKERS.match(line):
            line = " " * q.end() + line[q.end() :]
        m = _FENCE.match(line)
        if comment:
            comment = "-->" not in line
        elif fence is not None:
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) and not line[m.end() :].strip():
                fence = None
        # A backtick fence's info string cannot contain a backtick: ```` ```foo``` ```` is inline code.
        elif m and not (m.group(1)[0] == "`" and "`" in line[m.end() :]):
            fence, opened_at = m.group(1), number
        elif _HTML_COMMENT.match(line):
            comment, opened_at = "-->" not in line[line.index("<!--") + 4 :], number
        else:
            out.append(line)
            continue
        out.append(_blank(line))
    if fence is not None or comment:
        # CommonMark lets an unclosed fence or comment run to the end of the page. Here that would blank
        # every anchor after it out of every check below, so it is an error instead.
        raise ValueError(
            f"the {'fence' if comment is False else 'HTML comment'} opened at line {opened_at} never closes"
        )
    return "".join(out)


def _blocks(text: str) -> list[tuple[int, str, bool]]:
    """(offset, text, is_table_cell) of each stretch of prose one code span may cross."""
    prose = _prose(text)
    lines, raw = prose.splitlines(keepends=True), text.splitlines(keepends=True)
    blocks, start, pos, depth, table = [], None, 0, 0, False
    for i, line in enumerate(lines):
        quoted = _QUOTE_MARKERS.match(raw[i])
        level = quoted.group(0).count(">") if quoted else 0
        blank = not line.strip()
        # A blockquote (or a deeper one) interrupts a paragraph; a lazy line without `>` continues it.
        new_block = blank or _ONE_LINE_BLOCK.match(line) or _BLOCK_START.match(line) or level > depth
        if new_block:
            depth, table = level, False
        if not table and not blank and "|" in line and i + 1 < len(lines) and _TABLE_DELIMITER.match(lines[i + 1]):
            table = True
        if start is not None and (new_block or table):
            blocks.append((start, prose[start:pos], False))
            start = None
        if table:
            # GFM splits a row into cells before any inline parsing, so a span never crosses a `|`.
            edges = [0, *(m.start() for m in _CELL_PIPE.finditer(line)), len(line)]
            blocks += [(pos + a, line[a:b], True) for a, b in zip(edges, edges[1:])]
        elif _ONE_LINE_BLOCK.match(line):
            blocks.append((pos, line, False))
        elif not blank and start is None:
            start = pos
        pos += len(line)
    if start is not None:
        blocks.append((start, prose[start:], False))
    return blocks


def _code_spans(text: str) -> list[tuple[int, int, str]]:
    """(start, end, content) of every code span in the page's prose; content as CommonMark renders it."""
    spans = []
    for offset, block, cell in _blocks(text):
        runs = [(m.start(), m.end()) for m in _BACKTICK_RUN.finditer(block)]
        i = 0
        while i < len(runs):
            start, end = runs[i]
            # Outside a span a backslash escapes one backtick; inside one it is an ordinary character,
            # which is why only the opener is checked.
            slashes = start - len(block[:start].rstrip("\\"))
            start += slashes % 2
            close = next((j for j in range(i + 1, len(runs)) if runs[j][1] - runs[j][0] == end - start), None)
            if start == end or close is None:
                i += 1  # a backtick string with no closer of the same length is literal text
                continue
            content = re.sub(r"\n[ \t]*", " ", block[end : runs[close][0]])
            if content.startswith(" ") and content.endswith(" ") and content.strip():
                content = content[1:-1]
            if cell:
                content = content.replace("\\|", "|")  # GFM: `a\|b` in a table cell is `a|b`, even in code
            spans.append((offset + start, offset + runs[close][1], content))
            i = close + 1
    return spans


def _anchors(text: str) -> list[tuple[str, str, str]]:
    """(kind, path, target) for every backticked anchor on the page."""
    found = []
    for _, _, span in _code_spans(text):
        if m := _CODE_ANCHOR.match(span):
            found.append(("code", m.group(1), m.group(2).strip()))
        elif m := _KEY_ANCHOR.match(span):
            found.append(("key", m.group(1), m.group(2).strip()))
    return found


def _unchecked(text: str) -> list[str]:
    """Anchor-shaped prose that no anchor `_anchors` returned covers, as `line N: <the line>`."""
    prose = _prose(text)
    covered = [(s, e) for s, e, span in _code_spans(text) if _CODE_ANCHOR.match(span) or _KEY_ANCHOR.match(span)]
    lines = text.splitlines()
    misses = []
    for m in _ANCHOR_SHAPED.finditer(prose):
        if not any(s < m.start() < e for s, e in covered):
            number = prose.count("\n", 0, m.start()) + 1
            misses.append(f"line {number}: {lines[number - 1].strip()}")
    return misses


# --- resolvers ----------------------------------------------------------------------------------


@lru_cache(maxsize=None)
def _python_symbols(path: Path) -> frozenset[str]:
    """Dotted names DEFINED in a module. Imports are deliberately absent."""
    names: set[str] = set()

    def walk(body: list[ast.stmt], prefix: str, scope: str) -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(prefix + node.name)
                walk(node.body, f"{prefix}{node.name}.", "class" if isinstance(node, ast.ClassDef) else "function")
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
    return (
        re.search(
            rf"^\s*(?:export\s+)?(?:default\s+)?(?:declare\s+)?(?:async\s+)?"
            rf"(?:function\*?|const|let|var|class|interface|type|enum)\s+{n}\b"
            rf"|^\s*(?:(?:public|private|protected|static|readonly|async)\s+)*{n}\s*(?:<[^>]*>)?\([^)]*\)\s*[:{{]",
            src,
            re.MULTILINE,
        )
        is not None
    )


def _go_defines(src: str, name: str) -> bool:
    n = re.escape(name)
    return (
        re.search(
            rf"^func\s+(?:\([^)]*\)\s*)?{n}\s*[\[(]|^type\s+{n}\b|^(?:const|var)\s+{n}\b|^\t{n}\s+(?:\S+\s+)?=",
            src,
            re.MULTILINE,
        )
        is not None
    )


def _rego_defines(src: str, name: str) -> bool:
    n = re.escape(name)
    return re.search(rf"^(?:default\s+)?{n}\s*(?:\[|\{{|=|:=|if\b|contains\b|\()", src, re.MULTILINE) is not None


def _nginx_defines(src: str, target: str) -> bool:
    m = re.fullmatch(r"location\s+(\S+)", target)
    if not m:
        return False
    return re.search(rf"^\s*location\s+(?:[=~^*]+\s*)?{re.escape(m.group(1))}\s*\{{", src, re.MULTILINE) is not None


_GREP_RESOLVERS = {
    ".ts": _ts_defines,
    ".tsx": _ts_defines,
    ".js": _ts_defines,
    ".jsx": _ts_defines,
    ".go": _go_defines,
    ".rego": _rego_defines,
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
    if "." in target:
        # A grep finds `bar` anywhere in the file, not inside `Foo`, so it cannot back `Foo.bar` — it
        # used to check each part on its own and pass `Foo.bar` whenever both names existed somewhere.
        return f"`{target}`: a dotted name is checked only in Python — name the {path.suffix} symbol alone"
    return None if grep(src, target) else "no definition of it in this file"


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
    broken = [
        f"`{rel}{'::' if kind == 'code' else ': '}{target}` — {why}"
        for kind, rel, target in sorted(set(anchors))
        if (why := _resolve(kind, rel, target)) is not None
    ]
    assert not broken, f"{page} has anchors that resolve to nothing:\n  " + "\n  ".join(broken)


@pytest.mark.parametrize("page", _ANCHORED_PAGES)
def test_every_double_colon_span_is_a_well_formed_anchor(page):
    """A malformed anchor (`main.py ::cli`, `::cli`) would be skipped by the resolver, not failed by it."""
    spans = [s for _, _, s in _code_spans((_ROOT / page).read_text(encoding="utf-8")) if "::" in s]
    malformed = [s for s in spans if not _CODE_ANCHOR.match(s)]
    assert not malformed, f"{page} has `::` spans that are not `path::symbol`:\n  " + "\n  ".join(malformed)


@pytest.mark.parametrize("page", _ANCHORED_PAGES)
def test_nothing_anchor_shaped_is_left_unchecked(page):
    """Every `::` (and `file.yaml: `) in the page's prose is inside an anchor the resolver checked.

    This is what makes a parsing gap loud. The line-at-a-time parser saw 150 of the page's 152 `::`
    anchors and every test above still passed, because a test can only fail on what it is handed.
    """
    text = (_ROOT / page).read_text(encoding="utf-8")
    unchecked = _unchecked(text)
    assert not unchecked, (
        f"{page}: anchor-shaped text that no resolved anchor covers — an anchor left outside backticks or "
        f"malformed, or a construct this test's parser pairs wrongly:\n  " + "\n  ".join(unchecked)
    )
    in_prose = _prose(text).count("::")
    in_anchors = sum(1 + target.count("::") for kind, _, target in _anchors(text) if kind == "code")
    assert in_prose == in_anchors, f"{page}: {in_prose} `::` in prose, {in_anchors} in resolved anchors"


# --- controls: the checks above must be able to fail ---------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "`policies.py:1140`",
        "(`norviq/cli/main.py:49-53`)",
        "`ui/nginx.conf:26-27,64-70`",
        "`pyproject.toml:67-68`",
        "echoed back at `:1187,1197`",
        "(`_load_dotenv`, called at line 48)",
        "(`_load_dotenv`, called at line\n  48)",  # wrapped between the word and the number
        "`helm/norviq/templates/_helpers.tpl:20`",
        "`webhook/Dockerfile:5`",
        "`Makefile:3`",
        "`norviq/api/db/migrations/0007_keys.sql:12`",
        "`requirements.txt:4`",
        "`Dockerfile.api:52`",
        "`.env.example:3`",
    ],
)
def test_raw_citation_detector_flags(text):
    assert _raw_citations(text), text


@pytest.mark.parametrize(
    "text",
    [
        "`http://127.0.0.1:8080`",
        "`norviq-api:8080`",
        "`kubectl -n norviq port-forward svc/norviq-ui 8080:80`",
        "`registry.example.com:5000/norviq/api:0.2.6`",
        "the 64 KiB / 650-line / 25-regex-operation caps",
        "`norviq/cli/main.py::cli`",
        "the Dockerfile: 3 stages",
    ],
)
def test_raw_citation_detector_passes(text):
    assert not _raw_citations(text), text


@pytest.mark.parametrize(
    "text,spans",
    [
        # The case the line-at-a-time parser lost: a span wraps, and the anchor after it was never seen.
        (
            "errors are `Cannot connect to\n<url> - is the API running?` (`norviq/cli/api_client.py::APIClient._request`)",
            ["Cannot connect to <url> - is the API running?", "norviq/cli/api_client.py::APIClient._request"],
        ),
        (
            "emits\n`{timestamp, summary: {...},\nresults}` (`norviq/redteam/reporter.py::_payload`)",
            ["{timestamp, summary: {...}, results}", "norviq/redteam/reporter.py::_payload"],
        ),
        # A blank line ends the paragraph; a backtick string with no closer before it is literal text.
        ("an open `tick\n\nthen `a.py::b`", ["a.py::b"]),
        # A table cell, a heading and a list item are blocks of their own.
        ("| a | b |\n|---|---|\n| `x | `a.py::b` |\n| `y |", ["a.py::b"]),
        ("| a |\n|---|\n| `x \\| y` |", ["x | y"]),
        ("## `x\n`a.py::b`", ["a.py::b"]),
        ("- one `x\n- two `a.py::b`", ["a.py::b"]),
        # Fenced blocks are code, not prose, with either fence character.
        ("```bash\necho `not.py::anchor`\n```\n`a.py::b`", ["a.py::b"]),
        ("~~~\n`not.py::anchor`\n~~~\n`a.py::b`", ["a.py::b"]),
        ("````\n```\n`still.py::fenced`\n````\n`a.py::b`", ["a.py::b"]),
        # So are HTML comments; a blockquote's markers are not part of the span, and a quote interrupts.
        ("<!-- `not.py::rendered` -->\n`a.py::b`", ["a.py::b"]),
        ("<!--\n`not.py::rendered`\n-->\n`a.py::b`", ["a.py::b"]),
        ("> quoted `Cannot connect\n> to <url>` (`a.py::b`)", ["Cannot connect to <url>", "a.py::b"]),
        ("a paragraph `x\n> `a.py::b`", ["a.py::b"]),
        # Backtick strings pair only with one of the same length.
        ("``a ` b`` and `a.py::b`", ["a ` b", "a.py::b"]),
        # An escaped backtick opens nothing outside a span; inside one, the backslash is just a character.
        ("\\` then `a.py::b`", ["a.py::b"]),
        ("`C:\\` then `a.py::b`", ["C:\\", "a.py::b"]),
        # One leading and one trailing space are stripped, only together.
        ("`` `a.py::b` ``", ["`a.py::b`"]),
    ],
)
def test_code_spans_follow_commonmark(text, spans):
    assert [content for _, _, content in _code_spans(text)] == spans


@pytest.mark.parametrize(
    "text",
    [
        "a blank line breaks the pair: `open\n\nclose` `norviq/cli/main.py::cli`",
        "an anchor written without backticks: norviq/cli/main.py::cli",
        "a malformed one: `norviq/cli/main.py ::cli`",
        "a key path written without backticks: pyproject.toml: project.scripts.norviq",
        "| h | h |\n|---|---|\n| a cell `opens | the next closes` `norviq/cli/main.py::cli` |",
        "a wrap right after the separator renders as `norviq/cli/main.py::\npolicy_list`",
    ],
)
def test_unchecked_text_is_reported(text):
    assert _unchecked(text), text


@pytest.mark.parametrize(
    "text",
    [
        "`Cannot connect to\n<url>` (`norviq/cli/main.py::cli`)",
        "(`pyproject.toml: project.scripts.norviq`)",
        "```cpp\nstd::vector<int> v;\n```\n",
        "`ui/nginx.conf::location\n/api/`",  # wraps inside the target: still one anchor
    ],
)
def test_anchored_text_is_not_reported(text):
    assert not _unchecked(text), text


@pytest.mark.parametrize(
    "text,what",
    [
        ("before\n```\n`norviq/cli/main.py::nonexistent`\n", "fence opened at line 2"),
        ("before\n<!--\n`norviq/cli/main.py::nonexistent`\n", "HTML comment opened at line 2"),
    ],
)
def test_an_unclosed_block_is_an_error_not_a_hiding_place(text, what):
    with pytest.raises(ValueError, match=f"{what} never closes"):
        _prose(text)


@pytest.mark.parametrize(
    "kind,rel,target",
    [
        ("code", "norviq/cli/main.py", "policy_lsit"),  # typo
        ("code", "norviq/cli/main.py", "APIClient"),  # imported there, defined elsewhere
        ("code", "main.py", "cli"),  # bare basename
        ("code", "norviq/nope.py", "x"),  # no such file
        ("code", "norviq/api/routers/agents.py", "update_trust.frozen"),  # a local, not a symbol
        ("code", "norviq/cli/api_client.py", "APIClient.get_json"),  # no such method
        ("code", "norviq/config.py", "NorviqSettings.opa_mod"),  # no such attribute
        ("code", "ui/src/auth/session.ts", "setTokn"),
        ("code", "webhook/injector.go", "mintSidecarTokn"),
        ("code", "webhook/presets/strict.rego", "decison"),
        ("code", "ui/nginx.conf", "location /nope/"),
        ("code", "ui/src/auth/session.ts", "setToken.getToken"),  # both exist, neither inside the other
        ("code", "webhook/injector.go", "NewInjector.mintSidecarToken"),
        ("code", "docs/cli.md", "anything"),  # no resolver for the type
        ("key", "pyproject.toml", "project.scriptz.norviq"),
        ("key", "helm/norviq/values.yaml", "baselineClusterPolicy.enforcementMod"),
    ],
)
def test_resolver_rejects(kind, rel, target):
    assert _resolve(kind, rel, target) is not None, f"{rel} {target} should NOT resolve"


@pytest.mark.parametrize(
    "kind,rel,target",
    [
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
    ],
)
def test_resolver_accepts(kind, rel, target):
    assert _resolve(kind, rel, target) is None
