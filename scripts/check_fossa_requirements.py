#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail unless fossa-cli will read the Python closure out of the requirements files it discovers.

fossa.yml asserts that the scan summary lists a setuptools project that "succeeded". That proves the
target matched; it does not prove one dependency was read. fossa-cli's requirements parser
(src/Strategy/Python/ReqTxt.hs at v3.20.8) ends in `[] <$ ignored`: a line it cannot parse is dropped
without a warning, and a project whose every line was dropped succeeds with zero dependencies. A change
in how uv writes the export, or one marker the parser does not know, would let the gate grade less than
the file holds and still pass. Nothing about that is visible without the FOSSA API, so this reads the
input the way the scan will, before the scan:

  * the files: every file in the target directory whose name contains "req" and ends in ".txt", which
    is the setuptools discovery rule (src/Strategy/Python/Setuptools.hs, findProjects);
  * every line: blank, a comment, or a pinned requirement in a form the parser reads in full;
  * the result: not empty, and naming every package given on the command line.

The requirement form accepted here is deliberately NARROWER than the PEP 508 subset fossa-cli parses
(src/Strategy/Python/Util.hs, requirementParser): `name==version`, optionally `[extras]`, optionally
`; marker` where the marker is `env op 'string'` terms joined by ` and ` / ` or `, with parentheses,
using only the environment names that grammar lists. Every line accepted here, that grammar parses as
a name and a pinned version. A line rejected here may still parse there, but nothing here can vouch for
it, so it fails: check the line against Util.hs and widen this on purpose. fossa-cli itself is not run:
the check has to work offline and in a test, with neither the CLI nor a FOSSA key.

Standard library only: fossa.yml runs it with the runner's system python3.

Usage: check_fossa_requirements.py <target-dir> <required-package> [<required-package> ...]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Util.hs `identifier`: a letter or digit, then runs of [-_.] that must end on a letter or digit.
_NAME = r"[A-Za-z0-9](?:[-_.]*[A-Za-z0-9])*"
# Util.hs `version`, minus the leading whitespace it allows.
_VERSION = r"[A-Za-z0-9._*+!-]+"
# Util.hs `env_var`, verbatim. A marker naming anything else fails to parse and drops the line.
_ENV = (
    "python_version|python_full_version|os_name|sys_platform|platform_release|platform_system|"
    "platform_version|platform_machine|platform_python_implementation|implementation_name|"
    "implementation_version|extra"
)
# Util.hs `version_operator`.
_OP = r"===|==|!=|<=|>=|~=|<|>"
# Util.hs `python_str` in single quotes: `python_str_c` (space, tab, letters, digits and this
# punctuation) plus the double quote.
_STR = r"'[ \tA-Za-z0-9().{}\-_*#:;,/?\[\]!~`@$%^&=+|<>\"]*'"

_REQUIREMENT = re.compile(
    rf"(?P<name>{_NAME})(?:\[{_NAME}(?:[ \t]*,[ \t]*{_NAME})*\])?=={_VERSION}"
    rf"(?:[ \t]*;[ \t]*(?P<marker>.*?))?[ \t]*"
)
_TERM = re.compile(rf"(?:{_ENV})[ \t]*(?:{_OP})[ \t]*{_STR}")
_AND = re.compile(r"[ \t]+and[ \t]+")
_OR = re.compile(r"[ \t]+or[ \t]+")


class _NoParse(ValueError):
    pass


def _atom(s: str, i: int) -> int:
    # Util.hs `marker_expr`. Inside parentheses the closing one must follow the last term directly;
    # the grammar does not skip whitespace before it.
    if s.startswith("(", i):
        i = _disjunction(s, i + 1)
        if not s.startswith(")", i):
            raise _NoParse(i)
        return i + 1
    m = _TERM.match(s, i)
    if not m:
        raise _NoParse(i)
    return m.end()


def _conjunction(s: str, i: int) -> int:
    i = _atom(s, i)
    while m := _AND.match(s, i):
        i = _atom(s, m.end())
    return i


def _disjunction(s: str, i: int) -> int:
    i = _conjunction(s, i)
    while m := _OR.match(s, i):
        i = _conjunction(s, m.end())
    return i


def _marker_ok(marker: str) -> bool:
    try:
        return _disjunction(marker, 0) == len(marker)
    except _NoParse:
        return False


def requirement_name(line: str) -> str | None:
    """The package name fossa-cli reads from this line, or None when this check cannot vouch for it."""
    m = _REQUIREMENT.fullmatch(line.rstrip("\r\n"))
    if not m or (m["marker"] is not None and not _marker_ok(m["marker"])):
        return None
    return m["name"]


def normalise(name: str) -> str:
    """PEP 503: `Typing_Extensions` and `typing-extensions` are one package."""
    return re.sub(r"[-_.]+", "-", name).lower()


def is_discovered(filename: str) -> bool:
    """Setuptools.hs findProjects: "req" anywhere in the name and a .txt suffix, case-sensitive. So
    `dev-requirements.txt` is read too, which a `req*.txt` glob would miss."""
    return "req" in filename and filename.endswith(".txt")


def discovered(target: Path) -> list[Path]:
    """The files fossa-cli's setuptools strategy reads in `target`."""
    return sorted(p for p in target.iterdir() if p.is_file() and is_discovered(p.name))


def check(target: Path, required: list[str]) -> tuple[int, str]:
    """(exit code, message)."""
    files = discovered(target)
    if not files:
        return 1, f"no file in {target}/ is discovered by fossa-cli's setuptools rule (name contains 'req', ends .txt)"
    names: set[str] = set()
    unreadable: list[str] = []
    lines = []
    for path in files:
        count = 0
        for n, line in enumerate(path.read_text().splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            name = requirement_name(line)
            if name is None:
                unreadable.append(f"  {path.name}:{n}: {line}")
                continue
            names.add(normalise(name))
            count += 1
        lines.append(f"{path.name}: {count} pinned requirement(s) fossa-cli will read")
    if unreadable:
        lines.append(
            f"{len(unreadable)} line(s) are not in a form this check knows fossa-cli reads in full. Its parser "
            "drops a line it cannot read without a warning; check each against src/Strategy/Python/Util.hs:"
        )
        return 1, "\n".join(lines + unreadable)
    if not names:
        return 1, "\n".join(lines + ["the files fossa-cli will read name no package at all"])
    missing = sorted({normalise(r) for r in required} - names)
    if missing:
        return 1, "\n".join(lines + [f"fossa-cli would not read these packages, which must ship: {missing}"])
    return 0, "\n".join(lines + [f"{len(names)} package(s), including {', '.join(sorted(required))}"])


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__.rsplit("Usage: ", 1)[1].strip(), file=sys.stderr)
        return 2
    code, msg = check(Path(argv[0]), argv[1:])
    print(msg if code == 0 else f"::error::FOSSA's Python input is not what it should be\n{msg}")
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
