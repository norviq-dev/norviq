"""The FOSSA gate must fail on a finding AND on a payload it does not understand."""

from __future__ import annotations

import pytest

import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "scripts"))

from check_fossa_issues import ACCEPTED, UnrecognisedShape, gate, issues_from  # noqa: E402

VULN = {"type": "vulnerability", "revisionId": "pip+foo$1.0", "cve": "CVE-2099-0001"}
EXCEPTED = {"type": "vulnerability", "revisionId": "pip+litellm$1.100.4", "cve": "CVE-2024-6825"}


def test_one_vulnerability_fails_the_gate():
    code, msg = gate({"issues": [VULN]})
    assert code == 1 and "FAILED" in msg and "CVE-2099-0001" in msg


def test_a_documented_exception_passes_and_is_reported():
    code, msg = gate({"issues": [EXCEPTED]})
    assert code == 0 and "1 accepted" in msg


def test_capitalised_key_and_bare_list_are_read_not_ignored():
    assert gate({"Issues": [VULN]})[0] == 1
    assert gate([VULN])[0] == 1


@pytest.mark.parametrize("payload", [{}, {"summary": "ok"}, {"issues": None}, {"issues": "none"}, "ok", 42])
def test_an_unrecognised_shape_is_refused_not_passed(payload):
    """`{}` used to produce an empty list, zero findings, and PASS."""
    with pytest.raises(UnrecognisedShape):
        issues_from(payload)


def test_genuinely_empty_is_the_only_way_to_pass_clean():
    assert gate({"issues": []})[0] == 0


def test_the_k8s_module_matches_are_excepted_because_they_are_spurious():
    """FOSSA flags three CVEs against k8s.io/{apimachinery,client-go} at any v0.x. Their fixed
    versions (0.17.0, 0.19.6, and kubernetes 1.12.3 — not a library at all) are all far below the
    pinned v0.37.0. If one of these is ever removed from ACCEPTED, the removal should be because the
    advisory data changed, not because someone assumed a bump would clear it — it cannot."""
    for cve in ("CVE-2018-1002105", "CVE-2019-11250", "CVE-2020-8565"):
        code, msg = gate(
            {"issues": [{"type": "vulnerability", "revisionId": "go+k8s.io/client-go$v0.37.0", "cve": cve}]}
        )
        assert code == 0 and "accepted" in msg, cve


_ADVISORY_ID = re.compile(r"CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}")


def _security_md_exception_ids() -> set[str]:
    """Every advisory id in the FIRST column of SECURITY.md's accepted-exceptions table."""
    text = (_ROOT / "SECURITY.md").read_text()
    section = text.split("## Accepted dependency exceptions", 1)[1].split("\n## ", 1)[0]
    rows = [ln for ln in section.splitlines() if ln.startswith("|")]
    return {i for ln in rows for i in _ADVISORY_ID.findall(ln.split("|")[1])}


def test_the_security_md_table_and_the_allow_list_name_the_same_advisories():
    """SECURITY.md and the gate's allow-list are documented as being in lockstep, and they have not
    always been. The React Router row was once written into the table and never into the allow-list,
    so the gate kept failing on a vulnerability the document had already accepted. The opposite
    direction is worse: an id in the allow-list with no row in the table is an exception nobody wrote
    a reason for."""
    table = _security_md_exception_ids()
    assert table, "no advisory ids found in SECURITY.md's exceptions table; the parser no longer fits it"
    assert table == ACCEPTED, (
        f"in SECURITY.md's table only: {sorted(table - ACCEPTED)}; in ACCEPTED only: {sorted(ACCEPTED - table)}"
    )
