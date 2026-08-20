"""The two browser-e2e install paths must not drift apart.

There are two of them — `scripts/kind-e2e/00-up.sh` for a laptop and the `Install the chart` step in
`.github/workflows/kind-e2e.yml` for CI — and in one day they drifted twice, both silently:

  * `.github/kind/e2e-cluster.yaml` maps host 3400 -> node:30080 and its own comment says the Service
    is "patched to NodePort after install". Only 00-up.sh patched it. CI got the mapping and nothing
    listening behind it, so every request was accepted and reset: 27 `net::ERR_CONNECTION_RESET` in
    one shard, 20 specs failed across 8 unrelated files, and the run read as 20 product bugs.
  * The rate-limit ceiling the suite needs was set in 00-up.sh and nowhere else, so CI kept hitting
    the production default and 429'd whichever spec happened to be running.

Both fixes existed and read as applied. Neither applied to CI. That is the failure this module makes
loud: not "is the harness correct" — a test cannot know that — but "do the two halves still say the
same thing", which is exactly what nobody notices.

These are cheap string assertions on config files by design. The behaviour they stand for is proven
elsewhere (a throwaway kind cluster reproduced the reset and the fix); what is missing there is
anything that notices when one path silently stops doing it.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
WORKFLOW = REPO / ".github/workflows/kind-e2e.yml"
LOCAL_UP = REPO / "scripts/kind-e2e/00-up.sh"
CLUSTER = REPO / ".github/kind/e2e-cluster.yaml"
SHARED_VALUES = REPO / "scripts/kind-e2e/values-e2e.yaml"


def _workflow_text() -> str:
    return WORKFLOW.read_text()


def test_both_install_paths_use_the_shared_test_rig_values():
    """Anything both harnesses need lives in one file, or it lives in one of them."""
    assert SHARED_VALUES.exists(), f"{SHARED_VALUES} is the single home for test-rig settings"
    for path in (WORKFLOW, LOCAL_UP):
        assert "scripts/kind-e2e/values-e2e.yaml" in path.read_text(), (
            f"{path.relative_to(REPO)} no longer passes the shared test-rig values file, so it has "
            f"drifted from the other install path — the exact way the rate-limit ceiling ended up "
            f"set on a laptop and not in CI."
        )


def test_the_published_port_the_nodeport_and_the_base_url_agree():
    """Three numbers, three files, and a reset if any one of them moves.

    hostPort is what the suite connects to, containerPort is what the node publishes, and the
    `kubectl patch` nodePort is what puts a Service there. They are written in three separate files
    and nothing but this test relates them.
    """
    cluster = yaml.safe_load(CLUSTER.read_text())
    mapping = cluster["nodes"][0]["extraPortMappings"][0]
    host_port, container_port = mapping["hostPort"], mapping["containerPort"]

    wf = _workflow_text()

    patched = re.search(r'"nodePort"\s*:\s*(\d+)', wf)
    assert patched, (
        "the workflow never patches norviq-ui to a NodePort. The cluster publishes "
        f"host:{host_port} -> node:{container_port}; with no Service on {container_port} every "
        "request is accepted and reset."
    )
    assert int(patched.group(1)) == container_port, (
        f"the workflow patches nodePort={patched.group(1)} but the cluster publishes "
        f"containerPort={container_port} — traffic would reach a port with no listener."
    )

    base = re.search(r"PLAYWRIGHT_BASE_URL:\s*http://([\d.]+|localhost):(\d+)", wf)
    assert base, "the workflow no longer sets PLAYWRIGHT_BASE_URL to an http origin"
    assert int(base.group(2)) == host_port, (
        f"PLAYWRIGHT_BASE_URL points at :{base.group(2)} but the cluster publishes :{host_port}"
    )
    assert base.group(1) == str(mapping.get("listenAddress", "127.0.0.1")), (
        f"PLAYWRIGHT_BASE_URL names {base.group(1)} but the cluster binds "
        f"{mapping.get('listenAddress')}. `localhost` also resolves to ::1, where nothing listens, "
        "so name the address that is actually bound rather than depending on resolution order — "
        "that ambiguity is what let a dying tunnel look like an intermittent product failure."
    )


def test_ci_has_no_port_forward_for_the_console():
    """The NodePort exists to delete this. A fallback to it would hide the same bug again.

    The forward dies without the kubectl process exiting, so it cannot be supervised by watching for
    process death — two rounds of fixes tried. In CI there is no interactive operator to notice, and
    a fallback turns a loud failure into the intermittent one this replaced.
    """
    offenders = [
        line.strip()
        for line in _workflow_text().splitlines()
        if "port-forward" in line and not line.lstrip().startswith("#")
    ]
    assert not offenders, (
        "the console must be reached over the NodePort, with no tunnel in the path:\n  "
        + "\n  ".join(offenders)
    )


def test_every_script_a_workflow_runs_bare_is_executable():
    """A missing mode bit is a whole CI run, and this is the third time it has cost one.

    `.github/workflows/kind-e2e.yml` has `run: scripts/kind-e2e/l3.sh`. Invoked as a command rather
    than through `bash`, a 100644 file gives "Permission denied" and exit 126 — AFTER the cluster is
    built, the images are loaded and 47 browser specs have passed, so the job reports failure with a
    fully green Playwright tally above it and nothing that looks like a cause.

    The bit is invisible in review: the diff shows the script, not its mode, and it survives on a
    developer's machine where everything is run as `bash script.sh`. So assert it from the workflow
    text itself — anything invoked bare must be executable, whatever it is called and whenever it is
    added.
    """
    import re as _re

    offenders: list[str] = []
    for wf in sorted((REPO / ".github/workflows").glob("*.yml")):
        for line in wf.read_text().splitlines():
            # `run: scripts/foo.sh` — a bare invocation, not `bash scripts/foo.sh` and not a comment.
            m = _re.match(r"\s*run:\s+((?:scripts|\./scripts)/\S+\.sh)\s*$", line)
            if not m:
                continue
            script = REPO / m.group(1).lstrip("./")
            if not script.exists():
                offenders.append(f"{wf.name} runs {m.group(1)}, which does not exist")
            elif not os.access(script, os.X_OK):
                offenders.append(f"{wf.name} runs {m.group(1)} bare, but it is not executable")
    assert not offenders, "\n  ".join(["mode-bit problems:"] + offenders)
