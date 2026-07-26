# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Every container Norviq ships must be RUNNABLE as rendered — spec x runtime, not spec alone.

WHY THIS FILE EXISTS
--------------------
The injected enforcement sidecar crash-looped on *every* injected pod because
``readOnlyRootFilesystem: true`` was declared on a container whose mTLS client had to materialize a
cert/key as files. With no writable path it died at start with "No usable temporary directory found",
the readiness gate held the workload NotReady forever, and no tool call was ever authorized — the PEP
was simply down.

Nothing caught it because the two halves were tested by two different suites that never met: Go
asserted the injected *spec* (the securityContext block was present and correct), Python exercised the
cert *code* on a developer host that happened to have a writable /tmp. Nobody ever ran the code
*inside* the spec. A securityContext is not a static string; it is a runtime contract, and a container
whose hardening contradicts its own needs is a container that cannot start.

WHAT CLASS THIS CATCHES
-----------------------
Self-contradictory or under-specified pod specs, for **every** container the product ships (chart
Deployments/StatefulSets/Jobs, init containers included, plus the webhook-injected sidecar whose spec
lives in Go):

  * ``readOnlyRootFilesystem: true`` with no writable (emptyDir/PVC) mount — the exact fault above.
  * a probe pointed at a port the container never declares — a named port the kubelet cannot resolve
    is a *silent* permanent-NotReady trap, which for the PEP means enforcement never comes up.
  * missing resource requests/limits — an unbounded neighbour can get the enforcement pod evicted.
  * missing runAsNonRoot / allowPrivilegeEscalation:false / capabilities drop ALL.

ALLOW-LISTS ARE A RATCHET, NOT AN ESCAPE HATCH
----------------------------------------------
Some containers shipped today do not meet the bar. Each is listed below **by name, with the reason and
the exempted control only** (a Job exempted from ``runAsNonRoot`` is still held to drop-ALL). Two
properties keep the lists honest:

  * a container that is NOT listed gets no mercy — new containers must comply;
  * ``test_*_exemptions_are_not_stale`` fails if a listed container has since been fixed or removed,
    so the lists can only shrink.

Where an exemption rests on a factual claim, the claim itself is asserted (the bundled datastores are
exempt *because* the prod profile does not render them; the webhook is exempt from needing scratch
space *because* its Go sources contain no filesystem-write primitive — if that ever stops being true,
the exemption is void and this suite says so).

Skipped (not failed) when the ``helm`` binary is unavailable, matching the rest of tests/helm.
"""

from __future__ import annotations

import functools
import pathlib
import re
import shutil
import subprocess
from dataclasses import dataclass

import pytest
import yaml

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_CHART = _REPO_ROOT / "helm" / "norviq"
_PROD_VALUES = _CHART / "values-prod.yaml"
_WEBHOOK_DIR = _REPO_ROOT / "webhook"

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm binary not on PATH")

# The chart deliberately refuses to render without tenant namespaces (the baseline-policy guard), so
# every profile below carries them.
_QUOTA = ("--set", "policyQuotaNamespaces={default,chatbot-prod}")

# The fleet (multi-cluster hub) workloads are gated off by default but they still ship in the chart, so
# they are part of "every container this product ships" and are swept here too.
_FLEET = (
    "--set", "fleet.hub.enabled=true",
    "--set", "fleet.hub.postgresql.password=Str0ngFleetPw",
    "--set", "fleet.hub.pgUrl=postgresql://norviq:Str0ngFleetPw@fleet-postgresql-ha-rw:5432/norviq_fleet",
)

_PROFILES: dict[str, tuple[str, ...]] = {
    "default": _QUOTA,
    "fleet-hub": _QUOTA + _FLEET,
}

_WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}

# Volume sources that give the container somewhere to write. Secret/configMap/projected/downwardAPI
# volumes are read-only *by nature* even when `readOnly:` is omitted, so they can never satisfy the
# readOnlyRootFilesystem contract — that omission is precisely how the sidecar fault looked "mounted".
_WRITABLE_VOLUME_SOURCES = {"emptyDir", "persistentVolumeClaim", "ephemeral", "hostPath"}


# --------------------------------------------------------------------------------------------------
# Rendering + flattening
# --------------------------------------------------------------------------------------------------


@functools.lru_cache(maxsize=None)
def _render(args: tuple[str, ...]) -> str:
    res = subprocess.run(
        ["helm", "template", "norviq", str(_CHART), *args], capture_output=True, text=True
    )
    assert res.returncode == 0, f"helm template failed:\n{res.stderr}"
    return res.stdout


@dataclass(frozen=True)
class _Container:
    """One container as it would actually be admitted, with the pod context it inherits."""

    profile: str
    workload: str  # "<Kind>/<name>", e.g. "Deployment/norviq-api"
    name: str
    is_init: bool
    spec: dict
    pod: dict

    @property
    def cid(self) -> str:
        """Stable id used by the allow-lists: "<workload-name>/<container-name>"."""
        return f"{self.workload.split('/', 1)[1]}/{self.name}"

    def __str__(self) -> str:  # failure messages must name the container, not an index
        return f"{self.workload} [{'initContainer' if self.is_init else 'container'} {self.name}]"


def _pod_spec(doc: dict) -> dict:
    spec = doc["spec"]
    if doc["kind"] == "CronJob":
        return spec["jobTemplate"]["spec"]["template"]["spec"]
    return spec["template"]["spec"]


@functools.lru_cache(maxsize=None)
def _containers() -> tuple[_Container, ...]:
    """Every container in every rendered workload across every profile (first profile wins per id)."""
    seen: dict[str, _Container] = {}
    for profile, args in _PROFILES.items():
        for doc in yaml.safe_load_all(_render(args)):
            if not doc or doc.get("kind") not in _WORKLOAD_KINDS:
                continue
            workload = f"{doc['kind']}/{doc['metadata']['name']}"
            pod = _pod_spec(doc)
            for is_init, key in ((True, "initContainers"), (False, "containers")):
                for spec in pod.get(key) or []:
                    c = _Container(profile, workload, spec["name"], is_init, spec, pod)
                    seen.setdefault(c.cid, c)
    return tuple(seen.values())


def _volume_sources(pod: dict) -> dict[str, set[str]]:
    """volume name -> its source keys (``emptyDir``, ``secret``, ...)."""
    return {v["name"]: {k for k in v if k != "name"} for v in pod.get("volumes") or []}


def _writable_mounts(c: _Container) -> list[str]:
    """Mount paths the container can actually write to (mount not readOnly AND source writable)."""
    sources = _volume_sources(c.pod)
    return [
        m["mountPath"]
        for m in c.spec.get("volumeMounts") or []
        if not m.get("readOnly", False)
        and sources.get(m["name"], set()) & _WRITABLE_VOLUME_SOURCES
    ]


def _effective(c: _Container, key: str):
    """Container securityContext wins; otherwise inherit the pod-level value where k8s propagates it.

    ``runAsNonRoot``/``runAsUser``/``seccompProfile`` are pod-level-inheritable; ``capabilities``,
    ``allowPrivilegeEscalation`` and ``readOnlyRootFilesystem`` are container-only fields. Merging the
    way the kubelet does is the whole point — a pod-level ``runAsNonRoot: false`` (the bootstrap Jobs)
    must not be hidden by an empty container block.
    """
    csc = c.spec.get("securityContext") or {}
    if key in csc:
        return csc[key]
    if key in {"runAsNonRoot", "runAsUser", "seccompProfile"}:
        return (c.pod.get("securityContext") or {}).get(key)
    return None


def _fail(violations: list[str]) -> None:
    assert not violations, "\n".join(["", *(f"  - {v}" for v in violations)])


def _assert_not_stale(exemptions: dict, violating: set[str], what: str) -> None:
    """An exemption that no longer applies must be DELETED — that is what makes the list a ratchet."""
    live = {c.cid for c in _containers()}
    stale: list[str] = []
    for cid in exemptions:
        if cid not in live:
            stale.append(f"{cid}: container no longer rendered — drop this {what} exemption")
        elif cid not in violating:
            stale.append(f"{cid}: now compliant — drop this {what} exemption so it stays that way")
    _fail(stale)


# --------------------------------------------------------------------------------------------------
# (1) readOnlyRootFilesystem must not contradict the container's need to write  [the sidecar fault]
# --------------------------------------------------------------------------------------------------

# id -> why this container can live with a read-only rootfs and NO writable mount.
_ROOTFS_NO_SCRATCH_OK: dict[str, str] = {
    "norviq-webhook/webhook": (
        "Go admission server: reads its serving cert from a projected Secret and terminates TLS in "
        "memory. The claim 'writes nothing to its rootfs' is machine-checked by "
        "test_webhook_rootfs_exemption_claim_still_holds — if a write primitive ever lands in "
        "webhook/*.go this exemption is void and that test fails."
    ),
    "norviq-webhook/wait-for-api": (
        "busybox `nc -z` poll loop; opens a TCP socket and nothing else. No temp files, no state."
    ),
    # Every dependency wait-loop now renders from the shared norviq.waitFor helper, which applies the
    # same hardened profile the webhook's wait-for-api pioneered. `nc -z` needs no writable path, so a
    # read-only rootfs with no scratch mount is correct here rather than merely tolerated.
    "norviq-api/wait-for-postgres": ("shared norviq.waitFor helper: busybox `nc -z`, writes nothing."),
    "norviq-api/wait-for-redis": ("shared norviq.waitFor helper: busybox `nc -z`, writes nothing."),
    "norviq-engine/wait-for-postgres": ("shared norviq.waitFor helper: busybox `nc -z`, writes nothing."),
    "norviq-engine/wait-for-redis": ("shared norviq.waitFor helper: busybox `nc -z`, writes nothing."),
    "norviq-fleet-api/wait-for-fleet-postgres": (
        "shared norviq.waitFor helper: busybox `nc -z`, writes nothing."
    ),
}


def test_readonly_rootfs_containers_exist() -> None:
    """Guard the guard: if nothing renders with a read-only rootfs the sweep below is vacuous."""
    hardened = [c for c in _containers() if _effective(c, "readOnlyRootFilesystem") is True]
    assert hardened, "no container declares readOnlyRootFilesystem — the rootfs sweep proves nothing"


def test_readonly_rootfs_implies_a_writable_mount() -> None:
    """readOnlyRootFilesystem:true + zero writable mounts = a container that may not survive start."""
    violations = []
    for c in _containers():
        if _effective(c, "readOnlyRootFilesystem") is not True:
            continue
        if _writable_mounts(c):
            continue
        if c.cid in _ROOTFS_NO_SCRATCH_OK:
            continue
        mounted = [m["mountPath"] for m in c.spec.get("volumeMounts") or []]
        violations.append(
            f"{c}: readOnlyRootFilesystem=true but no writable (emptyDir/PVC) mount "
            f"(mounts present: {mounted or 'none'}). Add a tmpfs scratch mount "
            f"(emptyDir medium=Memory) or justify it in _ROOTFS_NO_SCRATCH_OK."
        )
    _fail(violations)


def test_rootfs_exemptions_are_not_stale() -> None:
    violating = {
        c.cid
        for c in _containers()
        if _effective(c, "readOnlyRootFilesystem") is True and not _writable_mounts(c)
    }
    _assert_not_stale(_ROOTFS_NO_SCRATCH_OK, violating, "read-only-rootfs")


def test_webhook_rootfs_exemption_claim_still_holds() -> None:
    """The webhook's exemption rests on 'it writes nothing'. Assert that, don't assume it.

    This is the sidecar fault's actual shape: hardening was correct on day one and became a crash the
    day someone added code that had to materialize a file. The webhook is the next container in line
    (it already holds the CA key in memory to sign sidecar client certs), so the moment a write
    primitive appears in its sources, the read-only rootfs must grow a scratch mount.
    """
    offenders = _go_write_primitives(_WEBHOOK_DIR)
    _fail(
        [
            f"webhook/{path}:{line}: {snippet} — the webhook container runs with "
            f"readOnlyRootFilesystem:true and no writable mount; this write would fail at runtime. "
            f"Mount a tmpfs scratch volume (as the injected sidecar does) or drop the exemption."
            for path, line, snippet in offenders
        ]
    )


_GO_WRITE_PRIMITIVES = re.compile(
    r"\b(?:os\.Create|os\.CreateTemp|os\.WriteFile|os\.MkdirTemp|os\.Mkdir|os\.MkdirAll|"
    r"os\.OpenFile|ioutil\.WriteFile|ioutil\.TempFile|ioutil\.TempDir)\b"
)


def _go_write_primitives(pkg_dir: pathlib.Path) -> list[tuple[str, int, str]]:
    """Non-test Go sources in ``pkg_dir`` that call a filesystem-write primitive.

    Takes the directory as an argument (rather than reading a module constant) so the detector itself
    can be exercised against a fixture tree — a guard nobody can prove is a guard nobody should trust.
    """
    hits: list[tuple[str, int, str]] = []
    for src in sorted(pkg_dir.glob("*.go")):
        if src.name.endswith("_test.go"):
            continue
        for n, line in enumerate(src.read_text().splitlines(), start=1):
            code = line.split("//", 1)[0]
            if _GO_WRITE_PRIMITIVES.search(code):
                hits.append((src.name, n, code.strip()))
    return hits


# --------------------------------------------------------------------------------------------------
# (2) the webhook-INJECTED sidecar: same contract, spec authored in Go
# --------------------------------------------------------------------------------------------------
# The data plane's pod spec is built by webhook/injector.go, so `helm template` cannot see it. The Go
# suite (webhook/injector_writable_tmp_test.go) owns the detailed assertions; what is asserted here is
# that the injected container obeys the SAME fleet-wide rule as every chart container, so the PEP is
# never quietly exempt from the invariant that took it down.


def _go_func_body(source: str, name: str) -> str:
    """The body of a top-level Go func, ended by the column-0 closing brace."""
    start = source.index(f"func {name}(")
    end = source.index("\n}\n", start)
    return source[start:end]


@functools.lru_cache(maxsize=None)
def _injector_source() -> str:
    return (_WEBHOOK_DIR / "injector.go").read_text()


def test_injected_sidecar_readonly_rootfs_has_tmpfs_scratch() -> None:
    """The injected PEP: read-only rootfs AND a writable, non-shared, in-memory scratch mount."""
    _assert_injected_sidecar_contract(_injector_source())


def _assert_injected_sidecar_contract(source: str) -> None:
    """Pure over the Go source so the guard can be proven against a mutated copy."""
    sec = _go_func_body(source, "sidecarSecurityContext")
    tmpl = _go_func_body(source, "newSidecarTemplate")
    vol = _go_func_body(source, "tmpVolumeTemplate")

    read_only = re.search(r'"readOnlyRootFilesystem":\s*(true|false)', sec)
    if not read_only or read_only.group(1) != "true":
        return  # no read-only rootfs -> the pairing rule does not apply

    violations: list[str] = []
    mount = re.search(r'\{"name":\s*tmpVolumeName,\s*"mountPath":\s*tmpMountPath([^}]*)\}', tmpl)
    if not mount:
        violations.append(
            "webhook/injector.go newSidecarTemplate: readOnlyRootFilesystem=true but the sidecar "
            "mounts no scratch volume (tmpVolumeName at tmpMountPath) — the mTLS cert load has "
            "nowhere to materialize its cert/key and the sidecar dies at start"
        )
    elif "readOnly" in mount.group(1):
        violations.append(
            "webhook/injector.go newSidecarTemplate: the scratch mount is marked readOnly — a "
            "read-only scratch mount is not scratch"
        )
    if '"emptyDir"' not in vol:
        violations.append(
            "webhook/injector.go tmpVolumeTemplate: the scratch volume is not emptyDir-backed, so it "
            "gives the sidecar no writable path"
        )
    elif '"medium": "Memory"' not in vol:
        violations.append(
            "webhook/injector.go tmpVolumeTemplate: scratch volume is not tmpfs (medium: Memory) — "
            "the short-lived mTLS client key would land on a real disk"
        )
    _fail(violations)


# --------------------------------------------------------------------------------------------------
# (3) probes must point at ports the container declares
# --------------------------------------------------------------------------------------------------


def _declared_ports(c: _Container) -> tuple[set[str], set[int]]:
    names = {p["name"] for p in c.spec.get("ports") or [] if "name" in p}
    numbers = {p["containerPort"] for p in c.spec.get("ports") or [] if "containerPort" in p}
    return names, numbers


def test_probe_ports_are_declared() -> None:
    """A probe aimed at an undeclared port is a silent permanent-NotReady trap.

    A *named* port the container never declares cannot be resolved by the kubelet at all, so the probe
    fails forever with nothing in the container log — for the API/engine that means the enforcement
    plane never becomes Ready and nobody can tell why from the pod's own output.
    """
    violations = []
    for c in _containers():
        names, numbers = _declared_ports(c)
        for probe_name in ("startupProbe", "readinessProbe", "livenessProbe"):
            probe = c.spec.get(probe_name)
            if not probe:
                continue
            for handler in ("httpGet", "tcpSocket", "grpc"):
                target = probe.get(handler)
                if not target or "port" not in target:
                    continue
                port = target["port"]
                if isinstance(port, str) and port not in names:
                    violations.append(
                        f"{c}: {probe_name}.{handler} targets named port {port!r} which the container "
                        f"does not declare (declared names: {sorted(names) or 'none'})"
                    )
                elif isinstance(port, int) and port not in numbers:
                    violations.append(
                        f"{c}: {probe_name}.{handler} targets port {port} which the container does not "
                        f"declare as a containerPort (declared: {sorted(numbers) or 'none'})"
                    )
    _fail(violations)


def test_probe_sweep_is_not_vacuous() -> None:
    """Guard the guard: the probe rule is only worth anything if probes actually render."""
    probed = [
        c
        for c in _containers()
        if any(c.spec.get(p) for p in ("startupProbe", "readinessProbe", "livenessProbe"))
    ]
    assert len(probed) >= 5, f"expected the control plane to declare probes, found {len(probed)}"


# --------------------------------------------------------------------------------------------------
# (4) resources: an unbounded container can get the PEP evicted
# --------------------------------------------------------------------------------------------------
# Required of every long-running container: requests.cpu, requests.memory, limits.memory. A container
# with no memory request is charged 0 against the node, which drags the whole pod's eviction ranking
# down — and the pod being ranked here is the one that authorizes tool calls.

_REQUIRED_RESOURCES = ("requests.cpu", "requests.memory", "limits.memory", "limits.cpu")

# id -> (exempt resource keys, reason)
_RESOURCE_EXEMPTIONS: dict[str, tuple[frozenset[str], str]] = {
    "norviq-api/tls-proxy": (
        frozenset({"limits.cpu"}),
        "TLS terminator on the enforcement hot path: a CPU limit adds CFS throttling latency to every "
        "authorization call. Memory is still bounded, which is what eviction ranking keys on.",
    ),
    # --- KNOWN GAP: short-lived containers currently ship with no resources at all. -----------------
    # They are not long-running, but they DO count toward the pod's QoS class, so this list should
    # shrink rather than grow.
}


def _missing_resources(c: _Container) -> list[str]:
    res = c.spec.get("resources") or {}
    missing = []
    for key in _REQUIRED_RESOURCES:
        section, field = key.split(".")
        if not (res.get(section) or {}).get(field):
            missing.append(key)
    return missing


def test_containers_declare_requests_and_limits() -> None:
    violations = []
    for c in _containers():
        exempt = _RESOURCE_EXEMPTIONS.get(c.cid, (frozenset(), ""))[0]
        missing = [k for k in _missing_resources(c) if k not in exempt]
        if missing:
            violations.append(
                f"{c}: missing resource {', '.join(missing)} — an unbounded container degrades the "
                f"pod's QoS class and can get the enforcement plane evicted under node pressure"
            )
    _fail(violations)


def test_resource_exemptions_are_not_stale() -> None:
    violating = {c.cid for c in _containers() if _missing_resources(c)}
    _assert_not_stale(_RESOURCE_EXEMPTIONS, violating, "resource")


# --------------------------------------------------------------------------------------------------
# (5) baseline pod security: non-root, no privilege escalation, no capabilities
# --------------------------------------------------------------------------------------------------

_SECURITY_CONTROLS = ("runAsNonRoot", "allowPrivilegeEscalation", "capabilities.drop=ALL")

# id -> (exempt controls, reason)
_SECURITY_EXEMPTIONS: dict[str, tuple[frozenset[str], str]] = {
    # Hook Jobs run kubectl+openssl as uid 0 to mint the internal CA. They still drop ALL caps and
    # forbid privilege escalation, and those controls stay enforced by the exemption being narrow.
    "norviq-internal-tls/tls-bootstrap": (
        frozenset({"runAsNonRoot"}),
        "pre-install hook Job: runs as uid 0 for the openssl/apk bootstrap; short-lived, hook-deleted, "
        "and still allowPrivilegeEscalation:false + drop ALL",
    ),
    "norviq-webhook-cert/cert-bootstrap": (
        frozenset({"runAsNonRoot"}),
        "pre-install hook Job: same bootstrap shape as norviq-internal-tls",
    ),
    # --- KNOWN GAP: bundled single-node datastores ship with no securityContext at all. -------------
    # Justified only because production does not run them: values-prod.yaml turns on the operator-
    # managed HA variants and the plain StatefulSets stop rendering entirely. That claim is asserted
    # by test_prod_profile_drops_the_unhardened_bundled_datastores — if it ever stops holding, these
    # exemptions must go.
    "norviq-postgresql/postgresql": (
        frozenset(_SECURITY_CONTROLS),
        "KNOWN GAP: bundled dev-convenience Postgres; prod runs CloudNativePG (values-prod.yaml)",
    ),
    "norviq-redis/redis": (
        frozenset(_SECURITY_CONTROLS),
        "KNOWN GAP: bundled dev-convenience Redis; prod runs the redis-operator (values-prod.yaml)",
    ),
    # --- KNOWN GAP: busybox wait-loop init containers on the app workloads. ------------------------
    # The webhook's own wait-for-api init container IS hardened, which is the shape the others should
    # copy; keeping these listed (rather than relaxing the rule) is what makes that visible.
    "fleet-postgresql/postgresql": (
        frozenset(_SECURITY_CONTROLS),
        "KNOWN GAP: bundled dev-convenience Postgres for the gated fleet hub; same shape (and same "
        "prod-replacement argument) as norviq-postgresql above",
    ),
}


def _failed_security_controls(c: _Container) -> list[str]:
    failed = []
    if _effective(c, "runAsNonRoot") is not True:
        failed.append("runAsNonRoot")
    if _effective(c, "allowPrivilegeEscalation") is not False:
        failed.append("allowPrivilegeEscalation")
    caps = _effective(c, "capabilities") or {}
    if "ALL" not in (caps.get("drop") or []):
        failed.append("capabilities.drop=ALL")
    return failed


def test_containers_meet_the_baseline_security_profile() -> None:
    violations = []
    for c in _containers():
        exempt = _SECURITY_EXEMPTIONS.get(c.cid, (frozenset(), ""))[0]
        failed = [f for f in _failed_security_controls(c) if f not in exempt]
        if failed:
            violations.append(
                f"{c}: securityContext must set {', '.join(failed)} "
                f"(runAsNonRoot=true / allowPrivilegeEscalation=false / capabilities.drop:[ALL]), "
                f"or be justified in _SECURITY_EXEMPTIONS"
            )
    _fail(violations)


def test_security_exemptions_are_not_stale() -> None:
    violating = {c.cid for c in _containers() if _failed_security_controls(c)}
    _assert_not_stale(_SECURITY_EXEMPTIONS, violating, "security")


def test_every_exemption_carries_a_reason() -> None:
    """An allow-list entry with an empty reason is a rubber stamp; fail rather than accumulate them."""
    blank = [
        f"{table}[{cid}]"
        for table, entries in (
            ("_ROOTFS_NO_SCRATCH_OK", _ROOTFS_NO_SCRATCH_OK.items()),
            ("_RESOURCE_EXEMPTIONS", ((k, v[1]) for k, v in _RESOURCE_EXEMPTIONS.items())),
            ("_SECURITY_EXEMPTIONS", ((k, v[1]) for k, v in _SECURITY_EXEMPTIONS.items())),
        )
        for cid, reason in entries
        if len(str(reason).strip()) < 20
    ]
    _fail(blank)


def test_prod_profile_drops_the_unhardened_bundled_datastores() -> None:
    """The datastore exemptions above are only honest while prod never renders those StatefulSets."""
    rendered = _render(
        (
            "-f", str(_PROD_VALUES),
            *_QUOTA,
            "--set", "postgresql.password=Str0ngPgPw",
            "--set", "redis.password=Str0ngRedisPw",
        )
    )
    bundled = [
        doc["metadata"]["name"]
        for doc in yaml.safe_load_all(rendered)
        if doc
        and doc.get("kind") == "StatefulSet"
        and doc["metadata"]["name"] in {"norviq-postgresql", "norviq-redis"}
    ]
    assert not bundled, (
        f"the prod profile now renders the unhardened bundled datastore(s) {bundled}; their "
        f"_SECURITY_EXEMPTIONS entries are no longer justified — harden them or keep prod on the "
        f"operator-managed HA variants"
    )


# --------------------------------------------------------------------------------------------------
# inventory guard — the whole sweep is only as good as what it sweeps
# --------------------------------------------------------------------------------------------------


def test_sweep_covers_every_shipped_workload() -> None:
    """If a workload stops rendering (or a profile stops being swept) the invariants go quiet.

    Every assertion above is a for-loop over ``_containers()``. An empty or truncated inventory turns
    the entire file green for the wrong reason, which is the same failure mode that let the sidecar
    ship: a suite that looked like coverage.
    """
    workloads = {c.workload for c in _containers()}
    expected = {
        "Deployment/norviq-api",
        "Deployment/norviq-engine",
        "Deployment/norviq-ui",
        "Deployment/norviq-webhook",
        "StatefulSet/norviq-postgresql",
        "StatefulSet/norviq-redis",
        "Job/norviq-internal-tls",
        "Job/norviq-webhook-cert",
        "Deployment/norviq-fleet-api",
        "StatefulSet/fleet-postgresql",
    }
    missing = sorted(expected - workloads)
    assert not missing, (
        f"these shipped workloads are no longer swept by the container runtime contract: {missing}. "
        f"If one was intentionally removed, drop it from `expected`; do not leave it unchecked."
    )
