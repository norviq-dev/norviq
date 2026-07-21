# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""End-to-end proof that the DATA plane enforces — not just the control plane.

Every enforcement proof this project had ran control-plane: ``POST /evaluate`` -> API -> OPA. That path
stays perfectly green while the *injected sidecar* — the actual PEP that intercepts an agent's tool
calls over its unix socket — is completely dead. That is exactly how the crash-loop blocker hid: the
sidecar died at start ("No usable temporary directory") on every injected pod for hours while the API,
the dashboards and every test reported healthy.

The class of bug this file exists to catch: **anything that is true of the rendered/injected spec but
false of the running container.** A spec assertion (Go webhook tests) proves the sidecar was *asked*
for; a control-plane assertion proves OPA *can* decide. Neither proves an agent's tool call is actually
intercepted. Only driving a real tool call through the real socket in a real pod does.

Two layers, and both matter:

1. **Offline (always runs).** The exact JSONL wire shape the live layer speaks is exercised against the
   real ``SidecarProxy._process_request`` and against a real ``SidecarProxy`` bound to a real AF_UNIX
   socket, driven by the *same* driver script the live layer ``kubectl exec``s into the pod. If the
   product's request keys, response keys, or forward/drop mapping drift, this fails in CI with no
   cluster at all — and the live layer can never silently be testing the wrong protocol.

2. **Live (opt-in).** With a cluster, it creates one throwaway agent pod in an operator-nominated
   injection-enabled namespace, asserts the sidecar is injected AND reaches Ready with zero restarts,
   drives a benign and a destructive tool call through the sidecar's unix socket from *inside the app
   container*, and asserts the destructive one is DROPPED and the decision lands in the audit trail
   attributed to ``framework=sidecar``.

Why the benign call is not decoration: the sidecar fails CLOSED, so "destructive was dropped" alone is
also satisfied by a sidecar that cannot reach the PDP at all. The benign call must be FORWARDED, and the
destructive drop must not carry the fail-closed rule id. Together they separate "enforcing" from "dead".

Opt-in and safety:
  * ``NRVQ_E2E=1``            — required; without it the live layer skips (safe in CI, no cluster).
  * ``NRVQ_E2E_NAMESPACE``    — required; the tenant namespace the operator opts in to pod creation.
  * ``NRVQ_TEST_KUBE_CONTEXT``— optional; otherwise the current kubectl context is used.
  * ``NRVQ_E2E_AGENT_IMAGE``  — optional; image for the throwaway pod (needs python3). Default below.
The only mutation is that one throwaway pod, which is deleted in fixture teardown and additionally
carries ``activeDeadlineSeconds`` so a leaked pod self-terminates. Nothing else is created or changed.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------------------------
# Contract constants — must mirror the product. Duplicated deliberately rather than imported from
# the Go injector: a test that reads the same constant as the code under test cannot detect drift.
# ---------------------------------------------------------------------------------------------
SIDECAR_CONTAINER = "norviq-sidecar"
SOCKET_MOUNT_PATH = "/var/run/norviq"
SOCKET_FILE_PATH = "/var/run/norviq/norviq-proxy.sock"
SOCKET_ENV_VAR = "NRVQ_SOCKET_PATH"
INJECTION_LABEL_KEY = "norviq-injection"
AGENT_CLASS_LABEL = "norviq.io/agent-class"

# The destructive call every deployment must refuse. Chosen because it is unambiguous: no policy that
# claims to govern an agent should forward a shell that wipes the filesystem.
DESTRUCTIVE_TOOL = "exec_shell"
DESTRUCTIVE_PARAMS = {"command": "rm -rf /"}
# A read-only tool the baseline is expected to permit — the control that proves the plane is LIVE
# rather than uniformly failing closed. Overridable for deployments with a narrower baseline.
BENIGN_TOOL = os.environ.get("NRVQ_E2E_BENIGN_TOOL", "search_kb")
BENIGN_PARAMS = {"query": "norviq data-plane probe"}
# RemoteEvaluator stamps this rule id when it cannot reach the central engine (fail-closed). A "drop"
# carrying it is NOT enforcement — it is an outage wearing enforcement's clothes.
FAIL_CLOSED_RULE_ID = "thin_proxy_fail_closed"

DEFAULT_AGENT_IMAGE = "python:3.12-slim"
# Deliberately different from the sidecar's uid (65534). The socket lives on a shared emptyDir and the
# proxy chmods it 0o777 precisely so a differently-uid'd app container can connect(). Running the probe
# as the same uid as the sidecar would hide a regression in that chmod.
AGENT_UID = 1000


# =============================================================================================
# Wire codec — the exact JSONL shape norviq/sidecar/proxy.py::_process_request reads and writes.
# The live layer and the offline layer both go through these, so the offline proof below is a
# proof about the bytes the live layer will actually put on the socket.
# =============================================================================================
def encode_tool_call(tool_name: str, tool_params: dict, session_id: str) -> str:
    """Encode one tool-call interception request as the single JSONL line the sidecar expects."""
    return json.dumps(
        {"tool_name": tool_name, "tool_params": tool_params, "session_id": session_id},
        separators=(",", ":"),
    )


def decode_proxy_response(raw: str) -> dict:
    """Decode the sidecar's JSONL response line into a dict."""
    return json.loads(raw.strip())


def is_dropped(response: dict) -> bool:
    """True when the sidecar refused to let the agent execute the tool."""
    return response.get("action") == "drop"


def is_forwarded(response: dict) -> bool:
    """True when the sidecar cleared the agent to execute the tool."""
    return response.get("action") == "forward"


def decision_of(response: dict) -> dict:
    """The embedded PolicyDecision ({} when the sidecar errored before deciding)."""
    value = response.get("decision")
    return value if isinstance(value, dict) else {}


# The script that runs INSIDE the agent container to speak to the sidecar. Kept as a module constant
# so the offline test can execute the byte-identical script against a real local socket — otherwise
# the in-pod driver would be the one piece of the live path that nothing ever exercises.
# argv: <socket path> <timeout seconds> <request json line>
IN_POD_SOCKET_DRIVER = r"""
import socket, sys

path, timeout, request = sys.argv[1], float(sys.argv[2]), sys.argv[3]
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(timeout)
sock.connect(path)
sock.sendall(request.encode("utf-8") + b"\n")
buf = b""
while not buf.endswith(b"\n"):
    chunk = sock.recv(65536)
    if not chunk:
        break
    buf += chunk
sock.close()
sys.stdout.write(buf.decode("utf-8").strip())
"""


# =============================================================================================
# LAYER 1 — offline protocol proof. No cluster, no network. Runs everywhere.
# =============================================================================================
# Import the sidecar stack defensively and skip ONLY layer 1 if it is unavailable.
#
# This used to be a module-level pytest.importorskip. That is a silent-coverage trap: importing
# norviq.sidecar.proxy transitively pulls the whole engine (redis, opentelemetry-exporter-otlp,
# networkx, ...), so ONE missing dependency skipped the ENTIRE file — including the layer 2 cluster
# tests, which need nothing but kubectl. A suite written to stop silent coverage loss must not lose
# coverage silently itself. Layer 2 now collects and runs regardless of the Python import chain.
try:  # pragma: no cover - import-availability branch
    from norviq.sdk.core.decisions import PolicyDecision
    from norviq.sdk.core.events import AgentIdentity
    from norviq.sdk.core.interceptor import ToolInterceptor
    from norviq.sidecar.proxy import SidecarProxy

    _SIDECAR_IMPORT_ERROR = ""
except Exception as exc:  # ModuleNotFoundError and anything raised at import time
    PolicyDecision = AgentIdentity = ToolInterceptor = SidecarProxy = None  # type: ignore[assignment]
    _SIDECAR_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

# Applied to layer 1 only. Layer 2 keeps its own opt-in (NRVQ_E2E) + kubectl gates.
requires_sidecar_imports = pytest.mark.skipif(
    bool(_SIDECAR_IMPORT_ERROR),
    reason=f"sidecar import chain unavailable ({_SIDECAR_IMPORT_ERROR})",
)


class _RecordingEvaluator:
    """Stand-in PDP that records the event it was handed and returns a fixed decision.

    Recording the event is the point: it is how we prove the encoder's field names are the ones the
    proxy actually reads. A typo'd key would leave tool_name empty, and ToolCallEvent rejects that.
    """

    def __init__(self, decision) -> None:
        self.decision = decision
        self.seen: list = []

    async def evaluate(self, event):
        self.seen.append(event)
        return self.decision


class _StaticResolver:
    """Identity resolver stub — the offline layer is about the wire, not about SPIFFE."""

    async def resolve(self):
        return AgentIdentity(
            spiffe_id="spiffe://norviq/ns/wire-test/sa/probe",
            namespace="wire-test",
            agent_class="probe",
        )


def _offline_proxy(decision) -> tuple:
    """A real SidecarProxy wired to a stub PDP — real request parsing, real response building."""
    proxy = SidecarProxy(socket_path="/nonexistent/never-bound.sock")
    evaluator = _RecordingEvaluator(decision)
    proxy._interceptor = ToolInterceptor(evaluator, _StaticResolver())
    proxy._emitter = None  # proxy mode: the central /evaluate owns the audit write, nothing local
    return proxy, evaluator


@requires_sidecar_imports
async def test_encoded_request_reaches_the_pdp_with_the_call_intact() -> None:
    """The bytes the live layer writes must arrive at the PDP as the real tool call.

    Guards the silent-mismatch failure: if the request keys drift, the proxy sees an empty tool name,
    the whole request errors, and the E2E layer would be "passing" while asserting nothing about a
    real tool call.
    """
    proxy, evaluator = _offline_proxy(PolicyDecision(decision="allow", rule_id="unit"))
    line = encode_tool_call(DESTRUCTIVE_TOOL, DESTRUCTIVE_PARAMS, "wire-session-1")

    response = decode_proxy_response(await proxy._process_request(line))

    assert "error" not in response, f"proxy could not parse our request line: {response}"
    assert len(evaluator.seen) == 1, "the request never reached the policy decision point"
    event = evaluator.seen[0]
    assert event.tool_name == DESTRUCTIVE_TOOL
    assert event.tool_params == DESTRUCTIVE_PARAMS
    assert event.session_id == "wire-session-1"
    # Audit attribution starts here: the sidecar must label its own decisions as sidecar-sourced,
    # which is what makes the live audit assertion meaningful.
    assert event.framework == "sidecar", "sidecar decisions must be attributable to the data plane"


@requires_sidecar_imports
async def test_block_becomes_drop_and_allow_becomes_forward() -> None:
    """The decision->action mapping IS the enforcement. A fail-open here forwards blocked tools."""
    blocked, _ = _offline_proxy(PolicyDecision(decision="block", rule_id="deny_destructive"))
    dropped = decode_proxy_response(await blocked._process_request(
        encode_tool_call(DESTRUCTIVE_TOOL, DESTRUCTIVE_PARAMS, "wire-session-2")
    ))
    assert is_dropped(dropped), f"a BLOCK decision must drop the tool call, got {dropped}"
    assert decision_of(dropped).get("decision") == "block"

    allowed, _ = _offline_proxy(PolicyDecision(decision="allow", rule_id="allow_read"))
    forwarded = decode_proxy_response(await allowed._process_request(
        encode_tool_call(BENIGN_TOOL, BENIGN_PARAMS, "wire-session-3")
    ))
    assert is_forwarded(forwarded), f"an ALLOW decision must forward the tool call, got {forwarded}"


@requires_sidecar_imports
async def test_unparseable_request_fails_closed() -> None:
    """Garbage on the socket must DROP. Forwarding on the error path is a bypass, not a graceful degrade."""
    proxy, evaluator = _offline_proxy(PolicyDecision(decision="allow", rule_id="unit"))
    response = decode_proxy_response(await proxy._process_request("{not json"))
    assert is_dropped(response), f"malformed input must fail closed, got {response}"
    assert not evaluator.seen, "a malformed request must never be evaluated as a real tool call"


@requires_sidecar_imports
async def test_in_pod_driver_script_speaks_the_protocol_over_a_real_socket() -> None:
    """Run the byte-identical in-pod driver against a real listening SidecarProxy.

    The live layer's driver is the one component that only ever executes inside a cluster. Without
    this, a broken driver would surface as a confusing E2E failure (or worse, be "fixed" by loosening
    the live assertions). Here it drives a genuine AF_UNIX server end to end, offline.
    """
    with tempfile.TemporaryDirectory() as tmp:
        # macOS caps AF_UNIX paths near 104 bytes; keep the socket name short.
        socket_path = str(Path(tmp) / "p.sock")
        proxy, _ = _offline_proxy(PolicyDecision(decision="block", rule_id="deny_destructive"))
        proxy._socket_path = socket_path
        server = await asyncio.start_unix_server(proxy._handle_connection, path=socket_path)
        try:
            line = encode_tool_call(DESTRUCTIVE_TOOL, DESTRUCTIVE_PARAMS, "driver-session")
            result = await asyncio.to_thread(
                subprocess.run,
                [sys.executable, "-c", IN_POD_SOCKET_DRIVER, socket_path, "10", line],
                capture_output=True,
                text=True,
                timeout=30,
            )
            assert result.returncode == 0, f"in-pod driver failed: {result.stderr}"
            response = decode_proxy_response(result.stdout)
            assert is_dropped(response), f"driver did not observe the drop: {response}"
        finally:
            server.close()
            await server.wait_closed()


# =============================================================================================
# LAYER 2 — live data-plane E2E. Opt-in; skips cleanly with no cluster.
# =============================================================================================
def _kubectl(*args: str, request_timeout: str = "30s", stdin: str | None = None,
             timeout: int = 120) -> subprocess.CompletedProcess[str]:
    """Run kubectl against the selected context. Read-only unless the caller says otherwise."""
    ctx = os.environ.get("NRVQ_TEST_KUBE_CONTEXT")
    cmd = ["kubectl", *(["--context", ctx] if ctx else []), f"--request-timeout={request_timeout}", *args]
    # argv list form, shell=False — the env-sourced context/namespace are argv elements, never a shell
    # string, so there is nothing to inject into. Test-only helper; the operator supplies both values.
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
    return subprocess.run(cmd, capture_output=True, text=True, input=stdin, timeout=timeout)


def _require_live_infrastructure() -> str:
    """Return the opted-in namespace, or skip. Never fails for a missing cluster."""
    if os.environ.get("NRVQ_E2E") != "1":
        pytest.skip("data-plane E2E is opt-in: set NRVQ_E2E=1 (needs a cluster with the chart installed)")
    if shutil.which("kubectl") is None:
        pytest.skip("kubectl not on PATH")
    namespace = os.environ.get("NRVQ_E2E_NAMESPACE", "").strip()
    if not namespace:
        pytest.skip("set NRVQ_E2E_NAMESPACE to an injection-enabled namespace you consent to pod creation in")
    res = _kubectl("get", "ns", namespace, "-o", "json")
    if res.returncode != 0:
        pytest.skip(f"namespace {namespace} unreachable: {res.stderr.strip()[:160]}")
    labels = json.loads(res.stdout).get("metadata", {}).get("labels", {}) or {}
    if labels.get(INJECTION_LABEL_KEY) != "enabled":
        pytest.skip(f"namespace {namespace} is not labelled {INJECTION_LABEL_KEY}=enabled (injection opt-in)")
    return namespace


def _pod_manifest(name: str, image: str) -> dict:
    """A minimal, restricted-PSA-compatible agent pod. Nothing privileged, nothing persistent."""
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "labels": {"app": "norviq-dataplane-probe", AGENT_CLASS_LABEL: "probe"},
        },
        "spec": {
            "restartPolicy": "Never",
            # Safety net: even if teardown never runs (killed test run), the pod removes itself.
            "activeDeadlineSeconds": 900,
            "terminationGracePeriodSeconds": 1,
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": AGENT_UID,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [
                {
                    "name": "agent",
                    "image": image,
                    "command": ["sleep", "900"],
                    "env": [{"name": "PYTHONDONTWRITEBYTECODE", "value": "1"}],
                    "resources": {
                        "requests": {"cpu": "10m", "memory": "32Mi"},
                        "limits": {"cpu": "500m", "memory": "256Mi"},
                    },
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "readOnlyRootFilesystem": True,
                        "capabilities": {"drop": ["ALL"]},
                    },
                }
            ],
        },
    }


def _get_pod(namespace: str, name: str) -> dict | None:
    res = _kubectl("get", "pod", name, "-n", namespace, "-o", "json")
    return json.loads(res.stdout) if res.returncode == 0 else None


def _container_status(pod: dict, container: str) -> dict | None:
    for status in pod.get("status", {}).get("containerStatuses", []) or []:
        if status.get("name") == container:
            return status
    return None


def _wait_until_ready(namespace: str, name: str, timeout_s: float | None = None) -> dict:
    """Poll until every container is Ready, surfacing the sidecar's own failure reason on timeout.

    Deliberately does NOT use `kubectl wait`: on the crash-loop regression `kubectl wait` just times
    out with "condition not met", which is precisely the uninformative signal that let the blocker sit
    unexplained. Here the terminal message names the container and the container's own reason.
    """
    # Image pulls dominate the wait on a cold node; operators with a warm cache can shorten it.
    if timeout_s is None:
        timeout_s = float(os.environ.get("NRVQ_E2E_READY_TIMEOUT", "180"))
    end = time.monotonic() + timeout_s
    last: dict | None = None
    while time.monotonic() < end:
        pod = _get_pod(namespace, name)
        if pod is not None:
            last = pod
            statuses = pod.get("status", {}).get("containerStatuses", []) or []
            if statuses and all(s.get("ready") for s in statuses):
                return pod
        time.sleep(2.0)
    detail = []
    for status in (last or {}).get("status", {}).get("containerStatuses", []) or []:
        state = status.get("state", {}) or {}
        reason = (state.get("waiting") or state.get("terminated") or {}).get("reason", "running")
        message = (state.get("waiting") or state.get("terminated") or {}).get("message", "")
        detail.append(
            f"{status.get('name')}: ready={status.get('ready')} reason={reason} "
            f"restarts={status.get('restartCount')} {message[:200]}"
        )
    pytest.fail(
        f"agent pod {namespace}/{name} never became Ready within {timeout_s:.0f}s — the enforcement "
        f"data plane cannot serve decisions. Container states:\n  " + "\n  ".join(detail or ["<no status>"])
    )
    raise AssertionError("unreachable")  # pragma: no cover - pytest.fail raises


@pytest.fixture(scope="module")
def agent_pod() -> tuple[str, str]:
    """Create one throwaway agent pod in the opted-in namespace; always delete it afterwards."""
    namespace = _require_live_infrastructure()
    image = os.environ.get("NRVQ_E2E_AGENT_IMAGE", DEFAULT_AGENT_IMAGE)
    name = f"norviq-dataplane-probe-{uuid.uuid4().hex[:8]}"
    created = _kubectl(
        "create", "-n", namespace, "-f", "-", stdin=json.dumps(_pod_manifest(name, image))
    )
    if created.returncode != 0:
        pytest.skip(f"cannot create the probe pod in {namespace}: {created.stderr.strip()[:200]}")
    try:
        _wait_until_ready(namespace, name)
        yield namespace, name
    finally:
        _kubectl("delete", "pod", name, "-n", namespace, "--ignore-not-found", "--wait=false")


@pytest.fixture(scope="module")
def data_plane_probe(agent_pod: tuple[str, str]) -> dict:
    """Drive one benign and one destructive tool call through the sidecar's unix socket.

    Executed from INSIDE the app container (not the sidecar) on purpose: that is the path a real agent
    takes, and it is the only way the shared-socket mount + cross-uid connect permission are exercised.
    """
    namespace, pod = agent_pod
    session_id = f"dataplane-{uuid.uuid4().hex[:12]}"

    def call(tool_name: str, tool_params: dict) -> dict:
        line = encode_tool_call(tool_name, tool_params, session_id)
        res = _kubectl(
            "exec", "-n", namespace, pod, "-c", "agent", "--",
            "python3", "-c", IN_POD_SOCKET_DRIVER, SOCKET_FILE_PATH, "15", line,
            request_timeout="60s",
        )
        assert res.returncode == 0, (
            f"could not reach the enforcement socket {SOCKET_FILE_PATH} from the agent container — "
            f"the PEP is not intercepting anything: {res.stderr.strip()[:400]}"
        )
        assert res.stdout.strip(), "the sidecar accepted the connection but returned no decision"
        return decode_proxy_response(res.stdout)

    return {
        "namespace": namespace,
        "pod": pod,
        "session_id": session_id,
        "benign": call(BENIGN_TOOL, BENIGN_PARAMS),
        "destructive": call(DESTRUCTIVE_TOOL, DESTRUCTIVE_PARAMS),
    }


def test_agent_pod_is_injected_with_the_enforcement_sidecar(agent_pod: tuple[str, str]) -> None:
    """Injection must happen for a plain pod in an opted-in namespace, and wire the app container up."""
    namespace, name = agent_pod
    pod = _get_pod(namespace, name)
    assert pod is not None, f"probe pod {namespace}/{name} disappeared"
    containers = {c["name"]: c for c in pod["spec"].get("containers", [])}
    assert SIDECAR_CONTAINER in containers, (
        f"no {SIDECAR_CONTAINER} container in {namespace}/{name} — the mutating webhook did not inject; "
        f"agent tool calls in this namespace are entirely unpoliced. containers={sorted(containers)}"
    )
    agent = containers.get("agent")
    assert agent is not None, "probe container missing from the mutated pod"
    mounts = {m.get("mountPath") for m in agent.get("volumeMounts", []) or []}
    assert SOCKET_MOUNT_PATH in mounts, (
        f"app container has no {SOCKET_MOUNT_PATH} mount — it cannot reach the PEP. mounts={sorted(mounts)}"
    )
    env = {e.get("name"): e.get("value") for e in agent.get("env", []) or []}
    assert env.get(SOCKET_ENV_VAR) == SOCKET_FILE_PATH, (
        f"app container is missing {SOCKET_ENV_VAR}={SOCKET_FILE_PATH}; an SDK-instrumented agent would "
        f"fall back to an unintercepted path. env={env}"
    )


def test_injected_sidecar_starts_and_stays_up(agent_pod: tuple[str, str]) -> None:
    """The crash-loop class, caught directly: injected, Ready, and never restarted.

    restartCount is checked because a sidecar that dies and is restarted back into Ready still had a
    window where tool calls hit a missing socket — and the app container's failure mode there is
    entirely up to the app.
    """
    namespace, name = agent_pod
    pod = _get_pod(namespace, name)
    assert pod is not None
    status = _container_status(pod or {}, SIDECAR_CONTAINER)
    assert status is not None, f"{SIDECAR_CONTAINER} has no container status in {namespace}/{name}"
    state = status.get("state", {}) or {}
    assert status.get("ready") is True, (
        f"{SIDECAR_CONTAINER} is not Ready (state={state}) — the PEP data plane is down while the "
        f"control plane keeps reporting healthy"
    )
    assert status.get("restartCount", 0) == 0, (
        f"{SIDECAR_CONTAINER} restarted {status.get('restartCount')} time(s) on a freshly created pod — "
        f"it is crash-looping at start: {state}"
    )


def test_benign_tool_call_is_forwarded_through_the_socket(data_plane_probe: dict) -> None:
    """Proves the plane is genuinely LIVE — not blanket-dropping because it cannot reach the PDP."""
    response = data_plane_probe["benign"]
    assert "error" not in response, f"sidecar errored on a well-formed request: {response}"
    rule_id = decision_of(response).get("rule_id", "")
    assert rule_id != FAIL_CLOSED_RULE_ID, (
        f"the sidecar could not reach the central policy engine (rule_id={rule_id}); every decision it "
        f"returns right now is an outage, not a policy result"
    )
    assert is_forwarded(response), (
        f"benign tool {BENIGN_TOOL!r} was not forwarded: {response}. If your baseline policy genuinely "
        f"denies it, set NRVQ_E2E_BENIGN_TOOL to a read-only tool the baseline permits."
    )


def test_destructive_tool_call_is_dropped_through_the_socket(data_plane_probe: dict) -> None:
    """The headline invariant: an agent asking the PEP to `rm -rf /` is refused, at the socket."""
    response = data_plane_probe["destructive"]
    assert is_dropped(response), (
        f"{DESTRUCTIVE_TOOL}({DESTRUCTIVE_PARAMS['command']!r}) was FORWARDED by the data plane: {response}"
    )
    decision = decision_of(response)
    assert decision, f"drop carried no decision payload (the sidecar errored rather than decided): {response}"
    assert decision.get("rule_id") != FAIL_CLOSED_RULE_ID, (
        "the destructive call was dropped only because the sidecar is failing closed — that is an "
        "outage, not proof of enforcement"
    )
    assert decision.get("decision") == "block", (
        f"expected a policy BLOCK for a destructive shell, got decision={decision.get('decision')!r} "
        f"rule_id={decision.get('rule_id')!r}"
    )


async def test_sidecar_decision_is_audited_as_sidecar_sourced(
    data_plane_probe: dict, api_client, auth_headers: dict[str, str]
) -> None:
    """A decision nobody can see is not governance.

    Attribution matters as much as presence: the row must carry ``framework=sidecar``. Without that,
    a dead data plane is indistinguishable from a live one in every dashboard, because control-plane
    and red-team traffic fill the same table.
    """
    namespace = data_plane_probe["namespace"]
    session_id = data_plane_probe["session_id"]
    found = None
    for _ in range(24):  # audit emission is fire-and-forget; poll ~12s
        resp = await api_client.get(
            f"/api/v1/audit/records?namespace={namespace}&framework=sidecar&limit=200",
            headers=auth_headers,
        )
        if resp.status_code in (401, 403):
            # Credentials are not the invariant under test (auth is covered by test_auth_hardening).
            # Skipping is honest here; a 401 says nothing about whether the decision was recorded.
            pytest.skip(f"audit API rejected the test token ({resp.status_code}) — set NRVQ_API_TOKEN")
        assert resp.status_code == 200, resp.text
        matches = [r for r in resp.json() if r.get("session_id") == session_id]
        if any(r.get("tool_name") == DESTRUCTIVE_TOOL for r in matches):
            found = matches
            break
        await asyncio.sleep(0.5)

    assert found, (
        f"no audit row with framework=sidecar and session_id={session_id} in namespace {namespace} — "
        f"the data plane made a decision that left no trail (audit errors are swallowed by design, so "
        f"this is exactly how the trail dies silently)"
    )
    blocked = [r for r in found if r.get("tool_name") == DESTRUCTIVE_TOOL]
    assert blocked and blocked[0].get("decision") == "block", (
        f"the destructive call was recorded but not as a block: {blocked}"
    )
