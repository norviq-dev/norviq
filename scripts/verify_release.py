#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the RELEASE ARTIFACT in a throwaway cluster, before a tag exists.

Every gate we had tested the source tree: 15 `helm template` calls, zero `helm install`, and no CI
workflow that creates a cluster. So the only thing that ever exercised a stamped, digest-pinned
chart in a running cluster was the release itself — the most expensive and least reversible place to
discover anything, and it burns a version number per attempt. Three shipped defects came straight out
of that hole: an uninstall hook pinned to a deleted image, a `--wait` deadlock, and a sidecar the
webhook refused to inject because release-stamping pins it by digest.

None of those are visible from `helm template ./helm/norviq`, because the checked-in chart carries
mutable `-latest` tags and the released one does not. This script closes that gap by testing what a
user receives:

    stamp the chart by DIGEST (as release.yml does)  ->  install it  ->  use it  ->  uninstall it

Checks are COLLECTED, not fatal: one run reports every failure it finds rather than stopping at the
first, because finding one bug per release cycle is the loop this exists to break.

    scripts/verify_release.py                 # upgrade path from the newest published chart <= this one
    scripts/verify_release.py --upgrade-from none   # fresh install instead, by explicit choice
    scripts/verify_release.py --keep          # leave the cluster up to poke at a failure
    scripts/verify_release.py --skip-create   # reuse a cluster from a previous --keep run
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHART = ROOT / "helm" / "norviq"
STAMP = ROOT / "scripts" / "release_stamp.py"
REPO = "ghcr.io/norviq-dev/norviq-engine"
CHART_REPO = "ghcr.io/norviq-dev/charts/norviq"
NS, TENANT = "norviq", "agents"
POLICY = "nrvq-verify-guard"
# The bundled single-instance store (templates/redis-statefulset.yaml), the same pod name in every release.
STORE_POD, STORE_CONTAINER = "norviq-redis-0", "redis"
# How long the store must stay up between the two samples check_store_after_upgrade takes.
STORE_STABLE_S = 15
# Only ever used against a throwaway kind cluster this script created and deletes.
VERIFY_PASSWORD = "verify-release-not-a-real-secret-9137"

# Every kubectl/helm call in this repo needs it on macOS; harmless on Linux runners.
ENV_EXTRA = {"GODEBUG": "netdns=go"}

# What a STOCK install answers for the gate's identity (TENANT, class chatbot, no class policy). From
# 0.2.6 the chart's namespace baseline enforces: the strict preset as authored, enforcementMode block,
# every control at its shipped default (20 act on the call, scope_violation_dangerous_tool records), so
# execute_sql is refused by strict_default_block. Through 0.2.5 the baseline ran in audit and the same
# call read audit + policy_audit_would_block:strict_default_block. (tool, params, decision, rule_id)
# tests/release/test_verify_release_expectations.py runs these through the real resolver, so a default
# the gate does not follow fails there rather than on release day.
STOCK_PROBES = [
    ("search_kb", {"q": "refund policy"}, "allow", "default_allow"),
    ("execute_sql", {"query": "SELECT * FROM users"}, "block", "strict_default_block"),
]
# The per-control way off and back, for the same execute_sql call: (effects PUT to /baseline/controls,
# decision, rule_id). Monitor must RECORD under the bare rule id (the saved controls replace the chart's
# copy; a chart that kept deciding would still block), and the default must block again.
CONTROL_ROUND_TRIP = [
    ({"strict_default_block": "monitor"}, "audit", "strict_default_block"),
    ({}, "block", "strict_default_block"),
]

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""), flush=True)
    return ok


def run(*cmd: str, timeout: int = 600, check_rc: bool = False) -> subprocess.CompletedProcess[str]:
    import os

    env = {**os.environ, **ENV_EXTRA}
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    if check_rc and res.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:3])}… failed rc={res.returncode}\n{res.stderr[-2000:]}")
    return res


def kubectl(ctx: str, *args: str, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    return run("kubectl", "--context", ctx, *args, timeout=timeout)


def helm(ctx: str, *args: str, timeout: int = 1200) -> subprocess.CompletedProcess[str]:
    return run("helm", "--kube-context", ctx, *args, timeout=timeout)


def wait_until(fn, timeout: int, interval: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if fn():
            return True
        time.sleep(interval)
    return False


# ---------------------------------------------------------------------------------------------
# stage 1 — build the artifact a release would publish
# ---------------------------------------------------------------------------------------------
def stamp(version: str, workdir: Path) -> Path:
    """A copy of the chart, versioned and pinned to real registry digests — release.yml's own step.

    Digests come from the `<comp>-latest` tags built by build.yml on main, so this pins the same
    bytes a release cut from this commit would. The POINT is the digest form: `@sha256:...` is what
    the checked-in chart never carries and what the shipped one always does.
    """
    chart = workdir / "norviq"
    shutil.copytree(CHART, chart)
    res = run(sys.executable, str(STAMP), version, "--chart-dir", str(chart),
              "--resolve", "--resolve-suffix", "latest", timeout=600)
    if res.returncode != 0:
        raise RuntimeError(f"release_stamp failed:\n{res.stdout}\n{res.stderr}")
    return chart


def check_stamped_shape(ctx: str, chart: Path) -> None:
    res = run("helm", "template", "norviq", str(chart), "--set-json",
              'policyQuotaNamespaces=["agents"]', "--set", "webhook.injection.enabled=true")
    if res.returncode != 0:
        check("stamped chart renders", False, res.stderr[-300:])
        return
    check("stamped chart renders", True)

    floating = re.findall(rf"{re.escape(REPO)}:[^\"'\s]+", res.stdout)
    check("no floating image tags in the stamped chart", not floating, f"{sorted(set(floating))[:3]}")
    # Third-party images too, with the gate release.yml runs: the line above only ever looked at
    # Norviq's repository and passed a chart with opa, valkey, postgres, nginx, busybox and curl on tags.
    import check_image_pins  # noqa: PLC0415 — sibling script; scripts/ is sys.path[0] when run directly

    bare = [ref for _n, ref in check_image_pins.unpinned(check_image_pins.find_refs(res.stdout))]
    check("every image in the stamped chart is digest-pinned", not bare, f"{sorted(set(bare))[:3]}")

    m = re.search(r"NRVQ_SIDECAR_IMAGE\s*\n\s*value:\s*\"([^\"]+)\"", res.stdout)
    check("injected sidecar is digest-pinned", bool(m and "@sha256:" in m.group(1)),
          m.group(1) if m else "NRVQ_SIDECAR_IMAGE absent")


# ---------------------------------------------------------------------------------------------
# stage 2 — install it the way automation does
# ---------------------------------------------------------------------------------------------
def install(ctx: str, chart: Path, webhook_image: str = "") -> bool:
    """--wait --atomic, because that is what CI/GitOps use and what deadlocked before 0.1.6."""
    for ns in (NS, TENANT):
        kubectl(ctx, "create", "namespace", ns)
    kubectl(ctx, "label", "namespace", TENANT, "norviq-injection=enabled", "--overwrite")

    extra: list[str] = []
    if webhook_image:
        # Only the TAG is overridden, so the candidate image must already be tagged under the chart's
        # own repository (build it as ghcr.io/norviq-dev/norviq-engine:<tag> and `kind load` it).
        # Clearing the digest is what lets the tag win; leaving it set keeps the pinned image and
        # silently tests the WRONG binary — the exact failure mode this script exists to prevent.
        # pullPolicy must drop to IfNotPresent as well: the chart ships `Always`, which makes the
        # kubelet ignore the `kind load`ed image and try to pull a tag that exists on no registry.
        tag = webhook_image.rpartition(":")[2]
        extra = ["--set", f"images.webhook.tag={tag}", "--set", "images.webhook.digest=",
                 "--set", "images.webhook.pullPolicy=IfNotPresent"]

    # Deliberately NO config.dbSslMode: the candidate chart derives it from the datastore in use, and a
    # gate that overrides it would never prove that a pure-defaults install can start. That is exactly
    # the failure this override used to hide.
    res = helm(ctx, "install", "norviq", str(chart), "-n", NS,
               "--set-json", f'policyQuotaNamespaces=["{TENANT}"]',
               "--set", "webhook.injection.enabled=true",
               *extra,
               "--wait", "--atomic", "--timeout", "12m", timeout=900)
    ok = res.returncode == 0 and "STATUS: deployed" in res.stdout
    return check("helm install --wait --atomic completes", ok,
                 "" if ok else (res.stderr or res.stdout)[-400:])


# ---------------------------------------------------------------------------------------------
# stage 3 — use it
# ---------------------------------------------------------------------------------------------
SIDECAR_PROBE = """apiVersion: v1
kind: Pod
metadata:
  name: nrvq-verify-probe
  namespace: %s
  labels:
    norviq.io/agent-class: chatbot
spec:
  containers:
    - name: app
      image: busybox:1.36
      command: ["sh", "-c", "sleep 300"]
""" % TENANT


def check_injection(ctx: str) -> None:
    """The flagship feature, against the STAMPED chart.

    Worth being precise about the failure this catches: with failurePolicy Fail, a webhook that
    refuses to build a patch does not silently skip injection — it REJECTS the pod. Turning the
    feature on stops tenant workloads from starting at all.
    """
    proc = subprocess.run(["kubectl", "--context", ctx, "apply", "-f", "-"],
                          input=SIDECAR_PROBE, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        check("agent pod is admitted", False, proc.stderr.strip()[-300:])
        check("sidecar is injected", False, "pod never created")
        return
    check("agent pod is admitted", True)

    names = ""

    def has_containers() -> bool:
        nonlocal names
        r = kubectl(ctx, "get", "pod", "nrvq-verify-probe", "-n", TENANT,
                    "-o", "jsonpath={range .spec.containers[*]}{.name} {end}")
        names = r.stdout.strip()
        return bool(names)

    wait_until(has_containers, 60)
    check("sidecar is injected", "norviq-sidecar" in names, f"containers: {names or '<none>'}")
    kubectl(ctx, "delete", "pod", "nrvq-verify-probe", "-n", TENANT, "--wait=false")


def _api(port: int, path: str, token: str = "", body: dict | None = None, method: str = "") -> dict:
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                 method=method or ("POST" if body else "GET"))
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    data = None
    if body is not None:
        req.add_header("Content-Type", "application/json")
        data = json.dumps(body).encode()
    with urllib.request.urlopen(req, data, timeout=30) as r:  # noqa: S310 — fixed localhost URL
        return json.loads(r.read().decode())


def check_enforcement(ctx: str) -> str:
    """A policy decision end to end: the product's actual job, on the released artifact."""
    r = kubectl(ctx, "get", "secret", "norviq-secrets", "-n", NS,
                "-o", "jsonpath={.data.NRVQ_AUTH_ADMIN_PASSWORD}")
    if not r.stdout.strip():
        check("enforcement probes", False, "admin password secret not readable")
        return ""
    password = base64.b64decode(r.stdout.strip()).decode()

    port = 18099
    pf = subprocess.Popen(["kubectl", "--context", ctx, "-n", NS, "port-forward",
                           "svc/norviq-ui", f"{port}:80"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_until(lambda: _reachable(port), 60):
            check("enforcement probes", False, "console port-forward never came up")
            return ""
        # The seeded admin lands `must_change`, and while that flag is set the API rejects every
        # authenticated call except change-password/logout/me — so a probe that just logs in gets a
        # 403 on /evaluate and looks like an enforcement failure. Clear it the way a human would,
        # then RE-LOGIN: the gate reads the JWT claim, not the row, so the pre-change token stays
        # locked out even after the password is updated.
        try:
            tok = _api(port, "/api/v1/auth/login", body={"username": "admin", "password": password})
            token = tok.get("access_token") or tok.get("token") or ""
            if tok.get("must_change"):
                _api(port, "/api/v1/auth/change-password", token,
                     {"current_password": password, "new_password": VERIFY_PASSWORD})
                tok = _api(port, "/api/v1/auth/login",
                           body={"username": "admin", "password": VERIFY_PASSWORD})
                token = tok.get("access_token") or tok.get("token") or ""
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            check("enforcement probes", False, f"login failed: {exc}")
            return ""
        if not token:
            check("enforcement probes", False, "login returned no token")
            return ""

        identity = {"namespace": TENANT, "agent_class": "chatbot",
                    "spiffe_id": f"spiffe://norviq/ns/{TENANT}/sa/chatbot", "workload": "chatbot"}
        # A STOCK install refuses a high-risk tool name (STOCK_PROBES): the namespace baseline enforces
        # from 0.2.6. This gate exists to prove the artifact ENFORCES, so the default is checked as a
        # block, and then the per-control way off is checked to reach the engine and come back
        # (CONTROL_ROUND_TRIP): a gate that only ever saw the block could not tell an artifact whose
        # console switch does nothing from one that works, and during 0.2.6 it did nothing (Off and
        # Monitor still came back block / deny_shell_execution) until saved controls replaced the
        # chart's copy.
        def _evaluate(tool: str, params: dict) -> dict:
            return _api(port, "/api/v1/evaluate", token,
                        {"tool_name": tool, "tool_params": params, "agent_identity": identity})

        for tool, params, want, want_rule in STOCK_PROBES:
            try:
                d = _evaluate(tool, params)
                got, rule = d.get("decision"), str(d.get("rule_id") or "")
                # The rule_id matters as much as the decision: an `audit` carrying `default_allow`
                # would mean NOTHING fired, which is a miss wearing a detection's clothing.
                check(f"evaluate {tool} -> {want} ({want_rule})",
                      got == want and want_rule in rule, f"got {got} ({rule})")
            except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
                check(f"evaluate {tool} -> {want}", False, str(exc))

        # …and it must actually stop the call once promoted, or the gate would pass an artifact that
        # can only ever observe.
        #
        # A 404 here is NOT a failure. This script exercises the RELEASE ARTIFACT — images built from
        # `<comp>-latest` on MAIN (see stamp() above) — so the API under test can legitimately predate
        # an endpoint that exists on the branch proposing the change. `PUT /baseline/controls` arrived
        # with the toggleable-controls work and is not on main yet, so it 404s here and would on any
        # PR that adds an endpoint its own gate then calls. Failing on that would make this gate red
        # for every such change and teach people to ignore it.
        #
        # It is reported as a SKIP with the reason, not silently swallowed: the moment main carries
        # the endpoint this becomes a real assertion, and until then the log says why it did not run.
        # DISCRIMINATE before skipping. A bare "404 -> skip" would also swallow a genuine regression:
        # the endpoint being REMOVED, or this script calling the wrong path or method. So probe the
        # same collection with GET first, which tells the two apart:
        #
        #   GET 404 too      -> the whole baseline router is absent      -> old artifact, SKIP
        #   GET ok, PUT 404  -> the router IS mounted and the PUT missed -> OUR bug, FAIL
        #
        # Verified while writing this: origin/main has zero @router routes in baseline_router.py and
        # zero include_router references for it, so the absent-router branch is the real state of the
        # published artifact today — not an assumption.
        router_present = True
        try:
            _api(port, "/api/v1/baseline/controls?namespace=" + TENANT, token)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                router_present = False
            # any other status (401/403/500) means the router IS there and answered — keep going and
            # let the PUT below be judged on its own result.
        except (urllib.error.URLError, OSError, json.JSONDecodeError):
            pass  # transport trouble: fall through and let the PUT report it

        for effects, want, want_rule in CONTROL_ROUND_TRIP:
            label = f"execute_sql -> {want} ({want_rule}) with baseline controls {effects or 'at the defaults'}"
            try:
                _api(port, "/api/v1/baseline/controls", token, {"namespace": TENANT, "effects": effects},
                     method="PUT")
            except urllib.error.HTTPError as exc:
                if exc.code == 404 and not router_present:
                    print("  [SKIP] baseline controls: this artifact has no /baseline/controls router at all "
                          "(released images are built from main) — becomes a real check once main has it")
                    return token
                # Router present but the PUT 404'd, or any other status: that is a real failure.
                check(label, False, f"HTTP {exc.code}" + ("" if router_present else " (and GET also 404)"))
                return token
            except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
                check(label, False, str(exc))
                return token
            # Exact rule id: a chart baseline that kept deciding in audit would read
            # policy_audit_would_block:strict_default_block. Polled briefly, because the evaluate can land
            # on the other API replica, which learns of the save over the policy stream.
            seen: dict = {}

            def _settled(effects_want: tuple[str, str] = (want, want_rule)) -> bool:
                try:
                    seen.update(_evaluate("execute_sql", {"query": "SELECT * FROM users"}))
                except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
                    seen.update(decision="error", rule_id=str(exc))
                return (seen.get("decision"), str(seen.get("rule_id") or "")) == effects_want

            check(label, wait_until(_settled, 15, 1.0), f"got {seen.get('decision')} ({seen.get('rule_id')})")
        return token
    finally:
        pf.terminate()


def _reachable(port: int, path: str = "/") -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=3):  # noqa: S310
            return True
    except Exception:
        return False


class _PortForward:
    """Port-forward to ONE pod. Addressing the Service would load-balance and defeat the point."""

    def __init__(self, ctx: str, pod: str, port: int, target: int = 8080) -> None:
        self.port = port
        self._p = subprocess.Popen(
            ["kubectl", "--context", ctx, "-n", NS, "port-forward", f"pod/{pod}", f"{port}:{target}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def __enter__(self) -> "_PortForward":
        wait_until(lambda: _reachable(self.port, "/readyz"), 60)
        return self

    def __exit__(self, *_exc: object) -> None:
        self._p.terminate()


def check_replica_propagation(ctx: str, token: str) -> None:
    """A policy written to ONE replica must be enforced by the OTHER, and unloaded from both.

    This is the HA claim the chart makes by defaulting api.replicas to 2, and it is invisible to
    every other check here: with one replica, or by talking to the Service (which load-balances),
    a broken propagation path looks identical to a working one. Each replica evaluates from its own
    in-process policy set, so without cross-replica invalidation a create/delete routed to replica A
    leaves replica B enforcing the old rules — and which answer a caller gets depends on which pod
    the load balancer picked. That is worse than a clean failure: enforcement becomes a coin flip.

    The API container listens plaintext on 8080 inside the pod (the tls-proxy sidecar terminates TLS
    on 8443 for in-cluster callers), so a per-POD forward reaches one replica directly.
    """
    pods = kubectl(ctx, "get", "pods", "-n", NS, "-l", "app.kubernetes.io/component=api",
                   "-o", "jsonpath={range .items[*]}{.metadata.name} {end}").stdout.split()
    if not check("two API replicas are serving", len(pods) >= 2, f"{len(pods)} replica(s): {pods}"):
        return
    a, b = pods[0], pods[1]

    identity = {"namespace": TENANT, "agent_class": "chatbot",
                "spiffe_id": f"spiffe://norviq/ns/{TENANT}/sa/chatbot", "workload": "chatbot"}

    def decision(port: int) -> str:
        try:
            d = _api(port, "/api/v1/evaluate", token,
                     {"tool_name": "search_kb", "tool_params": {"q": "x"}, "agent_identity": identity})
            return str(d.get("decision", "?"))
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            return f"error: {exc}"

    with _PortForward(ctx, a, 18101) as pa, _PortForward(ctx, b, 18102) as pb:
        base_a, base_b = decision(pa.port), decision(pb.port)
        if not check("baseline: both replicas allow search_kb", base_a == base_b == "allow",
                     f"A={base_a} B={base_b}"):
            return

        # A policy that CHANGES an observable decision. Asserting on the decision rather than on a
        # cache counter is the point: it proves the peer re-evaluates, not merely that it got a
        # message.
        rego = ('package norviq\n'
                'default decision = "allow"\n'
                'rule_id = "nrvq_verify_propagation"\n'
                'reason = "propagation probe"\n'
                'decision = "block" { input.tool_name == "search_kb" }\n')
        try:
            _api(pa.port, "/api/v1/policies", token, {
                "namespace": TENANT, "agent_class": "chatbot", "rego_source": rego,
                "enforcement_mode": "block", "priority": 200,
                "policy_name": "nrvq-verify-propagation", "saved_by": "verify_release",
            })
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            check("create a policy on replica A", False, str(exc))
            return
        check("create a policy on replica A", True)

        ok = wait_until(lambda: decision(pb.port) == "block", 60, interval=2)
        check("replica B enforces a policy written to replica A", ok, f"B={decision(pb.port)}")

        # Deleted from the NON-owning replica on purpose: the historical bug was a delete routed to
        # a replica that did not hold the key returning 404 while the row survived, so the policy
        # came back on restart.
        try:
            _api(pb.port, f"/api/v1/policies/{TENANT}/chatbot", token, method="DELETE")
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            check("delete the policy on replica B (the non-owner)", False, str(exc))
            return
        check("delete the policy on replica B (the non-owner)", True)

        ok = wait_until(lambda: decision(pa.port) == "allow", 60, interval=2)
        check("replica A stops enforcing a policy deleted on replica B", ok, f"A={decision(pa.port)}")

    # These are what make the decisions above non-vacuous. `remote_reloaded` / `remote_unloaded` fire
    # ONLY on the peer path: each loader stamps its own uuid origin on the event it publishes and
    # skips its own echo, so a pod never logs these for a write it performed itself. Seeing the
    # reload in B's log and the unload in A's is therefore proof the two forwards addressed
    # DIFFERENT pods — without them, a bug that pointed both at one replica would pass every
    # decision check above.
    logs_b = kubectl(ctx, "logs", b, "-n", NS, "-c", "api", "--tail=400").stdout
    logs_a = kubectl(ctx, "logs", a, "-n", NS, "-c", "api", "--tail=400").stdout
    reloaded = "remote_reloaded" in logs_b
    unloaded = "remote_unloaded" in logs_a
    check("the peer applied the create as a REMOTE event", reloaded,
          "" if reloaded else "NRVQ-REG-5017 absent from replica B")
    check("the peer applied the delete as a REMOTE event", unloaded,
          "" if unloaded else "NRVQ-REG-5016 absent from replica A")


def check_helm_test(ctx: str) -> None:
    res = helm(ctx, "test", "norviq", "-n", NS, "--timeout", "5m", timeout=400)
    check("helm test norviq", res.returncode == 0, (res.stderr or res.stdout).strip()[-300:])


# ---------------------------------------------------------------------------------------------
# stage 4 — remove it (the half nobody runs until a user complains)
# ---------------------------------------------------------------------------------------------
def check_uninstall(ctx: str) -> None:
    """Uninstall with finalizer-bearing CRs present — the 0.1.4 failure, as a gate.

    A tenant policy is created first ON PURPOSE: an uninstall with nothing to clean up proves
    nothing, and the finalizers are exactly what wedged it.
    """
    if not create_tenant_policy(ctx):
        return

    def finalized() -> bool:
        r = kubectl(ctx, "get", "nrvqpolicy", POLICY, "-n", TENANT,
                    "-o", "jsonpath={.metadata.finalizers}")
        return "policy-protection" in r.stdout

    check("controller finalizes the policy", wait_until(finalized, 90))
    _uninstall_and_assert_clean(ctx)


def _tenant_policy_manifest() -> str:
    return f"""apiVersion: norviq.io/v1alpha1
kind: NrvqPolicy
metadata:
  name: {POLICY}
  namespace: {TENANT}
spec:
  preset: strict
  enforcementMode: block
  priority: 400
  target:
    namespace: {TENANT}
"""


def create_tenant_policy(ctx: str) -> bool:
    """Create the tenant policy, RETRIED, with the wait reported rather than hidden. Each tenant namespace gets a
    Each tenant namespace gets a ResourceQuota counting count/nrvqpolicies.norviq.io, and Kubernetes
    REFUSES creates of a quota-tracked resource until the quota controller has computed usage for it
    — "status unknown for quota". On a fresh install the CRD and the quota land together, so the
    controller has to discover a brand-new resource type first. If that clears quickly it is a
    startup race worth documenting; if it never clears, tenants can never write a policy and this is
    the loudest bug in the product. Timing it is what tells the two apart, so the elapsed time is the
    result rather than something the retry hides.
    """
    manifest = _tenant_policy_manifest()
    t0 = time.monotonic()
    err = ""

    def created() -> bool:
        nonlocal err
        r = subprocess.run(["kubectl", "--context", ctx, "apply", "-f", "-"],
                           input=manifest, capture_output=True, text=True, timeout=120)
        err = r.stderr.strip()
        return r.returncode == 0

    ok = wait_until(created, 420, interval=10)
    waited = int(time.monotonic() - t0)
    return check("a tenant can create a policy after install", ok,
                 f"took {waited}s" if ok else f"still failing after {waited}s — {err[-200:]}")


def _uninstall_and_assert_clean(ctx: str) -> None:
    t0 = time.monotonic()
    res = helm(ctx, "uninstall", "norviq", "-n", NS, "--wait", "--timeout", "6m", timeout=420)
    elapsed = int(time.monotonic() - t0)
    check("helm uninstall completes", res.returncode == 0,
          f"{elapsed}s" + ("" if res.returncode == 0 else f" — {(res.stderr or res.stdout)[-300:]}"))

    left = kubectl(ctx, "get", "nrvqpolicies", "-A", "-o",
                   "jsonpath={range .items[*]}{.metadata.name}={.metadata.finalizers} {end}").stdout
    check("no policy is left holding a finalizer", "policy-protection" not in left, left.strip()[:200])

    # Classified by PHASE, not counted. A Completed hook/test pod is litter; a Running one means the
    # uninstall did not actually stop anything. Conflating them either cries wolf on every run (and
    # trains people to ignore the gate) or hides the case that matters, so name both.
    # `.status.phase` stays Running while a pod drains, so phase alone reports every graceful
    # shutdown as a survivor and the gate cries wolf on a healthy uninstall. What separates a leak
    # from a shutdown is `.metadata.deletionTimestamp` — set means Kubernetes is already removing it.
    # Give the drain a bounded window first, then judge only what is left WITHOUT one.
    def pods() -> list[tuple[str, str, str]]:
        raw = kubectl(ctx, "get", "pods", "-n", NS, "--no-headers", "-o",
                      "custom-columns=N:.metadata.name,P:.status.phase,D:.metadata.deletionTimestamp").stdout
        return [tuple(ln.split()[:3]) for ln in raw.splitlines() if ln.strip()]

    wait_until(lambda: not pods(), 90, interval=3)
    rows = pods()
    orphans = [n for n, _p, d in rows if d in ("<none>", "")]
    draining = [n for n, _p, d in rows if d not in ("<none>", "")]
    check("no pod is orphaned by the uninstall", not orphans, ", ".join(orphans))
    if draining:
        print(f"    note: {len(draining)} pod(s) still draining after 90s: {', '.join(draining)}")

    roles = kubectl(ctx, "get", "clusterrole", "-o", "name").stdout
    orphans = [r for r in roles.splitlines() if "/norviq" in r or "/nrvq" in r]
    check("cluster-scoped RBAC is removed", not orphans, f"{orphans[:3]}")

    t0 = time.monotonic()
    res = kubectl(ctx, "delete", "ns", NS, TENANT, "--timeout=180s", timeout=240)
    check("namespaces terminate", res.returncode == 0,
          f"{int(time.monotonic() - t0)}s" + ("" if res.returncode == 0 else " — stuck"))


# ---------------------------------------------------------------------------------------------
# stage 2u — the operation every EXISTING user performs
# ---------------------------------------------------------------------------------------------
# `auto` used to read `git tag` and pick the highest tag that was not the candidate's own version. It
# went wrong three ways, and the first one meant the upgrade path had never run in CI:
#
#   * CI's checkout is shallow and carries no tags, so the list was empty. On PR #122 (chart 0.2.5) the
#     job logged "(no earlier release to upgrade from — running the fresh-install path)" and reported
#     success. That is how the 0.2.5 -> 0.2.6 store crash (tests/helm/test_bundled_store_upgrade.py)
#     reached a release candidate without CI ever running an upgrade.
#   * "not equal" is not "older". It skipped the published 0.2.5 when the candidate was an unbumped
#     0.2.5, which is still a real upgrade of a real artifact. It would also pick a NEWER tag for an
#     older candidate and test a downgrade.
#   * A tag is not a published chart. v0.1.0 and v0.2.0 shipped no chart at all (CHANGELOG.md).
#
# So the list now comes from the registry `install_published` pulls from. Only published releases
# count, the candidate's own version included, and finding none is an error rather than a quiet switch
# to the fresh-install path.
_SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


class UpgradeSourceError(RuntimeError):
    """`--upgrade-from auto` could not name a published release. Never a reason to run the fresh path."""


def _version_key(version: str) -> tuple[int, int, int, int] | None:
    """(major, minor, patch, 1 for a release / 0 for a prerelease), or None for a non-SemVer tag.

    The last field orders a prerelease below its release (0.2.6-rc.1 < 0.2.6), which is all the ordering
    that is needed: prereleases are never picked as an upgrade source, only compared against as a candidate.
    """
    m = _SEMVER.match(version.strip().removeprefix("v"))
    if not m:
        return None
    return int(m[1]), int(m[2]), int(m[3]), 0 if m[4] else 1


def select_upgrade_source(candidate: str, published: Iterable[str]) -> str:
    """The newest published RELEASE that is <= `candidate`, or "" if there is none.

    Equal counts. An unbumped candidate upgraded from the published artifact with the same number is still
    an upgrade, and it is the one every existing user of that number performs. Prereleases are skipped
    because nobody runs one as the cluster they upgrade from. Registry tags that are not versions
    (cosign's `sha256-<digest>`, `artifacthub.io`) are ignored.
    """
    ceiling = _version_key(candidate)
    if ceiling is None:
        raise ValueError(f"candidate version {candidate!r} is not SemVer")
    releases = [(key, tag) for tag in published
                if (key := _version_key(tag)) is not None and key[3] == 1 and key <= ceiling]
    return max(releases)[1] if releases else ""


def published_chart_versions(repo: str = CHART_REPO) -> list[str]:
    """Every tag of the published chart, read from the OCI registry (anonymous pull token).

    `helm` has no command that lists OCI tags, but the registry API does, and it lists exactly what
    `helm install oci://... --version X` can fetch.
    """
    host, _, path = repo.partition("/")
    token_url = f"https://{host}/token?scope=repository:{path}:pull&service={host}"
    with urllib.request.urlopen(token_url, timeout=30) as r:  # noqa: S310 — fixed https registry URL
        token = json.loads(r.read().decode())["token"]
    tags: list[str] = []
    url = f"https://{host}/v2/{path}/tags/list?n=1000"
    while url:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 — fixed https registry URL
            tags += json.loads(r.read().decode()).get("tags") or []
            nxt = re.search(r'<([^>]+)>;\s*rel="next"', r.headers.get("Link", ""))
        url = urllib.parse.urljoin(f"https://{host}", nxt.group(1)) if nxt else ""
    return tags


def resolve_upgrade_source(requested: str, candidate: str,
                           list_published: Callable[[], list[str]] | None = None) -> str:
    """Turn `--upgrade-from` into a version to install first, or "" for the fresh-install path.

    Only an explicit `none` gives "". `auto` either names a published release or raises, and so does an
    empty value: `--upgrade-from ""` (an unset CI variable, say) used to fall through as the version ""
    and reach the fresh-install path, which is the silent switch this function exists to refuse.
    """
    if not requested.strip():
        raise UpgradeSourceError("--upgrade-from is empty. Pass auto, none, or a published version.")
    if requested == "none":
        return ""
    if requested != "auto":
        return requested
    try:
        published = (list_published or published_chart_versions)()
    except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
        raise UpgradeSourceError(f"could not list the published chart versions at oci://{CHART_REPO}: {exc}") from exc
    try:
        source = select_upgrade_source(candidate, published)
    except ValueError as exc:
        raise UpgradeSourceError(str(exc)) from exc
    if not source:
        releases = sorted((t for t in published if (k := _version_key(t)) and k[3] == 1), key=_version_key)
        raise UpgradeSourceError(
            f"no published release <= {candidate} at oci://{CHART_REPO} "
            f"(published releases: {', '.join(releases) or 'none'}). Nothing was upgraded, so nothing about "
            f"the upgrade path is known. Pass --upgrade-from none to verify a fresh install deliberately.")
    return source


def install_published(ctx: str, version: str) -> bool:
    """Install the PREVIOUS release from OCI — the cluster a user is upgrading from."""
    for ns in (NS, TENANT):
        kubectl(ctx, "create", "namespace", ns)
    kubectl(ctx, "label", "namespace", TENANT, "norviq-injection=enabled", "--overwrite")

    # This installs an ALREADY-PUBLISHED chart, which hard-codes config.dbSslMode=require and cannot
    # start against the bundled non-TLS Postgres without the override. Keep it here (unlike the
    # candidate install above) — the upgrade baseline has to be a release that actually boots.
    res = helm(ctx, "install", "norviq", f"oci://{CHART_REPO}", "--version", version, "-n", NS,
               "--set-json", f'policyQuotaNamespaces=["{TENANT}"]',
               "--set", "config.dbSslMode=disable",
               "--set", "webhook.injection.enabled=true",
               "--wait", "--timeout", "12m", timeout=900)
    ok = res.returncode == 0 and "STATUS: deployed" in res.stdout
    return check(f"install the previous release ({version}) from OCI", ok,
                 "" if ok else (res.stderr or res.stdout)[-400:])


def _api_pods(ctx: str) -> list[str]:
    """API pods that are not on their way out (a rollout lists the terminating ones too)."""
    r = kubectl(ctx, "get", "pods", "-n", NS, "-l", "app.kubernetes.io/component=api", "-o", "json")
    try:
        items = json.loads(r.stdout).get("items") or []
    except json.JSONDecodeError:
        return []
    return [p["metadata"]["name"] for p in items if not p["metadata"].get("deletionTimestamp")]


def seed_bundled_store(ctx: str) -> bool:
    """Write to the bundled store of the release being upgraded FROM, and get it onto the volume.

    The upgrade path used to install N-1 and upgrade straight away, with nothing ever written to the
    store, and that hid exactly the failure it needed to find. 0.2.5's Redis 7.4 leaves an RDB-12 dump on
    norviq-redis-pvc, and 0.2.6's Valkey 8.1 exits on it (measured live on 2026-10-30; see
    tests/helm/test_bundled_store_upgrade.py).

    A login and a logout are the most ordinary writes a user makes, and the logout leaves a `revoked:`
    entry in the store. SAVE then writes the dump that any install running for an hour with one change
    already has (Redis's default `save 3600 1`), so the run does not depend on the shutdown save landing.
    Keys and dump size are asserted, not assumed: a seed that silently wrote nothing would make every
    store check after the upgrade pass for the wrong reason.
    """
    r = kubectl(ctx, "get", "secret", "norviq-secrets", "-n", NS,
                "-o", "jsonpath={.data.NRVQ_AUTH_ADMIN_PASSWORD}")
    pods = _api_pods(ctx)
    if not r.stdout.strip() or not pods:
        return check("seed the pre-upgrade store (login + logout)", False,
                     "admin password secret not readable" if pods else "no API pod")
    password = base64.b64decode(r.stdout.strip()).decode()
    with _PortForward(ctx, pods[0], 18103) as pf:
        try:
            tok = _api(pf.port, "/api/v1/auth/login", body={"username": "admin", "password": password})
            token = tok.get("access_token") or tok.get("token") or ""
            # Allowed while the seeded admin is still `must_change`: logout validates the token itself.
            _api(pf.port, "/api/v1/auth/logout", token, method="POST")
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            return check("seed the pre-upgrade store (login + logout)", False, str(exc))

    # REDISCLI_AUTH, not `-a`: the password stays out of argv, as the StatefulSet itself is careful to do.
    r = kubectl(ctx, "exec", STORE_POD, "-n", NS, "-c", STORE_CONTAINER, "--", "sh", "-c",
                'export REDISCLI_AUTH="$REDIS_PASSWORD"; echo "keys=$(redis-cli DBSIZE)"; '
                'echo "save=$(redis-cli SAVE)"; echo "rdb=$(wc -c < /data/dump.rdb)"')
    got = dict(ln.split("=", 1) for ln in r.stdout.splitlines() if "=" in ln)
    keys = int(got["keys"]) if got.get("keys", "").strip().isdigit() else 0
    rdb = int(got["rdb"]) if got.get("rdb", "").strip().isdigit() else 0
    return check("the pre-upgrade store holds data and has saved it to its volume",
                 keys >= 1 and got.get("save", "").strip() == "OK" and rdb > 0,
                 f"{keys} key(s), SAVE {got.get('save', '?').strip()}, dump.rdb {rdb} bytes"
                 + ("" if r.returncode == 0 else f" — {r.stderr.strip()[-200:]}"))


def _candidate_store_image(chart: Path) -> str:
    out = run("helm", "template", "norviq", str(chart), "--set-json", f'policyQuotaNamespaces=["{TENANT}"]',
              "--show-only", "templates/redis-statefulset.yaml").stdout
    m = re.search(r'image:\s*"([^"]+)"', out)
    return m.group(1) if m else ""


def check_store_after_upgrade(ctx: str, chart: Path) -> None:
    """The store's pod must run the candidate's image, be Ready, and STAY up.

    Judged whether or not `helm upgrade` reported success. A store that exits on the old store's files is
    what makes `--wait` time out, and the timeout alone does not say why. In the live 0.2.5 -> 0.2.6 run
    the only line that did was in this pod's log: "Can't handle RDB format version 12".

    Sampled twice, STORE_STABLE_S apart. Both samples must be healthy, and the second must be the SAME pod
    (metadata.uid) running the SAME container (containerID) as the first. The container has no readiness
    probe, so it reads Ready the moment it starts, and a server that exits while loading its dump is briefly
    Ready between restarts. restartCount catches a container that restarted in place, but it starts again at
    0 on a new pod, so a store pod that was replaced inside the window (evicted, or deleted by a crash-looping
    StatefulSet's controller) looked healthy on restartCount alone; the uid and containerID catch it.
    """
    want = _candidate_store_image(chart)

    def sample() -> dict:
        r = kubectl(ctx, "get", "pod", STORE_POD, "-n", NS, "-o", "json")
        try:
            pod = json.loads(r.stdout)
        except json.JSONDecodeError:
            return {"ready": False, "image": "", "restarts": -1, "uid": "", "container": ""}
        cs = next((c for c in pod.get("status", {}).get("containerStatuses") or []
                   if c.get("name") == STORE_CONTAINER), {})
        image = next((c["image"] for c in pod["spec"]["containers"] if c["name"] == STORE_CONTAINER), "")
        return {"ready": bool(cs.get("ready")), "image": image, "restarts": int(cs.get("restartCount", 0)),
                "uid": pod.get("metadata", {}).get("uid", ""), "container": cs.get("containerID", "")}

    def healthy(s: dict) -> bool:
        return s["ready"] and s["image"] == want and s["restarts"] == 0

    wait_until(lambda: healthy(sample()), 120, interval=3)
    first = sample()
    time.sleep(STORE_STABLE_S)
    second = sample()
    same = first["uid"] == second["uid"] and first["container"] == second["container"]
    ok = bool(want) and healthy(first) and healthy(second) and same
    detail = f"{second['image'] or '?'} ready={second['ready']} restarts={second['restarts']}"
    if not same:
        detail += (f"; replaced within {STORE_STABLE_S}s (pod {first['uid'][:8] or '?'} -> {second['uid'][:8] or '?'}, "
                   f"container {first['container'][-12:] or '?'} -> {second['container'][-12:] or '?'})")
    if not ok:
        logs = kubectl(ctx, "logs", STORE_POD, "-n", NS, "-c", STORE_CONTAINER, "--previous", "--tail=4")
        if logs.returncode != 0:
            logs = kubectl(ctx, "logs", STORE_POD, "-n", NS, "-c", STORE_CONTAINER, "--tail=4")
        detail += f" (want {want or 'an image from the candidate chart'}) — " + " | ".join(
            ln.strip() for ln in logs.stdout.splitlines()[-4:])
    check("the store's pod runs the candidate image, is Ready, and was neither restarted nor replaced", ok, detail)


def _current_api_pods(ctx: str) -> list[str]:
    """API pods of the Deployment's CURRENT ReplicaSet, never an old one still draining.

    Matched on pod-template-hash of the ReplicaSet carrying the Deployment's own revision. A pod's phase
    or deletionTimestamp cannot tell an old pod from a new one in the moment between the old
    ReplicaSet's scale-down and the pod's removal, and an old pod answering /readyz is the false pass
    this check must not give.
    """
    def items(*args: str) -> list[dict]:
        try:
            return json.loads(kubectl(ctx, "get", *args, "-n", NS, "-o", "json").stdout).get("items") or []
        except json.JSONDecodeError:
            return []

    try:
        deploy = json.loads(kubectl(ctx, "get", "deploy", "norviq-api", "-n", NS, "-o", "json").stdout)
    except json.JSONDecodeError:
        return []
    revision = (deploy.get("metadata", {}).get("annotations") or {}).get("deployment.kubernetes.io/revision")
    hashes = {
        rs["metadata"]["labels"].get("pod-template-hash")
        for rs in items("rs", "-l", "app.kubernetes.io/component=api")
        if (rs["metadata"].get("annotations") or {}).get("deployment.kubernetes.io/revision") == revision
        and any(o.get("kind") == "Deployment" and o.get("name") == "norviq-api"
                for o in rs["metadata"].get("ownerReferences") or [])
    } - {None}
    return [p["metadata"]["name"] for p in items("pods", "-l", "app.kubernetes.io/component=api")
            if (p["metadata"].get("labels") or {}).get("pod-template-hash") in hashes
            and not p["metadata"].get("deletionTimestamp")]


def check_api_after_upgrade(ctx: str) -> None:
    """The API Deployment fully rolled out, and a pod of the NEW ReplicaSet saying on /readyz that it
    reaches the store.

    `kubectl rollout status` is the completion test. It waits for observedGeneration, updated, available
    and total replicas to agree, which means no old replica is still counted. The first version compared
    readyReplicas with updatedReplicas, which can agree while old pods still serve, and then picked any
    non-terminating API pod for /readyz, which could be an old one mid-rollout.
    """
    rollout = kubectl(ctx, "rollout", "status", "deployment/norviq-api", "-n", NS, "--timeout=180s",
                      timeout=240)
    rolled = rollout.returncode == 0
    payload: dict = {}
    pods = _current_api_pods(ctx) if rolled else []
    if pods:
        with _PortForward(ctx, pods[0], 18104) as pf:
            try:
                payload = _api(pf.port, "/readyz")
            except urllib.error.HTTPError as exc:  # 503 still carries the per-dependency payload
                try:
                    payload = json.loads(exc.read().decode())
                except (json.JSONDecodeError, OSError):
                    payload = {"status": f"HTTP {exc.code}"}
            except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
                payload = {"status": f"unreachable: {exc}"}
    last = (rollout.stdout or rollout.stderr).strip().splitlines()[-1:] or ["no output"]
    check("the API is Ready after the upgrade and reaches the store",
          rolled and bool(pods) and payload.get("redis") is True,
          f"rollout: {last[0][:160]}; /readyz on {pods[0] if pods else 'no current-revision pod'}: "
          f"{payload or 'not reached'}")


def snapshot(ctx: str) -> dict[str, str]:
    """State that MUST survive the upgrade, captured before it.

    The two secrets are the sharp ones. values.yaml promises they are generated once and then
    "reused, never rotated", and that is not a nicety: postgres only honours POSTGRES_PASSWORD when
    initdb runs on an empty data directory, so a regenerated password on upgrade leaves the API
    unable to open its own database — with the data still sitting there, intact and unreachable. The
    JWT secret is the same shape of problem for sessions. A template edit can break either silently,
    because a fresh install would still look perfect.
    """
    def secret(key: str) -> str:
        return kubectl(ctx, "get", "secret", "norviq-secrets", "-n", NS,
                       "-o", f"jsonpath={{.data.{key}}}").stdout.strip()

    def pvc_uids() -> str:
        return kubectl(ctx, "get", "pvc", "-n", NS, "-o",
                       "jsonpath={range .items[*]}{.metadata.name}:{.metadata.uid} {end}").stdout.strip()

    return {
        "pg_password": secret("NRVQ_PG_PASSWORD"),
        "api_secret": secret("NRVQ_API_SECRET_KEY"),
        "admin_password": secret("NRVQ_AUTH_ADMIN_PASSWORD"),
        "pvcs": pvc_uids(),
    }


def upgrade_to_candidate(ctx: str, chart: Path, webhook_image: str = "") -> bool:
    """--reset-then-reuse-values: the command the README and both runbooks tell operators to use."""
    extra: list[str] = []
    if webhook_image:
        tag = webhook_image.rpartition(":")[2]
        extra = ["--set", f"images.webhook.tag={tag}", "--set", "images.webhook.digest=",
                 "--set", "images.webhook.pullPolicy=IfNotPresent"]

    t0 = time.monotonic()
    res = helm(ctx, "upgrade", "norviq", str(chart), "-n", NS, "--reset-then-reuse-values",
               *extra, "--wait", "--timeout", "12m", timeout=900)
    ok = res.returncode == 0 and "STATUS: deployed" in res.stdout
    return check("helm upgrade --reset-then-reuse-values completes", ok,
                 f"{int(time.monotonic() - t0)}s" if ok else (res.stderr or res.stdout)[-400:])


def check_upgrade_preserved(ctx: str, chart: Path, before: dict[str, str]) -> None:
    after = snapshot(ctx)

    # Rotating either of these strands a working install: see snapshot()'s note. Compared by value,
    # never printed — these are live credentials even on a throwaway cluster.
    for key, what in [("pg_password", "the database password"),
                      ("api_secret", "the JWT signing secret"),
                      ("admin_password", "the admin password")]:
        check(f"upgrade reuses {what}", bool(before[key]) and before[key] == after[key],
              "" if before[key] == after[key] else "REGENERATED by the upgrade")

    check("datastore PVCs are the same volumes", bool(before["pvcs"]) and before["pvcs"] == after["pvcs"],
          "" if before["pvcs"] == after["pvcs"] else f"{before['pvcs']} -> {after['pvcs']}")

    # "Move all four image tags together" is a warning in getting-started because a partial upgrade
    # leaves the OLD policy enforcing while every version string reports the new one. Assert it
    # instead of warning about it: nothing may still be running an image the candidate does not pin.
    rendered = run("helm", "template", "norviq", str(chart), "--set-json",
                   f'policyQuotaNamespaces=["{TENANT}"]', "--set", "webhook.injection.enabled=true").stdout
    expected = set(re.findall(rf"{re.escape(REPO)}@sha256:[0-9a-f]{{64}}", rendered))
    running = set(re.findall(rf"{re.escape(REPO)}@sha256:[0-9a-f]{{64}}",
                             kubectl(ctx, "get", "pods", "-n", NS, "-o",
                                     "jsonpath={range .items[*]}{range .spec.containers[*]}{.image} {end}{end}").stdout))
    stale = running - expected
    check("no pod is left on a pre-upgrade image", not stale, f"{sorted(stale)[:2]}")

    r = kubectl(ctx, "get", "nrvqpolicy", POLICY, "-n", TENANT, "-o",
                "jsonpath={.metadata.name} {.metadata.finalizers}")
    check("the tenant policy survives the upgrade", POLICY in r.stdout, r.stdout.strip() or "GONE")


# ---------------------------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cluster", default="nrvq-verify")
    ap.add_argument("--version", default="", help="version to stamp (default: the repo's own)")
    ap.add_argument("--webhook-image", default="",
                    help="a locally built webhook image (already `kind load`ed) to run INSTEAD of the "
                         "pinned one. The rest of the chart stays digest-pinned, so this tests a "
                         "candidate webhook against the sidecar image a real release would inject.")
    ap.add_argument("--upgrade-from", default="auto", metavar="VERSION",
                    help="Verify the UPGRADE path instead of a fresh install: install this published "
                         "version from OCI, seed state, then upgrade to the candidate. 'auto' (the "
                         "default) picks the newest release published to the chart registry that is <= "
                         "the candidate, equal included, and FAILS if there is none; 'none' runs the "
                         "fresh-install path only.")
    ap.add_argument("--keep", action="store_true", help="leave the cluster up for debugging")
    ap.add_argument("--skip-create", action="store_true", help="reuse an existing cluster")
    args = ap.parse_args()

    for tool in ("kind", "helm", "kubectl", "docker"):
        if not shutil.which(tool):
            print(f"missing required tool: {tool}", file=sys.stderr)
            return 2

    version = args.version
    if not version:
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_release_versions as chk  # noqa: PLC0415

        version = chk.collect()["helm/norviq/Chart.yaml:version"]

    # Resolved before any cluster exists: a run that cannot name what it upgrades from should fail in
    # seconds, not after building a cluster to run a different test in.
    try:
        from_version = resolve_upgrade_source(args.upgrade_from, version)
    except UpgradeSourceError as exc:
        print(f"\nFAIL  --upgrade-from {args.upgrade_from}: {exc}", file=sys.stderr)
        return 1

    ctx = f"kind-{args.cluster}"
    print(f"\nverifying the RELEASE ARTIFACT for {version} in kind cluster {args.cluster}")
    print(f"path: upgrade from the published {from_version}\n" if from_version
          else "path: fresh install (--upgrade-from none)\n")

    if not args.skip_create:
        run("kind", "delete", "cluster", "--name", args.cluster, timeout=300)
        r = run("kind", "create", "cluster", "--name", args.cluster, timeout=600)
        if r.returncode != 0:
            print(r.stderr[-1000:], file=sys.stderr)
            return 2

    try:
        with tempfile.TemporaryDirectory() as td:
            print("stage 1 — stamp the chart as a release would")
            chart = stamp(version, Path(td))
            check_stamped_shape(ctx, chart)

            if from_version:
                # The upgrade path REPLACES the fresh install rather than running after it: a release
                # is installed fresh by new users and upgraded into by every existing one, and the
                # second is the larger population the moment a version ships. Fresh install is still
                # covered on demand with --upgrade-from none, and by the N-1 install below, which is
                # itself a fresh install of a published chart.
                print(f"\nstage 2 — install {from_version}, the release users are upgrading FROM")
                started = install_published(ctx, from_version)
                if started:
                    create_tenant_policy(ctx)
                    seed_bundled_store(ctx)
                    before = snapshot(ctx)
                    print(f"\nstage 2u — upgrade {from_version} -> {version}")
                    started = upgrade_to_candidate(ctx, chart, args.webhook_image)
                    # Run whether or not the upgrade reported success: when it times out, these are
                    # the checks that say which component did not come back, and why.
                    check_store_after_upgrade(ctx, chart)
                    check_api_after_upgrade(ctx)
                    if started:
                        check_upgrade_preserved(ctx, chart, before)
            else:
                print("\nstage 2 — install it the way automation does")
                started = install(ctx, chart, args.webhook_image)

            if started:
                print("\nstage 3 — use it")
                check_injection(ctx)
                token = check_enforcement(ctx)
                if token:
                    check_replica_propagation(ctx, token)
                check_helm_test(ctx)

                print("\nstage 4 — remove it")
                check_uninstall(ctx)
            else:
                print("  (install failed — later stages skipped)")
    finally:
        if not args.keep:
            run("kind", "delete", "cluster", "--name", args.cluster, timeout=300)

    failed = [(n, d) for n, ok, d in results if not ok]
    print(f"\n{'=' * 78}\n{len(results) - len(failed)}/{len(results)} checks passed")
    for name, detail in failed:
        print(f"  FAIL  {name}" + (f" — {detail}" if detail else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
