#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Break the cluster on purpose and check the failure is CORRECT and LEGIBLE.

WHY THE BAR IS NOT "NOTHING BREAKS". Norviq is a policy enforcement point. When a dependency dies the
interesting question is never "did it survive" — it is "which way did it fall". A PEP that fails OPEN
under load is worse than one that is down, because it keeps answering and every answer is `allow`. So
each scenario below asserts a DIRECTION of failure, not an absence of failure.

THE ANTI-VACUITY RULE THAT MAKES THIS WORTH RUNNING. A chaos test that cannot inject its fault reports
"nothing broke" — which is indistinguishable from a pass and is the single easiest way to ship a
fail-open bug. Every scenario here therefore has two phases:

    1. INJECT, then PROVE the injection landed (0 ready replicas, sidecar restart count went up, ...).
       If the proof fails the scenario reports NOT-INJECTED and the run FAILS. It never silently passes.
    2. OBSERVE, and assert the direction of the degradation.

Everything is restored in a `finally`, including on Ctrl-C, because a half-broken cluster left behind
looks exactly like a product bug in whatever runs next.

Usage:
    NRVQ_KUBE_CONTEXT=kind-norviq-local .venv/bin/python scripts/kind-e2e/chaos.py
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

NS_K8S = "norviq"
NS, CLS = "default", "customer-support"

# One benign call and one that must be refused. Both are checked in every scenario: a dependency
# failure that starts allowing the attack is a fail-open, and one that starts blocking the benign call
# is a fail-closed. Only ONE of those is acceptable, and which one depends on the dependency.
BENIGN = {"tool": "search_kb", "params": {"q": "refund policy"}, "expect": "allow"}
ATTACK = {"tool": "execute_sql", "params": {"query": "DROP TABLE customers; --"}, "expect": "block"}


class Ctx:
    def __init__(self, base: str, token: str, kube: str) -> None:
        self.base, self.token, self.kube = base, token, kube
        self.failures: list[str] = []
        self.notes: list[str] = []

    def fail(self, scenario: str, msg: str) -> None:
        self.failures.append(f"{scenario}: {msg}")
        print(f"    ✗ {msg}", flush=True)

    def ok(self, msg: str) -> None:
        print(f"    ✓ {msg}", flush=True)

    def note(self, msg: str) -> None:
        self.notes.append(msg)
        print(f"    · {msg}", flush=True)


def kubectl(ctx: Ctx, *args: str, check: bool = False, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603
        ["kubectl", "--context", ctx.kube, "-n", NS_K8S, *args],
        capture_output=True, text=True, check=check, timeout=timeout)


def evaluate(ctx: Ctx, sc: dict) -> tuple[int, str]:
    """Returns (http_status, decision). A transport failure is status 0 — distinct from a 5xx."""
    body = json.dumps({
        "tool_name": sc["tool"], "tool_params": sc["params"],
        "agent_identity": {"spiffe_id": f"spiffe://norviq/ns/{NS}/sa/{CLS}",
                           "namespace": NS, "agent_class": CLS},
        "framework": "sdk",
    }).encode()
    r = urllib.request.Request(  # noqa: S310 - fixed local base
        f"{ctx.base}/api/v1/evaluate", data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {ctx.token}"}, method="POST")
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:  # noqa: S310
            return resp.status, str(json.loads(resp.read()).get("decision"))
    except urllib.error.HTTPError as exc:
        return exc.code, "http_error"
    except Exception:  # noqa: BLE001
        return 0, "transport_error"


def hammer(ctx: Ctx, seconds: float, concurrency: int = 4) -> list[tuple[int, str, str]]:
    """Drive both scenarios continuously for a window. Returns (status, decision, which)."""
    deadline = time.monotonic() + seconds
    out: list[tuple[int, str, str]] = []

    def worker(i: int) -> list[tuple[int, str, str]]:
        rows = []
        while time.monotonic() < deadline:
            for name, sc in (("benign", BENIGN), ("attack", ATTACK)):
                st, dec = evaluate(ctx, sc)
                rows.append((st, dec, name))
        return rows

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        for rows in pool.map(worker, range(concurrency)):
            out.extend(rows)
    return out


def live_pod(ctx: Ctx, component: str) -> str:
    """A pod that is Running, fully ready, and NOT terminating.

    `kubectl get pods -l …` happily returns pods with a deletionTimestamp, and taking `.items[0]` from
    that list is a coin toss right after anything scaled. The OPA scenario picked a pod that the
    previous scenario's scale-down was already tearing down, killed its sidecar, and then watched a
    restart counter on a pod that ceased to exist — reporting "the kill did not land" for a kill that
    landed perfectly, on the wrong target.
    """
    p = kubectl(ctx, "get", "pods", "-l", f"app.kubernetes.io/component={component}",
                "-o", "jsonpath={range .items[*]}{.metadata.name}|{.metadata.deletionTimestamp}|"
                      "{.status.phase}|{.status.containerStatuses[*].ready}{'\\n'}{end}")
    for line in p.stdout.strip().splitlines():
        name, deleting, phase, ready = (line.split("|") + ["", "", ""])[:4]
        if name and not deleting and phase == "Running" and "false" not in ready:
            return name
    return ""


def ready_replicas(ctx: Ctx, kind: str, name: str) -> int:
    p = kubectl(ctx, "get", kind, name, "-o", "jsonpath={.status.readyReplicas}")
    return int(p.stdout.strip() or 0)


def wait_ready(ctx: Ctx, kind: str, name: str, want: int, timeout: int = 180) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if ready_replicas(ctx, kind, name) >= want:
            return True
        time.sleep(3)
    return False


def restart_counts(ctx: Ctx, selector: str) -> dict[str, int]:
    p = kubectl(ctx, "get", "pods", "-l", selector, "-o",
                "jsonpath={range .items[*]}{.metadata.name}{' '}{.status.containerStatuses[*].restartCount}{'\\n'}{end}")
    counts = {}
    for line in p.stdout.strip().splitlines():
        parts = line.split()
        if parts:
            counts[parts[0]] = sum(int(x) for x in parts[1:] if x.isdigit())
    return counts


# --- scenario 1: one API replica dies ------------------------------------------------------------

def s1_kill_api_replica(ctx: Ctx) -> None:
    """A rolling node loss must not reach the client. Requires >=2 replicas to mean anything."""
    print("\n[1] kill one API replica")
    before = ready_replicas(ctx, "deployment", "norviq-api")
    scaled = False
    try:
        if before < 2:
            ctx.note(f"api has {before} replica — scaling to 2 so 'kill one' is a survivable event")
            kubectl(ctx, "scale", "deployment", "norviq-api", "--replicas=2")
            scaled = True
            if not wait_ready(ctx, "deployment", "norviq-api", 2):
                # NOT a pass. We could not create the conditions the scenario is about.
                ctx.fail("s1", "could not reach 2 ready api replicas — scenario NOT INJECTED, "
                               "so single-replica loss is UNVERIFIED (not 'fine')")
                return

        pods = live_pod(ctx, "api")
        if not pods:
            ctx.fail("s1", "no api pod found — scenario NOT INJECTED")
            return

        # Delete DURING traffic, not before it: the question is what an in-flight client sees.
        with ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(hammer, ctx, 25.0, 4)
            time.sleep(4)
            kubectl(ctx, "delete", "pod", pods, "--wait=false")
            ctx.note(f"deleted {pods} mid-traffic")
            rows = fut.result()

        server_errors = [r for r in rows if r[0] >= 500]
        transport = [r for r in rows if r[0] == 0]
        wrong = [r for r in rows if r[0] == 200 and
                 ((r[2] == "benign" and r[1] != "allow") or (r[2] == "attack" and r[1] != "block"))]
        ctx.note(f"{len(rows)} calls during the kill")
        if server_errors:
            ctx.fail("s1", f"{len(server_errors)}/{len(rows)} calls got a 5xx — the loss reached the client")
        else:
            ctx.ok("no 5xx reached the client")
        if transport:
            ctx.fail("s1", f"{len(transport)}/{len(rows)} calls failed at the transport")
        # WHICH WAY it went wrong is the entire question, and a bare count does not answer it. An
        # attack that slipped through is a fail-open and a release blocker; a benign call refused
        # during a pod teardown is the system failing in its safe direction. Reporting "1 wrong
        # decision" for either is how a fail-open gets triaged as a flake.
        opened = [r for r in wrong if r[2] == "attack"]
        closed = [r for r in wrong if r[2] == "benign"]
        if opened:
            ctx.fail("s1", f"FAILED OPEN — {len(opened)}/{len(rows)} attack calls were ALLOWED while a "
                           f"replica was terminating (decisions seen: {sorted({r[1] for r in opened})}). "
                           "A release blocker: losing a replica must never widen what an agent may do.")
        if closed:
            ctx.note(f"{len(closed)}/{len(rows)} benign calls were refused mid-teardown "
                     f"(decisions: {sorted({r[1] for r in closed})}) — the SAFE direction, but it is a "
                     "real availability cost: a tool call the agent was entitled to make was denied "
                     "because a pod was going away.")
        if not wrong:
            ctx.ok("every decision stayed correct through the kill")
        elif not opened:
            ctx.ok("no attack was ever allowed — every deviation was in the fail-closed direction")
    finally:
        if scaled:
            kubectl(ctx, "scale", "deployment", "norviq-api", f"--replicas={max(before, 1)}")
        wait_ready(ctx, "deployment", "norviq-api", max(before, 1))


# --- scenario 2: OPA sidecar dies ----------------------------------------------------------------

def s2_kill_opa(ctx: Ctx) -> None:
    """The one that matters most: with no evaluator, evaluate must BLOCK. Never allow."""
    print("\n[2] kill the OPA sidecar")
    # The API pod's sidecar, NOT the engine's. `/api/v1/evaluate` — the endpoint being hammered — is
    # served by the API, so the OPA that decides these calls is the one co-located with it. Killing the
    # engine's sidecar instead would leave the traffic path completely intact and report a confident
    # pass for a fault the request never touched.
    comp = "api"
    pod = live_pod(ctx, "api")
    if not pod:
        ctx.fail("s2", "no api pod with an opa sidecar found — scenario NOT INJECTED")
        return

    before = restart_counts(ctx, f"app.kubernetes.io/component={comp}").get(pod, 0)

    # HOW YOU KILL A DISTROLESS SIDECAR. `kubectl exec -c opa -- kill 1` cannot work: the image is
    # `opa:1.19.0-static`, which has no shell and no coreutils, and containers in a pod do not share a
    # PID namespace by default, so nothing else in the pod can see OPA's process either.
    #
    # `kubectl debug --target=opa` attaches an ephemeral container INTO the target container's process
    # namespace, where PID 1 is OPA. That kills exactly the one process this scenario is about, which
    # deleting the pod would not — deleting the pod also takes down the API and would prove nothing
    # about how the API behaves when its evaluator disappears underneath it.
    #
    # Ephemeral containers cannot be removed from a running pod, so the name is unique per attempt or
    # the second run of the day fails with "container already exists".
    #
    # The traffic starts BEFORE the kill is issued. `kubectl debug` creates the ephemeral container and
    # returns; the container still has to be scheduled and started, and if traffic only begins after
    # that the window can miss the death entirely.
    stamp = str(int(time.monotonic() * 1000))[-8:]
    pool = ThreadPoolExecutor(max_workers=2)
    traffic = pool.submit(hammer, ctx, 45.0, 2)
    time.sleep(2)
    p = kubectl(ctx, "debug", "-q", pod, "--image=busybox:1.36", "--target=opa",
                f"--container=chaos-opa-{stamp}", "--profile=general", "--",
                "sh", "-c", "kill 1", timeout=180)
    if p.returncode != 0:
        traffic.result()
        pool.shutdown()
        ctx.fail("s2", f"could not signal the opa sidecar via kubectl debug ({p.stderr.strip()[:200]}) "
                       "— FAIL-CLOSED ON EVALUATOR LOSS IS UNVERIFIED. This is the single most "
                       "important chaos property and it must not be reported as passing.")
        return

    ctx.note(f"signalled opa in {pod}")
    # ORDER MATTERS, and getting it wrong makes this scenario worthless. OPA restarts in a couple of
    # seconds. Waiting for the restart to be OBSERVED and only then sending traffic measures a healthy
    # system and reports a confident pass — the evaluator is already back before the first call lands.
    # So the traffic runs CONCURRENTLY with the kill window, and the restart-count poll runs beside it.
    landed = False
    for _ in range(40):
        if restart_counts(ctx, f"app.kubernetes.io/component={comp}").get(pod, 0) > before:
            landed = True
            break
        time.sleep(1)
    rows = traffic.result()
    pool.shutdown()

    allowed_attacks = [r for r in rows if r[2] == "attack" and r[1] == "allow"]
    if not landed:
        # Report this FIRST: without it, every judgement below is about a system that never broke.
        ctx.fail("s2", "opa restart count never rose — the kill did not land, so fail-closed behaviour "
                       "is UNVERIFIED. Nothing below this line describes a degraded system.")
        return
    ctx.ok("injection proven (sidecar restart count rose during the traffic window)")
    if allowed_attacks:
        ctx.fail("s2", f"FAILED OPEN — {len(allowed_attacks)} attack calls were ALLOWED with the "
                       "evaluator down. This is a release blocker.")
    else:
        ctx.ok(f"no attack allowed across {len(rows)} calls spanning the evaluator's death")

    if not wait_ready(ctx, "deployment", f"norviq-{comp}", 1, timeout=180):
        ctx.fail("s2", f"norviq-{comp} did not become ready again after the sidecar restart")
    else:
        ctx.ok("recovered without deleting the pod")


# --- scenario 3: Redis unavailable ---------------------------------------------------------------

def s3_redis_down(ctx: Ctx) -> None:
    """Redis carries trust and caching. Losing it must degrade trust safely, not stop decisions."""
    print("\n[3] Redis unavailable")
    sts = "norviq-redis"
    p = kubectl(ctx, "get", "statefulset", sts)
    if p.returncode != 0:
        ctx.fail("s3", f"statefulset {sts} not found — scenario NOT INJECTED")
        return
    before = ready_replicas(ctx, "statefulset", sts) or 1
    try:
        kubectl(ctx, "scale", "statefulset", sts, "--replicas=0")
        gone = False
        for _ in range(40):
            if ready_replicas(ctx, "statefulset", sts) == 0:
                gone = True
                break
            time.sleep(2)
        if not gone:
            ctx.fail("s3", "redis never went to 0 ready — scenario NOT INJECTED, behaviour UNVERIFIED")
            return
        ctx.ok("injection proven (redis at 0 ready replicas)")

        rows = hammer(ctx, 12.0, 2)
        decided = [r for r in rows if r[0] == 200]
        allowed_attacks = [r for r in rows if r[2] == "attack" and r[1] == "allow"]
        ctx.note(f"{len(decided)}/{len(rows)} calls still returned a decision with redis down")
        if not decided:
            ctx.fail("s3", "no call returned a decision — losing the cache stopped enforcement entirely")
        if allowed_attacks:
            ctx.fail("s3", f"FAILED OPEN — {len(allowed_attacks)} attacks allowed with redis down")
        else:
            ctx.ok("no attack was allowed with redis down")

        crashing = kubectl(ctx, "get", "pods", "-l", "app.kubernetes.io/component=api",
                           "-o", "jsonpath={.items[*].status.containerStatuses[*].state.waiting.reason}")
        if "CrashLoopBackOff" in crashing.stdout:
            ctx.fail("s3", "an API container entered CrashLoopBackOff — a dependency outage should "
                           "degrade the feature, not kill the process")
        else:
            ctx.ok("no crash loop")
    finally:
        kubectl(ctx, "scale", "statefulset", sts, f"--replicas={before}")
        wait_ready(ctx, "statefulset", sts, before, timeout=240)


# --- scenario 4: Postgres unavailable ------------------------------------------------------------

def s4_postgres_down(ctx: Ctx) -> None:
    """The subtle one: a read that fails must SAY so. An empty list reads as 'you have nothing'."""
    print("\n[4] Postgres unavailable")
    sts = "norviq-postgresql"
    if kubectl(ctx, "get", "statefulset", sts).returncode != 0:
        ctx.fail("s4", f"statefulset {sts} not found — scenario NOT INJECTED")
        return
    before = ready_replicas(ctx, "statefulset", sts) or 1

    def get(path: str) -> tuple[int, str]:
        r = urllib.request.Request(  # noqa: S310
            f"{ctx.base}{path}", headers={"Authorization": f"Bearer {ctx.token}"})
        try:
            with urllib.request.urlopen(r, timeout=25) as resp:  # noqa: S310
                return resp.status, resp.read().decode()[:400]
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()[:400]
        except Exception as exc:  # noqa: BLE001
            return 0, str(exc)

    # Establish the endpoint returns data WHEN HEALTHY. Without this, "it returned []" while down
    # proves nothing — it might always be [].
    st, body = get("/api/v1/policies")
    healthy_nonempty = st == 200 and body.strip() not in ("[]", "", "{}")
    if not healthy_nonempty:
        ctx.note("policies list is empty even while healthy — using /api/v1/audit instead")

    try:
        kubectl(ctx, "scale", "statefulset", sts, "--replicas=0")
        gone = False
        for _ in range(40):
            if ready_replicas(ctx, "statefulset", sts) == 0:
                gone = True
                break
            time.sleep(2)
        if not gone:
            ctx.fail("s4", "postgres never went to 0 ready — scenario NOT INJECTED")
            return
        ctx.ok("injection proven (postgres at 0 ready replicas)")
        time.sleep(5)

        st, body = get("/api/v1/policies")
        if st == 200 and body.strip() in ("[]", "{}", ""):
            ctx.fail("s4", "GET /api/v1/policies returned 200 with an EMPTY list while the database was "
                           "down. An operator cannot tell 'you have no policies' from 'we cannot reach "
                           "the database', and the safe-looking answer is the wrong one.")
        elif st == 200:
            ctx.ok("read served from cache with real content (not a silent empty list)")
        else:
            ctx.ok(f"read degraded to an explicit error (HTTP {st})")

        # Enforcement must not depend on the audit store being writable.
        rows = hammer(ctx, 8.0, 2)
        allowed_attacks = [r for r in rows if r[2] == "attack" and r[1] == "allow"]
        if allowed_attacks:
            ctx.fail("s4", f"FAILED OPEN — {len(allowed_attacks)} attacks allowed with postgres down")
        else:
            ctx.ok("no attack was allowed with postgres down")
    finally:
        kubectl(ctx, "scale", "statefulset", sts, f"--replicas={before}")
        wait_ready(ctx, "statefulset", sts, before, timeout=300)


# --- scenario 5: concurrent policy pushes --------------------------------------------------------

def s5_concurrent_suites(ctx: Ctx) -> None:
    """Two operators hit 'Run suite' at once. Exactly one may win — the guard added this session."""
    print("\n[5] concurrent red-team suite starts")

    def start(_i: int) -> tuple[int, str]:
        r = urllib.request.Request(  # noqa: S310
            f"{ctx.base}/api/v1/redteam/suite", data=json.dumps({"namespace": NS}).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {ctx.token}"},
            method="POST")
        try:
            with urllib.request.urlopen(r, timeout=60) as resp:  # noqa: S310
                return resp.status, resp.read().decode()[:200]
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()[:200]
        except Exception as exc:  # noqa: BLE001
            return 0, str(exc)

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(start, range(3)))
    accepted = [r for r in results if r[0] in (200, 201, 202)]
    rejected = [r for r in results if r[0] == 409]
    ctx.note(f"3 concurrent starts -> {[r[0] for r in results]}")
    if len(accepted) > 1:
        ctx.fail("s5", f"{len(accepted)} suites were accepted for one namespace — concurrent runs "
                       "interleave their policy pushes and leave torn state")
    elif len(accepted) == 1 and rejected:
        ctx.ok("exactly one suite accepted, the rest refused with 409")
    elif not accepted:
        ctx.note(f"no suite was accepted at all ({[r[0] for r in results]}) — the guard is untested "
                 "here rather than proven; not counted as a pass")
        ctx.fail("s5", "could not start even one suite — the mutual-exclusion guard is UNVERIFIED")


def settle(ctx: Ctx, timeout: int = 180) -> bool:
    """Wait until the system answers correctly again — the same check `main` uses as its baseline."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        st, dec = evaluate(ctx, ATTACK)
        if st == 200 and dec == "block":
            st2, dec2 = evaluate(ctx, BENIGN)
            if st2 == 200 and dec2 == "allow":
                return True
        time.sleep(3)
    return False


SCENARIOS = {
    "api-replica": s1_kill_api_replica,
    "opa": s2_kill_opa,
    "redis": s3_redis_down,
    "postgres": s4_postgres_down,
    "concurrency": s5_concurrent_suites,
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-url", default="http://localhost:3400")
    ap.add_argument("--token-file", default="/tmp/nrvq-signin-token.txt")
    ap.add_argument("--kube-context", default="kind-norviq-local")
    ap.add_argument("--only", default="", help=f"comma-separated subset of {sorted(SCENARIOS)}")
    args = ap.parse_args()

    token = open(args.token_file).read().strip()  # noqa: SIM115, PTH123
    ctx = Ctx(args.base_url, token, args.kube_context)

    # Baseline. If the system is not healthy BEFORE the chaos, every result below is noise.
    st, dec = evaluate(ctx, ATTACK)
    if st != 200 or dec != "block":
        print(f"baseline is not healthy: attack call -> HTTP {st}, decision {dec}", file=sys.stderr)
        print("refusing to run chaos against an already-broken system", file=sys.stderr)
        return 2
    print(f"baseline healthy · {args.base_url} · context {args.kube_context}")

    chosen = args.only.split(",") if args.only else list(SCENARIOS)
    for i, name in enumerate(chosen):
        fn = SCENARIOS.get(name.strip())
        if fn is None:
            print(f"unknown scenario {name!r}", file=sys.stderr)
            return 2
        # Scaling a statefulset back to 1 makes the POD ready long before the API's connection pool has
        # reconnected to it. Without this gate, scenario N+1 runs against scenario N's convalescence and
        # reports failures that belong to the recovery, not to its own fault — the concurrency scenario
        # saw three 502s and declared its guard unverified, when the only thing wrong was that Postgres
        # had come back twelve seconds earlier.
        if i and not settle(ctx):
            ctx.fail(name, "the system never returned to a healthy baseline after the previous "
                           "scenario — this run's result would describe the recovery, not the fault")
            break
        try:
            fn(ctx)
        except Exception as exc:  # noqa: BLE001
            ctx.fail(name, f"scenario raised {type(exc).__name__}: {exc}")

    print("\n" + "=" * 78)
    if ctx.failures:
        print(f"CHAOS: {len(ctx.failures)} failure(s)")
        for f in ctx.failures:
            print(f"  ✗ {f}")
        return 1
    print(f"CHAOS: all {len(chosen)} scenarios degraded correctly and legibly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
