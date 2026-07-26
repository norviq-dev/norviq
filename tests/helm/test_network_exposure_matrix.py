# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""What is listening, and who can reach it? — an enforced, enumerated exposure matrix.

Norviq shipped ``--addr=0.0.0.0:8181`` on both OPA sidecars: OPA's admin API is unauthenticated AND
read-WRITE, so any pod in the cluster could have deleted the policy that governs it. Every auth test we
had probed from OUTSIDE through the API Service (which correctly 401s); :8181 is fronted by no Service at
all, so nothing outside-in could ever see it. The missing question was never "does this endpoint 401?" but
"what ports exist in this chart, what address does each one bind, and which of them can a hostile pod
dial?" — nobody had ever enumerated that.

This module answers it structurally instead of per-endpoint. It renders the chart locally (``helm
template``, several value profiles so the optional components are covered too), enumerates EVERY listening
surface it can see — bind flags (``--addr/--bind/--host/--listen``) in container commands/args, every
``containerPort``, every Service port — and demands that each one is either:

  (a) proven loopback-bound (127.0.0.1 / localhost / ::1) by an explicit bind flag, or
  (b) present in the EXPOSED_SURFACES allow-list below, WITH a written reason saying who can reach it
      and what stops them.

The class of bug this catches is therefore not "OPA binds 0.0.0.0" (a sibling module pins that one
specifically) but the general one that hid it: a NEW listener — a new component, a new sidecar, a new
Service port, a debug/metrics endpoint — silently becoming pod-to-pod reachable with nobody having
consciously decided it should be. Such a surface fails here with a message telling the author to justify
it in the allow-list or bind it to loopback.

Deliberately NOT reported: raw argv tokens. Container args contain credentials (e.g. redis
``--requirepass``), and this test's failure text lands in CI logs, so findings name the container and the
offending literal only.

Skipped (not failed) when the `helm` binary isn't on PATH, so the suite still runs in minimal envs.
"""

from __future__ import annotations

import functools
import pathlib
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Iterator

import pytest
import yaml

_CHART = pathlib.Path(__file__).resolve().parents[2] / "helm" / "norviq"

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm binary not on PATH")


# --- render profiles ------------------------------------------------------------------------------
#
# The matrix must see the OPTIONAL components too: a listener that only renders behind a feature flag is
# exactly the kind that escapes review. "default" is a stock install; "optional" turns on everything that
# ADDS a workload or a Service (fleet hub, sidecar injection, ingress, otel, the SPIFFE CSI volume).
# The HA datastore flags are intentionally NOT set — they REPLACE the in-chart StatefulSets with operator
# CRs (CloudNativePG / RedisFailover), which carry no pod spec this test could inspect, and would only
# shrink the matrix. (Those operators own their own exposure; see the note in postgresql-ha.yaml.)
#
# The fleet values below are render-time placeholders, not credentials: the chart's requireStrongSecret
# guard refuses to render the fleet hub while the shipped default password is still in place.
_NAMESPACES = ["--set", "policyQuotaNamespaces={default,chatbot-prod}"]

_PROFILES: dict[str, list[str]] = {
    "default": [],
    "optional": [
        "--set", "fleet.hub.enabled=true",
        "--set", "fleet.hub.postgresql.password=render-only-placeholder",
        "--set", "fleet.hub.pgUrl=postgresql://norviq:render-only-placeholder@fleet-postgresql:5432/norviq_fleet",
        "--set", "webhook.injection.enabled=true",
        "--set", "ingress.enabled=true",
        "--set", "otel.enabled=true",
        # enabling trace export now requires a collector endpoint (chart fails the render otherwise)
        "--set", "otel.endpoint=http://otel-collector:4317",
        "--set", "config.spiffeCsi.enabled=true",
    ],
}


# --- the allow-list: every intentionally cluster-reachable surface, and WHY --------------------------
#
# Keys are the stable surface ids produced by _surfaces() below:
#   "<workload>/<container>:<port>"  — a process listening inside a pod
#   "Service/<name>:<port>"          — a port any pod in the cluster can dial by name
# A surface missing from here fails the matrix. An entry here that no profile renders any more also fails
# (test_allow_list_has_no_stale_entries), so the list cannot rot into a rubber stamp.
EXPOSED_SURFACES: dict[str, str] = {
    # -- control-plane API -------------------------------------------------------------------------
    "norviq-api/api:8080": (
        "The product's own API. Authenticated: every route requires a bearer token (session JWT, OIDC "
        "token or API key) and 401s without one; login is rate-limited/lockout-protected. This is the "
        "one surface the whole system is designed to expose."
    ),
    "Service/norviq-api:8080": (
        "Fronts norviq-api/api:8080 — the console, the webhook controller and every injected sidecar "
        "reach the control plane through this name. Same auth as above."
    ),
    "norviq-api/tls-proxy:8443": (
        "nginx terminator for zero-touch internal TLS (config.internalTls). Serves the CA-signed API "
        "cert and requires a client cert minted by the same internal CA (mTLS), so an un-enrolled pod "
        "gets a handshake failure, not a request."
    ),
    "Service/norviq-api:8443": (
        "Fronts norviq-api/tls-proxy:8443 — the mTLS entrypoint injected sidecars use. Client-cert gated."
    ),
    # -- evaluator ---------------------------------------------------------------------------------
    "norviq-engine/engine:8282": (
        "Sidecar HTTP fallback (POST /v1/evaluate) run as a standalone evaluator Deployment. ADVISORY "
        "ONLY: it returns forward/drop for a submitted tool call and can neither read nor mutate policy, "
        "and it fails CLOSED (drop) on any malformed input. NOTE (accepted residual risk, tracked): it "
        "performs no caller authentication, so a pod that dials it can obtain decisions and append "
        "audit/trust events under the ENGINE's own identity. Justified only because the blast radius is "
        "advisory; re-justify (or require the service JWT / drop the Service) before widening it."
    ),
    "Service/norviq-engine:8282": (
        "Fronts norviq-engine/engine:8282. Cluster-reachable by name — see the residual-risk note above; "
        "nothing in the chart consumes this Service, so removing it is the cheaper fix if that risk grows."
    ),
    # -- console -----------------------------------------------------------------------------------
    "norviq-ui/ui:8080": (
        "nginx serving the static console bundle. Ships no data of its own: every byte the console "
        "renders comes from an authenticated call to norviq-api, and it proxies /api/* there."
    ),
    "Service/norviq-ui:80": (
        "Fronts norviq-ui/ui:8080 — the console entrypoint for the Ingress and for a port-forward. "
        "Serves static assets only; the data behind them is gated by the API's auth."
    ),
    # -- admission webhook -------------------------------------------------------------------------
    "norviq-webhook/webhook:8443": (
        "MutatingWebhook server. TLS-only, and the only client that ever calls it is the kube-apiserver "
        "via the MutatingWebhookConfiguration clientConfig; a request from anywhere else is an AdmissionReview "
        "the server rejects. The reachability that matters here (apiserver -> webhook) is mandatory: with "
        "failurePolicy=Fail, blocking it stops pod creation in injected namespaces."
    ),
    "Service/norviq-webhook:443": "The clientConfig target the apiserver dials. TLS + caBundle-pinned.",
    # -- datastores (in-chart, single-node/dev topology) -------------------------------------------
    "norviq-postgresql/postgresql:5432": (
        "Postgres. Password-authenticated, credentials only in norviq-secrets, and the server listens on "
        "the pod network because the api/engine pods must reach it — there is no loopback option for a "
        "cross-pod datastore. Bound further by agentEgressPolicy (agent pods may not dial it in the "
        "default proxy sidecar mode)."
    ),
    "Service/norviq-postgresql:5432": (
        "Fronts the Postgres StatefulSet — the DSN the API and engine connect with. Password-gated, and "
        "no other in-chart component resolves this name."
    ),
    "norviq-redis/redis:6379": (
        "Redis, started with --requirepass so an unauthenticated dial gets NOAUTH. Same cross-pod "
        "argument as Postgres; also covered by agentEgressPolicy."
    ),
    "Service/norviq-redis:6379": (
        "Fronts the Redis StatefulSet — the decision-cache and trust-store endpoint for the API and "
        "engine. Every connection must AUTH with the requirepass credential."
    ),
    # -- fleet hub (optional, multi-cluster) --------------------------------------------------------
    "norviq-fleet-api/fleet-api:8080": (
        "Fleet hub API (optional, fleet.hub.enabled). Validates the SAME bearer tokens as the spoke API "
        "(OIDC/HS256 via norviq-secrets + norviq-fleet-config), so it 401s without one. It binds "
        "0.0.0.0 by construction: spoke clusters dial it from outside this pod."
    ),
    "Service/norviq-fleet-api:8080": "Fronts the fleet hub API; the endpoint spoke clusters register against.",
    "fleet-postgresql/postgresql:5432": (
        "The fleet hub's own Postgres, separate from the spoke store. Password-authenticated, and the "
        "chart refuses to render it while the shipped default credential is still set."
    ),
    "Service/fleet-postgresql:5432": (
        "Fronts the fleet hub Postgres StatefulSet — the DSN in norviq-fleet-config. Password-gated, and "
        "only rendered when the optional fleet hub is enabled."
    ),
}

# Containers permitted to carry a literal 0.0.0.0 in their command/args, keyed "<workload>/<container>".
# This is deliberately separate from (and much narrower than) EXPOSED_SURFACES: a wildcard bind is the
# specific mistake that shipped, so it must be argued for by itself, not inherited from "port 8080 is fine".
WILDCARD_BIND_ALLOWED: dict[str, str] = {
    "norviq-fleet-api/fleet-api": (
        "uvicorn --host 0.0.0.0 for the fleet hub API: its clients are OTHER CLUSTERS, so a loopback bind "
        "would make the component pointless. The port it exposes is token-authenticated "
        "(see Service/norviq-fleet-api:8080)."
    ),
}

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]", "127.0.0.1/32"})

# The wildcard-bind literal, named once. This test never opens a socket — it SEARCHES rendered YAML for
# this string — so naming it here keeps the intent obvious and gives the SAST bind-all rule a single,
# reviewable waiver instead of one per occurrence.
_ANY_INTERFACE = "0.0.0.0"  # nosec B104 - a needle this test greps for in manifests, not a bind address

# Flags that declare WHERE a process listens, across the runtimes the chart starts (OPA, uvicorn, Go).
_BIND_FLAGS = frozenset({"--addr", "--address", "--bind", "--bind-address", "--host", "--listen", "--listen-address"})
_PORT_FLAGS = frozenset({"--port"})

# OPA's admin API. Unauthenticated and read-WRITE (PUT/DELETE /v1/policies): whoever reaches it owns
# enforcement. It gets its own hard assertions below rather than an allow-list slot.
_OPA_ADMIN_PORT = 8181


# --- rendering + enumeration ------------------------------------------------------------------------


@functools.lru_cache(maxsize=None)
def _render(profile: str) -> str:
    cmd = ["helm", "template", "norviq", str(_CHART), *_NAMESPACES, *_PROFILES[profile]]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, f"profile {profile!r} failed to render:\n{res.stderr}"
    return res.stdout


def _docs(profile: str) -> list[dict[str, Any]]:
    return [d for d in yaml.safe_load_all(_render(profile)) if isinstance(d, dict)]


@dataclass(frozen=True)
class _Container:
    workload: str          # Deployment/StatefulSet/Job name
    name: str              # container name
    labels: tuple[tuple[str, str], ...]   # pod template labels (for Service selector matching)
    tokens: tuple[str, ...]               # command + args, flattened
    ports: tuple[tuple[str | None, int], ...]  # (name, containerPort)
    host_ports: tuple[int, ...]
    host_network: bool

    @property
    def cid(self) -> str:
        return f"{self.workload}/{self.name}"


def _containers(profile: str) -> list[_Container]:
    """Every container the chart starts, including init containers and hook Jobs."""
    out: list[_Container] = []
    for doc in _docs(profile):
        if doc.get("kind") not in ("Deployment", "StatefulSet", "DaemonSet", "Job"):
            continue
        template = doc["spec"]["template"]
        pod = template["spec"]
        labels = tuple(sorted((template.get("metadata", {}).get("labels") or {}).items()))
        for group in ("initContainers", "containers"):
            for c in pod.get(group) or []:
                ports = tuple(
                    (p.get("name"), int(p["containerPort"])) for p in (c.get("ports") or []) if "containerPort" in p
                )
                out.append(
                    _Container(
                        workload=doc["metadata"]["name"],
                        name=c["name"],
                        labels=labels,
                        tokens=tuple(str(t) for t in ((c.get("command") or []) + (c.get("args") or []))),
                        ports=ports,
                        host_ports=tuple(int(p["hostPort"]) for p in (c.get("ports") or []) if "hostPort" in p),
                        host_network=bool(pod.get("hostNetwork")),
                    )
                )
    return out


def _split_host_port(value: str) -> tuple[str, int | None]:
    """Split an --addr-style value. Handles host-only, :port, host:port and [::1]:port."""
    if value.startswith("["):                       # bracketed IPv6 literal
        host, _, rest = value.partition("]")
        port = rest.lstrip(":")
        return host + "]", int(port) if port.isdigit() else None
    host, sep, port = value.rpartition(":")
    if not sep:                                     # no colon at all -> the whole thing is a host
        return value, None
    if not port.isdigit():                          # bare IPv6 with no port (a::b)
        return value, None
    return (host or _ANY_INTERFACE), int(port)      # a bare ":8181" means every interface


def _binds(container: _Container) -> dict[int | None, str]:
    """Bind addresses declared by flags, keyed by port (None = applies to whatever port this container serves).

    Understands both `--flag=value` and `--flag value`, and the uvicorn split form
    (`--host 0.0.0.0 --port 8080`). A container with no bind flag at all yields {} — its bind address is
    decided inside the image, which this test cannot see, so its ports are treated as cluster-exposed
    (fail-closed: an unproven bind must be argued for in the allow-list).
    """
    hosts: list[tuple[str, int | None]] = []
    ports: list[int] = []
    tokens = list(container.tokens)
    for i, token in enumerate(tokens):
        if "=" in token:
            flag, _, value = token.partition("=")
        else:
            flag = token
            nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
            value = nxt if nxt and not nxt.startswith("-") else ""
        if flag in _BIND_FLAGS and value:
            hosts.append(_split_host_port(value))
        elif flag in _PORT_FLAGS and value.isdigit():
            ports.append(int(value))

    resolved: dict[int | None, str] = {}
    for host, port in hosts:
        if port is not None:
            resolved[port] = host
        elif len(ports) == 1:                       # --host X --port N
            resolved[ports[0]] = host
        else:                                       # --host X alone: governs every port of this container
            resolved[None] = host
    return resolved


@dataclass(frozen=True)
class _Surface:
    sid: str            # allow-list key
    where: str          # human description for the failure message
    port: int
    bind: str | None    # declared bind address, when the chart states one

    @property
    def is_loopback(self) -> bool:
        return self.bind is not None and self.bind in _LOOPBACK_HOSTS


def _container_surfaces(profile: str) -> Iterator[_Surface]:
    """Every in-pod listener: declared containerPorts UNION ports named by a bind flag."""
    for c in _containers(profile):
        binds = _binds(c)
        declared = {port for _, port in c.ports}
        for port in sorted(declared | {p for p in binds if p is not None}):
            bind = binds.get(port, binds.get(None))
            yield _Surface(
                sid=f"{c.cid}:{port}",
                where=f"container {c.cid} listening on {port} (bind={bind or 'declared inside the image'})",
                port=port,
                bind=bind,
            )


def _service_surfaces(profile: str) -> Iterator[_Surface]:
    """Every Service port — reachable from ANY pod in the cluster by DNS name, with no NetworkPolicy in play."""
    for doc in _docs(profile):
        if doc.get("kind") != "Service":
            continue
        name = doc["metadata"]["name"]
        stype = doc["spec"].get("type", "ClusterIP")
        for p in doc["spec"].get("ports") or []:
            port = int(p["port"])
            yield _Surface(
                sid=f"Service/{name}:{port}",
                where=f"{stype} Service {name} port {port} -> {p.get('targetPort')}",
                port=port,
                bind=None,   # a Service is cluster-reachable by definition; it can never be "loopback"
            )


def _surfaces(profile: str) -> list[_Surface]:
    return [*_container_surfaces(profile), *_service_surfaces(profile)]


def _service_backends(profile: str) -> Iterator[tuple[str, int, _Container, int]]:
    """(service name, service port, backing container, container port) for every Service port.

    Resolves the Service selector against pod-template labels and the targetPort (name or number)
    against the container's declared ports — i.e. it answers "which process does this name actually reach".
    """
    containers = _containers(profile)
    for doc in _docs(profile):
        if doc.get("kind") != "Service":
            continue
        selector = doc["spec"].get("selector") or {}
        if not selector:
            continue
        backends = [c for c in containers if selector.items() <= dict(c.labels).items()]
        for p in doc["spec"].get("ports") or []:
            target = p.get("targetPort", p["port"])
            for c in backends:
                for pname, pnum in c.ports:
                    if (isinstance(target, int) and target == pnum) or (isinstance(target, str) and target == pname):
                        yield doc["metadata"]["name"], int(p["port"]), c, pnum


# --- guard the guard ---------------------------------------------------------------------------------


@pytest.mark.parametrize("profile", sorted(_PROFILES))
def test_matrix_actually_enumerates_the_chart(profile: str) -> None:
    """If enumeration silently returned nothing, every assertion below would pass vacuously."""
    surfaces = _surfaces(profile)
    assert len(surfaces) >= 12, f"profile {profile}: only {len(surfaces)} surfaces found — enumeration broke"
    sids = {s.sid for s in surfaces}
    # Known-good anchors: the API port, a Service, and the OPA sidecars must all be visible to the matrix.
    assert "norviq-api/api:8080" in sids
    assert "Service/norviq-api:8080" in sids
    assert sum(1 for s in surfaces if s.port == _OPA_ADMIN_PORT) == 2, sorted(sids)


def test_bind_flag_parser_understands_the_forms_used_by_the_chart() -> None:
    """The matrix is only as good as this parser — a parser that saw nothing would clear everything."""
    assert _split_host_port("127.0.0.1:8181") == ("127.0.0.1", 8181)
    assert _split_host_port(f"{_ANY_INTERFACE}:8181") == (_ANY_INTERFACE, 8181)
    assert _split_host_port(":8181") == (_ANY_INTERFACE, 8181)  # a bare :port IS every interface
    assert _split_host_port("[::1]:8181") == ("[::1]", 8181)
    assert _split_host_port(_ANY_INTERFACE) == (_ANY_INTERFACE, None)

    joined = _Container("w", "c", (), ("run", "--addr=127.0.0.1:8181"), (("opa", 8181),), (), False)
    assert _binds(joined) == {8181: "127.0.0.1"}
    split = _Container("w", "c", (), ("uvicorn", "--host", _ANY_INTERFACE, "--port", "8080"), (("http", 8080),), (), False)
    assert _binds(split) == {8080: _ANY_INTERFACE}
    spaced = _Container("w", "c", (), ("srv", "--bind", f"{_ANY_INTERFACE}:9000"), (), (), False)
    assert _binds(spaced) == {9000: _ANY_INTERFACE}
    assert _binds(_Container("w", "c", (), ("redis-server",), (("redis", 6379),), (), False)) == {}


# --- the matrix --------------------------------------------------------------------------------------


@pytest.mark.parametrize("profile", sorted(_PROFILES))
def test_every_listening_surface_is_loopback_or_justified(profile: str) -> None:
    """THE guard: a listener is either provably loopback-bound, or someone wrote down why it is safe."""
    unjustified = [s for s in _surfaces(profile) if not s.is_loopback and s.sid not in EXPOSED_SURFACES]
    assert not unjustified, (
        "Cluster-reachable listening surfaces with no recorded justification (profile "
        f"{profile!r}):\n"
        + "\n".join(f"  - {s.sid}  [{s.where}]" for s in sorted(unjustified, key=lambda s: s.sid))
        + "\n\nAny pod in the cluster can dial these. Either bind them to 127.0.0.1, or add each id to "
          "EXPOSED_SURFACES in this file with a reason stating WHO can reach it and WHAT authenticates "
          "them. Norviq's threat model is a compromised workload INSIDE the cluster, so 'it is only "
          "internal' is not a reason."
    )


def test_allow_list_has_no_stale_entries() -> None:
    """An entry no profile renders any more must be deleted, or the allow-list decays into a rubber stamp."""
    rendered = {s.sid for profile in _PROFILES for s in _surfaces(profile)}
    stale = sorted(set(EXPOSED_SURFACES) - rendered)
    assert not stale, f"EXPOSED_SURFACES entries that no longer render — delete them: {stale}"

    rendered_cids = {c.cid for profile in _PROFILES for c in _containers(profile)}
    stale_binds = sorted(set(WILDCARD_BIND_ALLOWED) - rendered_cids)
    assert not stale_binds, f"WILDCARD_BIND_ALLOWED entries for containers that no longer exist: {stale_binds}"


def test_every_justification_is_an_actual_justification() -> None:
    """A one-word 'ok' would defeat the point of the allow-list; require a real sentence."""
    for sid, reason in {**EXPOSED_SURFACES, **WILDCARD_BIND_ALLOWED}.items():
        assert len(reason.split()) >= 8, f"{sid}: justification is too thin to review: {reason!r}"


# --- the specific bypass that shipped ----------------------------------------------------------------


@pytest.mark.parametrize("profile", sorted(_PROFILES))
def test_opa_admin_port_binds_loopback_in_every_component(profile: str) -> None:
    """OPA's admin API is unauthenticated AND read-write: pod-to-pod reachability = deleting enforcement.

    Asserted per COMPONENT (not just for today's two sidecars) so a third component that adds an OPA is
    held to the same rule.
    """
    seen = 0
    for c in _containers(profile):
        binds = _binds(c)
        for _, port in c.ports:
            if port != _OPA_ADMIN_PORT:
                continue
            seen += 1
            bind = binds.get(port, binds.get(None))
            assert bind is not None, (
                f"{c.cid}: declares the OPA admin port {port} with no explicit bind flag — OPA defaults "
                "to a non-loopback bind, exposing an unauthenticated read-write policy API to every pod."
            )
            assert bind in _LOOPBACK_HOSTS, (
                f"{c.cid}: OPA admin port bound to {bind}, must be loopback. Any pod reaching :{port} can "
                "PUT/DELETE /v1/policies and silently disable enforcement."
            )
    assert seen, f"profile {profile}: no OPA admin port found at all — did the sidecar stop rendering?"


@pytest.mark.parametrize("profile", sorted(_PROFILES))
def test_opa_admin_port_is_published_by_no_service(profile: str) -> None:
    """Defense in depth: loopback is the control, but no Service may name :8181 either — by port,
    by targetPort, or by resolving to a container port that happens to be 8181."""
    for doc in _docs(profile):
        if doc.get("kind") != "Service":
            continue
        for p in doc["spec"].get("ports") or []:
            assert int(p["port"]) != _OPA_ADMIN_PORT, (
                f"Service {doc['metadata']['name']} publishes the OPA admin port {_OPA_ADMIN_PORT}"
            )
            target = p.get("targetPort")
            assert target != _OPA_ADMIN_PORT and target != str(_OPA_ADMIN_PORT), (
                f"Service {doc['metadata']['name']} targets the OPA admin port {_OPA_ADMIN_PORT}"
            )
    for svc, svc_port, container, container_port in _service_backends(profile):
        assert container_port != _OPA_ADMIN_PORT, (
            f"Service {svc}:{svc_port} resolves to {container.cid}:{container_port} — the OPA admin port"
        )


@pytest.mark.parametrize("profile", sorted(_PROFILES))
def test_no_container_arg_binds_all_interfaces(profile: str) -> None:
    """A literal 0.0.0.0 anywhere in a command/args is the exact shape of the shipped bypass.

    Reports the container id only — argv carries credentials (redis --requirepass) and this text goes to
    CI logs.
    """
    offenders = sorted(
        {c.cid for c in _containers(profile) if any(_ANY_INTERFACE in t for t in c.tokens)} - set(WILDCARD_BIND_ALLOWED)
    )
    assert not offenders, (
        f"Containers binding/naming 0.0.0.0 in their args without a recorded reason: {offenders}. "
        "Bind 127.0.0.1 if the client is in the same pod (the app talks to its sidecars over localhost), "
        "otherwise add the container to WILDCARD_BIND_ALLOWED with the reason it must be reachable "
        "from other pods."
    )


# --- reachability invariants that need no allow-list --------------------------------------------------


@pytest.mark.parametrize("profile", sorted(_PROFILES))
def test_no_service_fronts_a_loopback_bound_port(profile: str) -> None:
    """A Service pointing at a loopback listener is always a bug — and if the listener is OPA, a critical one.

    Either the Service leaks something meant to stay in-pod, or it is dead weight advertising a port that
    can never answer. Both deserve a failure.
    """
    for svc, svc_port, container, container_port in _service_backends(profile):
        bind = _binds(container).get(container_port, _binds(container).get(None))
        assert bind is None or bind not in _LOOPBACK_HOSTS, (
            f"Service {svc}:{svc_port} fronts {container.cid}:{container_port}, which binds {bind}. "
            "Either the port was meant to stay pod-private (drop the Service port) or the bind is wrong."
        )


@pytest.mark.parametrize("profile", sorted(_PROFILES))
def test_no_service_escapes_the_cluster_boundary(profile: str) -> None:
    """NodePort/LoadBalancer widen the audience from 'any pod' to 'anything that can route to a node'.

    The chart's own exposure story is Ingress (TLS + a single authenticated host). A component quietly
    shipping type: NodePort would change the blast radius of every finding above.
    """
    for doc in _docs(profile):
        if doc.get("kind") != "Service":
            continue
        stype = doc["spec"].get("type", "ClusterIP")
        assert stype == "ClusterIP", (
            f"Service {doc['metadata']['name']} is type {stype} — that publishes it beyond the cluster. "
            "Use the chart's Ingress path, or justify the node-level exposure here."
        )
        for p in doc["spec"].get("ports") or []:
            assert "nodePort" not in p, f"Service {doc['metadata']['name']} pins a nodePort on {p.get('port')}"


@pytest.mark.parametrize("profile", sorted(_PROFILES))
def test_no_pod_joins_the_host_network(profile: str) -> None:
    """hostNetwork/hostPort would put every listener above straight onto the node's interfaces, silently
    voiding the loopback control (127.0.0.1 in the host netns is the NODE's loopback, shared by everything
    on it)."""
    for c in _containers(profile):
        assert not c.host_network, f"{c.cid}: pod sets hostNetwork — every bind above becomes a node bind"
        assert not c.host_ports, f"{c.cid}: declares hostPort {list(c.host_ports)} — reachable via the node IP"
