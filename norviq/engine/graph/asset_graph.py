# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Asset graph builder for agent, tool, and data relationships."""

from __future__ import annotations

import copy
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

import networkx as nx
import structlog

from norviq.engine.graph.models import EdgeType, GraphEdge, GraphNode, NodeType, RiskLevel

log = structlog.get_logger()

TOOL_RISK_MAP = {
    "delete_record": RiskLevel.CRITICAL,
    "drop_table": RiskLevel.CRITICAL,
    "execute_sql": RiskLevel.CRITICAL,
    "exec_shell": RiskLevel.CRITICAL,
    "spawn_pod": RiskLevel.CRITICAL,
    "update_record": RiskLevel.HIGH,
    "modify_config": RiskLevel.HIGH,
    "send_email": RiskLevel.HIGH,
    "upload_file": RiskLevel.HIGH,
    "get_customer": RiskLevel.MEDIUM,
    "read_file": RiskLevel.MEDIUM,
    "get_order": RiskLevel.MEDIUM,
    "query_db": RiskLevel.MEDIUM,
    "search_kb": RiskLevel.LOW,
    "list_items": RiskLevel.LOW,
}

TOOL_DATA_MAP: dict[str, list[str]] = {
    "execute_sql": ["postgresql/users", "postgresql/orders", "postgresql/payments"],
    "get_customer": ["postgresql/customers"],
    "search_kb": ["elasticsearch/knowledge_base"],
    "send_email": ["smtp/outbound"],
    "read_file": ["filesystem/uploads"],
    "get_order": ["postgresql/orders"],
    "update_record": ["postgresql/users", "postgresql/orders"],
    "delete_record": ["postgresql/users", "postgresql/orders"],
}


# How long a removal is remembered. Past this, a process that still holds the removed node is caught
# by the synced-baseline rule in `merge_persisted` instead (it held the node at its last sync, the
# store no longer does, and it has not seen the node since), so the tombstone list stays bounded.
TOMBSTONE_TTL = timedelta(days=30)
TOMBSTONE_CAP = 10000

_EPOCH = datetime.min.replace(tzinfo=timezone.utc)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ts(value: object) -> datetime:
    """Parse a stored ISO stamp. Missing or unreadable (a snapshot written before stamps existed)
    sorts as the oldest possible time."""
    if not value:
        return _EPOCH
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return _EPOCH
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _seen(attrs: dict) -> datetime:
    """When an element was last active. Call edges written before `last_seen_at` existed carry
    `properties.last_timestamp`, which means the same thing."""
    return _ts(attrs.get("last_seen_at") or (attrs.get("properties") or {}).get("last_timestamp"))


def _tombstones_of(payload: dict) -> dict:
    """The snapshot's tombstones; absent in a snapshot written before they existed."""
    value = payload.get("tombstones")
    return value if isinstance(value, dict) else {}


def knows_tombstones(payload: dict | None) -> bool:
    """Whether ``payload`` was written by a release that records tombstones.

    This release writes the ``tombstones`` key on every snapshot, empty or not. A snapshot without it
    was written by a pod on the previous release, which drops tombstones it never read. Its silence
    says nothing about what was removed, so the store has to find the removals elsewhere."""
    return isinstance(payload, dict) and isinstance(payload.get("tombstones"), dict)


def baseline_of(payload: dict) -> dict[tuple[str, ...], tuple[int, datetime]]:
    """Count and last activity of every element in ``payload``, keyed as ``_synced`` is."""
    base: dict[tuple[str, ...], tuple[int, datetime]] = {}
    for node in payload.get("nodes", []) or []:
        if isinstance(node, dict) and node.get("id"):
            base[("n", str(node["id"]))] = (_count(node), _seen(node))
    for edge in payload.get("edges", []) or []:
        if isinstance(edge, dict) and edge.get("source") and edge.get("target"):
            base[("e", str(edge["source"]), str(edge["target"]))] = (_count(edge), _seen(edge))
    return base


def _clamped(attrs: dict, horizon: datetime) -> dict:
    """``attrs`` with an activity stamp later than ``horizon`` pulled back to it: the same dict when
    nothing is later, a copy otherwise. See `AssetGraphBuilder._clamp_future`."""
    stamp = horizon.isoformat(timespec="microseconds")
    if attrs.get("last_seen_at"):
        return {**attrs, "last_seen_at": stamp} if _ts(attrs["last_seen_at"]) > horizon else attrs
    props = attrs.get("properties")
    if isinstance(props, dict) and props.get("last_timestamp") and _ts(props["last_timestamp"]) > horizon:
        return {**attrs, "properties": {**props, "last_timestamp": stamp}}
    return attrs


def _count(attrs: dict) -> int:
    """The additive counter on a tool node or a call edge (0 for everything else). An unreadable count
    raises, as `record_tool_call` does on the same field, rather than being merged as 0."""
    return int((attrs.get("properties") or {}).get("call_count", 0) or 0)


class AssetGraphBuilder:
    """Build and maintain directed runtime asset graphs.

    Every API replica holds its own builder per namespace and records the calls it serves. The
    persisted snapshot is the shared copy, so a save must MERGE into it rather than replace it (see
    `merge_persisted`). Two pieces of state make that merge exact:

    * ``_synced`` — what the store held for each element when this process last synced. A local
      counter minus its synced value is this process's unsaved contribution, so counts from several
      replicas add up instead of the last writer's number winning.
    * ``_tombstones`` — node id -> removal time, persisted in the snapshot. A removal made on one
      replica is honoured by every other replica's next save instead of being re-saved by it.

    Both orderings compare times stamped on different pods, so they are stamped on a shared clock
    where there is one (see `now`).
    """

    def __init__(self, max_nodes: int = 5000, wall_clock: Callable[[], datetime] | None = None) -> None:
        """Initialize with an empty directed graph. ``wall_clock`` is this process's clock (tests)."""
        self._graph = nx.DiGraph()
        self._max_nodes = max(100, max_nodes)
        self._clock = 0
        self._synced: dict[tuple[str, ...], tuple[int, datetime]] = {}
        self._tombstones: dict[str, str] = {}
        self._wall_clock = wall_clock or _utcnow
        self._clock_offset = timedelta(0)
        self._referenced = False

    def wall_now(self) -> datetime:
        """This process's own clock, uncorrected."""
        return self._wall_clock()

    def now(self) -> datetime:
        """The time this builder stamps activity and removals with.

        Activity stamps order one replica's change against another's (trust score, last decision)
        and tombstones decide which copies a removal covers. On pod wall clocks a pod running an hour
        fast won every trust comparison for that hour, and its removals covered calls made after them.
        So the store reads the database clock (Redis TIME without a database) on each save and this
        is the local clock corrected by the offset measured then. Between saves the error is the drift
        since, which is small next to the skew it removes."""
        return self._wall_clock() + self._clock_offset

    @property
    def has_reference_clock(self) -> bool:
        """Whether a save has measured the shared clock; until then stamps are not bounded."""
        return self._referenced

    def set_reference_clock(self, reference: datetime, local: datetime) -> None:
        """Record that the shared clock read ``reference`` when this process's read ``local``."""
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=timezone.utc)
        self._clock_offset = reference - local
        self._referenced = True

    def _stamp(self) -> str:
        return self.now().isoformat(timespec="microseconds")

    @property
    def graph(self) -> nx.DiGraph:
        """Expose underlying graph for analysis."""
        return self._graph

    def add_agent(self, spiffe_id: str, agent_class: str, namespace: str, trust_score: float = 0.8) -> None:
        """Add or update an agent node.

        Identity grouping: the node stays keyed by SPIFFE ID (so delegation + graph analysis keep their
        single-identity view), but ``agent_classes`` accumulates EVERY class observed under this identity.
        When more than one class shares one SPIFFE ID, the read model expands them into distinguishable
        sub-nodes (see api/routers/graphs.py) so distinct chatbots never silently collapse.
        """
        node = GraphNode(
            id=spiffe_id,
            type=NodeType.AGENT,
            label=agent_class or spiffe_id.split("/")[-1],
            namespace=namespace,
            properties={
                "agent_class": agent_class,
                "agent_classes": [agent_class] if agent_class else [],
                "trust_score": trust_score,
                "trust_category": self._trust_category(trust_score),
            },
        )
        self._graph.add_node(spiffe_id, **node.__dict__)
        self._touch_node(spiffe_id)
        self._enforce_node_limit()

    def _merge_agent_class(self, spiffe_id: str, agent_class: str) -> None:
        """Record another agent_class seen under an existing SPIFFE identity (order-preserving, unique)."""
        if not agent_class or spiffe_id not in self._graph:
            return
        props = self._graph.nodes[spiffe_id].setdefault("properties", {})
        classes = list(props.get("agent_classes") or ([props["agent_class"]] if props.get("agent_class") else []))
        if agent_class not in classes:
            classes.append(agent_class)
        props["agent_classes"] = classes

    def add_tool(self, tool_name: str, namespace: str = "") -> None:
        """Add or update a tool node."""
        tool_id = f"tool:{tool_name}"
        risk = TOOL_RISK_MAP.get(tool_name, RiskLevel.MEDIUM).value
        node = GraphNode(
            id=tool_id,
            type=NodeType.TOOL,
            label=tool_name,
            namespace=namespace,
            properties={"risk_level": risk, "call_count": 0},
        )
        self._graph.add_node(tool_id, **node.__dict__)
        self._touch_node(tool_id)
        self._enforce_node_limit()

    def add_mcp_server(self, server_id: str, namespace: str = "", transport: str = "") -> str:
        """Add or update an MCP server node, returning its node id.

        The id is prefixed like `add_tool`'s, and for the same reason: node ids share one namespace in
        the graph, so a server called `read_file` and a tool called `read_file` would otherwise be one
        node with two meanings.

        Deliberately carries NO trust or pin state. Those live in `mcp_servers` and `mcp_tool_pins`
        where an operator changes them, and a copy here would be a second answer to "is this server
        registered" that goes stale the moment somebody clicks Block. What the graph contributes is the
        thing the tables cannot show: the shape — which agents reach which servers, through which
        tools.
        """
        node_id = f"mcp:{server_id}"
        node = GraphNode(
            id=node_id,
            type=NodeType.MCP_SERVER,
            label=server_id,
            namespace=namespace,
            properties={"server_id": server_id, "transport": transport, "tool_count": 0},
        )
        self._graph.add_node(node_id, **node.__dict__)
        self._touch_node(node_id)
        self._enforce_node_limit()
        return node_id

    def record_mcp_serving(self, server_id: str, tool_name: str, namespace: str = "",
                           transport: str = "") -> None:
        """Record that `server_id` served `tool_name` — a `serves` edge, server -> tool.

        Called from the decision path with `input.mcp.server`, so the graph learns the topology from
        the same traffic everything else is derived from rather than from a second inventory that
        could disagree with it.
        """
        if not server_id or not tool_name:
            return
        node_id = f"mcp:{server_id}"
        if node_id not in self._graph:
            self.add_mcp_server(server_id, namespace, transport)
        tool_id = f"tool:{tool_name}"
        if tool_id not in self._graph:
            self.add_tool(tool_name, namespace)
        if not self._graph.has_edge(node_id, tool_id):
            edge = GraphEdge(source=node_id, target=tool_id, type=EdgeType.SERVES)
            self._graph.add_edge(node_id, tool_id, **edge.__dict__)
            props = self._graph.nodes[node_id].setdefault("properties", {})
            props["tool_count"] = int(props.get("tool_count", 0)) + 1
        self._touch_edge(node_id, tool_id)
        self._touch_node(node_id)
        self._touch_node(tool_id)

    def get_mcp_servers(self) -> list[dict[str, object]]:
        """Return all MCP server node dictionaries."""
        return self._nodes_by_type(NodeType.MCP_SERVER)

    def add_data(self, data_uri: str, data_type: str = "database", sensitivity: str = "medium") -> None:
        """Add or update a data node."""
        data_id = f"data:{data_uri}"
        node = GraphNode(
            id=data_id,
            type=NodeType.DATA,
            label=data_uri,
            properties={"data_type": data_type, "sensitivity": sensitivity},
        )
        self._graph.add_node(data_id, **node.__dict__)
        self._touch_node(data_id)
        self._enforce_node_limit()

    def record_tool_call(self, spiffe_id: str, tool_name: str, decision: str, namespace: str = "",
                         agent_class: str = "", trust_score: float | None = None) -> None:
        """Record an agent to tool call edge.

        `trust_score` is the score the evaluator just computed for this call. It is optional only so
        existing callers/tests keep working; when it is None the agent node keeps `add_agent`'s default
        rather than being overwritten with a fabricated value.
        """
        self._ensure_tool_call_nodes(spiffe_id, tool_name, namespace, agent_class, trust_score)
        tool_id = f"tool:{tool_name}"
        self._upsert_call_edge(spiffe_id, tool_id, decision)
        self._increment_tool_counter(tool_id)
        self._record_mapped_data(tool_name)
        log.debug("nrvq.graph.tool_call_recorded", agent=spiffe_id, tool=tool_name, code="NRVQ-GRP-11000")

    def _ensure_tool_call_nodes(self, spiffe_id: str, tool_name: str, namespace: str, agent_class: str,
                                trust_score: float | None = None) -> None:
        """Create missing agent or tool nodes before call-edge write."""
        if spiffe_id not in self._graph:
            if trust_score is None:
                self.add_agent(spiffe_id, agent_class, namespace)
            else:
                self.add_agent(spiffe_id, agent_class, namespace, trust_score=trust_score)
        else:
            # Same identity, another class (e.g. two agent-class labels on one service account) — record it
            # so the read model can render distinguishable sub-nodes instead of collapsing them.
            self._merge_agent_class(spiffe_id, agent_class)
            # Trust MOVES between calls — that is the whole point of behavioural trust — so an existing
            # node must track it, not keep whatever it was created with. Without this the score froze at
            # first sight and every trust-derived read (severity, critical paths, low_trust_agents) was
            # computed from a stale number.
            if trust_score is not None:
                props = self._graph.nodes[spiffe_id].setdefault("properties", {})
                props["trust_score"] = float(trust_score)
                # Category is DERIVED from the score (add_agent sets both at creation). Updating one
                # without the other would leave the node self-contradictory — a 0.2 score still labelled
                # the category it was created with — and the console reads the category.
                props["trust_category"] = self._trust_category(float(trust_score))
        tool_id = f"tool:{tool_name}"
        if tool_id not in self._graph:
            self.add_tool(tool_name, namespace)

    def _upsert_call_edge(self, spiffe_id: str, tool_id: str, decision: str) -> None:
        """Insert or update call edge metadata."""
        if self._graph.has_edge(spiffe_id, tool_id):
            edge = self._graph[spiffe_id][tool_id]
            props = edge.get("properties", {})
            props["call_count"] = int(props.get("call_count", 0)) + 1
            props["last_decision"] = decision
            props["last_timestamp"] = self.now().isoformat()
            self._touch_edge(spiffe_id, tool_id)
            self._touch_node(spiffe_id)
            self._touch_node(tool_id)
            return
        edge = GraphEdge(
            source=spiffe_id,
            target=tool_id,
            type=EdgeType.CALLS,
            properties={"call_count": 1, "last_decision": decision, "last_timestamp": self.now().isoformat()},
        )
        self._graph.add_edge(spiffe_id, tool_id, **edge.__dict__)
        self._touch_edge(spiffe_id, tool_id)
        self._touch_node(spiffe_id)
        self._touch_node(tool_id)

    def _increment_tool_counter(self, tool_id: str) -> None:
        """Track aggregate call count on tool nodes."""
        props = self._graph.nodes[tool_id].setdefault("properties", {})
        props["call_count"] = int(props.get("call_count", 0)) + 1

    # What a tool's VERB implies about the asset it touches, used when the static map says nothing.
    # Deliberately coarse: the point is that the asset exists and is reachable, not to invent a
    # precise URI the call never named.
    _VERB_ASSET = {
        "delete": ("compute/destructive", "critical", "write"),
        "write": ("compute/mutating", "high", "write"),
        "send": ("network/egress", "high", "write"),
        "read": ("data/read", "medium", "read"),
    }

    def _record_mapped_data(self, tool_name: str) -> None:
        """Create tool→data edges — from the static map, and from the tool's verb when it is silent.

        THE STATIC MAP WAS THE WHOLE WORLD, AND IT HAS EIGHT ENTRIES (F-042). `exec_shell`,
        `drop_table`, `spawn_pod`, `modify_config` and `upload_file` are all in `TOOL_RISK_MAP` — the
        product already calls them critical — and none of them is in `TOOL_DATA_MAP`, so none produced
        a data edge. Blast radius is computed by walking those edges, which is why
        `GET /graph/blast-radius/{spiffe}` returned 200 with `total_reachable: 0` and
        `attack_paths: []` for an agent with 300+ evaluations and 130 `shell_exec` calls. An
        all-empty blast radius for a busy agent does not read as "we cannot see this" — it reads as
        "nothing is reachable", which is the most dangerous thing a security console can say wrongly.
        And it can never have been right, because a map of eight literal names cannot cover the tools
        a customer actually deploys.

        So the map becomes a SEED — precise URIs where we genuinely know them — and any other tool
        falls back to the asset its verb implies. `classify_tool` is the product's one notion of what a
        call does and is already used for enforcement, so this is the same fact reused rather than a
        second taxonomy that can disagree with the first.

        A verb-derived node is marked `derived: True` so the console can distinguish "this is the
        orders table" from "this tool destroys something we could not name". Reporting a guess as a
        precise asset would be its own kind of lie.
        """
        mapped = TOOL_DATA_MAP.get(tool_name, [])
        if mapped:
            for data_uri in mapped:
                self.record_data_access(tool_name, data_uri)
            return
        # Imported HERE, not at module scope: `capability.source_registry` imports `graph.models`, so a
        # top-level import closes a cycle (graph -> analyzer -> asset_graph -> capability -> graph).
        # Local keeps the one notion of a verb without restructuring either package.
        from norviq.engine.capability import classify_tool

        try:
            verb, _risk = classify_tool(tool_name)
        except Exception:  # noqa: BLE001 - the graph is evidence, never enforcement; never break a call
            log.warning("nrvq.graph.classify_failed", tool=tool_name, code="NRVQ-ENG-2066")
            return
        asset = self._VERB_ASSET.get(str(getattr(verb, "value", verb)))
        if asset is None:
            return  # genuinely unclassifiable: an edge to "unknown" would be noise, not evidence
        data_uri, sensitivity, access_type = asset
        self.add_data(data_uri, data_type="derived", sensitivity=sensitivity)
        self.record_data_access(tool_name, data_uri, access_type=access_type)

    def record_delegation(self, from_agent: str, to_agent: str, depth: int = 1) -> None:
        """Record agent delegation edge."""
        if not self._graph.has_node(from_agent):
            self.add_agent(from_agent, "", "")
        if not self._graph.has_node(to_agent):
            self.add_agent(to_agent, "", "")
        edge = GraphEdge(source=from_agent, target=to_agent, type=EdgeType.DELEGATES, properties={"chain_depth": depth})
        self._graph.add_edge(from_agent, to_agent, **edge.__dict__)
        self._touch_edge(from_agent, to_agent)

    def record_data_access(self, tool_name: str, data_uri: str, access_type: str = "read") -> None:
        """Record tool to data access edge."""
        tool_id = f"tool:{tool_name}"
        data_id = f"data:{data_uri}"
        if tool_id not in self._graph:
            self.add_tool(tool_name)
        if data_id not in self._graph:
            self.add_data(data_uri)
        if self._graph.has_edge(tool_id, data_id):
            self._touch_edge(tool_id, data_id)
            return
        edge = GraphEdge(source=tool_id, target=data_id, type=EdgeType.ACCESSES, properties={"access_type": access_type})
        self._graph.add_edge(tool_id, data_id, **edge.__dict__)
        self._touch_edge(tool_id, data_id)

    def get_agents(self) -> list[dict[str, object]]:
        """Return all agent node dictionaries."""
        return self._nodes_by_type(NodeType.AGENT)

    def get_tools(self) -> list[dict[str, object]]:
        """Return all tool node dictionaries."""
        return self._nodes_by_type(NodeType.TOOL)

    def get_data(self) -> list[dict[str, object]]:
        """Return all data node dictionaries."""
        return self._nodes_by_type(NodeType.DATA)

    def _nodes_by_type(self, node_type: NodeType) -> list[dict[str, object]]:
        """Filter nodes by type value."""
        return [self._graph.nodes[node_id] for node_id in self._graph if self._graph.nodes[node_id].get("type") == node_type]

    def get_node_count(self) -> dict[str, int]:
        """Return node and edge counts by category.

        Keyed off the enum rather than an if/elif chain: the chain silently dropped any kind nobody
        had remembered to add a branch for, so a new node type would appear in the graph, be rendered,
        be traversed, and count as nothing — a total that quietly disagreed with the picture.
        """
        counts = {"agents": 0, "tools": 0, "data": 0, "mcp_servers": 0,
                  "edges": self._graph.number_of_edges()}
        buckets = {NodeType.AGENT: "agents", NodeType.TOOL: "tools", NodeType.DATA: "data",
                   NodeType.MCP_SERVER: "mcp_servers"}
        for node_id in self._graph:
            bucket = buckets.get(self._graph.nodes[node_id].get("type"))
            if bucket is not None:
                counts[bucket] += 1
        return counts

    def remove_node(self, node_id: str) -> bool:
        """Remove a node AND its incident edges — admin housekeeping for a decommissioned or junk
        node (e.g. a probe tool). Returns False when the node isn't present. The graph is otherwise
        append-only, so this is the only sanctioned way a node leaves before LRU-cap eviction.

        Also records a tombstone that travels in the snapshot. Without it the removal lived only in
        this process: another replica still holding the node saved it straight back, so the node
        reappeared and a second DELETE could 404 on a node the console was still showing."""
        if node_id not in self._graph:
            return False
        self._drop_node(node_id)
        self._tombstones[node_id] = self._stamp()
        return True

    def removal_undo(self, node_id: str) -> Callable[[], None]:
        """Capture ``node_id`` before `remove_node`; the returned callable puts it back.

        For a removal whose snapshot write then fails. Without it the builder kept the tombstone, so
        the next ordinary save carried out a removal the API had just reported as failed. Calls recorded
        on the node while the write was in flight are kept: the restored count is added to theirs."""
        if node_id not in self._graph:
            return lambda: None
        node = copy.deepcopy(dict(self._graph.nodes[node_id]))
        edges = [(s, t, copy.deepcopy(dict(self._graph[s][t])))
                 for s, t in list(self._graph.in_edges(node_id)) + list(self._graph.out_edges(node_id))]
        synced = {k: v for k, v in self._synced.items()
                  if (k[0] == "n" and k[1] == node_id) or (k[0] == "e" and node_id in k[1:])}
        previous = self._tombstones.get(node_id)

        def undo() -> None:
            if node_id in self._graph:
                self._add_count(self._graph.nodes[node_id], _count(node))
            else:
                self._graph.add_node(node_id, **copy.deepcopy(node))
            for src, tgt, attrs in edges:
                if src not in self._graph or tgt not in self._graph:
                    continue
                if self._graph.has_edge(src, tgt):
                    self._add_count(self._graph[src][tgt], _count(attrs))
                else:
                    self._graph.add_edge(src, tgt, **copy.deepcopy(attrs))
            self._synced.update(synced)
            if previous is None:
                self._tombstones.pop(node_id, None)
            else:
                self._tombstones[node_id] = previous

        return undo

    @staticmethod
    def _add_count(attrs: dict, amount: int) -> None:
        props = attrs.setdefault("properties", {})
        if amount and "call_count" in props:
            props["call_count"] = _count(attrs) + amount

    def to_dict(self) -> dict[str, object]:
        """Serialize graph into JSON-safe node and edge arrays.

        ``tombstones`` is always written, empty or not: its absence is how a snapshot written by a
        previous-release pod is told apart (`knows_tombstones`). Readers that only look at
        ``nodes``/``edges`` are unaffected.

        The payload is a deep copy. A save serializes it, awaits Redis and Postgres, then hands the same
        payload to `mark_persisted`. With a shallow copy its ``properties`` dicts were the live ones, so
        a call recorded during those awaits was marked as stored without being in the row, and the next
        merge subtracted it from the count."""
        nodes = [{"id": node_id, **copy.deepcopy(data)} for node_id, data in self._graph.nodes(data=True)]
        edges = [{"source": src, "target": tgt, **copy.deepcopy(data)}
                 for src, tgt, data in self._graph.edges(data=True)]
        return {"nodes": nodes, "edges": edges, "tombstones": dict(self._tombstones)}

    def from_dict(self, data: dict[str, object]) -> None:
        """Load graph from serialized dictionary (any snapshot this product has written)."""
        self._graph.clear()
        # Deep copies: the live graph must not share property dicts with the caller's payload.
        for node in data.get("nodes", []):  # type: ignore[union-attr]
            node_copy = copy.deepcopy(dict(node))
            node_id = str(node_copy.pop("id"))
            self._graph.add_node(node_id, **node_copy)
        for edge in data.get("edges", []):  # type: ignore[union-attr]
            edge_copy = copy.deepcopy(dict(edge))
            src = str(edge_copy.pop("source"))
            tgt = str(edge_copy.pop("target"))
            self._graph.add_edge(src, tgt, **edge_copy)
        self._clock = len(self._graph.nodes)
        self._tombstones = {str(k): str(v) for k, v in _tombstones_of(data).items()}
        # A loaded snapshot IS the persisted state, so nothing in it is an unsaved contribution.
        self.mark_persisted(data)

    def mark_persisted(self, payload: dict[str, object]) -> None:
        """Record ``payload`` as what the store now holds. Called after a successful save, so that
        anything recorded while the save was in flight stays counted as unsaved."""
        self._synced = baseline_of(payload)

    def merged_copy(self, stored: dict[str, object] | None,
                    base: dict[tuple[str, ...], tuple[int, datetime]] | None) -> tuple[dict, dict]:
        """``stored`` merged with this builder, as a payload, leaving this builder untouched.

        For a write that is not a sync with the database (the cache while the database is down): this
        builder's baseline must keep describing what the DATABASE holds, or its next real save counts
        the wrong share as already saved. ``base`` is what of this builder ``stored`` already holds
        (None: the database baseline). Returns the payload and the baseline to pass the next time
        ``stored`` is a payload this returned."""
        local = self.to_dict()
        copy_ = AssetGraphBuilder(self._max_nodes, wall_clock=self._wall_clock)
        copy_._clock_offset, copy_._referenced = self._clock_offset, self._referenced
        copy_.from_dict(local)
        copy_._synced = dict(self._synced if base is None else base)
        copy_.merge_persisted(stored)
        return copy_.to_dict(), baseline_of(local)

    def merge_persisted(self, stored: dict[str, object] | None) -> None:
        """Fold the persisted snapshot into this builder, in place, before it is saved back.

        Several API replicas each record the calls they serve into their own builder. Saving a whole
        builder as the new snapshot meant the last replica to write erased every node, edge and count
        the others had recorded since. This makes the save a merge instead:

        * elements only in the store are added; elements only here are kept;
        * counters add: this builder keeps its own unsaved calls and gains everyone else's, measured
          against what the store held at this builder's last sync (``_synced``);
        * every other property (trust score, last decision) is taken from whichever copy was active
          most recently;
        * a tombstone from either side removes every copy of the node that was last active before the
          removal, and an element this builder had synced but the store has since dropped (removed
          or evicted elsewhere) goes too, unless it has been active here since. ``stored`` None means
          there is no snapshot at all, which drops nothing.

        Edits happen in place and without awaiting, so calls recorded concurrently by this process are
        kept. The caller must hold the per-namespace lock across load -> merge -> write.
        """
        absent = stored is None
        stored = stored or {}
        if self._referenced:
            stored = self._clamp_future(stored)
        for node_id, removed_at in _tombstones_of(stored).items():
            if _ts(removed_at) > _ts(self._tombstones.get(str(node_id))):
                self._tombstones[str(node_id)] = str(removed_at)
        self._prune_tombstones()

        s_nodes: dict[str, dict] = {}
        for node in stored.get("nodes", []) or []:  # type: ignore[union-attr]
            if isinstance(node, dict) and node.get("id"):
                attrs = {k: v for k, v in node.items() if k != "id"}
                if not self._removed_after(str(node["id"]), attrs):
                    s_nodes[str(node["id"])] = attrs
        s_edges: dict[tuple[str, str], dict] = {}
        for edge in stored.get("edges", []) or []:  # type: ignore[union-attr]
            if isinstance(edge, dict) and edge.get("source") and edge.get("target"):
                key = (str(edge["source"]), str(edge["target"]))
                attrs = {k: v for k, v in edge.items() if k not in ("source", "target")}
                if not (self._removed_after(key[0], attrs) or self._removed_after(key[1], attrs)):
                    s_edges[key] = attrs

        self._apply_tombstones_locally()
        if absent:
            # No snapshot at all (the cached copy expired with no database behind it, or the rows were
            # deleted) is not a store that dropped these elements. Without this, every element this
            # builder had synced and not touched since was deleted from it and from the next snapshot.
            self._synced = {}

        for node_id, attrs in s_nodes.items():
            base = self._synced.get(("n", node_id))
            if node_id in self._graph:
                self._merge_element(self._graph.nodes[node_id], attrs, base)
            elif base is None or _seen(attrs) > base[1]:
                self._clock += 1
                self._graph.add_node(node_id, **copy.deepcopy(attrs))
                self._graph.nodes[node_id]["last_seen_tick"] = self._clock
        for node_id in list(self._graph.nodes):
            if node_id not in s_nodes:
                self._reconcile_unstored(("n", node_id), self._graph.nodes[node_id],
                                         lambda nid=node_id: self._graph.remove_node(nid))

        for (src, tgt), attrs in s_edges.items():
            if src not in self._graph or tgt not in self._graph:
                continue  # an endpoint is gone (removed, or evicted here and inactive): so is the edge
            base = self._synced.get(("e", src, tgt))
            if self._graph.has_edge(src, tgt):
                self._merge_element(self._graph[src][tgt], attrs, base)
            elif base is None or _seen(attrs) > base[1]:
                self._graph.add_edge(src, tgt, **copy.deepcopy(attrs))
        for src, tgt in list(self._graph.edges):
            if (src, tgt) not in s_edges:
                self._reconcile_unstored(("e", src, tgt), self._graph[src][tgt],
                                         lambda s=src, t=tgt: self._graph.remove_edge(s, t))

        # tool_count is derived (distinct tools served); after a union it has to be recounted.
        for node_id, data in self._graph.nodes(data=True):
            if data.get("type") == NodeType.MCP_SERVER:
                served = sum(1 for _, _, e in self._graph.out_edges(node_id, data=True) if e.get("type") == EdgeType.SERVES)
                data.setdefault("properties", {})["tool_count"] = served
        self._enforce_node_limit()
        # The store's values are now this builder's baseline; whatever exceeds them is unsaved work.
        self._synced = {}
        for node_id, attrs in s_nodes.items():
            if node_id in self._graph:
                self._synced[("n", node_id)] = (_count(attrs), _seen(attrs))
        for (src, tgt), attrs in s_edges.items():
            if self._graph.has_edge(src, tgt):
                self._synced[("e", src, tgt)] = (_count(attrs), _seen(attrs))

    def _clamp_future(self, stored: dict) -> dict:
        """Bound what a fast clock can do: no stamp, here or in ``stored``, is later than `now`.

        Only once `now` is on the shared clock. A stamp from a pod whose clock ran ahead (before its
        first save measured the offset, or a pod on a release without it) would otherwise win every
        comparison and cover every later call with its removal until real time caught up. Clamped, it
        ties with the present and anything that happens afterwards is newer. Returns ``stored`` with
        the clamped elements replaced by copies; the caller's payload is not modified."""
        horizon = self.now()
        stamp = horizon.isoformat(timespec="microseconds")
        out = dict(stored)
        for key in ("nodes", "edges"):
            if isinstance(stored.get(key), list):
                out[key] = [_clamped(x, horizon) if isinstance(x, dict) else x for x in stored[key]]
        stones = _tombstones_of(stored)
        if any(_ts(at) > horizon for at in stones.values()):
            out["tombstones"] = {nid: (stamp if _ts(at) > horizon else at) for nid, at in stones.items()}
        for _, attrs in self._graph.nodes(data=True):
            clamped = _clamped(attrs, horizon)
            if clamped is not attrs:
                attrs.update(clamped)
        for _, _, attrs in self._graph.edges(data=True):
            clamped = _clamped(attrs, horizon)
            if clamped is not attrs:
                attrs.update(clamped)
        for node_id, at in list(self._tombstones.items()):
            if _ts(at) > horizon:
                self._tombstones[node_id] = stamp
        return out

    def _removed_after(self, node_id: str, attrs: dict) -> bool:
        """True when ``node_id`` has a tombstone and ``attrs`` were last active before it."""
        removed_at = self._tombstones.get(node_id)
        return removed_at is not None and _seen(attrs) <= _ts(removed_at)

    def _apply_tombstones_locally(self) -> None:
        """Drop local copies a tombstone covers. A node active here AFTER the removal is new evidence
        and stays, but only with what this process recorded since its last sync: the count it synced
        before the removal belongs to the copy that was removed."""
        for node_id in list(self._tombstones):
            removed_at = _ts(self._tombstones[node_id])
            if node_id not in self._graph:
                continue
            if _seen(self._graph.nodes[node_id]) <= removed_at:
                self._drop_node(node_id)
                continue
            for src, tgt in list(self._graph.in_edges(node_id)) + list(self._graph.out_edges(node_id)):
                if _seen(self._graph[src][tgt]) <= removed_at:
                    self._graph.remove_edge(src, tgt)
                    self._synced.pop(("e", src, tgt), None)
            for key in [("n", node_id)] + [("e", s, t) for s, t in
                                           list(self._graph.in_edges(node_id)) + list(self._graph.out_edges(node_id))]:
                base = self._synced.get(key)
                if base is not None and base[1] <= removed_at:
                    attrs = self._graph.nodes[node_id] if key[0] == "n" else self._graph[key[1]][key[2]]
                    self._subtract_count(attrs, base[0])
                    self._synced.pop(key, None)

    def _reconcile_unstored(self, key: tuple[str, ...], attrs: dict, drop) -> None:
        """A local element the store does not hold. Never synced: it is new here, keep it. Synced but
        since dropped from the store and not active here since: it was removed or evicted elsewhere,
        drop it. Active here since: keep only this process's unsaved part."""
        base = self._synced.get(key)
        if base is None:
            return
        if _seen(attrs) <= base[1]:
            drop()
        else:
            self._subtract_count(attrs, base[0])
        self._synced.pop(key, None)

    @staticmethod
    def _subtract_count(attrs: dict, amount: int) -> None:
        props = attrs.get("properties")
        if isinstance(props, dict) and "call_count" in props:
            props["call_count"] = max(0, _count(attrs) - amount)

    @staticmethod
    def _merge_element(local: dict, stored: dict, base: tuple[int, datetime] | None) -> None:
        """Merge the stored copy of one node or edge into the local copy (see `merge_persisted`)."""
        local_props = local.setdefault("properties", {})
        stored_props = stored.get("properties") or {}
        if "call_count" in local_props or "call_count" in stored_props:
            others = _count(stored) - (base[0] if base else 0)
            local_props["call_count"] = max(0, _count(local) + others)
        if _seen(stored) > _seen(local):
            for key, value in stored.items():
                if key not in ("properties", "last_seen_tick"):
                    local[key] = copy.deepcopy(value)
            for key, value in stored_props.items():
                if key not in ("call_count", "agent_classes", "tool_count"):
                    local_props[key] = copy.deepcopy(value)
        if "agent_classes" in local_props or "agent_classes" in stored_props:
            classes = list(local_props.get("agent_classes") or [])
            for klass in stored_props.get("agent_classes") or []:
                if klass and klass not in classes:
                    classes.append(klass)
            local_props["agent_classes"] = classes

    def _drop_node(self, node_id: str) -> None:
        """Remove a node with its edges, and forget their synced baselines."""
        for src, tgt in list(self._graph.in_edges(node_id)) + list(self._graph.out_edges(node_id)):
            self._synced.pop(("e", src, tgt), None)
        self._synced.pop(("n", node_id), None)
        self._graph.remove_node(node_id)

    def _prune_tombstones(self) -> None:
        """Forget removals older than TOMBSTONE_TTL, and keep at most TOMBSTONE_CAP of the newest."""
        cutoff = self.now() - TOMBSTONE_TTL
        kept = sorted(((at, nid) for nid, at in self._tombstones.items() if _ts(at) >= cutoff),
                      key=lambda pair: _ts(pair[0]), reverse=True)[:TOMBSTONE_CAP]
        self._tombstones = {nid: at for at, nid in kept}

    def _trust_category(self, score: float) -> str:
        """Convert numeric trust score to category label."""
        if score >= 0.7:
            return "high"
        if score >= 0.4:
            return "medium"
        return "low"

    def _touch_node(self, node_id: str) -> None:
        """Update node recency: the per-process tick drives eviction, the wall-clock stamp orders this
        replica's change against another's when snapshots are merged."""
        self._clock += 1
        self._graph.nodes[node_id]["last_seen_tick"] = self._clock
        self._graph.nodes[node_id]["last_seen_at"] = self._stamp()

    def _touch_edge(self, src: str, tgt: str) -> None:
        """Stamp an edge's last activity, for the same cross-replica ordering as `_touch_node`."""
        self._graph[src][tgt]["last_seen_at"] = self._stamp()

    def _enforce_node_limit(self) -> None:
        """Evict least recently used nodes above cap."""
        while self._graph.number_of_nodes() > self._max_nodes:
            victim = self._oldest_node_id()
            if victim is None:
                return
            self._drop_node(victim)

    def _oldest_node_id(self) -> str | None:
        """Return node id with oldest recency marker."""
        if not self._graph.nodes:
            return None
        # Wall-clock first: after a merge the per-process ticks of nodes that came from another replica
        # say nothing about how recently they were active. Within one process both orders agree.
        return min(self._graph.nodes, key=lambda node_id: (_seen(self._graph.nodes[node_id]),
                                                           int(self._graph.nodes[node_id].get("last_seen_tick", 0))))
