# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Asset graph builder for agent, tool, and data relationships."""

from __future__ import annotations

from datetime import datetime, timezone

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


class AssetGraphBuilder:
    """Build and maintain directed runtime asset graphs."""

    def __init__(self, max_nodes: int = 5000) -> None:
        """Initialize with an empty directed graph."""
        self._graph = nx.DiGraph()
        self._max_nodes = max(100, max_nodes)
        self._clock = 0

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

    def record_tool_call(self, spiffe_id: str, tool_name: str, decision: str, namespace: str = "", agent_class: str = "") -> None:
        """Record an agent to tool call edge."""
        self._ensure_tool_call_nodes(spiffe_id, tool_name, namespace, agent_class)
        tool_id = f"tool:{tool_name}"
        self._upsert_call_edge(spiffe_id, tool_id, decision)
        self._increment_tool_counter(tool_id)
        self._record_mapped_data(tool_name)
        log.debug("nrvq.graph.tool_call_recorded", agent=spiffe_id, tool=tool_name, code="NRVQ-GRP-11000")

    def _ensure_tool_call_nodes(self, spiffe_id: str, tool_name: str, namespace: str, agent_class: str) -> None:
        """Create missing agent or tool nodes before call-edge write."""
        if spiffe_id not in self._graph:
            self.add_agent(spiffe_id, agent_class, namespace)
        else:
            # Same identity, another class (e.g. two agent-class labels on one service account) — record it
            # so the read model can render distinguishable sub-nodes instead of collapsing them.
            self._merge_agent_class(spiffe_id, agent_class)
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
            props["last_timestamp"] = datetime.now(timezone.utc).isoformat()
            self._touch_node(spiffe_id)
            self._touch_node(tool_id)
            return
        edge = GraphEdge(
            source=spiffe_id,
            target=tool_id,
            type=EdgeType.CALLS,
            properties={"call_count": 1, "last_decision": decision, "last_timestamp": datetime.now(timezone.utc).isoformat()},
        )
        self._graph.add_edge(spiffe_id, tool_id, **edge.__dict__)
        self._touch_node(spiffe_id)
        self._touch_node(tool_id)

    def _increment_tool_counter(self, tool_id: str) -> None:
        """Track aggregate call count on tool nodes."""
        props = self._graph.nodes[tool_id].setdefault("properties", {})
        props["call_count"] = int(props.get("call_count", 0)) + 1

    def _record_mapped_data(self, tool_name: str) -> None:
        """Create tool to data edges for configured data mappings."""
        for data_uri in TOOL_DATA_MAP.get(tool_name, []):
            self.record_data_access(tool_name, data_uri)

    def record_delegation(self, from_agent: str, to_agent: str, depth: int = 1) -> None:
        """Record agent delegation edge."""
        if not self._graph.has_node(from_agent):
            self.add_agent(from_agent, "", "")
        if not self._graph.has_node(to_agent):
            self.add_agent(to_agent, "", "")
        edge = GraphEdge(source=from_agent, target=to_agent, type=EdgeType.DELEGATES, properties={"chain_depth": depth})
        self._graph.add_edge(from_agent, to_agent, **edge.__dict__)

    def record_data_access(self, tool_name: str, data_uri: str, access_type: str = "read") -> None:
        """Record tool to data access edge."""
        tool_id = f"tool:{tool_name}"
        data_id = f"data:{data_uri}"
        if tool_id not in self._graph:
            self.add_tool(tool_name)
        if data_id not in self._graph:
            self.add_data(data_uri)
        if self._graph.has_edge(tool_id, data_id):
            return
        edge = GraphEdge(source=tool_id, target=data_id, type=EdgeType.ACCESSES, properties={"access_type": access_type})
        self._graph.add_edge(tool_id, data_id, **edge.__dict__)

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
        """Return node and edge counts by category."""
        counts = {"agents": 0, "tools": 0, "data": 0, "edges": self._graph.number_of_edges()}
        for node_id in self._graph:
            node_type = self._graph.nodes[node_id].get("type")
            if node_type == NodeType.AGENT:
                counts["agents"] += 1
            elif node_type == NodeType.TOOL:
                counts["tools"] += 1
            elif node_type == NodeType.DATA:
                counts["data"] += 1
        return counts

    def remove_node(self, node_id: str) -> bool:
        """Remove a node AND its incident edges — admin housekeeping for a decommissioned or junk
        node (e.g. a probe tool). Returns False when the node isn't present. The graph is otherwise
        append-only, so this is the only sanctioned way a node leaves before LRU-cap eviction."""
        if node_id not in self._graph:
            return False
        self._graph.remove_node(node_id)
        return True

    def to_dict(self) -> dict[str, list[dict[str, object]]]:
        """Serialize graph into JSON-safe node and edge arrays."""
        nodes = [{"id": node_id, **data} for node_id, data in self._graph.nodes(data=True)]
        edges = [{"source": src, "target": tgt, **data} for src, tgt, data in self._graph.edges(data=True)]
        return {"nodes": nodes, "edges": edges}

    def from_dict(self, data: dict[str, object]) -> None:
        """Load graph from serialized dictionary."""
        self._graph.clear()
        for node in data.get("nodes", []):  # type: ignore[union-attr]
            node_copy = dict(node)
            node_id = str(node_copy.pop("id"))
            self._graph.add_node(node_id, **node_copy)
        for edge in data.get("edges", []):  # type: ignore[union-attr]
            edge_copy = dict(edge)
            src = str(edge_copy.pop("source"))
            tgt = str(edge_copy.pop("target"))
            self._graph.add_edge(src, tgt, **edge_copy)
        self._clock = len(self._graph.nodes)

    def _trust_category(self, score: float) -> str:
        """Convert numeric trust score to category label."""
        if score >= 0.7:
            return "high"
        if score >= 0.4:
            return "medium"
        return "low"

    def _touch_node(self, node_id: str) -> None:
        """Update node recency marker used for eviction."""
        self._clock += 1
        self._graph.nodes[node_id]["last_seen_tick"] = self._clock

    def _enforce_node_limit(self) -> None:
        """Evict least recently used nodes above cap."""
        while self._graph.number_of_nodes() > self._max_nodes:
            victim = self._oldest_node_id()
            if victim is None:
                return
            self._graph.remove_node(victim)

    def _oldest_node_id(self) -> str | None:
        """Return node id with oldest recency marker."""
        if not self._graph.nodes:
            return None
        return min(self._graph.nodes, key=lambda node_id: int(self._graph.nodes[node_id].get("last_seen_tick", 0)))
