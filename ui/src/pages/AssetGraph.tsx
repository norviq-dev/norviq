import { useEffect, useMemo, useState } from "react";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApp } from "../store/AppContext";
import { apiUrl } from "../api/client";
import { AssetGraphCanvas } from "../components/asset-graph/AssetGraphCanvas";
import { AssetGraphFilters, type AssetGraphFiltersState } from "../components/asset-graph/AssetGraphFilters";
import { AssetGraphLegend } from "../components/asset-graph/AssetGraphLegend";
import { AssetNodeDetail } from "../components/asset-graph/AssetNodeDetail";
import type { AssetGraphResponse, AssetNode } from "../components/asset-graph/types";

const DEFAULT_FILTERS: AssetGraphFiltersState = {
  types: ["agent", "tool", "data", "namespace"],
  riskLevels: ["low", "medium", "high", "critical"],
  search: ""
};

export default function AssetGraph() {
  const { namespace, timeRange } = useApp();
  const [data, setData] = useState<AssetGraphResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>("");
  const [filters, setFilters] = useState<AssetGraphFiltersState>(DEFAULT_FILTERS);
  const [selectedNode, setSelectedNode] = useState<AssetNode | null>(null);

  useEffect(() => {
    let alive = true;
    const token = localStorage.getItem("nrvq_token");
    setLoading(true);
    setError("");
    fetch(apiUrl(`/api/v1/asset-graph?namespace=${encodeURIComponent(namespace)}&range=${encodeURIComponent(timeRange)}`), {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    })
      .then(async (res) => {
        if (!res.ok) throw new Error(`Request failed: ${res.status}`);
        const json = (await res.json()) as AssetGraphResponse;
        if (alive) setData(json);
      })
      .catch((e: unknown) => {
        if (alive) setError(e instanceof Error ? e.message : "Failed to load");
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [namespace, timeRange]);

  const filtered = useMemo(() => {
    if (!data) return { nodes: [], edges: [] };
    const nodes = data.nodes.filter(
      (node) =>
        filters.types.includes(node.type) &&
        (!node.properties.risk_level || filters.riskLevels.includes(node.properties.risk_level)) &&
        (!filters.search || node.name.toLowerCase().includes(filters.search.toLowerCase()))
    );
    const allowed = new Set(nodes.map((node) => node.id));
    const edges = data.edges.filter((edge) => allowed.has(edge.source) && allowed.has(edge.target));
    return { nodes, edges };
  }, [data, filters]);

  if (loading) return <div>Loading asset graph...</div>;
  if (error) return <div>Failed to load asset graph: {error}</div>;
  if (!data || data.nodes.length === 0) return <div>No assets observed for this namespace.</div>;

  return (
    <div className="page-enter">
      <PageHead title="Asset Graph" subtitle={`Showing: ${namespace}`} />
      <Panel title="Asset Relationships" sub={`${filtered.nodes.length} nodes, ${filtered.edges.length} edges`}>
        <AssetGraphFilters filters={filters} onChange={setFilters} />
        <AssetGraphLegend />
        <AssetGraphCanvas
          nodes={filtered.nodes}
          edges={filtered.edges}
          selectedNodeId={selectedNode?.id}
          onSelectNode={(node) => {
            setSelectedNode(node);
          }}
        />
      </Panel>
      {selectedNode && <AssetNodeDetail node={selectedNode} onClose={() => setSelectedNode(null)} />}
    </div>
  );
}
