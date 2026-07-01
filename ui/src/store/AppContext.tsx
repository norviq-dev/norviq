import { createContext, ReactNode, useContext, useEffect, useMemo, useState } from "react";
import { oidcEnabled, login } from "../auth/oidc";
import { fetchClusterInfo } from "../api/client";
import { fleetEnabled, fetchFleetClusters } from "../api/fleet";
import { setRemoteClusterContext, setSelectedClusterId } from "../api/clusterGuard";

export type Section = "security" | "intelligence" | "settings";
export type TimeRange = "1h" | "6h" | "24h" | "7d" | "30d";

export function sectionFromPath(pathname: string): Section {
  // F-64: /fleet is multi-cluster MANAGEMENT — it now lives under Security Operations (not Intelligence/Analytics).
  if (pathname === "/" || pathname.startsWith("/threats") || pathname.startsWith("/asset-graph"))
    return "intelligence";
  if (pathname.startsWith("/settings")) return "settings";
  return "security";  // includes /fleet, /policies, /audit, /agents, /test
}

type AppContextValue = {
  activeSection: Section;
  timeRange: TimeRange;
  selectedCluster: string;
  selectedNamespace: string;
  // The cluster this console actually serves (/cluster-info) — immutable after load. The Overview uses it to
  // tell "local cluster (full telemetry)" apart from a remote cluster picked in the nav (hub-rollup summary).
  servedCluster: string;
  // F-69: a REMOTE cluster is selected (fleet mode, selection != the served cluster). When true, no page may render
  // or mutate local data under the remote label — pages show hub rollups or an honest deep-link to the spoke console.
  isRemote: boolean;
  // Display label for the active scope ("All clusters" | cluster id | servedCluster).
  scopeCluster: string;
  // The selected cluster's own console URL (from /fleet/clusters console_url, F-69 Stage 4) — drives the deep-link;
  // "" when unknown (the deep-link then shows the cluster id + guidance instead of a dead link).
  selectedClusterConsoleUrl: string;
  cluster: string;
  namespace: string;
  // Live, fleet-aware selector source (F046): replaces the old hardcoded CLUSTERS/NS_BY_CLUSTER.
  clusters: string[];
  namespaces: string[];
  setActiveSection: (value: Section) => void;
  setTimeRange: (value: TimeRange) => void;
  setCluster: (value: string) => void;
  setNamespace: (value: string) => void;
};

const AppContext = createContext<AppContextValue | null>(null);

export function AppProvider({ children }: { children: ReactNode }) {
  const [activeSection, setActiveSection] = useState<Section>("intelligence");
  const [timeRange, setTimeRange] = useState<TimeRange>("24h");
  // F-69: persist the selected cluster so a refresh / deep-link keeps the remote scope (otherwise a reload silently
  // drops back to the served cluster). Validated against the live cluster list in load() below.
  const [selectedCluster, setClusterState] = useState(() => localStorage.getItem("nrvq_cluster") ?? "");
  const [servedCluster, setServedCluster] = useState("");
  const [selectedNamespace, setNamespaceState] = useState("default");
  const [clusters, setClusters] = useState<string[]>([]);
  // id -> console_url (F-69 Stage 4); used to build the spoke deep-link for a remote selection.
  const [clusterConsoleUrls, setClusterConsoleUrls] = useState<Record<string, string>>({});
  const [namespaces, setNamespaces] = useState<string[]>([]);

  useEffect(() => {
    const KEY = "nrvq_token";
    if (localStorage.getItem(KEY)) return;
    // A3: when an IdP is configured, log in via OIDC (Auth Code + PKCE). The callback stores the token.
    if (oidcEnabled) {
      if (window.location.pathname !== "/auth/callback") {
        login().catch((e) => console.error("[oidc] login redirect failed", e));
      }
      return;
    }
    // No IdP configured: keep the dev-token bootstrap for local development.
    if (import.meta.env.DEV) {
      const devToken = import.meta.env.VITE_DEV_TOKEN;
      if (devToken) {
        localStorage.setItem(KEY, devToken);
        console.log("[dev] Auto-injected JWT token for local API");
        window.location.reload();
      } else {
        console.warn("[dev] VITE_DEV_TOKEN not set in ui/.env.local - UI requests will be unauthenticated");
      }
    }
  }, []);

  // Load the live cluster + namespace lists once a token is present. Fleet ON -> clusters from the hub
  // (/fleet/clusters); fleet OFF -> the single real deployment (/cluster-info). Namespaces always come
  // from /cluster-info (this deployment's real, observed namespaces) — never a hardcoded map.
  useEffect(() => {
    let cancelled = false;
    async function load() {
      if (!localStorage.getItem("nrvq_token")) return;
      try {
        const info = await fetchClusterInfo();
        let clusterIds = [info.cluster_id];
        let consoleUrls: Record<string, string> = {};
        if (fleetEnabled) {
          try {
            const fc = await fetchFleetClusters();
            if (fc.length) {
              clusterIds = fc.map((c) => c.id);
              consoleUrls = Object.fromEntries(fc.map((c) => [c.id, c.console_url ?? ""]));
            }
          } catch {
            /* hub unreachable -> fall back to the local single cluster (still real) */
          }
        }
        if (cancelled) return;
        setClusters(clusterIds);
        setClusterConsoleUrls(consoleUrls);
        setServedCluster(info.cluster_id);
        setNamespaces(info.namespaces);
        // F-30: default the pill to the ACTUALLY-SERVED cluster (/cluster-info), not the non-deterministically
        // ordered fleet list's [0] (which made the label flip fleet-a/b/c across navigations). The console only
        // ever serves its own cluster's data, so this is the truthful, stable label.
        setClusterState((prev) => (prev && clusterIds.includes(prev) ? prev : info.cluster_id || clusterIds[0] || ""));
        setNamespaceState((prev) => (info.namespaces.includes(prev) ? prev : info.namespaces[0] ?? "default"));
      } catch {
        /* unauthenticated or API down -> leave lists empty (honest empty selector) */
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  const setCluster = (value: string) => {
    setClusterState(value);
    try {
      localStorage.setItem("nrvq_cluster", value);
    } catch {
      /* storage disabled — selection just won't survive a reload */
    }
    if (!namespaces.includes(selectedNamespace)) setNamespaceState(namespaces[0] ?? "default");
  };

  const setNamespace = (value: string) => setNamespaceState(value);

  // F-69: a remote cluster is selected when fleet is on and the selection differs from the served cluster (or is
  // "All clusters"). Only then do pages switch to hub rollups / deep-links and mutations get blocked.
  const isRemote = fleetEnabled && selectedCluster !== "" && selectedCluster !== servedCluster;
  const scopeCluster = selectedCluster === "all" ? "All clusters" : selectedCluster || servedCluster;
  const selectedClusterConsoleUrl = clusterConsoleUrls[selectedCluster] ?? "";

  // Keep the stateless api-client guard in sync: the UI refuses a cluster-scoped mutation while remote (F-69), and
  // declares the intended target cluster on every mutation so the SERVER can enforce it too (R2 backstop).
  useEffect(() => {
    setRemoteClusterContext(isRemote);
    setSelectedClusterId(selectedCluster || servedCluster);
  }, [isRemote, selectedCluster, servedCluster]);

  const value = useMemo(
    () => ({
      activeSection,
      timeRange,
      selectedCluster,
      selectedNamespace,
      servedCluster,
      isRemote,
      scopeCluster,
      selectedClusterConsoleUrl,
      // Backward-compatible aliases for existing pages/components.
      cluster: selectedCluster,
      namespace: selectedNamespace,
      clusters,
      namespaces,
      setActiveSection,
      setTimeRange,
      setCluster,
      setNamespace
    }),
    [
      activeSection,
      timeRange,
      selectedCluster,
      selectedNamespace,
      servedCluster,
      isRemote,
      scopeCluster,
      selectedClusterConsoleUrl,
      clusters,
      namespaces
    ]
  );
  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export function useApp() {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error("useApp must be used within AppProvider");
  return ctx;
}
