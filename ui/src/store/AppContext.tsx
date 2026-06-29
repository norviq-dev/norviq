import { createContext, ReactNode, useContext, useEffect, useMemo, useState } from "react";
import { oidcEnabled, login } from "../auth/oidc";
import { fetchClusterInfo } from "../api/client";
import { fleetEnabled, fetchFleetClusters } from "../api/fleet";

export type Section = "security" | "intelligence" | "settings";
export type TimeRange = "1h" | "6h" | "24h" | "7d" | "30d";

export function sectionFromPath(pathname: string): Section {
  if (pathname === "/" || pathname.startsWith("/threats") || pathname.startsWith("/asset-graph")) return "intelligence";
  if (pathname.startsWith("/settings")) return "settings";
  return "security";
}

type AppContextValue = {
  activeSection: Section;
  timeRange: TimeRange;
  selectedCluster: string;
  selectedNamespace: string;
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
  const [selectedCluster, setClusterState] = useState("");
  const [selectedNamespace, setNamespaceState] = useState("default");
  const [clusters, setClusters] = useState<string[]>([]);
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
        if (fleetEnabled) {
          try {
            const fc = await fetchFleetClusters();
            if (fc.length) clusterIds = fc.map((c) => c.id);
          } catch {
            /* hub unreachable -> fall back to the local single cluster (still real) */
          }
        }
        if (cancelled) return;
        setClusters(clusterIds);
        setNamespaces(info.namespaces);
        setClusterState((prev) => (prev && clusterIds.includes(prev) ? prev : clusterIds[0] ?? ""));
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
    if (!namespaces.includes(selectedNamespace)) setNamespaceState(namespaces[0] ?? "default");
  };

  const setNamespace = (value: string) => setNamespaceState(value);

  const value = useMemo(
    () => ({
      activeSection,
      timeRange,
      selectedCluster,
      selectedNamespace,
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
    [activeSection, timeRange, selectedCluster, selectedNamespace, clusters, namespaces]
  );
  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export function useApp() {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error("useApp must be used within AppProvider");
  return ctx;
}
