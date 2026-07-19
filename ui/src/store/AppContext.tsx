import { createContext, ReactNode, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { oidcEnabled, login } from "../auth/oidc";
import { getToken, tokenSubject } from "../auth/session";
import { fetchClusterInfo, fetchSettings, RuntimeSettings } from "../api/client";
import { primeApiCache, readFreshApiCache } from "../hooks/useApi";
import { fleetEnabled, fetchFleetClusters } from "../api/fleet";
import { setRemoteClusterContext, setSelectedClusterId } from "../api/clusterGuard";

export type Section = "security" | "intelligence" | "settings";
export type TimeRange = "1h" | "6h" | "24h" | "7d" | "30d";

export function sectionFromPath(pathname: string): Section {
  // /fleet is multi-cluster MANAGEMENT — it lives under Security Operations.
  if (pathname === "/" || pathname.startsWith("/threats") || pathname.startsWith("/asset-graph"))
    return "intelligence";
  if (pathname.startsWith("/settings")) return "settings";
  return "security";  // includes /fleet, /policies, /audit, /agents, /test
}

// The server-enforced governance posture of the SELECTED scope — the one source of truth every
// page that makes an enforcement claim ("ENFORCING", "blocked", "proven-blocking") must consult.
// mode "audit" = Monitor (evaluate & log would-block, live traffic NOT blocked). namespace "all" carries
// the cluster DEFAULT posture (per-ns overrides may differ — pages that aggregate handle that per-row).
export type Posture = {
  namespace: string;
  mode: RuntimeSettings["enforcement_mode"] | null; // null = not yet loaded / API unreachable (unknown, NOT "block")
  applyMode: NonNullable<RuntimeSettings["apply_mode"]> | null; // "dry_run_only" = policy edits frozen
  loading: boolean;
};

type AppContextValue = {
  activeSection: Section;
  timeRange: TimeRange;
  selectedCluster: string;
  selectedNamespace: string;
  // The cluster this console actually serves (/cluster-info) — immutable after load. The Overview uses it to
  // tell "local cluster (full telemetry)" apart from a remote cluster picked in the nav (hub-rollup summary).
  servedCluster: string;
  // A REMOTE cluster is selected (fleet mode, selection != the served cluster). When true, no page may render
  // or mutate local data under the remote label — pages show hub rollups or an honest deep-link to the spoke console.
  isRemote: boolean;
  // Display label for the active scope ("All clusters" | cluster id | servedCluster).
  scopeCluster: string;
  // The selected cluster's own console URL (from /fleet/clusters console_url) — drives the deep-link;
  // "" when unknown (the deep-link then shows the cluster id + guidance instead of a dead link).
  selectedClusterConsoleUrl: string;
  cluster: string;
  namespace: string;
  // Live, fleet-aware selector source: replaces the old hardcoded CLUSTERS/NS_BY_CLUSTER.
  clusters: string[];
  namespaces: string[];
  // Governance posture of the selected scope + a refresh hook for pages that mutate it
  // (Target Settings / Settings save paths call refreshPosture so the global banner updates live).
  posture: Posture;
  refreshPosture: () => void;
  setActiveSection: (value: Section) => void;
  setTimeRange: (value: TimeRange) => void;
  setCluster: (value: string) => void;
  setNamespace: (value: string) => void;
};

const AppContext = createContext<AppContextValue | null>(null);

const NS_KEY = "nrvq_namespace";
const NS_OWNER_KEY = "nrvq_namespace_sub"; // Which identity stored the ns selection

// Initial namespace resolution, in precedence order:
//   1. the URL's ?ns= (shareable links / refresh keep the exact scope the sender saw)
//   2. the stored selection — but ONLY if it was stored by the SAME identity; a scoped viewer
//      signing in after an admin must not inherit the admin's (possibly invalid) namespace.
//   3. "all"
function initialNamespace(search: string): string {
  try {
    const urlNs = new URLSearchParams(search).get("ns");
    if (urlNs) return urlNs;
    const owner = localStorage.getItem(NS_OWNER_KEY);
    const sub = tokenSubject();
    if (owner && sub && owner !== sub) return "all";
    return localStorage.getItem(NS_KEY) ?? "all";
  } catch {
    return "all";
  }
}

export function AppProvider({ children }: { children: ReactNode }) {
  const [activeSection, setActiveSection] = useState<Section>("intelligence");
  const [timeRange, setTimeRange] = useState<TimeRange>("24h");
  const location = useLocation();
  const navigate = useNavigate();
  // Persist the selected cluster so a refresh / deep-link keeps the remote scope (otherwise a reload silently
  // drops back to the served cluster). Validated against the live cluster list in load() below.
  const [selectedCluster, setClusterState] = useState(() => localStorage.getItem("nrvq_cluster") ?? "");
  const [servedCluster, setServedCluster] = useState("");
  // Persist the selected namespace like the cluster, so a chosen concrete namespace STICKS across navigation
  // instead of resetting to the aggregate "All namespaces" every route change. Empty/absent → "all" (the
  // aggregate guard still applies); we never silently auto-default to a concrete namespace.
  // URL ?ns= wins over the stored selection, and the stored selection is identity-scoped.
  const [selectedNamespace, setNamespaceState] = useState(() => initialNamespace(location.search));
  const [clusters, setClusters] = useState<string[]>([]);
  // id -> console_url; used to build the spoke deep-link for a remote selection.
  const [clusterConsoleUrls, setClusterConsoleUrls] = useState<Record<string, string>>({});
  const [namespaces, setNamespaces] = useState<string[]>([]);

  useEffect(() => {
    const KEY = "nrvq_token";
    if (getToken()) return;
    // When an IdP is configured, log in via OIDC (Auth Code + PKCE). The callback stores the token.
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
      if (!getToken()) return;
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
        // Default the pill to the ACTUALLY-SERVED cluster (/cluster-info), not the non-deterministically
        // ordered fleet list's [0] (which made the label flip fleet-a/b/c across navigations). The console only
        // ever serves its own cluster's data, so this is the truthful, stable label.
        setClusterState((prev) => (prev && clusterIds.includes(prev) ? prev : info.cluster_id || clusterIds[0] || ""));
        // Default to "All namespaces" so the console shows every namespace's data on load (a fresh
        // deploy's traffic often lands outside "default"). Keep an explicit prior selection if still valid.
        setNamespaceState((prev) => (prev === "all" || info.namespaces.includes(prev) ? prev : "all"));
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
    if (selectedNamespace !== "all" && !namespaces.includes(selectedNamespace)) setNamespaceState("all");
  };

  const setNamespace = (value: string) => {
    setNamespaceState(value);
    try {
      localStorage.setItem(NS_KEY, value); // Survive navigation + reload
      localStorage.setItem(NS_OWNER_KEY, tokenSubject() ?? ""); // Identity-scoped
    } catch {
      /* storage disabled — selection just won't persist */
    }
  };

  // Keep ?ns= on the URL in sync with the selection (state → URL, replace-only so history
  // isn't spammed). "all" is the default and stays OFF the URL for clean links. Other query params
  // (audit deep-link filters, intent_draft, …) are preserved untouched.
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const urlNs = params.get("ns");
    const wantNs = selectedNamespace === "all" ? null : selectedNamespace;
    if (urlNs === wantNs) return;
    if (wantNs === null) params.delete("ns");
    else params.set("ns", wantNs);
    const query = params.toString();
    navigate(`${location.pathname}${query ? `?${query}` : ""}${location.hash}`, { replace: true });
  }, [selectedNamespace, location.pathname, location.search, location.hash, navigate]);

  // Governance posture of the selected scope. "all" (no ns param) returns the cluster DEFAULT
  // posture. postureVersion lets mutating pages (Target Settings / Settings) force a refetch so the
  // global banner reflects a mode flip immediately.
  const [posture, setPosture] = useState<Posture>({ namespace: "all", mode: null, applyMode: null, loading: false });
  const [postureVersion, setPostureVersion] = useState(0);
  // Share the settings fetch with the pages that also read it (PolicyPacks uses the same
  // `settings:${ns}` useApi key), so a namespace switch doesn't issue a duplicate GET. refreshPosture bumps
  // postureVersion which (via the mutating pages' invalidateApiCache("settings:")) forces a real refetch.
  const SETTINGS_KEY = `settings:${selectedNamespace}`; // must match PolicyPacks' useApi cacheKey exactly
  const refreshPosture = useCallback(() => setPostureVersion((v) => v + 1), []);
  useEffect(() => {
    if (!getToken()) return;
    let cancelled = false;
    const applyPosture = (s: RuntimeSettings) =>
      setPosture({
        namespace: selectedNamespace,
        mode: s.enforcement_mode ?? null,
        applyMode: s.apply_mode ?? "enforce",
        loading: false
      });
    // Read-through: reuse a fresh cached settings entry a page already loaded (dedupes the fetch).
    const cached = readFreshApiCache(SETTINGS_KEY, 15_000) as RuntimeSettings | undefined;
    if (cached) {
      applyPosture(cached);
      return;
    }
    setPosture((p) => ({ ...p, loading: true }));
    fetchSettings(selectedNamespace)
      .then((s) => {
        if (cancelled) return;
        primeApiCache(SETTINGS_KEY, s); // write-through: a page's useApi(settings:) now gets a hit
        applyPosture(s);
      })
      .catch(() => {
        // Unknown posture is surfaced as unknown (null) — never assumed to be "block".
        if (!cancelled) setPosture({ namespace: selectedNamespace, mode: null, applyMode: null, loading: false });
      });
    return () => {
      cancelled = true;
    };
  }, [selectedNamespace, postureVersion, SETTINGS_KEY]);

  // A remote cluster is selected when fleet is on and the selection differs from the served cluster (or is
  // "All clusters"). Only then do pages switch to hub rollups / deep-links and mutations get blocked.
  const isRemote = fleetEnabled && selectedCluster !== "" && selectedCluster !== servedCluster;
  const scopeCluster = selectedCluster === "all" ? "All clusters" : selectedCluster || servedCluster;
  const selectedClusterConsoleUrl = clusterConsoleUrls[selectedCluster] ?? "";

  // Keep the stateless api-client guard in sync: the UI refuses a cluster-scoped mutation while remote, and
  // declares the intended target cluster on every mutation so the SERVER can enforce it too (backstop).
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
      posture,
      refreshPosture,
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
      namespaces,
      posture,
      refreshPosture
    ]
  );
  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export function useApp() {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error("useApp must be used within AppProvider");
  return ctx;
}
