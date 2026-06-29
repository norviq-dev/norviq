import { createContext, ReactNode, useContext, useEffect, useMemo, useState } from "react";
import { oidcEnabled, login } from "../auth/oidc";

export const CLUSTERS = ["local", "production-aks", "staging-aks", "dev-aks"];
export const NS_BY_CLUSTER: Record<string, string[]> = {
  local: ["default"],
  "production-aks": ["default", "chatbot-prod", "payments", "analytics", "platform"],
  "staging-aks": ["staging-default", "qa"],
  "dev-aks": ["dev-default"]
};
// Env-driven: set VITE_ENV_LABEL per environment (.env.production sets it). Falls back to "local"
// so nothing presumes a specific cluster name when the env var is unset.
const DEFAULT_CLUSTER = import.meta.env.VITE_ENV_LABEL || "local";

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
  setActiveSection: (value: Section) => void;
  setTimeRange: (value: TimeRange) => void;
  setCluster: (value: string) => void;
  setNamespace: (value: string) => void;
};

const AppContext = createContext<AppContextValue | null>(null);

export function AppProvider({ children }: { children: ReactNode }) {
  const [activeSection, setActiveSection] = useState<Section>("intelligence");
  const [timeRange, setTimeRange] = useState<TimeRange>("24h");
  const [selectedCluster, setClusterState] = useState(DEFAULT_CLUSTER);
  const [selectedNamespace, setNamespaceState] = useState("default");

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

  const setCluster = (value: string) => {
    setClusterState(value);
    setNamespaceState((NS_BY_CLUSTER[value] ?? ["default"])[0]);
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
      setActiveSection,
      setTimeRange,
      setCluster,
      setNamespace
    }),
    [activeSection, timeRange, selectedCluster, selectedNamespace]
  );
  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export function useApp() {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error("useApp must be used within AppProvider");
  return ctx;
}
