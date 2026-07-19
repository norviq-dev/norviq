// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

import { Suspense, lazy } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { fleetEnabled } from "./api/fleet";
import { Shell } from "./components/layout/Shell";
import { ClusterScoped } from "./components/common/ClusterScoped";
import { ClusterScopedMonitor } from "./components/common/ClusterScopedMonitor";
import { RemoteAgents } from "./components/common/RemoteAgents";
import { AppProvider } from "./store/AppContext";
import { OidcCallback } from "./auth/OidcCallback";
import { Login } from "./auth/Login";
import { getMustChange, getToken } from "./auth/session";
import { BrandLoader } from "./components/common/BrandLoader";

const Dashboard = lazy(() => import("./pages/Dashboard").then((m) => ({ default: m.Dashboard })));
const PolicyCatalog = lazy(() => import("./pages/PolicyCatalog").then((m) => ({ default: m.PolicyCatalog })));
const PolicyPacks = lazy(() => import("./pages/PolicyPacks").then((m) => ({ default: m.PolicyPacks })));
const TargetSettings = lazy(() => import("./pages/TargetSettings").then((m) => ({ default: m.TargetSettings })));
const AuditLog = lazy(() => import("./pages/AuditLog").then((m) => ({ default: m.AuditLog })));
const AgentMonitor = lazy(() => import("./pages/AgentMonitor").then((m) => ({ default: m.AgentMonitor })));
const PolicyTester = lazy(() => import("./pages/PolicyTester").then((m) => ({ default: m.PolicyTester })));
const RedTeam = lazy(() => import("./pages/RedTeam"));
// RedTeam is a shipped, routed feature (see the /redteam route below): efficacy scorecard + per-attack results.
const AssetGraph = lazy(() => import("./pages/AssetGraph"));
const AttackGraph = lazy(() => import("./pages/AttackGraph").then((m) => ({ default: m.AttackGraph })));
const Compliance = lazy(() => import("./pages/Compliance").then((m) => ({ default: m.Compliance })));
const AccountSettings = lazy(() =>
  import("./pages/AccountSettings").then((m) => ({ default: m.AccountSettings }))
);
const APIKeys = lazy(() => import("./pages/APIKeys").then((m) => ({ default: m.APIKeys })));
const GeneralSettings = lazy(() =>
  import("./pages/GeneralSettings").then((m) => ({ default: m.GeneralSettings }))
);
const ConnectionSettings = lazy(() =>
  import("./pages/ConnectionSettings").then((m) => ({ default: m.ConnectionSettings }))
);
const AboutPage = lazy(() => import("./pages/AboutPage").then((m) => ({ default: m.AboutPage })));
const Fleet = lazy(() => import("./pages/Fleet").then((m) => ({ default: m.Fleet })));

function App() {
  // Handle the OIDC redirect outside the authenticated Shell (no token exists yet at this point).
  if (window.location.pathname === "/auth/callback") {
    return <OidcCallback />;
  }
  // Dev convenience: keep the local dev-token bootstrap (never used in a built image).
  if (import.meta.env.DEV && !localStorage.getItem("nrvq_token") && import.meta.env.VITE_DEV_TOKEN) {
    localStorage.setItem("nrvq_token", import.meta.env.VITE_DEV_TOKEN as string);
  }
  // The login gate. No valid session (or the /login route) → the login screen instead of
  // a blank/unauthenticated console. A session still flagged must_change (default admin password) is
  // funneled back into Login, which opens directly on its First-login (change password) view — the prompt,
  // not a server-side lock.
  if (!getToken() || getMustChange() || window.location.pathname === "/login") {
    return <Login />;
  }
  return (
    <AppProvider>
      <Shell>
        <Suspense fallback={<div data-testid="route-loader" style={{ position: "relative", minHeight: "60vh", display: "flex", alignItems: "center", justifyContent: "center" }}><BrandLoader size={56} label="Loading Norviq" /></div>}>
          <Routes>
            {/* Dashboard (Overview) stays mounted for a remote cluster — it shows hub rollups + deep-link tiles. */}
            <Route path="/" element={<Dashboard />} />
            <Route path="/policies" element={<Navigate to="/policies/catalog" replace />} />
            {/* Per-cluster DETAIL pages must not render the served cluster's data under a remote
                label — <ClusterScoped> swaps them for the spoke deep-link when a remote cluster is selected. */}
            <Route path="/policies/catalog" element={<ClusterScoped page="Policy Catalog"><PolicyCatalog /></ClusterScoped>} />
            <Route path="/policies/packs" element={<ClusterScoped page="Policy Packs"><PolicyPacks /></ClusterScoped>} />
            <Route path="/policies/targets" element={<ClusterScoped page="Target Settings"><TargetSettings /></ClusterScoped>} />
            <Route path="/audit" element={<ClusterScoped page="Audit Log"><AuditLog /></ClusterScoped>} />
            {/* Agents is centralized — a remote cluster renders its REAL relayed agents at the hub (with
                freshness); a stale/unreachable spoke falls back to the deep-link. Local renders the full page. */}
            <Route
              path="/agents"
              element={
                <ClusterScopedMonitor
                  page="Agents"
                  hubView={(cluster, hb) => <RemoteAgents cluster={cluster} lastHeartbeat={hb} />}
                >
                  <AgentMonitor />
                </ClusterScopedMonitor>
              }
            />
            <Route path="/test" element={<ClusterScoped page="Policy Tester"><PolicyTester /></ClusterScoped>} />
            <Route path="/redteam" element={<ClusterScoped page="Red Team"><RedTeam /></ClusterScoped>} />
            <Route path="/threats" element={<Navigate to="/threats/graph" replace />} />
            <Route path="/asset-graph" element={<ClusterScoped page="Asset Graph"><AssetGraph /></ClusterScoped>} />
            <Route path="/threats/graph" element={<ClusterScoped page="Attack Graph"><AttackGraph /></ClusterScoped>} />
            {/* Compliance is now a top-level page; the old MITRE route redirects to it. */}
            <Route path="/compliance" element={<ClusterScoped page="Compliance"><Compliance /></ClusterScoped>} />
            <Route path="/threats/mitre" element={<Navigate to="/compliance" replace />} />
            <Route path="/settings" element={<Navigate to="/settings/general" replace />} />
            <Route path="/settings/account" element={<AccountSettings />} />
            <Route path="/settings/api-keys" element={<APIKeys />} />
            <Route path="/settings/general" element={<GeneralSettings />} />
            <Route path="/settings/connections" element={<ConnectionSettings />} />
            <Route path="/settings/about" element={<AboutPage />} />
            {/* Single-cluster-first: /fleet exists only when fleet is enabled; otherwise it redirects home so the
                single-cluster product surfaces no fleet route at all. */}
            <Route path="/fleet" element={fleetEnabled ? <Fleet /> : <Navigate to="/" replace />} />
          </Routes>
        </Suspense>
      </Shell>
    </AppProvider>
  );
}

export default App;
