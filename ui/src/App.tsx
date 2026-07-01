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

const Dashboard = lazy(() => import("./pages/Dashboard").then((m) => ({ default: m.Dashboard })));
const PolicyCatalog = lazy(() => import("./pages/PolicyCatalog").then((m) => ({ default: m.PolicyCatalog })));
const PolicyPacks = lazy(() => import("./pages/PolicyPacks").then((m) => ({ default: m.PolicyPacks })));
const TargetSettings = lazy(() => import("./pages/TargetSettings").then((m) => ({ default: m.TargetSettings })));
const AuditLog = lazy(() => import("./pages/AuditLog").then((m) => ({ default: m.AuditLog })));
const AgentMonitor = lazy(() => import("./pages/AgentMonitor").then((m) => ({ default: m.AgentMonitor })));
const PolicyTester = lazy(() => import("./pages/PolicyTester").then((m) => ({ default: m.PolicyTester })));
// RedTeam page is retained but unrouted (Day-8 stub) until the feature ships.
const AssetGraph = lazy(() => import("./pages/AssetGraph"));
const AttackGraph = lazy(() => import("./pages/AttackGraph").then((m) => ({ default: m.AttackGraph })));
const MITRECoverage = lazy(() => import("./pages/MITRECoverage").then((m) => ({ default: m.MITRECoverage })));
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
  return (
    <AppProvider>
      <Shell>
        <Suspense fallback={<div style={{ padding: 24, color: "var(--text-secondary)" }}>Loading...</div>}>
          <Routes>
            {/* Dashboard (Overview) stays mounted for a remote cluster — it shows hub rollups + deep-link tiles (Stage 3). */}
            <Route path="/" element={<Dashboard />} />
            <Route path="/policies" element={<Navigate to="/policies/catalog" replace />} />
            {/* F-69 Stage 2: per-cluster DETAIL pages must not render the served cluster's data under a remote
                label — <ClusterScoped> swaps them for the spoke deep-link when a remote cluster is selected. */}
            <Route path="/policies/catalog" element={<ClusterScoped page="Policy Catalog"><PolicyCatalog /></ClusterScoped>} />
            <Route path="/policies/packs" element={<ClusterScoped page="Policy Packs"><PolicyPacks /></ClusterScoped>} />
            <Route path="/policies/targets" element={<ClusterScoped page="Target Settings"><TargetSettings /></ClusterScoped>} />
            <Route path="/audit" element={<ClusterScoped page="Audit Log"><AuditLog /></ClusterScoped>} />
            {/* Stage 3: Agents is centralized — a remote cluster renders its REAL relayed agents at the hub (with
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
            <Route path="/threats" element={<Navigate to="/threats/graph" replace />} />
            <Route path="/asset-graph" element={<ClusterScoped page="Asset Graph"><AssetGraph /></ClusterScoped>} />
            <Route path="/threats/graph" element={<ClusterScoped page="Attack Graph"><AttackGraph /></ClusterScoped>} />
            <Route path="/threats/mitre" element={<ClusterScoped page="MITRE Coverage"><MITRECoverage /></ClusterScoped>} />
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
