// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

import { Suspense, lazy } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { Shell } from "./components/layout/Shell";
import { AppProvider } from "./store/AppContext";
import { OidcCallback } from "./auth/OidcCallback";

const Dashboard = lazy(() => import("./pages/Dashboard").then((m) => ({ default: m.Dashboard })));
const PolicyCatalog = lazy(() => import("./pages/PolicyCatalog").then((m) => ({ default: m.PolicyCatalog })));
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
            <Route path="/" element={<Dashboard />} />
            <Route path="/policies" element={<Navigate to="/policies/catalog" replace />} />
            <Route path="/policies/catalog" element={<PolicyCatalog />} />
            <Route path="/policies/targets" element={<TargetSettings />} />
            <Route path="/audit" element={<AuditLog />} />
            <Route path="/agents" element={<AgentMonitor />} />
            <Route path="/test" element={<PolicyTester />} />
            <Route path="/threats" element={<Navigate to="/threats/graph" replace />} />
            <Route path="/asset-graph" element={<AssetGraph />} />
            <Route path="/threats/graph" element={<AttackGraph />} />
            <Route path="/threats/mitre" element={<MITRECoverage />} />
            <Route path="/settings" element={<Navigate to="/settings/general" replace />} />
            <Route path="/settings/account" element={<AccountSettings />} />
            <Route path="/settings/api-keys" element={<APIKeys />} />
            <Route path="/settings/general" element={<GeneralSettings />} />
            <Route path="/settings/connections" element={<ConnectionSettings />} />
            <Route path="/settings/about" element={<AboutPage />} />
            <Route path="/fleet" element={<Fleet />} />
          </Routes>
        </Suspense>
      </Shell>
    </AppProvider>
  );
}

export default App;
