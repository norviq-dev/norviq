// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

import {
  Award,
  BarChart3,
  Beaker,
  Info,
  Key,
  LayoutDashboard,
  LogOut,
  Network,
  Plug,
  ShieldCheck,
  SlidersHorizontal,
  Target,
  User,
  Users,
  type LucideIcon
} from "lucide-react";
import { NavLink } from "react-router-dom";
import { logout } from "../../api/client";
import { Section, useApp } from "../../store/AppContext";

type NavItem = { to: string; label: string; icon: LucideIcon };
type Group = { id: string; label: string; items: NavItem[] };

const PANEL_CONFIG: Record<Section, { title: string; groups: Group[] }> = {
  security: {
    title: "SECURITY OPERATIONS",
    groups: [
      {
        id: "enforcement",
        label: "ENFORCEMENT",
        items: [
          { to: "/policies/catalog", label: "Policy Catalog", icon: ShieldCheck },
          { to: "/policies/targets", label: "Target Settings", icon: Target }
        ]
      },
      {
        id: "monitoring",
        label: "MONITORING",
        items: [
          { to: "/audit", label: "Audit Log", icon: BarChart3 },
          { to: "/agents", label: "Agents", icon: Users }
        ]
      },
      {
        id: "testing",
        label: "TESTING",
        items: [
          { to: "/test", label: "Policy Tester", icon: Beaker }
          // Red Team is a Day-8 stub; hidden from nav until the feature ships.
        ]
      }
    ]
  },
  intelligence: {
    title: "INTELLIGENCE",
    groups: [
      {
        id: "analytics",
        label: "ANALYTICS",
        items: [{ to: "/", label: "Overview", icon: LayoutDashboard }]
      },
      {
        id: "threat-intel",
        label: "THREAT INTEL",
        items: [
          { to: "/asset-graph", label: "Asset Graph", icon: Network },
          { to: "/threats/graph", label: "Attack Graph", icon: Network },
          { to: "/threats/mitre", label: "MITRE Coverage", icon: Award }
        ]
      }
    ]
  },
  settings: {
    title: "SETTINGS",
    groups: [
      {
        id: "user",
        label: "USER",
        items: [
          { to: "/settings/account", label: "Account Settings", icon: User },
          { to: "/settings/api-keys", label: "API Keys", icon: Key }
        ]
      },
      {
        id: "system",
        label: "SYSTEM",
        items: [
          { to: "/settings/general", label: "General", icon: SlidersHorizontal },
          { to: "/settings/connections", label: "Connections", icon: Plug }
        ]
      },
      {
        id: "about",
        label: "ABOUT",
        items: [{ to: "/settings/about", label: "About Norviq", icon: Info }]
      }
    ]
  }
};

export default function ExpandedPanel({
  overlay = false,
  onNavigate
}: {
  overlay?: boolean;
  onNavigate?: () => void;
}) {
  const { activeSection } = useApp();
  const config = PANEL_CONFIG[activeSection];

  return (
    <div className={`sb-panel${overlay ? " sb-panel-overlay" : ""}`}>
      <div className="sb-brand">{config.title}</div>
      <nav className="sb-nav">
        {config.groups.map((group) => (
          <div key={group.id} className="nav-group">
            <div className="nav-section">{group.label}</div>
            {group.items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === "/"}
                className={({ isActive }) => `sb-link${isActive ? " active" : ""}`}
                onClick={onNavigate}
              >
                <item.icon size={16} />
                <span>{item.label}</span>
              </NavLink>
            ))}
          </div>
        ))}
        {activeSection === "settings" && (
          <div className="nav-group" style={{ marginTop: "auto" }}>
            <button className="sb-link logout-link" type="button" onClick={logout}>
              <LogOut size={16} />
              <span>Logout</span>
            </button>
          </div>
        )}
      </nav>
      <div className="sb-foot">
        © 2026 Norviq Contributors
        <br />
        All rights reserved. · Version 0.1.0
      </div>
    </div>
  );
}
