// Header — the top application bar: global search (with keyboard-navigable results), the time-range
// selector, notifications, the cluster/namespace scope selectors, and the governance-posture chip.

import {
  Bell,
  Check,
  ChevronDown,
  Menu,
  Search,
  Server,
  X
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { isTimeScoped } from "../../lib/routeMeta";
import {
  fetchAllAgents,
  fetchAuditStats,
  fetchMe,
  fetchSearch,
  logout,
  Me
} from "../../api/client";
import { fleetEnabled } from "../../api/fleet";
import { TimeRange, useApp } from "@/store/AppContext";

type Dropdown = "cluster" | "inbox" | null;
type InboxPayload = { blockedCount: number; lowTrustCount: number; checkedAt: Date };
type ToolResult = { tool_name?: string; decision?: string; timestamp?: string };
type AgentResult = { spiffe_id?: string; agent_class?: string; score?: number; trust_score?: number };
type PolicyResult = { namespace?: string; agent_class?: string; mode?: string };

function debounce<T extends (...args: string[]) => void>(fn: T, delay: number) {
  let timeout: ReturnType<typeof setTimeout> | null = null;
  return (...args: Parameters<T>) => {
    if (timeout) clearTimeout(timeout);
    timeout = setTimeout(() => fn(...args), delay);
  };
}

export function Header({
  isTablet,
  onMenuToggle,
  tabletMenuOpen,
  showMenuButton = true
}: {
  isTablet: boolean;
  onMenuToggle: () => void;
  tabletMenuOpen: boolean;
  showMenuButton?: boolean;
}) {
  const {
    selectedCluster,
    selectedNamespace,
    clusters,
    namespaces,
    timeRange,
    posture,
    setCluster,
    setNamespace,
    setTimeRange
  } = useApp();
  const navigate = useNavigate();
  // The time-range selector is shown ONLY on routes the global range genuinely drives (one source of
  // truth in lib/routeMeta) — hidden on current-state pages (Catalog/Packs/Targets) and on pages with their
  // own in-page range picker (Compliance/Attack Graph/Asset Graph), so there is no dead/duplicate control.
  const timeScoped = isTimeScoped(useLocation().pathname);
  // The cluster selector only repoints the Fleet page; on every other page the data is the local cluster's.
  // So allow switching ONLY on /fleet and show a read-only "viewing local cluster" notice elsewhere (no false affordance).
  const [open, setOpen] = useState<Dropdown | "user">(null);
  const [searchText, setSearchText] = useState("");
  const [searchFocused, setSearchFocused] = useState(false);
  const [toolResults, setToolResults] = useState<ToolResult[]>([]);
  const [agentResults, setAgentResults] = useState<AgentResult[]>([]);
  const [policyResults, setPolicyResults] = useState<PolicyResult[]>([]);
  const [searchLoading, setSearchLoading] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [inboxLoading, setInboxLoading] = useState(false);
  const [inboxData, setInboxData] = useState<InboxPayload | null>(null);
  const [me, setMe] = useState<Me | null>(null);
  const inboxCacheRef = useRef<{ ns: string; timestamp: number; payload: InboxPayload } | null>(null);
  const searchAbortRef = useRef<AbortController | null>(null);
  const searchInputRef = useRef<HTMLInputElement | null>(null);
  const searchContainerRef = useRef<HTMLDivElement | null>(null);
  const close = () => setOpen(null);

  const compactCluster = useMemo(() => {
    if (!isTablet) return selectedCluster;
    if (selectedCluster.startsWith("production")) return "prod";
    if (selectedCluster.startsWith("staging")) return "stg";
    if (selectedCluster.startsWith("dev")) return "dev";
    return selectedCluster;
  }, [isTablet, selectedCluster]);

  // The signed-in user, resolved by the server (/me).
  useEffect(() => {
    let active = true;
    fetchMe()
      .then((m) => {
        if (active) setMe(m);
      })
      .catch(() => {
        /* unauthenticated -> leave null; the avatar shows a neutral placeholder */
      });
    return () => {
      active = false;
    };
  }, []);

  const displayName = me?.name || me?.sub || "—";
  const displayRole = me?.role || "—";
  const initials =
    (me?.name || me?.sub || "")
      .split(/[\s@._-]+/)
      .filter(Boolean)
      .map((w) => w[0])
      .join("")
      .slice(0, 2)
      .toUpperCase() || "?";

  const loadInbox = useCallback(async () => {
    const now = Date.now();
    // Inbox is scoped to the SELECTED namespace — cache per namespace so a switch doesn't show the
    // previous scope's counts.
    if (
      inboxCacheRef.current &&
      inboxCacheRef.current.ns === selectedNamespace &&
      now - inboxCacheRef.current.timestamp < 60_000
    ) {
      setInboxData(inboxCacheRef.current.payload);
      return;
    }

    setInboxLoading(true);
    try {
      const [stats, agents] = await Promise.all([
        fetchAuditStats("24h", selectedNamespace),
        fetchAllAgents()
      ]);
      const blockedCount = Number(stats?.blocked ?? 0);
      // SearchAgent has no namespace field, but the SPIFFE id encodes it (spiffe://…/ns/{ns}/sa/…) —
      // scope the low-trust count to the selected namespace client-side.
      const inScope = (agent: { spiffe_id?: string }) =>
        selectedNamespace === "all" || (agent.spiffe_id ?? "").includes(`/ns/${selectedNamespace}/`);
      const lowTrustCount = (agents ?? []).filter((agent) => {
        if (!inScope(agent)) return false;
        const score =
          typeof agent.score === "number"
            ? agent.score
            : typeof agent.trust_score === "number"
            ? agent.trust_score
            : null;
        return score != null && score < 0.4;
      }).length;
      const payload = { blockedCount, lowTrustCount, checkedAt: new Date() };
      inboxCacheRef.current = { ns: selectedNamespace, timestamp: now, payload };
      setInboxData(payload);
    } catch {
      const payload = { blockedCount: 0, lowTrustCount: 0, checkedAt: new Date() };
      setInboxData(payload);
    } finally {
      setInboxLoading(false);
    }
  }, [selectedNamespace]);

  const inboxBadgeCount = (inboxData?.blockedCount ?? 0) + (inboxData?.lowTrustCount ?? 0);
  const searchPanelOpen = !isTablet && searchFocused && searchText.trim().length > 0;
  // Both the tablet popup and the desktop dropdown render the same results panel (results shown on
  // every viewport width, including ≤1023px).
  const tabletPanelOpen = isTablet && searchOpen && searchText.trim().length > 0;
  const hasSearchResults = toolResults.length + agentResults.length + policyResults.length > 0;

  const formatTimeAgo = (value?: string) => {
    if (!value) return "just now";
    const date = new Date(value);
    const diffMinutes = Math.max(0, Math.floor((Date.now() - date.getTime()) / 60_000));
    if (diffMinutes < 1) return "just now";
    if (diffMinutes < 60) return `${diffMinutes}m ago`;
    const hours = Math.floor(diffMinutes / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
  };

  // Shared between the desktop inline dropdown and the tablet popup — one render path so the
  // two widths can never diverge again.
  const closeSearch = useCallback(() => {
    setSearchFocused(false);
    setSearchOpen(false);
  }, []);

  const renderSearchResults = () => (
    <>
      {searchLoading ? (
        <div style={{ padding: 12, color: "#A0A0A0", fontSize: 13 }}>Searching...</div>
      ) : hasSearchResults ? (
        <>
          {toolResults.length > 0 && (
            <>
              <div className="dd-head">TOOLS</div>
              {toolResults.map((item, idx) => (
                <button
                  key={`${item.tool_name ?? "tool"}-${idx}`}
                  type="button"
                  className="dd-item"
                  style={{ padding: 10, borderBottom: "1px solid #2A2A2A", borderRadius: 0 }}
                  onClick={() => {
                    navigate(`/audit?tool_name=${encodeURIComponent(item.tool_name ?? "")}`);
                    closeSearch();
                  }}
                >
                  🔧 {item.tool_name ?? "unknown"} — {item.decision ?? "audit"} — {formatTimeAgo(item.timestamp)}
                </button>
              ))}
            </>
          )}
          {agentResults.length > 0 && (
            <>
              <div className="dd-head">AGENTS</div>
              {agentResults.map((item, idx) => (
                <button
                  key={`${item.agent_class ?? "agent"}-${idx}`}
                  type="button"
                  className="dd-item"
                  style={{ padding: 10, borderBottom: "1px solid #2A2A2A", borderRadius: 0 }}
                  onClick={() => {
                    navigate("/agents");
                    closeSearch();
                  }}
                >
                  👤 {item.agent_class ?? "unknown"} — trust{" "}
                  {((typeof item.score === "number" ? item.score : item.trust_score) ?? 0).toFixed(2)}
                </button>
              ))}
            </>
          )}
          {policyResults.length > 0 && (
            <>
              <div className="dd-head">POLICIES</div>
              {policyResults.map((item, idx) => (
                <button
                  key={`${item.namespace ?? "ns"}-${item.agent_class ?? "class"}-${idx}`}
                  type="button"
                  className="dd-item"
                  style={{ padding: 10, borderBottom: "1px solid #2A2A2A", borderRadius: 0 }}
                  onClick={() => {
                    navigate("/policies/catalog");
                    closeSearch();
                  }}
                >
                  📋 {item.namespace ?? "default"}/{item.agent_class ?? "unknown"} — {item.mode ?? "audit"}
                </button>
              ))}
            </>
          )}
        </>
      ) : (
        <div style={{ padding: 12, color: "#A0A0A0", fontSize: 13 }}>
          No results for '{searchText.trim()}'
        </div>
      )}
    </>
  );

  const runSearch = useCallback(async (query: string) => {
    const q = query.trim();
    if (!q) {
      setToolResults([]);
      setAgentResults([]);
      setPolicyResults([]);
      setSearchLoading(false);
      return;
    }

    searchAbortRef.current?.abort();
    const controller = new AbortController();
    searchAbortRef.current = controller;
    setSearchLoading(true);
    try {
      // ONE server-scoped, bounded call (replaces a three-endpoint client-side fan-out).
      const results = await fetchSearch(q, controller.signal);
      if (controller.signal.aborted) return;
      setToolResults((results.tools ?? []).slice(0, 3));
      setAgentResults((results.agents ?? []).slice(0, 3));
      setPolicyResults((results.policies ?? []).slice(0, 3));
    } catch (error) {
      if (!(error instanceof DOMException && error.name === "AbortError")) {
        setToolResults([]);
        setAgentResults([]);
        setPolicyResults([]);
      }
    } finally {
      if (!controller.signal.aborted) setSearchLoading(false);
    }
  }, [setToolResults, setAgentResults, setPolicyResults]);

  const debouncedSearch = useMemo(() => debounce(runSearch, 300), [runSearch]);

  useEffect(() => {
    debouncedSearch(searchText);
    return () => {
      searchAbortRef.current?.abort();
    };
  }, [debouncedSearch, searchText]);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        searchInputRef.current?.focus();
        setSearchFocused(true);
      }
      if (e.key === "Escape") {
        setSearchFocused(false);
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  useEffect(() => {
    const onPointerDown = (event: MouseEvent) => {
      if (!searchContainerRef.current) return;
      if (!searchContainerRef.current.contains(event.target as Node)) {
        setSearchFocused(false);
      }
    };
    document.addEventListener("mousedown", onPointerDown);
    return () => document.removeEventListener("mousedown", onPointerDown);
  }, []);

  return (
    <header className="topbar">
      <div className="tb-left-center">
        {isTablet && showMenuButton && (
          <button className="icon-btn tablet-menu-btn" title="Menu" onClick={onMenuToggle}>
            <Menu size={20} style={{ color: tabletMenuOpen ? "var(--accent)" : undefined }} />
          </button>
        )}
        <button className="cluster-sel" onClick={() => setOpen(open === "cluster" ? null : "cluster")}>
          <Server size={15} style={{ color: "var(--accent)" }} />
          <span className="mono">
            {/* Single-cluster-first: the cluster concept only appears when fleet is enabled. Off -> namespace only. */}
            {fleetEnabled && <>{compactCluster} / </>}
            <span style={{ color: "var(--text-primary)" }}>{selectedNamespace === "all" ? "All namespaces" : selectedNamespace}</span>
          </span>
          <ChevronDown size={14} style={{ color: "var(--text-secondary)" }} />
        </button>
        {open === "cluster" && (
          <div className="dropdown cluster-dd">
            {fleetEnabled && (
              <div className="cluster-col">
                <div className="dd-head">CLUSTER</div>
                {/* The global nav dropdown is the ONE cluster switcher.
                    Switching repoints the fleet view in place — no force-navigation. */}
                {[...new Set(["all", ...clusters])].map((c) => (
                  <button
                    key={c}
                    className={`dd-item${c === selectedCluster ? " sel" : ""}`}
                    onClick={() => { setCluster(c); close(); }}
                  >
                    <span>{c === "all" ? "All clusters" : c}</span>
                    {c === selectedCluster && <Check size={14} style={{ color: "var(--allow)" }} />}
                  </button>
                ))}
              </div>
            )}
            <div className="cluster-col" style={fleetEnabled ? { borderLeft: "1px solid var(--border)" } : undefined}>
              <div className="dd-head">NAMESPACES</div>
              {/* dedupe: "all" is the synthetic "All namespaces" sentinel — a tenant ns literally named "all"
                  (a fleet-wide policy) would otherwise render a duplicate entry. */}
              {[...new Set(["all", ...namespaces])].map((ns) => (
                <button
                  key={ns}
                  className={`dd-item${ns === selectedNamespace ? " sel" : ""}`}
                  onClick={() => {
                    setNamespace(ns);
                    close();
                  }}
                >
                  <span>{ns === "all" ? "All namespaces" : ns}</span>
                  {ns === selectedNamespace && <Check size={14} style={{ color: "var(--allow)" }} />}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Rendered only where the global range drives the page (see lib/routeMeta). */}
      {timeScoped && (
      <div className="time-range-wrap" role="group" aria-label="Time range" data-testid="time-range">
        {(["1h", "6h", "24h", "7d", "30d"] as TimeRange[]).map((range) => {
          const isActive = timeRange === range;
          return (
            <button
              key={range}
              type="button"
              // Visible ACTIVE state — teal --accent fill + aria-pressed + an `active` class,
              // keyboard-focusable (native button), distinct from the muted inactive chips. No off-palette hex.
              className={`range-chip${isActive ? " active" : ""}`}
              aria-pressed={isActive}
              data-testid={`range-chip-${range}`}
              onClick={() => setTimeRange(range)}
              style={{
                padding: "4px 12px",
                borderRadius: 16,
                fontSize: 12,
                fontWeight: isActive ? 600 : 500,
                border: "none",
                cursor: "pointer",
                background: isActive ? "var(--accent)" : "transparent",
                color: isActive ? "var(--bg-void)" : "var(--text-secondary)"
              }}
              onMouseEnter={(e) => {
                if (!isActive) e.currentTarget.style.color = "var(--text-primary)";
              }}
              onMouseLeave={(e) => {
                if (!isActive) e.currentTarget.style.color = "var(--text-secondary)";
              }}
            >
              {range}
            </button>
          );
        })}
      </div>
      )}

      {!isTablet && (
        <div className="tb-search" ref={searchContainerRef}>
          <Search size={14} style={{ color: "var(--text-secondary)" }} />
          <input
            ref={searchInputRef}
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            onFocus={() => setSearchFocused(true)}
            placeholder="Search tools, agents, rules..."
            aria-label="Search"
            onKeyDown={(e) => {
              if (e.key === "Escape") {
                setSearchFocused(false);
                (e.target as HTMLInputElement).blur();
              }
            }}
            style={{
              flex: 1,
              background: "transparent",
              border: "none",
              color: "var(--text-primary)",
              outline: "none",
              fontSize: 13.5
            }}
          />
          <span className="kbd">⌘K</span>
          {searchPanelOpen && (
            <div
              className="dropdown"
              style={{
                top: "calc(100% + 8px)",
                left: 0,
                right: 0,
                width: "100%",
                background: "#171717",
                border: "1px solid #2A2A2A",
                borderRadius: 12,
                overflow: "hidden"
              }}
            >
              {renderSearchResults()}
            </div>
          )}
        </div>
      )}

      <div className="tb-right">
        {/* Governance posture of the selected scope — Monitor = evaluate & log would-block but
            ALLOW, so every "blocked/enforcing" claim is qualified by this chip. Lives top-RIGHT with the
            other status controls (inbox/account). Click-through → Target Settings. */}
        {posture.mode === "audit" && (
          <button
            type="button"
            className="posture-chip"
            data-testid="posture-chip-monitor"
            title={`${posture.namespace === "all" ? "Cluster default" : `Namespace ${posture.namespace}`} is in Monitor mode — decisions are evaluated and logged, live traffic is NOT blocked. Click to change in Target Settings.`}
            onClick={() => navigate("/policies/targets")}
            style={{
              display: "inline-flex", alignItems: "center", gap: 7, padding: "4px 11px", borderRadius: 999,
              fontSize: 11.5, fontWeight: 600, background: "rgba(255,176,32,0.10)",
              border: "1px solid rgba(255,176,32,0.35)", color: "var(--escalate)", cursor: "pointer", whiteSpace: "nowrap"
            }}
          >
            <span aria-hidden="true" style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--escalate)" }} />
            Monitor mode
          </button>
        )}
        {posture.applyMode === "dry_run_only" && (
          <button
            type="button"
            className="posture-chip"
            data-testid="posture-chip-frozen"
            title="Policy edits are FROZEN for this scope (change control) — live policy still enforces. Click to review in Target Settings."
            onClick={() => navigate("/policies/targets")}
            style={{
              display: "inline-flex", alignItems: "center", gap: 6, padding: "4px 10px", borderRadius: 999,
              fontSize: 11, fontWeight: 600, background: "transparent", border: "1px solid var(--text-muted)",
              color: "var(--text-secondary)", cursor: "pointer", whiteSpace: "nowrap"
            }}
          >
            Edits frozen
          </button>
        )}
        {isTablet && (
          <button className="icon-btn" title="Search" onClick={() => setSearchOpen((v) => !v)}>
            <Search size={18} />
          </button>
        )}
        <button
          className="icon-btn"
          title="Inbox"
          onClick={() => {
            if (open === "inbox") {
              setOpen(null);
              return;
            }
            setOpen("inbox");
            void loadInbox();
          }}
        >
          <Bell size={20} />
          {inboxBadgeCount > 0 && <span className="bell-badge">{inboxBadgeCount}</span>}
        </button>
        <button
          className="avatar"
          title="Account"
          onClick={() => setOpen(open === "user" ? null : "user")}
        >
          {initials}
        </button>
        {open === "inbox" && (
          <div
            className="dropdown"
            style={{
              top: 46,
              right: 0,
              width: 320,
              background: "#171717",
              border: "1px solid #2A2A2A",
              borderRadius: 12,
              overflow: "hidden"
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "10px 12px",
                borderBottom: "1px solid #2A2A2A",
                fontSize: 13,
                fontWeight: 600
              }}
            >
              <span>Inbox · {selectedNamespace === "all" ? "all namespaces" : selectedNamespace}</span>
              <button className="icon-btn" style={{ width: 28, height: 28 }} onClick={close} title="Close">
                <X size={16} />
              </button>
            </div>
            {inboxLoading ? (
              <div style={{ padding: 12, color: "#A0A0A0", fontSize: 13 }}>Checking alerts...</div>
            ) : (
              <>
                {(inboxData?.blockedCount ?? 0) > 0 && (
                  <button
                    type="button"
                    className="dd-item"
                    style={{ padding: 12, borderBottom: "1px solid #2A2A2A", borderRadius: 0 }}
                    onClick={() => {
                      // Deep-link carries the current namespace so the Audit Log lands pre-scoped.
                      const nsq = selectedNamespace === "all" ? "" : `&ns=${encodeURIComponent(selectedNamespace)}`;
                      navigate(`/audit?decision=block${nsq}`);
                      close();
                    }}
                  >
                    🔴 {inboxData?.blockedCount} tool calls blocked in last 24h
                  </button>
                )}
                {(inboxData?.lowTrustCount ?? 0) > 0 && (
                  <button
                    type="button"
                    className="dd-item"
                    style={{ padding: 12, borderBottom: "1px solid #2A2A2A", borderRadius: 0 }}
                    onClick={() => {
                      const nsq = selectedNamespace === "all" ? "" : `?ns=${encodeURIComponent(selectedNamespace)}`;
                      navigate(`/agents${nsq}`);
                      close();
                    }}
                  >
                    🟡 {inboxData?.lowTrustCount} agent(s) below trust threshold
                  </button>
                )}
                {(inboxData?.blockedCount ?? 0) === 0 && (inboxData?.lowTrustCount ?? 0) === 0 && (
                  <div style={{ padding: 12, borderBottom: "1px solid #2A2A2A", fontSize: 13 }}>
                    🟢 All systems healthy — no alerts
                  </div>
                )}
                <div style={{ padding: "8px 12px", color: "#666666", fontSize: 11 }}>
                  Last checked: {inboxData?.checkedAt ? inboxData.checkedAt.toLocaleTimeString() : "just now"}
                </div>
              </>
            )}
          </div>
        )}
        {open === "user" && (
          <div
            className="dropdown"
            style={{
              top: 46,
              right: 0,
              width: 320,
              background: "#171717",
              border: "1px solid #2A2A2A",
              borderRadius: 12,
              overflow: "hidden"
            }}
          >
            <div style={{ padding: "12px 14px" }}>
              <div style={{ fontSize: 14, fontWeight: 500, color: "#FFFFFF" }}>{displayName}</div>
              {/* Surface the server-resolved permission scope (role + namespace) so the operator
                  always sees who they are signed in as and what they can reach. */}
              <div style={{ fontSize: 12, color: "#A0A0A0", marginTop: 2 }}>
                {displayRole} · {me?.namespace ? `namespace: ${me.namespace}` : "all namespaces"}
              </div>
            </div>
            <div className="dd-divider" />
            <button
              className="dd-item"
              style={{ padding: 12, borderRadius: 0, borderBottom: "1px solid #2A2A2A" }}
              onClick={() => {
                navigate("/settings/account");
                close();
              }}
            >
              Account Settings
            </button>
            <button
              className="dd-item"
              style={{ padding: 12, borderRadius: 0, borderBottom: "1px solid #2A2A2A" }}
              onClick={() => {
                navigate("/settings/api-keys");
                close();
              }}
            >
              API Keys
            </button>
            <button
              className="dd-item"
              style={{ padding: 12, borderRadius: 0 }}
              onClick={() => window.open("https://norviq.dev/docs", "_blank", "noreferrer")}
            >
              Documentation ↗
            </button>
            <div className="dd-divider" />
            <button
              className="dd-item"
              style={{ padding: 12, borderRadius: 0 }}
              onClick={logout}
              onMouseEnter={(e) => {
                e.currentTarget.style.color = "#FF3B5C";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.color = "";
              }}
            >
              Logout
            </button>
          </div>
        )}
      </div>

      {isTablet && searchOpen && (
        <div className="tablet-search-pop" style={{ position: "relative" }}>
          <Search size={14} style={{ color: "var(--text-secondary)" }} />
          <input
            // Focus the field the moment the popup opens, so keystrokes go to the input, not the page.
            autoFocus
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            placeholder="Search tools, agents, rules..."
            aria-label="Search"
            onKeyDown={(e) => {
              if (e.key === "Escape") closeSearch();
            }}
            style={{
              flex: 1,
              background: "transparent",
              border: "none",
              color: "var(--text-primary)",
              outline: "none",
              fontSize: 13.5
            }}
          />
          {tabletPanelOpen && (
            <div
              className="dropdown"
              style={{
                position: "absolute",
                top: "calc(100% + 8px)",
                left: 0,
                right: 0,
                width: "100%",
                background: "#171717",
                border: "1px solid #2A2A2A",
                borderRadius: 12,
                overflow: "hidden",
                zIndex: 60
              }}
            >
              {renderSearchResults()}
            </div>
          )}
        </div>
      )}

      {open && <div className="dd-catch" onClick={close}></div>}
    </header>
  );
}
