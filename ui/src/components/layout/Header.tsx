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
  ApiError,
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
// A count is `null` when its lookup FAILED — never 0. "We could not measure this" must not render like
// "we measured, and it is fine", so each source keeps its own outcome and `errors` says what broke.
type InboxPayload = {
  blockedCount: number | null;
  lowTrustCount: number | null;
  checkedAt: Date;
  errors: string[];
};
type ToolResult = { tool_name?: string; decision?: string | null; timestamp?: string };
type AgentResult = { spiffe_id?: string; agent_class?: string; score?: number; trust_score?: number };
// CONTRACT B: the server deliberately sends NO mode for a policy hit (routers/search.py: the loader's
// in-memory entry has no enforcement_mode and it refuses to fabricate one). So the field is optional AND
// nullable here, and the renderer states "mode unknown" — never a concrete posture.
type PolicyResult = { namespace?: string; agent_class?: string; mode?: string | null };

/** The sentence to show for a failed lookup — the server's own detail when it gave one. */
function failureText(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error ?? "");
  // A dead session is named, not reported as a generic outage. `apiGetWithSignal` (client.ts) is the one
  // fetch helper that neither routes a 401 to /login nor throws ApiError, so the ⌘K palette cannot rely
  // on either — hence the string check as well. (Flagged to the client.ts owner; see the report.)
  if ((error instanceof ApiError && error.status === 401) || message === "Request failed: 401")
    return "your session has expired — sign in again";
  const detail = message.trim();
  // `detailOf` (client.ts) falls back to the RAW body when it is not a FastAPI error envelope, so an
  // ingress/proxy error page arrives here as a page of markup. Pasting that into a 320px dropdown as
  // though it were the server's explanation is neither readable nor honest about what we know — which is
  // the status. Anything that looks like markup, or is far too long to be a sentence, is reported as such.
  if (!detail || detail.startsWith("<") || detail.length > 200)
    return error instanceof ApiError ? `the request failed (HTTP ${error.status})` : "the request failed";
  return detail;
}

/** "trust 0.87" for a scored agent, "trust unknown" for one the registry has never scored. */
function trustLabel(agent: AgentResult): string {
  const score = typeof agent.score === "number" ? agent.score : agent.trust_score;
  return typeof score === "number" && Number.isFinite(score) ? `trust ${score.toFixed(2)}` : "trust unknown";
}

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
    // A REMOTE cluster is selected (fleet on, selection != the cluster this console serves). Every number
    // the header can reach — posture, blocked calls, low-trust agents — is answered by the LOCAL api, so
    // under a remote label it describes the wrong cluster. Same rule ClusterScoped applies to routed pages;
    // the header sits ABOVE the routes App.tsx deliberately leaves unwrapped (/fleet, /).
    isRemote,
    scopeCluster,
    servedCluster,
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
  // Non-null when the LAST search failed — the panel then says so instead of "No results".
  const [searchError, setSearchError] = useState<string | null>(null);
  const [searchOpen, setSearchOpen] = useState(false);
  const [inboxLoading, setInboxLoading] = useState(false);
  const [inboxData, setInboxData] = useState<InboxPayload | null>(null);
  const [me, setMe] = useState<Me | null>(null);
  // The namespace an inbox answer is ABOUT. The cache key and the staleness guard below both key on it, so
  // a count can never be displayed under a namespace it was not measured for. The CLUSTER is deliberately
  // NOT part of the key: a remote selection is refused outright in loadInbox, so every answer that exists
  // here is the served cluster's — and folding the (asynchronously discovered) cluster id into the key
  // would discard a perfectly good answer the moment /cluster-info resolved. The reset effect below still
  // drops the state on a cluster switch.
  const inboxNsRef = useRef(selectedNamespace);
  const inboxRequestRef = useRef(0);
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

  const loadInbox = useCallback(async (force = false) => {
    // Never read the LOCAL cluster's alerts under a REMOTE cluster's label — the dropdown says so instead.
    if (isRemote) {
      setInboxData(null);
      return;
    }
    // Captured at REQUEST time: everything below describes THIS namespace, whatever is selected when the
    // answer eventually arrives.
    const scope = selectedNamespace;
    const requestId = ++inboxRequestRef.current;
    const now = Date.now();
    // Inbox is scoped to the SELECTED namespace — cache per namespace so a switch doesn't show the
    // previous scope's counts. `force` is the Retry/Check-now path: a failed check must be re-runnable.
    if (
      !force &&
      inboxCacheRef.current &&
      inboxCacheRef.current.ns === scope &&
      now - inboxCacheRef.current.timestamp < 60_000
    ) {
      setInboxData(inboxCacheRef.current.payload);
      // This answer is complete, and it now owns the dropdown: an OLDER request still running for another
      // namespace no longer clears the spinner (it must not), so leaving it set would strand a cached,
      // already-known answer behind "Checking alerts...".
      setInboxLoading(false);
      return;
    }

    setInboxLoading(true);
    try {
      // Settled INDEPENDENTLY. A Promise.all rejects as a whole, so one failed lookup erased the other's
      // real answer: a successful "9 tool calls blocked" disappeared — and the dropdown showed the green
      // all-clear — because the unrelated /agents call happened to fail.
      const [statsOutcome, agentsOutcome] = await Promise.allSettled([
        fetchAuditStats("24h", selectedNamespace),
        fetchAllAgents()
      ]);

      const errors: string[] = [];

      let blockedCount: number | null = null;
      if (statsOutcome.status === "fulfilled") {
        const blocked = statsOutcome.value?.blocked;
        if (typeof blocked === "number" && Number.isFinite(blocked)) blockedCount = blocked;
        else errors.push("Blocked calls: the server returned no count.");
      } else {
        errors.push(`Blocked calls: ${failureText(statsOutcome.reason)}.`);
      }

      let lowTrustCount: number | null = null;
      if (agentsOutcome.status === "rejected") {
        errors.push(`Low-trust agents: ${failureText(agentsOutcome.reason)}.`);
      } else if (!Array.isArray(agentsOutcome.value)) {
        // A 200 whose body is not a list is not an empty list. `.filter` on it THREW out of this whole
        // handler — past the `finally`, with no `catch` — which took the blocked count we had ALREADY
        // measured down with it and left the dropdown saying "not checked for this scope yet", offering
        // a Retry that fails the same way and never naming a reason. Settling the two lookups
        // independently is not enough on its own if the parsing of one can still erase the other.
        errors.push("Low-trust agents: the server returned no agent list.");
      } else {
        // SearchAgent has no namespace field, but the SPIFFE id encodes it (spiffe://…/ns/{ns}/sa/…) —
        // scope the low-trust count to the selected namespace client-side.
        const inScope = (agent: { spiffe_id?: string }) =>
          selectedNamespace === "all" || (agent.spiffe_id ?? "").includes(`/ns/${selectedNamespace}/`);
        lowTrustCount = agentsOutcome.value.filter((agent) => {
          if (!inScope(agent)) return false;
          const score =
            typeof agent.score === "number"
              ? agent.score
              : typeof agent.trust_score === "number"
              ? agent.trust_score
              : null;
          return score != null && score < 0.4;
        }).length;
      }

      const payload: InboxPayload = { blockedCount, lowTrustCount, checkedAt: new Date(), errors };
      // Only a COMPLETE check is cached, under the scope it describes. Remembering a failure for 60s would
      // make Retry a no-op and keep the "we didn't check" state on screen after the outage cleared.
      if (errors.length === 0) inboxCacheRef.current = { ns: scope, timestamp: now, payload };
      // The scope can change WHILE these two lookups are in flight — the switch is one click and the
      // requests are not instant. Clearing the state on the switch is NOT enough on its own: the older
      // request then lands afterwards and re-populates the badge and the dropdown with the previous
      // scope's counts under the new scope's label — the same defect, rebuilt through the async path.
      if (inboxNsRef.current !== scope) return;
      setInboxData(payload);
    } finally {
      // Only the NEWEST request owns the spinner: a superseded one clearing it would put "Alerts haven't
      // been checked for this scope yet" on screen while a check is actually running.
      if (inboxRequestRef.current === requestId) setInboxLoading(false);
    }
  }, [isRemote, selectedNamespace]);

  // The bell describes the SELECTED scope, but loadInbox only ever runs on a click — so after a scope
  // switch the previous namespace's counts stayed on the badge on every page (a "7" from `payments` read
  // as seven blocked calls in `default`). Drop them the moment the scope changes; the per-scope cache
  // is kept, so switching back is still free.
  const inboxScopeRef = useRef({ ns: selectedNamespace, cluster: selectedCluster });
  useEffect(() => {
    const previous = inboxScopeRef.current;
    inboxScopeRef.current = { ns: selectedNamespace, cluster: selectedCluster };
    inboxNsRef.current = selectedNamespace;
    // `selectedCluster` starts EMPTY and is filled in when /cluster-info answers. That first ""→"local-1"
    // transition is the console learning its own label, not the operator switching scope — treating it as
    // one threw away a check that had just completed (open the bell during page load and the counts
    // appeared, then silently reverted to "Alerts haven't been checked for this scope yet").
    const clusterSwitched = previous.cluster !== "" && previous.cluster !== selectedCluster;
    if (previous.ns !== selectedNamespace || clusterSwitched) setInboxData(null);
  }, [selectedNamespace, selectedCluster]);

  // Only the counts we actually got. A failed source contributes nothing to the number and instead makes
  // the badge amber — silence after a failed check is exactly the inversion this console cannot afford.
  const inboxKnownCount = (inboxData?.blockedCount ?? 0) + (inboxData?.lowTrustCount ?? 0);
  const inboxIncomplete = !!inboxData && inboxData.errors.length > 0;
  // The posture object describes `posture.namespace` — the scope its /settings read was issued FOR. A
  // namespace switch leaves the PREVIOUS scope's mode in place until the new read settles (AppContext only
  // flips `loading`), so until both agree we do not know the posture of the scope on screen. That matters
  // because an empty chip area is itself a claim: "confirmed block". Switching from a `block` namespace to
  // an `audit` one rendered no chip for the whole of the new request — the console silently stating that a
  // Monitor-mode namespace was enforcing.
  const postureForScope = posture.namespace === selectedNamespace && !posture.loading;
  const postureScopeLabel = selectedNamespace === "all" ? "the cluster default" : `namespace ${selectedNamespace}`;
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
      ) : searchError ? (
        // A search that never RAN must not read as a search that found nothing. "No results" told an
        // operator that a tool is not governed at the moment nobody could ask.
        <div style={{ padding: 12, fontSize: 13, lineHeight: 1.6 }} data-testid="search-error">
          <div style={{ color: "var(--escalate)", fontWeight: 600 }}>Search unavailable</div>
          <div style={{ color: "var(--text-secondary)", marginTop: 4 }}>
            This is not “no matches” — the search could not run, so nothing here has been checked.
          </div>
          <div className="mono" style={{ color: "var(--text-muted)", marginTop: 6, fontSize: 11.5 }}>
            {searchError}
          </div>
          <button
            type="button"
            className="btn btn-outline"
            style={{ marginTop: 10 }}
            onClick={() => void runSearch(searchText)}
          >
            Retry
          </button>
        </div>
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
                  {/* An absent decision is unknown, not "audit": defaulting to a concrete posture states
                      a governance outcome the record never carried. */}
                  🔧 {item.tool_name ?? "unknown"} —{" "}
                  {item.decision?.trim() ? item.decision : "decision unknown"} — {formatTimeAgo(item.timestamp)}
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
                  {/* An unscored agent is "trust unknown". Printing 0.00 puts the WORST possible score on
                      an agent nobody has scored — a measurement we never made. */}
                  👤 {item.agent_class ?? "unknown"} — {trustLabel(item)}
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
                  {/* CONTRACT B: no mode on the wire ⇒ say so. The old `?? "audit"` labelled every policy
                      hit Monitor/not-enforcing, including namespaces actively in block mode. */}
                  📋 {item.namespace ?? "default"}/{item.agent_class ?? "unknown"} —{" "}
                  {item.mode?.trim() ? item.mode : "mode unknown"}
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
      setSearchError(null);
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
      setSearchError(null);
    } catch (error) {
      if (!(error instanceof DOMException && error.name === "AbortError")) {
        // Record WHY there is nothing to show. Clearing the arrays silently made a dead endpoint (or a
        // dead session) indistinguishable from "this tool is not governed here".
        setToolResults([]);
        setAgentResults([]);
        setPolicyResults([]);
        setSearchError(failureText(error));
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
            other status controls (inbox/account). Click-through → Target Settings.

            THREE states, never two. The absence of a chip means "confirmed block" and nothing else:
            an UNKNOWN posture (AppContext sets mode=null when /settings 429s or 5xxs — "unknown, NOT
            block") used to render the identical empty DOM, so a namespace that is wide open in Monitor
            mode looked exactly like one that is enforcing. And a REMOTE selection gets no local posture
            at all — the numbers behind this chip come from the cluster this console serves. */}
        {isRemote ? (
          <span
            className="posture-chip"
            data-testid="posture-chip-remote"
            title={`This console serves ${servedCluster || "its own cluster"} and cannot read ${scopeCluster}'s enforcement posture. Open ${scopeCluster}'s own console to see it.`}
            style={{
              display: "inline-flex", alignItems: "center", gap: 7, padding: "4px 11px", borderRadius: 999,
              fontSize: 11.5, fontWeight: 600, background: "transparent",
              border: "1px solid var(--text-muted)", color: "var(--text-secondary)", whiteSpace: "nowrap"
            }}
          >
            Posture unknown · {scopeCluster}
          </span>
        ) : (
          <>
          {postureForScope && posture.mode === "audit" && (
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
          {postureForScope && posture.applyMode === "dry_run_only" && (
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
          {!postureForScope && (
            <span
              className="posture-chip"
              data-testid="posture-chip-checking"
              title={`The enforcement posture of ${postureScopeLabel} has not been read yet. This is NOT a confirmation that live traffic is being blocked.`}
              style={{
                display: "inline-flex", alignItems: "center", gap: 7, padding: "4px 11px", borderRadius: 999,
                fontSize: 11.5, fontWeight: 600, background: "transparent", border: "1px dashed var(--text-muted)",
                color: "var(--text-muted)", whiteSpace: "nowrap"
              }}
            >
              Checking posture…
            </span>
          )}
          {postureForScope && posture.mode === null && (
            <button
              type="button"
              className="posture-chip"
              data-testid="posture-chip-unknown"
              title={`The enforcement posture of ${postureScopeLabel} could not be read. This is NOT a confirmation that live traffic is being blocked. Click to check Target Settings.`}
              onClick={() => navigate("/policies/targets")}
              style={{
                display: "inline-flex", alignItems: "center", gap: 7, padding: "4px 11px", borderRadius: 999,
                fontSize: 11.5, fontWeight: 600, background: "transparent", border: "1px solid var(--text-muted)",
                color: "var(--text-secondary)", cursor: "pointer", whiteSpace: "nowrap"
              }}
            >
              <span aria-hidden="true" style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--text-muted)" }} />
              Posture unknown
            </button>
          )}
          </>
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
          {!isRemote && (inboxKnownCount > 0 || inboxIncomplete) && (
            <span
              className="bell-badge"
              data-testid={inboxIncomplete ? "bell-badge-incomplete" : "bell-badge"}
              aria-label={
                inboxIncomplete
                  ? `Alert check incomplete — ${inboxKnownCount} known, at least one check failed`
                  : `${inboxKnownCount} alerts`
              }
              // Amber, not the block-red of a real count: the number behind it is partial because a
              // lookup failed. The dropdown names which one.
              style={inboxIncomplete ? { background: "var(--escalate)", color: "var(--bg-void)" } : undefined}
            >
              {inboxIncomplete && inboxKnownCount === 0 ? "!" : inboxKnownCount}
            </span>
          )}
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
              <span>
                Inbox · {isRemote ? `${scopeCluster} / ` : ""}
                {selectedNamespace === "all" ? "all namespaces" : selectedNamespace}
              </span>
              <button className="icon-btn" style={{ width: 28, height: 28 }} onClick={close} title="Close">
                <X size={16} />
              </button>
            </div>
            {isRemote ? (
              // The blocked-call and low-trust counts are answered by the LOCAL api. Showing them under a
              // remote cluster's name would let an operator read a remote fleet's safety off this one's.
              <div
                data-testid="inbox-remote"
                style={{ padding: 12, fontSize: 13, lineHeight: 1.6, color: "var(--text-secondary)" }}
              >
                Alerts for <span className="mono">{scopeCluster}</span> aren’t readable from this console — it
                serves <span className="mono">{servedCluster || "another cluster"}</span>. Open{" "}
                <span className="mono">{scopeCluster}</span>’s own console to see them.
              </div>
            ) : inboxLoading ? (
              <div style={{ padding: 12, color: "#A0A0A0", fontSize: 13 }}>Checking alerts...</div>
            ) : !inboxData ? (
              // No completed check for THIS scope (first open, or the scope just changed under an open
              // dropdown). Not an all-clear — offer the check instead of implying one happened.
              <div data-testid="inbox-unchecked" style={{ padding: 12, fontSize: 13, lineHeight: 1.6 }}>
                <div style={{ color: "var(--text-secondary)" }}>
                  Alerts haven’t been checked for this scope yet.
                </div>
                <button type="button" className="btn btn-outline" style={{ marginTop: 10 }} onClick={() => void loadInbox(true)}>
                  Check now
                </button>
              </div>
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
                    🔴 {inboxData?.blockedCount} tool {inboxData?.blockedCount === 1 ? "call" : "calls"} blocked in last 24h
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
                    🟡 {inboxData?.lowTrustCount} {inboxData?.lowTrustCount === 1 ? "agent" : "agents"} below trust threshold
                  </button>
                )}
                {/* The all-clear requires BOTH counts to have actually come back, and both to be zero.
                    It used to render whenever the numbers were zero — including the zeros this component
                    invented when the lookup failed, which is a green, timestamped all-clear from a check
                    that never completed. */}
                {inboxData.errors.length === 0 &&
                  inboxData.blockedCount === 0 &&
                  inboxData.lowTrustCount === 0 && (
                    <div style={{ padding: 12, borderBottom: "1px solid #2A2A2A", fontSize: 13 }}>
                      🟢 All systems healthy — no alerts
                    </div>
                  )}
                {inboxData.errors.length > 0 && (
                  <div
                    data-testid="inbox-error"
                    style={{ padding: 12, borderBottom: "1px solid #2A2A2A", fontSize: 13, lineHeight: 1.6 }}
                  >
                    <div style={{ color: "var(--escalate)", fontWeight: 600 }}>
                      {inboxData.blockedCount === null && inboxData.lowTrustCount === null
                        ? "Couldn’t check alerts — this is not the same as no alerts."
                        : "Partial check — this list is incomplete."}
                    </div>
                    {inboxData.errors.map((message) => (
                      <div key={message} style={{ color: "var(--text-secondary)", marginTop: 4 }}>
                        {message}
                      </div>
                    ))}
                    <button
                      type="button"
                      className="btn btn-outline"
                      style={{ marginTop: 10 }}
                      onClick={() => void loadInbox(true)}
                    >
                      Retry
                    </button>
                  </div>
                )}
                <div style={{ padding: "8px 12px", color: "#666666", fontSize: 11 }}>
                  {/* "Last checked" on a failed lookup stamps a time on a check that never finished. */}
                  {inboxData.errors.length > 0 ? "Last attempted" : "Last checked"}:{" "}
                  {inboxData.checkedAt.toLocaleTimeString()}
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
