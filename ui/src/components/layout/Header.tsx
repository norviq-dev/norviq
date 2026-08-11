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
  fetchCoverageByCategory,
  fetchMe,
  fetchSearch,
  logout,
  Me
} from "../../api/client";
import { fleetEnabled } from "../../api/fleet";
import { useApi } from "../../hooks/useApi";
import { TimeRange, useApp } from "@/store/AppContext";

type Dropdown = "cluster" | "inbox" | null;
// A count is `null` when its lookup FAILED — never 0. "We could not measure this" must not render like
// "we measured, and it is fine", so each source keeps its own outcome and `errors` says what broke.
type InboxPayload = {
  blockedCount: number | null;
  lowTrustCount: number | null;
  frozenCount: number | null;
  checkedAt: Date;
  errors: string[];
};
type ToolResult = { tool_name?: string; decision?: string | null; timestamp?: string };
type AgentResult = { spiffe_id?: string; agent_class?: string; score?: number; trust_score?: number };
/** The /agents fields the bell's alert counts need. `synthetic` and `category` are both emitted by
 *  agents.py `_agent_row` (on the hot AND the cold-registry path); `synthetic` is missing from client.ts's
 *  `SearchAgent`, which is why tsc never flagged the bell reading past it — declared here so this component
 *  reads the same two fields every other consumer of /agents does. (Flagged to the client.ts owner.) */
type InboxAgentRow = {
  spiffe_id?: string;
  score?: number;
  trust_score?: number;
  category?: string;
  synthetic?: boolean;
};
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
      let frozenCount: number | null = null;
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
        // ONE definition of "low trust", and it is the SERVER's. This used to re-derive the tier from a
        // literal `score < 0.4`, which disagreed with the /agents page the alert DEEP-LINKS TO, in both
        // directions:
        //  · it counted SYNTHETIC probe/eval identities. agents.py stamps `synthetic` on every row
        //    precisely "so the Overview trust donut + Agent Monitor exclude them and RECONCILE with the
        //    asset/attack graph, which already hides exactly these probes by default" — every other
        //    consumer honours it (Dashboard's donut, AgentMonitor, Asset/Attack Graph). So after a
        //    red-team run the bell showed "2 agents below trust threshold" and the page it opened
        //    reported "Low Trust 0" and listed neither of them.
        //  · and it MISSED a real one whenever the namespace raises `trust_threshold`: the calculator
        //    moves BOTH tier boundaries with it (`_tiers`: low = high × 0.4/0.7), so at t=0.9 an agent
        //    scoring 0.45 is categorised "low" server-side while `0.45 < 0.4` is false — the bell showed
        //    no badge and the dropdown read "All systems healthy".
        // `category` is exactly what AgentMonitor's own tiles count (`a.category === "low" | "frozen"`).
        const rows = agentsOutcome.value as InboxAgentRow[];
        const alerting = rows.filter((agent) => inScope(agent) && agent.synthetic !== true);
        const categoryOf = (agent: InboxAgentRow) => (agent.category ?? "").trim().toLowerCase();
        lowTrustCount = alerting.filter((agent) => categoryOf(agent) === "low").length;
        // A frozen identity is an admin kill-switch, and the old score-based predicate happened to catch it
        // (a frozen agent scores 0). Counting only "low" would have dropped it from the bell silently, so it
        // gets its own line — matching the Agents page's own separate Frozen tile rather than being folded
        // into a number whose label says "below trust threshold".
        frozenCount = alerting.filter((agent) => categoryOf(agent) === "frozen").length;
        // A row with no `category` cannot be tiered, and an untiered row must not quietly become a
        // not-low row: that is the "we could not measure it" → "we measured, and it is fine" inversion.
        const untiered = alerting.filter((agent) => !categoryOf(agent)).length;
        if (untiered > 0)
          errors.push(
            `Low-trust agents: ${untiered} of ${alerting.length} agents carried no trust category — the counts below are a floor.`
          );
      }

      const payload: InboxPayload = { blockedCount, lowTrustCount, frozenCount, checkedAt: new Date(), errors };
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
  const inboxKnownCount =
    (inboxData?.blockedCount ?? 0) + (inboxData?.lowTrustCount ?? 0) + (inboxData?.frozenCount ?? 0);
  const inboxIncomplete = !!inboxData && inboxData.errors.length > 0;
  // The posture object describes `posture.namespace` — the scope its /settings read was issued FOR. A
  // namespace switch leaves the PREVIOUS scope's mode in place until the new read settles (AppContext only
  // flips `loading`), so until both agree we do not know the posture of the scope on screen. That matters
  // because an empty chip area is itself a claim: "confirmed block". Switching from a `block` namespace to
  // an `audit` one rendered no chip for the whole of the new request — the console silently stating that a
  // Monitor-mode namespace was enforcing.
  const postureForScope = posture.namespace === selectedNamespace && !posture.loading;
  const postureScopeLabel = selectedNamespace === "all" ? "the cluster default" : `namespace ${selectedNamespace}`;

  // ---- MONITOR: the ENGINE's rule, the same field the Overview keys on. --------------------------
  // `posture.mode` comes from /settings, whose `_effective` MERGES the cluster-wide default
  // (`row.enforcement_mode if row … else app_settings.enforcement_mode`). The evaluator does not: it softens
  // a would-block ONLY on an explicit per-namespace override (`_resolve_posture`: "`monitor` is True ONLY
  // when the namespace explicitly overrides enforcement_mode to 'audit' — a null/global mode does NO
  // softening"; the global mode reaches only `_no_policy_decision`, the un-policed default). So on a cluster
  // deployed global-audit — which is what the shipped dev profile does (helm values-dev.yaml
  // `enforcementMode: audit`) — /settings answers "audit" for EVERY namespace that has no row of its own,
  // all of which the engine really blocks, and this chip stated "live traffic is NOT blocked" two inches
  // above an Overview tile counting real enforced blocks. client.ts:790 documents the invariant verbatim:
  // "Any claim about would-blocks must key on THIS field, not on the settings posture."
  //
  // coverage.py's `namespace_mode` IS that field (it reads namespace_settings directly, no global fallback),
  // and the Overview already keys `monitorScope` on it — so ask for it here too rather than inventing a
  // second signal. Asked for ONLY when the settings posture claims Monitor (an enforcing cluster pays
  // nothing), only for a CONCRETE namespace (`_namespace_mode(None)` returns "block" for the aggregate on
  // purpose — "don't imply monitor across the fleet" — which is not an answer about any namespace), and
  // never under a remote label. The cacheKey is the Overview's key VERBATIM so both share one entry.
  const settingsSaysMonitor = postureForScope && posture.mode === "audit";
  const canConfirmEngineMode = !isRemote && settingsSaysMonitor && selectedNamespace !== "all";
  const engineCoverage = useApi(
    () => (canConfirmEngineMode ? fetchCoverageByCategory(selectedNamespace) : Promise.resolve(null)),
    [canConfirmEngineMode, selectedNamespace],
    { cacheKey: canConfirmEngineMode ? `dashboard-coverage:${selectedNamespace}` : undefined, staleTimeMs: 60_000 }
  );
  // `null` = NOT CONFIRMED (not asked, still in flight, failed, or an answer about another scope — the
  // payload echoes the scope it was computed for, so compare it). Never resolved to a posture by default.
  // Only the two values the field is DEFINED to carry count as an answer: `namespace_mode` is optional in
  // the payload type, and collapsing an absent/unrecognised value into "block" would publish "the engine
  // still ENFORCES this namespace" — a hard enforcement claim — out of a field that said nothing.
  const engineMonitorModeRaw =
    canConfirmEngineMode && engineCoverage.data && engineCoverage.data.namespace === selectedNamespace
      ? engineCoverage.data.namespace_mode
      : undefined;
  const engineMonitorMode: "audit" | "block" | null =
    engineMonitorModeRaw === "audit" ? "audit" : engineMonitorModeRaw === "block" ? "block" : null;
  const monitorChipLabel = engineMonitorMode === "block" ? "Monitor: cluster default" : "Monitor mode";
  const monitorChipTitle =
    engineMonitorMode === "audit"
      ? `Namespace ${posture.namespace} is in Monitor mode — decisions are evaluated and logged, live traffic is NOT blocked. Click to change in Target Settings.`
      : engineMonitorMode === "block"
      ? `The CLUSTER-WIDE default is Monitor, but namespace ${posture.namespace} does not set Monitor itself — so the engine still ENFORCES its policy blocks, and only the un-policed default is relaxed to allow. Click to review in Target Settings.`
      : // Not "the cluster default": with no namespace selected the console reads /settings with NO
        // ?namespace (client.ts drops it for "all") and the endpoint defaults the parameter to "default", so
        // the value is the `default` namespace's row merged with the global — not a cluster-wide reading.
        `${
          posture.namespace === "all"
            ? 'With no namespace selected, Settings reads Monitor for the unscoped scope — the "default" namespace merged with the cluster-wide default, not a posture for every namespace'
            : `Namespace ${posture.namespace} reads Monitor mode in Settings, and that reading merges the cluster-wide default`
        }. The engine softens a would-block only where the namespace sets Monitor itself — which has NOT been confirmed here, so this is not a confirmation that live traffic is unblocked. Click to check Target Settings.`;
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
          {settingsSaysMonitor && (
            <button
              type="button"
              className="posture-chip"
              data-testid="posture-chip-monitor"
              // Which of the three postures this chip is actually asserting — the flat "live traffic is NOT
              // blocked" is now reachable ONLY on `audit`, i.e. only when the engine really is softening.
              data-engine-mode={engineMonitorMode ?? "unconfirmed"}
              title={monitorChipTitle}
              onClick={() => navigate("/policies/targets")}
              style={{
                display: "inline-flex", alignItems: "center", gap: 7, padding: "4px 11px", borderRadius: 999,
                fontSize: 11.5, fontWeight: 600, background: "rgba(255,176,32,0.10)",
                border: "1px solid rgba(255,176,32,0.35)", color: "var(--escalate)", cursor: "pointer", whiteSpace: "nowrap"
              }}
            >
              <span aria-hidden="true" style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--escalate)" }} />
              {monitorChipLabel}
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
                    {/* "at LOW trust", not "below trust threshold". The count is `category === "low"`, and
                        `_categorize` puts the low boundary at `trust_threshold × 0.4/0.7` — so at t=0.9 an
                        agent scoring 0.6 IS below the threshold and is "medium", i.e. not counted. The old
                        label promised a wider population than the number, and named a different one from the
                        page this row opens, whose tile is "Low Trust". One population, one name. */}
                    🟡 {inboxData?.lowTrustCount} {inboxData?.lowTrustCount === 1 ? "agent is" : "agents are"} at low trust
                  </button>
                )}
                {(inboxData?.frozenCount ?? 0) > 0 && (
                  <button
                    type="button"
                    className="dd-item"
                    data-testid="inbox-frozen"
                    style={{ padding: 12, borderBottom: "1px solid #2A2A2A", borderRadius: 0 }}
                    onClick={() => {
                      const nsq = selectedNamespace === "all" ? "" : `?ns=${encodeURIComponent(selectedNamespace)}`;
                      navigate(`/agents${nsq}`);
                      close();
                    }}
                  >
                    🔴 {inboxData?.frozenCount} {inboxData?.frozenCount === 1 ? "agent is" : "agents are"} trust-frozen
                  </button>
                )}
                {/* The all-clear requires BOTH counts to have actually come back, and both to be zero.
                    It used to render whenever the numbers were zero — including the zeros this component
                    invented when the lookup failed, which is a green, timestamped all-clear from a check
                    that never completed. */}
                {inboxData.errors.length === 0 &&
                  inboxData.blockedCount === 0 &&
                  inboxData.lowTrustCount === 0 &&
                  inboxData.frozenCount === 0 && (
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
