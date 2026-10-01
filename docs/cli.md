<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->

# CLI Reference

`norviq` is a thin, scriptable client over the control-plane REST API. Almost every subcommand is one
HTTP call to `norviq-api` plus a formatter — which is the point: anything the console can do to
policies, audit records and agent trust, a shell script can do too, against the same endpoints and the
same authorization checks. Three commands break that pattern and are called out where they appear:
`login` and `admin reset-password` shell out to `kubectl exec` (no API call at all), and `redteam`
drives `POST /api/v1/evaluate` in a loop.

The command tree is built with Click in `norviq/cli/main.py`; the entry point is
`norviq = "norviq.cli.main:main"` (`pyproject.toml:67-68`).

## 1. Install

The CLI ships in the base package — `click` is a first-class dependency (`pyproject.toml:32`), so no
extra is needed:

```bash
pip install norviq            # 0.2.0, matching the chart version
norviq --help
```

The SDK extras (`norviq[langchain]`, `norviq[crewai]`, …) add framework adapters for in-process
enforcement and change nothing about the CLI. See [Integrating agents](guides/integrating-agents.md).

There is **no `norviq --version` flag** — the group in `norviq/cli/main.py:49-53` declares
`--api-url`, `--token` and `--output` and nothing else. Use `pip show norviq` to confirm which
version you have.

## 2. Pointing the CLI at a cluster

| Setting | Flag | Environment variable | Default | Set at |
|---|---|---|---|---|
| API base URL | `--api-url` | `NRVQ_API_URL` | `http://127.0.0.1:8080` | `norviq/cli/main.py:21,50` |
| Bearer token | `--token` | `NRVQ_API_TOKEN` | `""` (unauthenticated) | `norviq/cli/main.py:51` |
| Output format | `-o`, `--output` | *(none)* | `table` | `norviq/cli/main.py:52` |

The default `http://127.0.0.1:8080` assumes the port-forward from
[getting-started](getting-started.md): `kubectl -n norviq port-forward svc/norviq-ui 8080:80`. That
works for the CLI as well as the console because the UI's nginx reverse-proxies `/api/`, `/healthz`
and `/readyz` through to `norviq-api:8080` (`ui/nginx.conf:26-27,64-70`) — one port-forward serves
both. If you port-forward `svc/norviq-api` directly instead, point `--api-url` at that.

Every request carries a 10-second timeout (`norviq/cli/api_client.py:14`) and, when a token is
present, an `Authorization: Bearer` header (`api_client.py:20-25`). There is **no persistent config
file**: configuration is flags, environment variables, and `.env` files. Nothing the CLI does ever
writes to disk.

### `.env` loading, and the two loaders that disagree

Two separate `.env` readers run, with different roots and different precedence. This matters mostly
to contributors running from a checkout:

1. `norviq/config.py:13-41` (`_preload_env_files`) loads `.env` then `.env.local` from the
   **package's parent directory** — the repository root in a source or editable install — and writes
   them into `os.environ`. It strips surrounding quotes (`config.py:27`) and refuses to overwrite a
   variable that was already in the real environment (`config.py:31-32`). It runs on import of
   `norviq.config`, which the CLI pulls in transitively via `norviq.redteam.runner`
   (`norviq/cli/main.py:18`).
2. `norviq/cli/main.py:24-33` (`_load_dotenv`, called at line 48) loads `.env` from the **current
   working directory** using `os.environ.setdefault`, and does **not** strip quotes.

Because (1) runs first and (2) only fills in gaps, a repo-root `.env` silently wins over the `.env`
in the directory you are standing in. A `pip install norviq` user is unaffected — loader (1) looks in
`site-packages/`, finds nothing, and does nothing — but in a checkout, `NRVQ_API_URL` in
`<repo>/.env` overrides the one in `./.env`. Verified behavior, not a design intent.

The quoting difference is the sharper edge: in a cwd `.env`, `NRVQ_API_TOKEN="ey..."` yields a token
whose first and last characters are literal double quotes, and every call 401s. Write it unquoted.

### Getting a token

`NRVQ_API_TOKEN` accepts either credential the API's `_authenticate` recognizes
(`norviq/api/auth.py:174-188`):

- **A session JWT** — what `norviq login` mints (§6) and what the console holds. Short-lived; the
  `login` default is 3600 seconds.
- **A `nrvq_`-prefixed API key** — issued by `POST /api/v1/keys` (`norviq/api/routers/keys.py:84`),
  admin-only, returned exactly once at creation and stored only as a hash. There is no `norviq keys`
  subcommand; issue and revoke keys from the console or with `curl`. For anything unattended (CI, a
  cron job), an API key is the right credential — it does not expire in an hour and it can be scoped
  to one namespace and role.

The CLI **does not store a token anywhere**. `norviq login` prints one to your terminal; putting it
into the environment is your step:

```bash
export NRVQ_API_TOKEN="$(...)"   # or add it, unquoted, to ./.env
```

The console is the component that persists a token: the `#access_token=` deep-link `login` prints is
consumed by `ui/src/auth/Login.tsx:161-168`, which stores it in browser `localStorage`.

Only `norviq status` works without a token — `/healthz` and `/readyz` carry no auth dependency
(`norviq/api/routers/health.py:19,26`). Every `/api/v1` endpoint the CLI calls requires a valid
bearer. (The API is not *entirely* bearer-gated under `/api/v1` — `POST /api/v1/auth/login`
necessarily is not, `norviq/api/routers/auth_login.py:83-88` — but the CLI does not wrap it.)

The write paths add a role check, and it is not one check but two:

| Gate | Accepts | Commands |
|---|---|---|
| `require_admin` (`norviq/api/auth.py:227-231`) | role `admin` only | `policy apply` (`policies.py:1140`), `policy rollback` (`policies.py:867`), `agent reset-trust` / `agent freeze` (`agents.py:431`), `fleet join` / `fleet leave` (`fleet_enroll.py:84,145`) |
| `require_admin_or_service` (`norviq/api/auth.py:234-243`) | role `admin` **or** role `service` | `policy create` (`policies.py:433`), `policy delete` (`policies.py:761`), `policy dry-run` (`policies.py:1069`) |

The split is deliberate least-privilege, not an oversight: the `service` role exists for the webhook
CRD controller, which syncs `NrvqPolicy` objects through create/delete only, so rollback and apply
stay admin-only (`norviq/api/auth.py:237-239`). On the three `_or_service` paths there is a second,
namespace-level gate: any caller whose role is not `admin` — a `service`-role JWT, a namespace-scoped
API key — is floored to its own `namespace` claim and gets a 403 for any other namespace
(`_enforce_apikey_write_scope`, `policies.py:159-178`). A full-admin credential returns early from
that check and is unrestricted (`policies.py:169-170`).

## 3. Output formats

`-o json` prints `json.dumps(data, indent=2, default=str)` of the raw API response
(`norviq/cli/formatters.py:14-16`); `-o table` (the default) prints a column-aligned table of a fixed
column subset followed by `(N results)` (`formatters.py:19-34`), or `No results.` when the list is
empty.

`-o` is honored by **eight** commands. The rest print a hand-written summary and ignore it entirely:

| Honors `-o json` | Ignores `-o` (fixed human output) |
|---|---|
| `policy list`, `policy get`, `policy versions`\*, `audit list`, `audit stats`, `audit top-blocked`, `agent list`, `agent get` | `status`, `policy create`, `policy rollback`, `policy dry-run`, `policy apply`, `policy delete`, `agent reset-trust`, `agent freeze`, `fleet *`, `config *`, `login`, `admin reset-password`, `redteam *` |

\* `policy versions` honors `-o json` (`main.py:130`), and that is the only way to see a historical
version's Rego: the endpoint returns `rego_source` per row (`norviq/api/routers/policies.py:851-854`)
but the table's three columns drop it. It serves the loader's **in-memory** history, capped at the 10
newest per scope (`_MAX_VERSIONS`, `norviq/engine/policy_loader.py:24,221`) — the DB retains more
(`policy_version_keep_count`/`keep_days`), so a version older than the tenth is neither listed here
nor rollable — `loader.rollback` searches the same in-memory list
(`norviq/engine/policy_loader.py:405-411`) and a miss becomes a 404 (`policies.py:876-882`).

`redteam` has its own `--output` with a third value, `markdown`; it does not read the group's `-o`.
See [`norviq redteam`](#norviq-redteam--attack-simulation) below.

The CLI's structlog lines (`nrvq.cli.started` on every invocation, `nrvq.cli.command_ok` on success)
are written to **stderr**, so `-o json` output on stdout pipes straight into `jq`. The codes in those
lines (`NRVQ-CLI-8000`..`8004`) are catalogued in [error-codes.md](error-codes.md).

## 4. Exit codes

| Code | Meaning | Raised at |
|---|---|---|
| `0` | Command completed. **Not** a claim that the result was good — see the caveats below. | — |
| `1` | API unreachable, request timeout, non-2xx response, unparseable JSON body; also `login`/`admin reset-password` failures, and any uncaught Python exception | `norviq/cli/api_client.py:85-88`, `click.ClickException` |
| `2` | Click usage error: missing argument, unknown command, invalid `click.Choice` value | Click |

Three places where a `0` does not mean what a CI job would want it to mean:

- **`redteam run` always exits 0**, whatever the pass rate. The command body
  (`norviq/redteam/runner.py:42-46`) just calls the suite, which prints the report and returns
  (`runner.py:55-60`); there is no `ctx.exit`. To gate a pipeline on red-team results, parse
  `--output json` and check `.summary.pass_rate` yourself — the rate is nested under `summary`, not
  at the top level (`norviq/redteam/reporter.py:46-60`).
- **`policy dry-run` exits 0 on invalid Rego.** The endpoint answers `200` with `valid: false` when
  OPA fails to compile (`norviq/api/routers/policies.py:1079-1087`), and the CLI prints only four
  fields — none of them `valid` or `errors`. Read the `Recommendation:` line: `Invalid rego — fix
  errors before deploying`. (Submissions that trip the *pre-compile* validator — size caps, forbidden
  builtins — return 422 and do exit 1.)
- **`norviq status` exits 1 exactly when you most want to run it.** `/readyz` returns HTTP **503**
  when any hard dependency is down (`norviq/api/routers/health.py:59-62`), `raise_for_status()` turns
  that into a fatal error, and the command prints `ERROR: API error (503): ...` instead of its own
  `Redis: Disconnected` line. The `Disconnected` branches at `norviq/cli/main.py:70-71` are
  unreachable against a real API: a 200 from `/readyz` already implies every probe passed. Treat
  `norviq status` as a binary healthy/not-healthy check and read `kubectl -n norviq get pods` or curl
  `/readyz` directly for the breakdown.

Error messages are deliberately specific about the two failures that dominate: `Cannot connect to
<url> - is the API running?` (`api_client.py:57`) and `Authentication failed - check NRVQ_API_TOKEN.`
on any 401 (`api_client.py:73`).

---

## 5. Command reference

### `norviq status`

`GET /healthz` + `GET /readyz`, no auth required. Prints three lines: API, Redis, DB. See the exit-code
caveat above before scripting against it.

```bash
$ norviq status
API:   Online
Redis: Connected
DB:    Connected
```

`/readyz` also reports `policies_warm` and, when `opa_mode=server` — the shipped default, set at
`norviq/config.py:113` — `opa`. The CLI prints neither. Curl the endpoint if you need them.

### `norviq policy` — authoring and lifecycle

| Command | Arguments / flags | API call |
|---|---|---|
| `list` | — | `GET /api/v1/policies` |
| `get` | `NAMESPACE AGENT_CLASS` | `GET /api/v1/policies/{ns}/{class}` |
| `create` | `-f/--file` (required, must exist), `-n/--namespace` (required), `-c/--class` (required), `--mode block\|audit\|escalate` (default `block`) | `POST /api/v1/policies` |
| `versions` | `NAMESPACE AGENT_CLASS` | `GET .../versions` |
| `rollback` | `NAMESPACE AGENT_CLASS VERSION` (int) | `POST .../rollback` |
| `dry-run` | `-f/--file`, `-n/--namespace`, `-c/--class` (all required) | `POST /api/v1/policies/dry-run` |
| `apply` | `NAMESPACE AGENT_CLASS`, `--target-ns` (required), `--target-type agent_class\|workload\|namespace` (default `agent_class`), `--mode` (default `block`) | `POST .../apply` |
| `delete` | `NAMESPACE AGENT_CLASS`, `--yes` to skip the confirmation prompt | `DELETE /api/v1/policies/{ns}/{class}` |

`create` reads the file verbatim and posts it as `rego_source` with `saved_by: "cli"`
(`norviq/cli/main.py:103-109`). It clears the same *static* validator the console's Save button
clears — they are the same endpoint — `validate_rego_source`
(`norviq/api/routers/policies.py:676-704`): the 64 KiB / 500-line / 25-regex-operation caps, the
forbidden-builtin and cross-package `data.` reject (`policies.py:648-673`), and the mandatory
`default decision` resolver check (`policies.py:565-607`). All three are described in
[Writing policies](guides/writing-policies.md). A rejected policy comes back as a 422 and exits 1
with the API's `detail` string.

**`create` does not OPA-compile the policy.** The only OPA compile in the policy path is
`_validate_rego` (`policies.py:888-920`), and only `POST /policies/dry-run` calls it. `create_policy`
runs the static validator and then `loader.create` (`norviq/engine/policy_loader.py:146-241`), whose
final step is `evaluator.load_policy` — a copy-on-write dict assignment, not a push to OPA
(`norviq/engine/evaluator.py:2194-2202`). So Rego that satisfies the regexes but does not compile is
accepted with a 200, persisted, and loaded into the read path; it first surfaces on a real tool call
as a fail-closed block carrying `rule_id: evaluator_error`
(`norviq/engine/evaluator.py:1885-1888`) — an outage for that scope, not a save-time error. Run
`policy dry-run` on the file first. The console does exactly that: its editor calls the dry-run
endpoint separately (`ui/src/api/client.ts:889`) before it posts the save.

The table for `policy list` shows `namespace`, `agent_class`, `current_version`, `rego_length`. The
endpoint returns more per row — `target_type`, `enforcement_mode`, `priority`, `last_applied`,
`matches`, `matches_basis` (`norviq/api/routers/policies.py:333-353`) — and `matches` in particular
is `null` when the scope is *not measurable* from audit or the count query failed, never a measured
zero; `matches_basis` names which of the two it is. Use `-o json` when you care about any of that;
the table will not show it.

**`--target-type` is inert.** `apply` sends it, the API echoes it back in the response and logs it,
and nothing reads it: `apply_to_target` is called with the *path's* `agent_class` as the target class
regardless (`norviq/api/routers/policies.py:1163-1170`, echoed back at `:1187,1197`). The scope that actually gets
written is `(--target-ns, AGENT_CLASS)`. Passing `--target-type workload` does not produce a workload
policy.

Worked example — validate a candidate against the last 24 hours of real traffic, then save and apply
it in audit mode first:

```bash
export NRVQ_API_TOKEN=nrvq_...          # admin key: create/delete/dry-run take admin-or-service, apply admin only

# 1. Replay it against recent traffic for this scope. Read the recommendation, not the exit code.
norviq policy dry-run -f support.rego -n chatbot-prod -c support-agent

# 2. Save. This loads into the read path immediately — it enforces on the next call.
norviq policy create -f support.rego -n chatbot-prod -c support-agent --mode audit

# 3. Confirm what landed, then flip to blocking.
norviq policy get chatbot-prod support-agent
norviq policy apply chatbot-prod support-agent --target-ns chatbot-prod --mode block

# 4. If it goes wrong: list history and roll back.
norviq policy versions chatbot-prod support-agent
norviq policy rollback chatbot-prod support-agent 3
```

Step 2 is not a staging action. `create_policy` loads straight into the read path, which is why a
namespace marked dry-run-only rejects it exactly like `apply` does
(`norviq/api/routers/policies.py:436-439`). `--mode audit` is what makes step 2 safe, not the absence
of an apply.

`policy dry-run` prints four fields (`norviq/cli/main.py:153-156`) and drops the most
decision-relevant one. The endpoint returns `newly_blocked` and `newly_blocked_samples` — the
currently-allowed calls this candidate would *flip* to blocked, which is the number the
recommendation string is built from (`norviq/api/routers/policies.py:1104-1107`) — and the CLI prints
neither. The `Recommendation:` line carries the count in prose; no flag will give you the samples.
Use the console's dry-run panel, or call the endpoint directly, when you need to see which calls flip.

Reserved scopes are refused with a 422 explaining the supported path — but **not uniformly across
create/apply/delete**, and the asymmetry is deliberate rather than a gap:

| Scope | `policy create` | `policy apply` | `policy delete` |
|---|---|---|---|
| namespace `__cluster__` | 422 (`policies.py:454-461`) | 422 as `--target-ns` (`policies.py:1145-1152`) | 422, never deletable |
| class `__pack__`, `__pack_override__`, `__pack_weaken__` | 422 (`policies.py:474-481`) | 422 | 422; revert through the packs router |
| class `__baseline__`, `__guardrail__` | **allowed** — authored through this endpoint on purpose (`policies.py:466,469`) | 422 | 422 unless `?confirm_managed=true` (`policies.py:763-770`) |
| class `<class>__remediation__` | **allowed** — the console's compliance-apply path (`policies.py:470-473`) | 422 | 422 unless `?confirm_managed=true` |

The delete guard itself is `_reserved_scope_delete_error` (`policies.py:76-87`). Note the trap in the
last two rows: `norviq policy delete` sends no query parameters (`norviq/cli/main.py:120`), so it can
never supply `confirm_managed` — a `__baseline__` or `__guardrail__` you created with `norviq policy
create` cannot be removed with `norviq policy delete`. Use `curl` or the console for that. Sector
packs are toggled through `/api/v1/policy-packs` (`norviq/api/routers/packs.py:75-247`), which the
CLI does not wrap at all.

### `norviq audit` — decision history

| Command | Flags | API call |
|---|---|---|
| `list` | `-n/--namespace`, `-d/--decision allow\|block\|escalate\|audit`, `-t/--tool`, `--range` (default `24h`), `-l/--limit` (default `20`) | `GET /api/v1/audit/records` |
| `stats` | `--range`, `-n/--namespace` | `GET /api/v1/audit/stats` |
| `top-blocked` | `--range`, `-n/--namespace` | `GET /api/v1/audit/top-blocked` |

`--range` accepts `1h`, `6h`, `24h`, `7d`, `30d` — enforced **server-side** by a `Literal` type on
each of the three routes (`norviq/api/routers/audit.py:127,186,273`), not by the CLI, which passes
the string through unchecked. A typo produces a 422 and exit 1, not a usage error. `-l/--limit` is
capped at 500 by the API (`audit.py:128`); above that, 422.

`-t/--tool` is a case-insensitive **substring** match applied server-side across the whole range, not
an exact match (`audit.py:133-134,149`). `-t sql` matches `execute_sql`.

**`audit list` and `audit stats` count different populations.** `/audit/stats` and `/audit/top-blocked`
always exclude red-team traffic (`framework == "redteam"`) and synthetic/probe identities so the
console's headline reconciles with its Compliance and MITRE views (`audit.py:193-198,241`, `audit.py:281-284,297-299`).
`/audit/records` only does so when `exclude_synthetic=true` — and the CLI never sends it
(`norviq/cli/main.py:183`). So `norviq audit list` includes rows that `norviq audit stats` has
already discarded, and the two will not add up after you have run `redteam run`. There is no CLI flag
to align them.

`top-blocked` has no limit flag; you always get the API's default top 5 (`audit.py:274`).

```bash
# Everything the enforcement point blocked in one namespace in the last hour, newest first.
norviq audit list -n chatbot-prod -d block --range 1h -l 50

# The same window as a summary, plus the tools driving it.
norviq audit stats -n chatbot-prod --range 1h
norviq audit top-blocked -n chatbot-prod --range 1h

# Which rule fired, per record — the table shows rule_id, but not the reason string.
norviq -o json audit list -n chatbot-prod -d block --range 1h \
  | grep -v '^[0-9-]\{10\} [0-9:]\{8\} \[' \
  | jq -r '.[] | "\(.timestamp) \(.tool_name) \(.rule_id) \(.reason)"'
```

The `list` table shows `timestamp`, `tool_name`, `decision`, `rule_id`, `namespace`, `trust_score`,
`latency_ms`. The JSON additionally carries `id`, `event_id`, `reason`, `agent_id`, `agent_class`,
`session_id`, `framework` and, for calls that arrived over MCP, an `mcp` provenance object naming the
server the call came from (`norviq/api/routers/audit.py:75-99`). `framework` is the *caller-declared*
decision source, not a validated enum — `POST /evaluate` accepts any string and defaults it to `""`
(`norviq/api/routers/evaluate.py:269`). Values the shipped enforcement points send are `sidecar`
(`norviq/sidecar/proxy.py:220,260`), `sidecar-http` (`norviq/sidecar/http_fallback.py:50,57`), `mcp`
(`norviq/mcp/firewall.py:552`) and `redteam` (`norviq/redteam/simulator.py:115`); the SDK adapters
supply their own. Only the exact string `redteam` drives the stats/top-blocked exclusion above — a
misspelled value is counted as real traffic.

### `norviq agent` — roster and trust

| Command | Arguments / flags | API call |
|---|---|---|
| `list` | — | `GET /api/v1/agents` |
| `get` | `SPIFFE_ID` | `GET /api/v1/agents/{spiffe_id}` |
| `reset-trust` | `SPIFFE_ID`, `--score FLOAT` (default `0.8`) | `PUT /api/v1/agents/{spiffe_id}/trust` |
| `freeze` | `SPIFFE_ID` | `PUT .../trust` with `{"score": 0.0}` |

Pass the full SPIFFE ID, quoted. The scheme's `//` survives into the request path unmodified and the
route's `:path` converter accepts it (`norviq/api/routers/agents.py:383`), so no escaping is needed:

```bash
norviq agent get 'spiffe://norviq/ns/chatbot-prod/sa/support-agent'
```

`agent list` takes no `--namespace` or `--limit`, though the endpoint supports both
(`norviq/api/routers/agents.py:93-94`; the default limit is 1000, `agents.py:31`). An admin token
therefore lists every namespace — but only up to that 1000-row default, which the CLI has no way to
raise; a namespace-scoped token lists its own namespace. Filter client-side, or call the endpoint.

**`reset-trust` does not reset.** `PUT /agents/{id}/trust` has full-state, mutually exclusive
semantics (`norviq/api/routers/agents.py:425-441`):

| `--score` | Effect |
|---|---|
| `0` | **Freeze** — every call blocked; any existing cap cleared. This is what `agent freeze` sends. |
| `0 < s < 1` | A **tighten-only cap**: the engine uses `min(computed, s)`. It can push an agent toward escalate/frozen; it can never raise trust above what behavior earned. |
| `1.0` | **Clear** both the freeze and the cap — back to purely behavioral trust. |

So `norviq agent reset-trust <id>`, with its default `--score 0.8`, *installs a cap at 0.8*. The
command that actually undoes a freeze or a cap is `norviq agent reset-trust <id> --score 1.0`. The
name is misleading; the behavior above is what the endpoint does.

Both writes are *intended* to be durable, and mostly are: after the Redis write the endpoint stamps
`frozen`/`trust_cap` onto `agent_registry` (`agents.py:450-455`), and `warm_agent_overrides` re-seeds
those columns into Redis at startup (`agents.py:463-466`), so a Redis flush does not silently lift a
kill switch. Two limits before you rely on it. The DB write is **best-effort**: it sits inside a
`try/except` that logs `NRVQ-API-7033` and lets the call return `200` anyway
(`agents.py:456-457`) — a successful `Agent frozen:` line is not proof the freeze was persisted. And
it is an `UPDATE … WHERE spiffe_id = :s`, so an agent that has no `agent_registry` row yet gets no
durable record at all; the code's own note says such an agent is stamped on its next registration
path (`agents.py:446-447`). Freezing an agent the registry already knows about is the covered case.

One cosmetic wart: `reset-trust` echoes the category the endpoint returns, and the endpoint builds
that response with `category=""` for any non-zero score (`agents.py:442`). Expect
`Trust reset: <id> -> 0.8 ()` — an empty parenthetical, not a missing category.

```bash
# Contain a misbehaving agent immediately, then verify.
norviq agent freeze 'spiffe://norviq/ns/chatbot-prod/sa/support-agent'
norviq agent get   'spiffe://norviq/ns/chatbot-prod/sa/support-agent'

# After the incident: actually release it.
norviq agent reset-trust 'spiffe://norviq/ns/chatbot-prod/sa/support-agent' --score 1.0
```

### `norviq redteam` — attack simulation

Defined in `norviq/redteam/runner.py` and attached to the tree at `norviq/cli/main.py:280`. The group
is spelled `redteam`, one word.

| Command | Flags | Behavior |
|---|---|---|
| `catalog` | — | Prints the built-in attack list. **Offline** — no API call. |
| `run` | `--api-url`, `--token`, `--agent` (default `test-agent`), `--namespace` (default `default`), `--category`, `-o/--output table\|json\|markdown` | Runs the suite (optionally one category) against `POST /api/v1/evaluate` |
| `single` | `--api-url`, `--token`, `ATTACK_ID` | Runs one attack by ID |

`--api-url`/`--token` here are per-command overrides layered over the group's context: flag wins,
else the group's value (from `--api-url`/`NRVQ_API_URL`), else the default
(`norviq/redteam/runner.py:22-27`). `norviq --api-url X redteam run` and
`norviq redteam run --api-url X` are both correct.

`run`'s `-o` is a *different option* from the group's and does not inherit it —
`norviq -o json redteam run` still prints a table. Put the flag after `run`.

The catalog is 34 attacks (`norviq/redteam/attacks.py`), each posting a synthetic tool call with
`framework: "redteam"` so it is excluded from the real-traffic aggregates:

| `--category` value | Count | IDs |
|---|---|---|
| `prompt_injection` | 3 | PI-001…003 |
| `data_leakage` | 5 | DL-001…003, PII-001, PCI-001 |
| `supply_chain` | 2 | SC-001, SC-002 |
| `excessive_agency` | 3 | EA-001…003 |
| `unbounded_consumption` | 1 | RL-001 |
| `cross_tenant` | 2 | CT-001, CT-002 |
| `sql_injection` | 3 | SQL-001…003 |
| `shell_injection` | 2 | SH-001, SH-002 |
| `trust_manipulation` | 1 | TM-001 |
| `chain_exploit` | 2 | CE-001, CE-002 |
| `policy_bypass` | 2 | PB-001, PB-002 |
| `sector_policy` | 3 | FIN-001, PHI-001, OT-001 |
| `mcp_identity` | 3 | MCP-01…03 |
| `policy_composition` | 2 | MCP-04, MCP-05 |

`--category` takes the **value**, not the enum name (`prompt_injection`, not `OWASP_LLM01`). It is
not validated by Click: an unrecognized value raises an uncaught `ValueError` from
`AttackCategory(category)` (`runner.py:52`) and you get a Python traceback and exit 1, not a usage
message.

Two behaviors worth knowing before you run this against a shared cluster. `RL-001` deliberately
replays a single call `evaluator_rate_limit_per_window + 1` times — 61 requests at the default
(`norviq/config.py:128`, `norviq/redteam/simulator.py:147`) — because the control it tests is the
rate limiter, not a single evaluation. So a full run is 94 `POST /evaluate` calls at the defaults —
33 attacks once each, plus RL-001's 61 — and each decision lands in the audit log tagged
`framework: redteam`, which `audit list` will show you and `audit stats` will not (see
[`norviq audit`](#norviq-audit--decision-history)).

```bash
# What is in the catalog — no cluster needed.
norviq redteam catalog

# Full suite against a specific class, as machine-readable output.
norviq redteam run --namespace chatbot-prod --agent support-agent -o json > redteam.json

# One category while iterating on a policy.
norviq redteam run --namespace chatbot-prod --agent support-agent --category data_leakage

# One attack, to confirm a specific fix.
norviq redteam single DL-001
```

Because `run` always exits 0, a CI gate has to read the report. Mind the shape: `-o json` emits
`{timestamp, summary: {total, passed, failed, errors, pass_rate, duration_seconds}, by_category,
results}` (`norviq/redteam/reporter.py:46-60`), so the rate is at `.summary.pass_rate`. A gate on a
bare `.pass_rate` reads `null`, and `null >= 95` is false — it would fail every run, including a
clean one.

```bash
norviq redteam run --namespace chatbot-prod --agent support-agent -o json \
  | grep -v '^[0-9-]\{10\} [0-9:]\{8\} \[' \
  | jq -e '.summary.pass_rate >= 95' > /dev/null
```

A category that reads below 100% is not automatically a failing control. `MCP-01`/`MCP-02` are a
deliberate pair: 01 shows the write allowlist working, 02 shows its limit — the server id it keys on
is self-asserted, so an attacker claiming to *be* the allowlisted server is admitted by the rule that
just refused them. One of that pair is expected to fail, by design, and the reasoning is in
`norviq/redteam/attacks.py:109-112`. Note that the `mcp_identity` bucket in `by_category` is not that
pair — it holds three attacks, `MCP-01`…`MCP-03` (`attacks.py:113-115`), so it cannot read the 50%
the pair alone would; read the per-attack `results` entries rather than the category percentage when
you are judging this control.

### `norviq fleet` — enrollment

Opt-in, and only relevant if you are running a hub. A default install is single-cluster and stays
that way. See [deployment.md](deployment.md) for the hub side.

| Command | Arguments | API call |
|---|---|---|
| `status` | — | `GET /api/v1/fleet/status` |
| `join` | `TOKEN` (hub-minted) | `POST /api/v1/fleet/join` |
| `leave` | — | `POST /api/v1/fleet/leave` |

```bash
$ norviq fleet status
Mode: single-cluster  cluster: (local)  hub: -

$ norviq fleet join eyJ...            # token comes from the hub
Joined fleet as cluster 'eu-prod-1' (hub https://hub.example.internal).

$ norviq fleet leave
Left fleet. Shed 4 pushed policy/policies.
```

`join` is admin-only and does real work server-side: it verifies the token, re-checks the embedded
hub URL against the SSRF guard at the point of use, claims the token single-use at the hub, persists
the enrollment, and starts the relay and puller live (`norviq/api/routers/fleet_enroll.py:75-133`).
`leave` stops both and *sheds* every policy the fleet pushed, reconciling back to single-cluster —
the count in the output is the number of policy keys removed (`fleet_enroll.py:136-171`). Neither is
a local-only toggle.

### `norviq config` — thin, and mostly a no-op

| Command | Behavior |
|---|---|
| `show` | Prints the resolved API URL, a masked token (`****` + last 4), and the output format. Useful. |
| `set KEY VALUE` | Accepts `api_url`, `token`, `output`; rejects anything else with `Unsupported key`. **Has no effect.** |

`config set` writes into the Click context dict for the current process
(`norviq/cli/main.py:275`) and then exits. Nothing is persisted, and the `APIClient` was already
constructed from the original values at `main.py:57` — so even within one invocation, setting
`api_url` or `token` changes nothing. It is documented here because it exists and prints a
success-looking `Set key=value`, not because it does anything. Use `--api-url`/`--token`, the
environment variables, or a `.env` file.

```bash
$ norviq config show
API URL: http://127.0.0.1:8080
Token: ****kQ2f
Output: table
```

---

## 6. `norviq login` — first login without an IdP

`login` does not call the API. It runs `kubectl exec` against the api pod and executes the in-pod
token minter (`norviq/cli/main.py:329-346`):

```
kubectl [--context CTX] -n NS exec deploy/norviq-api -c api -- \
  python -m norviq.api.token_mint --ttl TTL
```

| Flag | Default | Purpose |
|---|---|---|
| `-n`, `--namespace` | `norviq` | Namespace of the Norviq release |
| `--context` | current context | kubectl context |
| `--ttl` | `3600` | Token lifetime in seconds |
| `--console-url` | `http://localhost:8080` | Base URL where you reach the console, used to build the deep link |

The design point is that the HS256 signing key never leaves the pod. `norviq/api/token_mint.py:58-68`
writes **only** the token to stdout, and the CLI captures the last line of it; the key is never
printed, never logged, and never travels to your workstation. The minted claims are
`role: admin`, `namespace: "*"` (`token_mint.py:24-34`).

Output is a `<console-url>/login#access_token=<jwt>` deep link plus the bare token. Opening the link
signs you into the console (`ui/src/auth/Login.tsx:161-168`); the bare token is what you paste into
`NRVQ_API_TOKEN` for the CLI. **Nothing is written to disk** — the token lives only in your terminal
scrollback until you export it.

```bash
# Mint a 4-hour admin token against a named context, then use it from the CLI.
norviq login -n norviq --context prod-aks --ttl 14400 --console-url https://norviq.example.com
export NRVQ_API_TOKEN='<the token it printed>'
norviq policy list
```

Failure modes are explicit `ClickException`s (exit 1): `kubectl not found on PATH`, a 30-second
timeout reaching the pod, a non-zero `kubectl exec` with the stderr attached, or an empty token.

`login` requires `kubectl exec` into the api pod, which is a cluster-admin-shaped permission. It is a
bootstrap and break-glass path, not the steady-state one — for day-to-day console access use local
login or your IdP ([security-model.md](security-model.md)), and for unattended CLI use issue an API
key.

## 7. `norviq admin reset-password` — no-egress recovery

Same shape as `login`: `kubectl exec` into the api pod, running
`python -m norviq.api.admin_reset --username <u>` (`norviq/cli/main.py:379-396`). No email, no SMTP,
no outbound network — the recovery assumes you already have cluster access, so it uses that instead
of a mail round-trip.

| Flag | Default | Purpose |
|---|---|---|
| `-n`, `--namespace` | `norviq` | Namespace of the release |
| `--context` | current context | kubectl context |
| `-u`, `--username` | `admin` | Local user to reset |
| `--console-url` | `http://localhost:8080` | Printed in the sign-in hint only |

The in-pod script generates a one-time password from an unambiguous alphabet (no `0/O/1/l/I`)
(`norviq/api/admin_reset.py:33-37`), stores its hash, and sets `must_change=True` so the next login
forces a change (`admin_reset.py:51-53`). Length is `max(20, auth_min_password_length)`
(`admin_reset.py:73`) — 20 characters at the shipped `auth_min_password_length` of 12
(`norviq/config.py:393`), longer if you have raised that. Only the password reaches stdout; it is not
logged.

```bash
$ norviq admin reset-password -n norviq -u admin --console-url https://norviq.example.com
Reset 'admin'. Sign in with this ONE-TIME password (you will be forced to set a new one):

     username: admin
     password: rH7kPqXm3vTnBzWyLd42

  Console: https://norviq.example.com/login
```

This only resets **local** users. It does nothing for OIDC/SSO identities, which your IdP owns. The
in-pod script also has a `--to-default` flag restoring the documented weak default password; the CLI
deliberately does not expose it, so a reset through `norviq` always produces a random one-time
credential.

---

## 8. Summary of gaps

Behaviors above that are real and worth knowing before you script against the CLI. None of these are
planned features; they are what the code does today, at version 0.2.0.

| Gap | Where |
|---|---|
| `norviq status` errors out (exit 1) instead of reporting a degraded dependency | `main.py:67-71` vs `health.py:59-62` |
| `redteam run` exits 0 regardless of pass rate; the rate to gate on is `.summary.pass_rate`, not `.pass_rate` | `runner.py:42-46`, `reporter.py:46-60` |
| `policy apply --target-type` is accepted, echoed, and ignored | `policies.py:1163-1170` |
| `policy create` never OPA-compiles — non-compiling Rego saves with a 200 and fails closed at call time | `policies.py:462` vs `policies.py:888-920` |
| `policy delete` cannot pass `?confirm_managed=true`, so a `__baseline__`/`__guardrail__` it can create it cannot remove | `main.py:120` vs `policies.py:763-770` |
| `policy versions`/`rollback` see only the 10 newest versions the loader holds in memory | `policy_loader.py:24,405-411` |
| `policy dry-run` never surfaces `newly_blocked` / `newly_blocked_samples` — the flips | `main.py:153-156` |
| `agent reset-trust` installs a cap at `--score` (default 0.8); only `--score 1.0` clears | `agents.py:425-441` |
| A freeze/cap on an agent with no `agent_registry` row persists nowhere, and the DB write is best-effort | `agents.py:446-457` |
| `config set` prints success and changes nothing | `main.py:275` |
| `audit list` includes red-team/synthetic rows that `audit stats` excludes | `main.py:183`, `audit.py:241` |
| `agent list` cannot filter by namespace or set a limit, though the endpoint supports both | `main.py:215-221` |
| `redteam run --category <invalid>` raises an uncaught `ValueError` traceback | `runner.py:52` |
| A repo-root `.env` overrides the cwd `.env`; the cwd loader does not strip quotes | `config.py:13-41` vs `main.py:24-33` |
| No `--version` flag; no `keys` subcommand for API-key issuance | `main.py:49-53` |
