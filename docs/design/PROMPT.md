# Kickoff prompt for Claude Design

Paste this as-is.

---

```
Redesign four surfaces of the Norviq security console and produce high-fidelity mockups.

Repo:   /Users/san/Documents/Development/norviq/norviq-migration/repo
Branch: integrate/mcp-and-builder   (NOT main — the APIs below exist only here)

Start by reading docs/design/README.md, then 00-foundations.md and 05-data-contracts.md.
Each surface has its own brief. Every fact in the pack is verified against source;
anything marked "(opinion)" is mine and you should argue with it.

Norviq intercepts an AI agent's tool calls and decides whether to allow them. The idea
the whole product turns on: an allowlist of tool NAMES is not a security control — the
control is scoping a tool's ARGUMENTS ("send_email, but only to @acme.com, and never
carrying a credential").

Work in this order:
  1. docs/design/01-tools-page.md            new page — a tool registry with no UI today
  2. docs/design/02-visual-policy-builder.md the redesign that matters most
  3. docs/design/04-propose-from-traffic.md  currently renders against CSS classes that don't exist
  4. docs/design/03-mcp-servers.md           healthiest surface; elevate, don't rebuild

The one non-negotiable: today, argument scoping is reachable only by noticing and clicking
a small "+ scope" affordance inside a chip. Operators do not know it exists, so the product's
differentiator is invisible. A first-time operator must discover it WITHOUT being told.

Constraints:
- Dark theme only. There is no light mode and no toggle — do not design one.
- Use the existing tokens, component kit and layout shell in 00-foundations.md. A palette-
  consistency test fails the build on novel colours. Flag anything you need that doesn't exist.
- The audience is a security engineer: dense, scannable, tables over cards.
- Provenance is never optional. "Declared" (has a schema, arguments scopeable) and "observed"
  (just a name seen in traffic) must never be merged into one list — that exact flattening was
  the bug this work fixed.
- The registry informs, never restricts. Free-text tool entry must survive everywhere; a
  deny-by-default policy has to be writable for a tool nobody has called yet.
- Empty is the DEFAULT state, not an edge case. Most installs have zero declared tools.

Deliver per surface: layout, key states (empty / loading / populated / error), and the new
components each needs. Each brief ends with acceptance criteria — treat those as the contract.
```

---

## Shorter variant

If you want something you can paste in a chat box without scrolling:

```
Redesign the Norviq console: Tools (new), Visual Policy Builder, Propose from traffic, MCP Servers.

Repo /Users/san/Documents/Development/norviq/norviq-migration/repo, branch integrate/mcp-and-builder.
Read docs/design/README.md first — the full brief pack is in docs/design/, with verified tokens,
component kit and real API payloads.

Norviq decides whether an AI agent may make a tool call. Its differentiator is scoping a tool's
ARGUMENTS, not just allowing it by name — and today that is hidden behind an unlabeled "+ scope"
chip button, so nobody knows it exists. Making it discoverable is the primary job.

Dark theme only, reuse the existing design system, tables over cards, and never merge "declared"
tools (schema known, scopeable) with merely "observed" ones. Priority order and acceptance
criteria are in the briefs.
```
