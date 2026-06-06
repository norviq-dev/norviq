<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->

# Norviq UI Manual Walkthrough - Day 9

Run through every page on port-forwarded AKS UI. Document any bug.

## Policy Catalog (/policies)
- [ ] Page loads without console errors
- [ ] Lists policies with namespace, agent_class, version, priority columns
- [ ] Create Policy button opens editor
- [ ] Monaco editor loads with Rego syntax highlighting
- [ ] Dry Run button posts to /api/v1/policies/dry-run
- [ ] Save persists to DB (verify via SELECT)
- [ ] Edit existing policy updates version
- [ ] Delete prompts confirmation

## Policy Tester (/test)
- [ ] Tool dropdown lists known tools
- [ ] Pre-fill works for each Quick Test button
- [ ] Evaluate returns decision + rule_id + trust signals
- [ ] Trust signals render with color coding
- [ ] History table grows with each evaluation
- [ ] Clicking history row refills form

## Audit Log (/audit)
- [ ] Records load with most recent first
- [ ] Filter by decision (allow/block/escalate) works
- [ ] Filter by tool name works
- [ ] Filter by namespace works
- [ ] Live WebSocket tail shows new events
- [ ] Export to CSV/JSON works

## Agents (/agents)
- [ ] All known agents listed with trust scores
- [ ] Trust badge color matches category
- [ ] Click agent opens detail page with signal history chart
- [ ] Freeze button works (verify trust -> 0 in DB)
- [ ] Unfreeze works

## Asset Graph (/asset-graph)
- [ ] Graph visualization renders
- [ ] Nodes labeled by type (agent, tool, data)
- [ ] Edges show relationships
- [ ] Zoom/pan works
- [ ] Click node shows detail panel

## Attack Graph (/threats/graph)
- [ ] Attack paths visualized
- [ ] Risk score per path shown
- [ ] Filter by severity works

## Overview / KPIs (/)
- [ ] Total evaluations chart loads
- [ ] Decision distribution pie chart loads
- [ ] Trust score histogram loads
- [ ] Time-range selector updates charts

## MITRE Coverage (/threats/mitre)
- [ ] MITRE ATLAS techniques listed
- [ ] Covered (green) vs uncovered (gray) marked
- [ ] Click technique shows linked policies

## Settings (/settings)
- [ ] NrvqConfig values displayed
- [ ] Edit + save updates config (verify via kubectl get NrvqConfig)

## Sign-in / Sign-out
- [ ] Sign-in form submits to /api/v1/auth/login
- [ ] JWT token stored in browser
- [ ] Sign-out clears token

## Cross-Cutting
- [ ] Sidebar navigation works for every page
- [ ] Page refresh does not lose state
- [ ] Dark theme is consistent across pages
- [ ] No 404s or 500s in browser network tab
