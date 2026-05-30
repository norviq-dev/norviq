---
name: norviq-design
description: Use this skill to generate well-branded interfaces and assets for Norviq, either for production or throwaway prototypes/mocks/etc. Contains essential design guidelines, colors, type, fonts, assets, and UI kit components for prototyping.
user-invocable: true
---

Read the README.md file within this skill, and explore the other available files.
If creating visual artifacts (slides, mocks, throwaway prototypes, etc), copy assets out and create static HTML files for the user to view. If working on production code, you can copy assets and read the rules here to become an expert in designing with this brand.
If the user invokes this skill without any other guidance, ask them what they want to build or design, ask some questions, and act as an expert designer who outputs HTML artifacts _or_ production code, depending on the need.

## What's here
- `README.md` — product context, content + visual foundations, iconography, manifest. **Start here.**
- `colors_and_type.css` — all design tokens (color, type, radius, shadow, motion) + semantic
  type classes (`.norviq-h1`, `.norviq-stat`, `.norviq-code`…) and `.norviq-panel` /
  `.norviq-app-bg` surfaces. Import this first in any artifact.
- `fonts/` — self-hosted Outfit (`.ttf`, weights 100–900); JetBrains Mono loads from Google Fonts.
- `assets/` — iconography & logo sourcing notes (Lucide via CDN; logo lockup).
- `preview/` — small specimen cards (colors, type, spacing, components, brand).
- `ui_kits/dashboard/` — interactive recreation of the Norviq command center; reusable
  React components (sidebar, header, KPI cards, gauge/charts, data tables, decision/trust
  badges, label-based Policy Target control, Rego editor).

## Norviq in one breath
A dark **SOC command-center** for runtime security of AI-agent tool calls in Kubernetes.
Deep navy "void" surfaces, electric-blue accent, and four sacred decision colors
(ALLOW green `#00e5a0`, BLOCK red `#ff3b5c`, ESCALATE amber `#ffb020`, AUDIT violet `#7c5cfc`).
Outfit + JetBrains Mono. Lucide icons. ECharts. Terse, operational, machine-adjacent copy.
No emoji. Quiet shadows; glow signals "live". Everything substantial lives in a `.panel`.
