# Assets

Brand assets for Norviq, derived from the supplied logo artwork.

## Logo / brand mark
The Norviq mark is an **Algiz-inspired geometric "Y"** — two beveled blades rising from a split
central stem — paired with the lowercase **norviq** wordmark. Supplied as black-on-white artwork
and processed here into clean, anti-aliased, **transparent** assets tinted for each surface:

| File | Use |
|---|---|
| `norviq-lockup-white.png` | Full logo (mark + wordmark), **light-on-dark** — primary |
| `norviq-lockup-black.png` | Full logo, **dark-on-light** (navy `#0c1425`) — reversed |
| `norviq-mark-white.png` | Symbol only, white — favicon, app icon, sidebar |
| `norviq-mark-black.png` | Symbol only, navy — on light surfaces |
| `norviq-wordmark-white.png` | Wordmark only, white |

Rules: white on any surface darker than `#152040`, navy on light. Clear space ≈ the mark's stem
width on all sides. Don't recolor, rotate, stretch, or add effects. The mark reads cleanly at 16px.
Source artwork: `uploads/WhatsApp Image 2026-05-30 at 7.35.44 AM.jpeg`.

## Icons — Lucide (CDN)
The product imports `lucide-react`. For HTML artifacts, load the same icon set from CDN:

```html
<script src="https://unpkg.com/lucide@latest"></script>
<script>lucide.createIcons();</script>
```

```html
<i data-lucide="layout-dashboard"></i>
```

Sidebar nav mapping (from source): Dashboard → `layout-dashboard`, Policies → `clipboard-list`,
Audit Log → `activity`, Agents → `bot`, Threats → `network`, Settings → `settings`.
Header: `search`, `bell`. Controls: `chevron-down`, `check`, `x`, `triangle-alert`, `radar`,
`arrow-up-circle`, `rotate-ccw`, `snowflake`.

**If you have vector (SVG) source for the mark, share it** — I'll vendor an SVG for infinite
scalability; the current assets are high-resolution transparent PNGs keyed from the artwork.
