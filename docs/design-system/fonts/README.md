# Fonts

- **Outfit** — all UI text. **Self-hosted** from the uploaded brand files in this folder
  (`Outfit-Thin … Outfit-Black.ttf`), wired via `@font-face` in `colors_and_type.css` across
  weights 100–900. Default UI weight is 600 (SemiBold).
- **JetBrains Mono** — all code/identifiers. Still delivered from **Google Fonts** (no local
  files were uploaded for it; CDN delivery is fine).

`colors_and_type.css` loads them like so:

```css
@import url("https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap");
@font-face { font-family: "Outfit"; font-weight: 400; src: url("fonts/Outfit-Regular.ttf") format("truetype"); }
/* …100/200/300/500/600/700/800/900 likewise… */
```

Weight → file map: 100 Thin · 200 ExtraLight · 300 Light · 400 Regular · 500 Medium ·
600 SemiBold · 700 Bold · 800 ExtraBold · 900 Black.

If you want JetBrains Mono self-hosted too, upload its `.ttf`/`.woff2` files and I'll wire them.
