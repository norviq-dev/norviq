// Replace monaco-editor's VENDORED DOMPurify with the patched release we already depend on.
//
// WHY A SCRIPT AND NOT AN OVERRIDE. monaco-editor does not import the `dompurify` package. It ships
// its own copy at esm/vs/base/browser/dompurify/dompurify.js and imports it by RELATIVE path from
// domSanitize.js:
//
//     import purify from './dompurify/dompurify.js';
//
// so `overrides.dompurify` in package.json resolves the standalone package to a fixed version that
// nothing then imports. That is exactly what happened: `npm ls dompurify` reported 3.4.14 overridden,
// `npm audit --omit=dev` reported 0 vulnerabilities, and the built bundle still carried
// `t.version=\`3.2.7\`` — vulnerable to GHSA-55q2-fjhq-7xh7, in the sanitizer behind the console's
// rego editor. The tooling was clean and the shipped artefact was not.
//
// The advisory is about IN_PLACE hook removal leaving a detached subtree executable, and monaco's
// domSanitize.js uses addHook / removeAllHooks / sanitize — precisely that API. This is not
// theoretical for this codebase.
//
// Upstream does not rescue us: monaco 0.56.0 (current latest) vendors 3.4.8, also inside the
// vulnerable range. So the copy has to be replaced at build time until a monaco release vendors
// >= 3.4.13.
//
// WHY prebuild RATHER THAN postinstall. Dockerfile.ui runs `npm ci` then `npm run build`. An install
// lifecycle hook is skipped under --ignore-scripts and would put the fix at the mercy of how the
// image happens to install. `prebuild` runs as part of the build that produces the artefact, which is
// the thing that must not ship vulnerable.
//
// The script FAILS the build if it cannot do its job. A patch step that silently no-ops is the same
// defect shape as the override it replaces, and this file exists because of one of those.
import { readFileSync, writeFileSync, existsSync } from 'node:fs'

const VENDORED = 'node_modules/monaco-editor/esm/vs/base/browser/dompurify/dompurify.js'
const REPLACEMENT = 'node_modules/dompurify/dist/purify.es.mjs'
const MIN_SAFE = [3, 4, 13] // GHSA-55q2-fjhq-7xh7 first patched in 3.4.13

const die = (msg) => {
  console.error(`\n  patch-vendored-dompurify: ${msg}\n`)
  process.exit(1)
}
const parse = (v) => v.split('.').map(Number)
const gte = (a, b) => {
  for (let i = 0; i < 3; i++) {
    if ((a[i] ?? 0) > (b[i] ?? 0)) return true
    if ((a[i] ?? 0) < (b[i] ?? 0)) return false
  }
  return true
}

if (!existsSync(VENDORED)) {
  // monaco reorganised or dropped the vendored copy. Do not guess — a silent skip here is how the
  // vulnerable build shipped last time.
  die(`${VENDORED} not found. monaco-editor's layout changed; re-verify whether it still vendors ` +
      `DOMPurify before removing this script.`)
}
if (!existsSync(REPLACEMENT)) die(`${REPLACEMENT} not found — is dompurify still a dependency?`)

// Read the version from the replacement's own licence banner rather than its package.json —
// dompurify does not export ./package.json, so require()ing it throws ERR_PACKAGE_PATH_NOT_EXPORTED.
// The banner is in the exact bytes being copied, which is the more honest source anyway.
const replacementRaw = readFileSync(REPLACEMENT, 'utf8')
const vm = replacementRaw.match(/DOMPurify (\d+\.\d+\.\d+)/)
if (!vm) die(`could not read a version banner from ${REPLACEMENT}`)
const pkgVersion = vm[1]
if (!gte(parse(pkgVersion), MIN_SAFE)) {
  die(`the dompurify dependency is ${pkgVersion}, which is not >= ${MIN_SAFE.join('.')} ` +
      `(GHSA-55q2-fjhq-7xh7). Bump it before building.`)
}

const vendored = readFileSync(VENDORED, 'utf8')
const already = vendored.includes(`DOMPurify ${pkgVersion}`)

// The replacement must expose the same default export monaco imports, and the same three functions
// domSanitize.js calls. Check rather than assume — a shape mismatch would break the editor at runtime
// rather than at build time, which is far worse than a failed build.
const replacement = replacementRaw
if (!/export\s*\{\s*purify as default\s*\}/.test(replacement)) {
  die(`${REPLACEMENT} no longer ends in \`export { purify as default }\`; the drop-in assumption ` +
      `this script relies on has changed.`)
}
for (const fn of ['addHook', 'removeAllHooks', 'sanitize']) {
  if (!replacement.includes(fn)) die(`${REPLACEMENT} does not define ${fn}, which monaco calls.`)
}

if (already) {
  console.log(`  patch-vendored-dompurify: monaco already vendors ${pkgVersion} — nothing to do`)
  process.exit(0)
}

const before = (vendored.match(/DOMPurify (\d+\.\d+\.\d+)/) || [, 'unknown'])[1]
// Drop the sourceMappingURL — the .map is not copied alongside, and a dangling reference produces a
// build warning that reads like a real problem.
writeFileSync(VENDORED, replacement.replace(/\n\/\/# sourceMappingURL=.*\s*$/, '\n'), 'utf8')

const after = readFileSync(VENDORED, 'utf8')
if (!after.includes(`DOMPurify ${pkgVersion}`)) die('write completed but the version banner did not change')

console.log(`  patch-vendored-dompurify: monaco vendored DOMPurify ${before} -> ${pkgVersion} (GHSA-55q2-fjhq-7xh7)`)
