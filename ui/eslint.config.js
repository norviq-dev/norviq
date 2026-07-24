// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Security-focused ESLint gate for the console UI — the JS/TS half of the SAST gate
// (docs/engineering/security-baseline.md). Intentionally NARROW: it runs eslint-plugin-security's
// rules promoted to `error` (so CI fails closed on a NEW finding), NOT a style/recommended ruleset —
// the goal is security parity with the Python side (bandit/semgrep), not lint noise. TS/TSX is parsed
// via typescript-eslint's parser; these rules are AST-based and need no type information.
import security from "eslint-plugin-security";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

export default [
  { ignores: ["dist/**", "node_modules/**", "coverage/**", "**/*.d.ts"] },
  {
    files: ["src/**/*.{ts,tsx,js,jsx,mjs,cjs}"],
    plugins: {
      security,
      // Registered ONLY so the codebase's pre-existing inline `eslint-disable` directives for these
      // rules resolve — their rules stay off (see below). Without this, ESLint errors "rule not found"
      // on every such directive.
      "react-hooks": reactHooks,
      "@typescript-eslint": tseslint.plugin,
    },
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: { ecmaFeatures: { jsx: true }, sourceType: "module" },
    },
    // The disable directives above are for rules this gate does not run, so they read as "unused";
    // that is expected for a security-only gate — don't fail the build on it.
    linterOptions: { reportUnusedDisableDirectives: "off" },
    rules: {
      // Out of scope for this SECURITY gate but referenced by inline directives in the codebase.
      "react-hooks/exhaustive-deps": "off",
      "@typescript-eslint/no-explicit-any": "off",
      // Promote the plugin's advisory `warn` defaults to `error` so the gate fails closed.
      "security/detect-buffer-noassert": "error",
      "security/detect-child-process": "error",
      "security/detect-disable-mustache-escape": "error",
      "security/detect-eval-with-expression": "error",
      "security/detect-new-buffer": "error",
      "security/detect-no-csrf-before-method-override": "error",
      "security/detect-non-literal-fs-filename": "error",
      "security/detect-non-literal-regexp": "error",
      "security/detect-non-literal-require": "error",
      "security/detect-possible-timing-attacks": "error",
      "security/detect-pseudoRandomBytes": "error",
      "security/detect-unsafe-regex": "error",
      "security/detect-bidi-characters": "error",
      // detect-object-injection fires on ordinary bracket access (obj[key]) and has a very high
      // false-positive rate in TS/React; it is not a reliable security signal and is widely disabled.
      // The actionable rules above stay on.
      "security/detect-object-injection": "off",
    },
  },
];
