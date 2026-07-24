// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Register a real Rego language + Monarch tokenizer with Monaco. The policy editors set
// defaultLanguage="rego", but Rego is not a built-in Monaco language, so highlighting was plaintext.
// This adds keywords, builtins, strings, comments, numbers and brackets so authored policy is readable.

type Monaco = typeof import("monaco-editor");

let registered = false;

/** Idempotently register the `rego` language with the given Monaco instance (call from Editor beforeMount). */
export function registerRego(monaco: Monaco): void {
  if (registered) return;
  const langs = monaco.languages.getLanguages?.() ?? [];
  if (langs.some((l) => l.id === "rego")) {
    registered = true;
    return;
  }
  monaco.languages.register({ id: "rego" });

  monaco.languages.setLanguageConfiguration("rego", {
    comments: { lineComment: "#" },
    brackets: [["{", "}"], ["[", "]"], ["(", ")"]],
    autoClosingPairs: [
      { open: "{", close: "}" },
      { open: "[", close: "]" },
      { open: "(", close: ")" },
      { open: '"', close: '"' },
      { open: "`", close: "`" }
    ]
  });

  monaco.languages.setMonarchTokensProvider("rego", {
    defaultToken: "",
    keywords: [
      "package", "import", "as", "default", "not", "with", "else", "some", "every", "in", "if", "contains", "null", "true", "false"
    ],
    builtins: [
      "input", "data", "count", "sum", "max", "min", "sort", "walk", "lower", "upper", "trim", "split", "concat",
      "contains", "startswith", "endswith", "sprintf", "to_number", "is_string", "is_number", "is_object", "is_array",
      "regex", "json", "base64", "object", "array", "time", "net", "glob", "semver", "units"
    ],
    operators: [":=", "==", "!=", "<", ">", "<=", ">=", "=", "+", "-", "*", "/", "%", "|", "&"],
    symbols: /[=><!~?:&|+\-*/^%]+/,
    tokenizer: {
      root: [
        [/#.*$/, "comment"],
        [/[a-zA-Z_]\w*(?=\s*\()/, { cases: { "@builtins": "predefined", "@default": "identifier" } }],
        [
          /[a-zA-Z_]\w*/,
          { cases: { "@keywords": "keyword", "@builtins": "predefined", "@default": "identifier" } }
        ],
        [/"([^"\\]|\\.)*$/, "string.invalid"],
        [/"/, { token: "string.quote", next: "@string" }],
        [/`/, { token: "string.quote", next: "@rawstring" }],
        // eslint-disable-next-line security/detect-unsafe-regex -- false positive: linear pattern (two \d+ split by a literal '.', optional linear exponent; no nested quantifier → no ReDoS), and it only tokenizes the user's own editor text
        [/\d+\.\d+([eE][-+]?\d+)?/, "number.float"],
        [/\d+/, "number"],
        [/[{}()[\]]/, "@brackets"],
        [/@symbols/, { cases: { "@operators": "operator", "@default": "" } }]
      ],
      string: [
        [/[^"\\]+/, "string"],
        [/\\./, "string.escape"],
        [/"/, { token: "string.quote", next: "@pop" }]
      ],
      rawstring: [
        [/[^`]+/, "string"],
        [/`/, { token: "string.quote", next: "@pop" }]
      ]
    }
  });
  registered = true;
}
