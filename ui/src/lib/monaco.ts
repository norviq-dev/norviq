// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// SLIM-MONACO: point @monaco-editor/react's loader at the LOCALLY BUNDLED monaco-editor instead of its
// default, which fetches Monaco's AMD loader + language chunks from cdn.jsdelivr.net at first editor open.
// For a security console that CDN dependency is wrong: it breaks air-gapped/offline installs and pins an
// untracked monaco version. Importing this module (side-effect) before any <Editor> mounts makes Vite
// bundle Monaco + its editor worker into the (already route-lazy) editor chunks — no third-party fetch.
import { loader } from "@monaco-editor/react";
// Minimal editor CORE only — NOT the "monaco-editor" barrel, which bundles all ~40 built-in language
// contributions (typescript, solidity, …) we never use. We register Rego ourselves (lib/monaco-rego),
// so the core editor API is all we need — this drops the multi-MB language payload.
import * as monaco from "monaco-editor/esm/vs/editor/editor.api";
import editorWorker from "monaco-editor/esm/vs/editor/editor.worker?worker";

// The Rego editor registers a custom, lightweight language (see lib/monaco-rego.ts) with no language
// service, so the base editor worker is the only one needed. Serving it locally keeps syntax highlighting
// and folding off the main thread without any language-specific workers.
self.MonacoEnvironment = {
  getWorker() {
    return new editorWorker();
  },
};

loader.config({ monaco });
