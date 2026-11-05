// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Empty collection literals whose element type OPA's type checker can see. The TypeScript mirror of
// norviq/engine/empty_literals.py — read that module's docstring for the measurements. In short:
// OPA 1.21 types a bare `{}`, `set()` or `[]` as having NO members, so `names[x]`, `names[_]` and
// `not names[x]` over one are compile errors (`rego_type_error: undefined ref`), and a module that does
// not compile fails every call it governs closed as `evaluator_error`. 1.19 accepted all of them.
//
// Each form is a comprehension that never yields: OPA types it from its head (string), its value is
// the same empty collection, and its KIND is the one it replaces — `{}` is an empty OBJECT in Rego, so
// EMPTY_OBJECT is an object, not a set. tests/engine/test_empty_literals.py pins these strings to the
// Python ones byte for byte.

export const EMPTY_OBJECT = '{k: k | k := ""; false}';
export const EMPTY_SET = '{s | s := ""; false}';
export const EMPTY_ARRAY = '[s | s := ""; false]';

/** A partial-set rule that never fires — the same text as norviq/api/baseline.py's `_NEVER_FIRES`. */
export function neverFires(setName: string): string {
  return `${setName}[id] { false; id := "__never__" }`;
}
