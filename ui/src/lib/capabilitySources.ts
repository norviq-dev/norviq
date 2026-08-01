// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Visual Policy Builder — Phase 2b. Capability-source mirror for the `sourceVerb` condition type.
//
// This is a COMPILE-TIME MIRROR (hand-transcribed, read-only) of the Python capability registry at
// `norviq/engine/capability/source_registry.py`'s `_REGISTRY` dict (specifically each source's
// `_VerbSpec.tool_fragments`, `_SourceSpec.display`, and `_SourceSpec.wave`). That Python module is the
// GROUND TRUTH — this file is never imported by it and does not import it (it's Python; this is a
// browser-side TS compiler input). Only wave-1 (elasticsearch, postgresql) and wave-2 (smtp, webhook,
// s3, filesystem) sources are mirrored; the registry's dynamic/source-agnostic `classify_tool` path
// (token-lexicon based, for arbitrary cloud/control-plane tool names) has no analogue here — the
// builder's `sourceVerb` condition only targets the fixed, named sources below.
//
// PRODUCTIZATION FOLLOW-UP (out of scope for this spike, same doctrine as builderCompile.ts's embedded-
// graph-blob note): a real product would expose this table via a `GET /api/v1/capability/sources`
// endpoint (backed by the real Python registry) and have the UI fetch it, instead of a hand-mirrored
// constant that can drift from `_REGISTRY` if the Python side changes without this file being updated
// in lockstep. Building that endpoint is a separate backend PR against
// norviq/api/routers (a new router) — not this UI-only spike (pipeline FROZEN for this spike).

/** The abstract operation a tool performs against a source — mirrors Python's `Verb` enum (minus
 *  UNKNOWN, which the builder's closed dropdown never offers). */
export type CapabilityVerb = "read" | "write" | "delete" | "send";

/** Canonical, fixed verb order (read < write < delete < send) — used for the source's verb dropdown
 *  and the compiler's stable (source,verb) predicate emission order (mirrors builderTemplates.ts's
 *  DETECTOR_ORDER doctrine: a fixed universe order, not graph node order, for stable diffs). */
export const CAPABILITY_VERB_ORDER: readonly CapabilityVerb[] = ["read", "write", "delete", "send"];

/** The 6 mirrored source keys — wave-1 (datastores) first, then wave-2 (egress / object-store),
 *  exactly the order given in the Phase 2b brief. */
export type CapabilitySourceKey = "elasticsearch" | "postgresql" | "smtp" | "webhook" | "s3" | "filesystem";

export const CAPABILITY_SOURCE_ORDER: readonly CapabilitySourceKey[] = [
  "elasticsearch",
  "postgresql",
  "smtp",
  "webhook",
  "s3",
  "filesystem"
];

export interface CapabilitySourceSpec {
  key: CapabilitySourceKey;
  /** Human-readable display name, mirrors Python `_SourceSpec.display`. */
  display: string;
  /** 1 = shipped/validated, 2 = modelled-but-not-yet-primary — mirrors Python `_SourceSpec.wave`. */
  wave: 1 | 2;
  /** verb -> lowercased substring tool-name fragments, mirrors each verb's `_VerbSpec.tool_fragments`.
   *  A verb absent from this map means the source does not expose it (e.g. egress sources expose only
   *  "send"). Fragments are stored in the Python declaration's own order; callers that need a
   *  deterministic emission order (the compiler) sort them independently — see builderCompile.ts. */
  verbs: Partial<Record<CapabilityVerb, readonly string[]>>;
}

// Fragment lists below are transcribed VERBATIM from source_registry.py's `_es_specs`, `_pg_specs`,
// `_egress_specs`, `_object_store_specs` (as of the version pinned into this spike's `norviq/` tree —
// diffed byte-identical against norviq-migration/repo's copy at mirror time).
const READ_FRAGMENTS: readonly string[] = ["search", "read", "get", "list", "query", "fetch", "select", "scan"];

export const CAPABILITY_SOURCES: Record<CapabilitySourceKey, CapabilitySourceSpec> = {
  elasticsearch: {
    key: "elasticsearch",
    display: "Elasticsearch",
    wave: 1,
    verbs: {
      read: READ_FRAGMENTS,
      write: ["index", "write", "update", "put", "upsert", "bulk"],
      delete: ["delete", "drop", "purge", "truncate", "clear"]
    }
  },
  postgresql: {
    key: "postgresql",
    display: "PostgreSQL",
    wave: 1,
    verbs: {
      read: READ_FRAGMENTS,
      write: ["insert", "write", "update", "put", "upsert", "modify"],
      delete: ["delete", "drop", "truncate", "purge"]
    }
  },
  smtp: {
    key: "smtp",
    display: "SMTP / email",
    wave: 2,
    verbs: {
      send: ["send", "post", "upload", "publish", "webhook", "http", "email", "sms", "export"]
    }
  },
  webhook: {
    key: "webhook",
    display: "Webhook",
    wave: 2,
    verbs: {
      send: ["send", "post", "upload", "publish", "webhook", "http", "email", "sms", "export"]
    }
  },
  s3: {
    key: "s3",
    display: "S3",
    wave: 2,
    verbs: {
      read: READ_FRAGMENTS,
      write: ["put", "write", "upload", "post"],
      delete: ["delete", "remove", "purge"]
    }
  },
  filesystem: {
    key: "filesystem",
    display: "Filesystem",
    wave: 2,
    verbs: {
      read: READ_FRAGMENTS,
      write: ["put", "write", "upload", "post"],
      delete: ["delete", "remove", "purge"]
    }
  }
};

/** Look up a source spec by its (possibly untrusted/free-form) key. Returns undefined for anything not
 *  in the mirror — callers must treat that as "unknown source", never guess. */
export function sourceSpec(source: string): CapabilitySourceSpec | undefined {
  return (CAPABILITY_SOURCES as Record<string, CapabilitySourceSpec>)[source];
}

/** The verbs `source` exposes, in the fixed CAPABILITY_VERB_ORDER (not insertion order) — e.g. an
 *  egress source (smtp/webhook) returns just `["send"]`. Empty array for an unknown source. */
export function verbsForSource(source: string): CapabilityVerb[] {
  const spec = sourceSpec(source);
  if (!spec) return [];
  return CAPABILITY_VERB_ORDER.filter((v) => spec.verbs[v] !== undefined);
}

/** The tool-name fragments identifying `verb` on `source` (a fresh, mutable copy — callers may sort/
 *  dedupe it, e.g. the compiler sorts before emitting a rego set literal). Null for an unknown
 *  source, or a source that does not expose `verb` at all (distinguishes "unknown" from "exposes
 *  nothing", though both are compile errors upstream). */
export function fragmentsFor(source: string, verb: string): string[] | null {
  const spec = sourceSpec(source);
  if (!spec) return null;
  const frags = spec.verbs[verb as CapabilityVerb];
  return frags ? [...frags] : null;
}

/** One selectable (source, verb) pair for the UI's cascading dropdown, plus the source's display name
 *  so the dropdown never has to re-look-up CAPABILITY_SOURCES per row. */
export interface CapabilitySourceVerbPair {
  source: CapabilitySourceKey;
  verb: CapabilityVerb;
  sourceDisplay: string;
}

/**
 * Every (source, verb) pair this mirror knows about, in a FIXED canonical order (CAPABILITY_SOURCE_ORDER
 * outer, CAPABILITY_VERB_ORDER inner) — independent of any graph's node order. Used both by the UI's
 * source/verb dropdowns (source first, verb options filtered to what that source supports) and by
 * builderCompile.ts to decide a deterministic emission order for the `bld_srcverb_<source>_<verb>`
 * predicate blocks it actually uses (mirrors builderTemplates.ts's DETECTOR_ORDER doctrine).
 */
export function listCapabilitySourceVerbPairs(): CapabilitySourceVerbPair[] {
  const pairs: CapabilitySourceVerbPair[] = [];
  for (const source of CAPABILITY_SOURCE_ORDER) {
    const spec = CAPABILITY_SOURCES[source];
    for (const verb of CAPABILITY_VERB_ORDER) {
      if (spec.verbs[verb] !== undefined) pairs.push({ source, verb, sourceDisplay: spec.display });
    }
  }
  return pairs;
}
