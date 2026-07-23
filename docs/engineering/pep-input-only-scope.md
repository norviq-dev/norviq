<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->

# PEP scope: Norviq evaluates tool INPUTS (a known boundary)

## The boundary
Norviq's enforcement point (PEP) intercepts a tool call and evaluates its **inputs** — `tool_name` + `tool_params`
— against policy, then allows/blocks/escalates **before** the tool body runs. This is the right place to stop a
*destructive or exfiltrating action* (a wire, a valve close, an export to `s3://exfil`).

It does **not**, by default, evaluate the tool's **output** (return value). An *allowed* tool whose return payload
happens to carry sensitive data can therefore surface that data to the agent/LLM even though the call itself was
benign on its inputs. As a concrete example, a finance `export_statement` called with clean params
(no PAN/SSN in the params) is allowed, and its body can emit sensitive data — the input-PEP has nothing to match
on. The primary mitigation is **policy coverage on the inputs** (an export/egress tool to an external
destination is blocked regardless of params), which stops the *action*. The output itself is out of the input-PEP's
view.

This is a deliberate architectural boundary, documented here so it is a **known limitation, not a hidden gap**.

## Mitigations available today
1. **Input-side coverage (primary).** Egress/export tools to external destinations are blocked by the sector packs
   (telecom, finance/healthcare); destructive verbs, SoD, injection, PII/PCI-in-params, cross-tenant, and
   OT control are all enforced on inputs. Most real exfil/abuse routes through a tool *call* that the input-PEP sees.
2. **Opt-in output-DLP hook (default OFF).** `settings.sdk_output_dlp_enabled` (env `NRVQ_SDK_OUTPUT_DLP_ENABLED`)
   turns on a minimal output redactor shared by **every** SDK framework adapter — langchain, langgraph, crewai,
   autogen, semantic-kernel — via `norviq/sdk/core/wrapping.py::_output_dlp`: an allowed tool's **string return** is
   scanned and PAN/SSN are masked (`****1111` / `***-**-6789`) before propagation, logged as `NRVQ-SDK-1043`.
   Default OFF = exact passthrough (zero hot-path / behavior change).

   Know its limits before relying on it. It is a **capability, not full output-DLP**:
   - It only inspects a `str` return. A dict/list/dataframe/object return passes through untouched.
   - It only masks PAN and SSN (whatever `mask_text` covers) — not names, addresses, keys, or free-form secrets.
   - It **redacts**; it never blocks or escalates. The call is already allowed and already ran.
   - It lives in the **in-process SDK path only**. A tool call routed through the injected sidecar's cross-process
     path is not covered.

## Roadmap (not in scope this round)
Full output-DLP — structured/maskable evaluation of every tool return, enforced (block/redact) via policy, across the
sidecar cross-process path as well as the in-process SDK — is future work. The opt-in hook above is the seam it will
build on.

## Where this is implemented
- SDK hook: `norviq/sdk/core/wrapping.py` (`_output_dlp`), called by each framework adapter under
  `norviq/sdk/<framework>/adapter.py`; the `sdk_output_dlp_enabled` setting is in `norviq/config.py`.
- Masking reuse: `norviq/engine/masking.py::mask_text` (same masker as the audit masking / log redaction).
- Input-side coverage that closes the demonstrated route: the sector packs under `policies/sector/`.
