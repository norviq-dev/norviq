# PEP scope: Norviq evaluates tool INPUTS (a known boundary) — F-22

## The boundary
Norviq's enforcement point (PEP) intercepts a tool call and evaluates its **inputs** — `tool_name` + `tool_params`
— against policy, then allows/blocks/escalates **before** the tool body runs. This is the right place to stop a
*destructive or exfiltrating action* (a wire, a valve close, an export to `s3://exfil`).

It does **not**, by default, evaluate the tool's **output** (return value). An *allowed* tool whose return payload
happens to carry sensitive data can therefore surface that data to the agent/LLM even though the call itself was
benign on its inputs. The live-pentest demonstrated this: a finance `export_statement` called with clean params
(no PAN/SSN in the params) was allowed, and its simulated body emitted a canary — the input-PEP had nothing to match
on. The primary mitigation is **policy coverage on the inputs** (F-21: an export/egress tool to an external
destination is blocked regardless of params), which stops the *action*. The output itself is out of the input-PEP's
view.

This is a deliberate architectural boundary, documented here so it is a **known limitation, not a hidden gap**.

## Mitigations available today
1. **Input-side coverage (primary).** Egress/export tools to external destinations are blocked by the sector packs
   (telecom F-17, finance/healthcare F-21); destructive verbs, SoD, injection, PII/PCI-in-params, cross-tenant, and
   OT control are all enforced on inputs. Most real exfil/abuse routes through a tool *call* that the input-PEP sees.
2. **Opt-in output-DLP hook (F-22, default OFF).** `settings.sdk_output_dlp_enabled` (env `NRVQ_SDK_OUTPUT_DLP_ENABLED`)
   turns on a minimal output redactor in the SDK adapter (`norviq/sdk/langchain/adapter.py::_output_dlp`): an allowed
   tool's **string return** is scanned and PAN/SSN are masked (`****1111` / `***-**-6789`) before propagation, logged
   as `NRVQ-SDK-1043`. Default OFF = exact passthrough (zero hot-path / behavior change). This is a **capability, not
   full output-DLP**.

## Roadmap (not in scope this round)
Full output-DLP — structured/maskable evaluation of every tool return, enforced (block/redact) via policy, across the
sidecar cross-process path as well as the in-process SDK — is future work. The opt-in hook above is the seam it will
build on.

## Where this is referenced
- SDK hook: `norviq/sdk/langchain/adapter.py` (`_output_dlp`), setting in `norviq/config.py`.
- Masking reuse: `norviq/engine/masking.py::mask_text` (same masker as the F-19 audit masking / F-28 log redaction).
- Finding: F-22 (and F-21, the input-side fix that closes the demonstrated route).
