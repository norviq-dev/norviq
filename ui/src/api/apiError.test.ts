// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * The error shape every API caller sees.
 *
 * Two defects motivated this, and both were invisible in a green test run:
 *  - `response.status` was discarded, so no caller could branch on a 409 — the rug-pull race on
 *    `POST /mcp/pins/approve`, and the most important thing that surface can report;
 *  - the thrown message was the raw body, so a FastAPI error reached the operator as
 *    `{"detail":"…"}` with braces and quotes intact.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, apiGet, apiSend } from "./client";

/**
 * Await a call that must reject, and hand back the typed error.
 *
 * Better than `.catch((e) => e)` twice over: it satisfies the compiler (a bare catch yields `unknown`),
 * and it FAILS when the call unexpectedly resolves — where the catch form would quietly hand the
 * resolved value to assertions that then read as passing.
 */
async function failing(call: Promise<unknown>): Promise<ApiError> {
  try {
    await call;
  } catch (e) {
    return e as ApiError;
  }
  throw new Error("expected the call to reject, but it resolved");
}

function respond(status: number, body: string) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: status >= 200 && status < 300,
      status,
      text: async () => body,
      json: async () => JSON.parse(body)
    })
  );
}

describe("ApiError", () => {
  beforeEach(() => {
    sessionStorage.setItem("nrvq_token", "t.t.t");
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    sessionStorage.clear();
  });

  it("carries the status, so a caller can branch on a 409 instead of showing a red toast", async () => {
    // The rug pull, live: the server changed its definition again between render and click.
    respond(409, JSON.stringify({ detail: "digest does not match the approved or the currently-served definition" }));
    const err = await failing(apiSend("/api/v1/mcp/pins/approve", "POST", {}));
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(409);
  });

  it("unwraps a FastAPI detail into prose — no braces reach the operator", async () => {
    respond(422, JSON.stringify({ detail: "no recorded traffic for class 'support-bot'; run it in monitor mode first" }));
    const err = await failing(apiSend("/api/v1/intents/propose", "POST", {}));
    expect(err.message).toBe("no recorded traffic for class 'support-bot'; run it in monitor mode first");
    expect(err.message).not.toContain("{");
    expect(err.message).not.toContain("detail");
  });

  it("joins a 422 validation LIST rather than printing the array", async () => {
    respond(422, JSON.stringify({ detail: [{ msg: "field required" }, { msg: "value is not a valid integer" }] }));
    const err = await failing(apiSend("/api/v1/policies", "POST", {}));
    expect(err.message).toBe("field required; value is not a valid integer");
  });

  it("passes a plain-text body through — a proxy's error is already the sentence we want", async () => {
    respond(502, "upstream connect error");
    const err = await failing(apiGet("/api/v1/tools"));
    expect(err.message).toBe("upstream connect error");
    expect(err.status).toBe(502);
  });

  it("falls back to the status when the body is empty", async () => {
    respond(500, "");
    const err = await failing(apiGet("/api/v1/tools"));
    expect(err.message).toBe("Request failed: 500");
  });

  it("keeps the raw body for diagnostics even after parsing a detail", async () => {
    const body = JSON.stringify({ detail: "pin not found", trace_id: "abc123" });
    respond(404, body);
    const err = await failing(apiGet("/api/v1/mcp/pins"));
    expect(err.body).toBe(body);
  });

  it("gives apiGet a real message — it used to drop the body entirely", async () => {
    // `apiGet` previously threw `Request failed: <status>` and discarded the response, so a read failure
    // could only ever report its number.
    respond(503, JSON.stringify({ detail: "pin store unreachable" }));
    const err = await failing(apiGet("/api/v1/tools"));
    expect(err.message).toBe("pin store unreachable");
  });

  it("is still an Error, so every existing `(err as Error).message` caller keeps working", async () => {
    respond(400, JSON.stringify({ detail: "namespace is required" }));
    const err = await failing(apiSend("/api/v1/mcp/pins/observe", "POST", {}));
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toBe("namespace is required");
  });
});
