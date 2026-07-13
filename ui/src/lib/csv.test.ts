// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

import { describe, it, expect } from "vitest";
import { csvCell, toCsv } from "./csv";

describe("csv (F-46)", () => {
  it("quotes cells containing comma, quote, or newline", () => {
    expect(csvCell("plain")).toBe("plain");
    expect(csvCell("a,b")).toBe('"a,b"');
    expect(csvCell('he said "hi"')).toBe('"he said ""hi"""');
    expect(csvCell("line1\nline2")).toBe('"line1\nline2"');
    expect(csvCell(null)).toBe("");
  });

  it("serializes rows with an ordered header from audit records", () => {
    const rows = [
      { timestamp: "t1", decision: "block", tool_name: "send_email", reason: "exfil, blocked" },
      { timestamp: "t2", decision: "allow", tool_name: "search_kb", reason: "ok" }
    ];
    const csv = toCsv(rows, ["timestamp", "decision", "tool_name", "reason"]);
    const lines = csv.split("\n");
    expect(lines[0]).toBe("timestamp,decision,tool_name,reason");
    expect(lines[1]).toBe('t1,block,send_email,"exfil, blocked"'); // reason quoted (has a comma)
    expect(lines[2]).toBe("t2,allow,search_kb,ok");
  });

  it("emits just the header when there are no rows", () => {
    expect(toCsv([], ["a", "b"])).toBe("a,b");
  });
});
