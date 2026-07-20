// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Render defense: the spoke-reported console_url is only turned into a real link when it is http(s).
// A javascript:/data: url renders NO anchor (inert text), so "Open console" can't XSS a hub admin.

import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { RemoteClusterPage } from "./RemoteClusterNotice";

describe("RemoteClusterNotice — console_url scheme defense", () => {
  it("emits a link for an https url", () => {
    render(<RemoteClusterPage page="Agents" cluster="fleet-b" consoleUrl="https://fleet-b.example" />);
    const link = screen.getByRole("link", { name: /open fleet-b/i });
    expect(link).toHaveAttribute("href", "https://fleet-b.example");
  });

  it("emits a link for an http url", () => {
    render(<RemoteClusterPage page="Agents" cluster="fleet-b" consoleUrl="http://127.0.0.1:18081" />);
    expect(screen.getByRole("link", { name: /open fleet-b/i })).toHaveAttribute("href", "http://127.0.0.1:18081");
  });

  it("renders NO anchor for a javascript: url (falls back to inert text)", () => {
    render(<RemoteClusterPage page="Agents" cluster="fleet-b" consoleUrl="javascript:alert(1)" />);
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
    expect(screen.getByText(/own console to view this/i)).toBeInTheDocument();
  });

  it("renders NO anchor for a data: url", () => {
    render(<RemoteClusterPage page="Agents" cluster="fleet-b" consoleUrl="data:text/html,<script>alert(1)</script>" />);
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });
});
