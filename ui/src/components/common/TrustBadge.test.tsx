// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { TrustBadge } from "./TrustBadge";

describe("TrustBadge", () => {
  it("shows a known band as itself", () => {
    render(<TrustBadge category="Medium" />);
    expect(screen.getByText("medium")).toBeInTheDocument();
  });

  it("does not label an unscored agent frozen", () => {
    // The API reads "unscored" for an agent whose freeze was lifted and that has not called since. Every
    // category the badge did not know used to fall back to "frozen".
    render(<TrustBadge category="unscored" />);
    expect(screen.getByText("unscored")).toBeInTheDocument();
    expect(screen.queryByText("frozen")).toBeNull();
  });

  it("says unknown for an empty category", () => {
    render(<TrustBadge category="" />);
    expect(screen.getByText("unknown")).toBeInTheDocument();
  });
});
