// SPDX-License-Identifier: Apache-2.0
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Settings } from "./Settings";

function renderPage() {
  return render(
    <MemoryRouter>
      <Settings />
    </MemoryRouter>
  );
}

describe("Settings Save (#8)", () => {
  beforeEach(() => localStorage.clear());
  afterEach(() => localStorage.clear());

  it("persists settings to localStorage and shows a confirmation", async () => {
    renderPage();
    const trust = screen.getByDisplayValue("0.7");
    fireEvent.change(trust, { target: { value: "0.55" } });

    fireEvent.click(screen.getByRole("button", { name: /save changes/i }));

    // visible confirmation
    await waitFor(() => expect(screen.getByText(/settings saved/i)).toBeInTheDocument());

    // actually persisted
    const stored = JSON.parse(localStorage.getItem("nrvq_settings") ?? "{}");
    expect(stored.trustThreshold).toBe("0.55");
    expect(stored.mode).toBe("block");
  });

  it("notes that settings are saved locally only (no server store yet)", () => {
    renderPage();
    expect(screen.getByText(/saved locally \(no server settings store yet\)/i)).toBeInTheDocument();
  });

  it("re-hydrates persisted settings on mount", () => {
    localStorage.setItem(
      "nrvq_settings",
      JSON.stringify({ mode: "audit", trustThreshold: "0.42", violationPenalty: "0.05", rateLimit: "120" })
    );
    renderPage();
    expect(screen.getByDisplayValue("0.42")).toBeInTheDocument();
    expect(screen.getByDisplayValue("120")).toBeInTheDocument();
  });
});
