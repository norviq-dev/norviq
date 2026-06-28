// SPDX-License-Identifier: Apache-2.0
import { render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import MITRECoverage from "./MITRECoverage";
import { AppProvider } from "../store/AppContext";

const server = setupServer();
beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function renderPage() {
  return render(
    <MemoryRouter>
      <AppProvider>
        <MITRECoverage />
      </AppProvider>
    </MemoryRouter>
  );
}

describe("MITRECoverage page (#7)", () => {
  it("renders a matrix with covered vs uncovered techniques (not a placeholder)", async () => {
    server.use(
      http.get("/api/v1/mitre/coverage", () =>
        HttpResponse.json({
          namespace: "default",
          covered: 1,
          total: 2,
          techniques: [
            {
              technique_id: "AML.T0048",
              name: "Prompt Injection to Tool Misuse",
              policies: ["llm01_prompt_injection"],
              covered_policies: ["llm01_prompt_injection"],
              covered: true
            },
            {
              technique_id: "AML.T0099",
              name: "Uncovered Technique",
              policies: ["some_policy"],
              covered_policies: [],
              covered: false
            }
          ]
        })
      )
    );
    renderPage();

    expect(await screen.findByText("AML.T0048")).toBeInTheDocument();
    expect(screen.getByText("AML.T0099")).toBeInTheDocument();
    // covered vs gap badges both present
    await waitFor(() => expect(screen.getByText("Covered")).toBeInTheDocument());
    expect(screen.getByText("Gap")).toBeInTheDocument();
    // coverage summary rendered (no "coming soon")
    expect(screen.getByText(/1\/2 covered/i)).toBeInTheDocument();
    expect(screen.queryByText(/coming soon/i)).not.toBeInTheDocument();
  });
});
