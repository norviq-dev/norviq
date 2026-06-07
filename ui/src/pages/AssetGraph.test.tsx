import { render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import AssetGraph from "./AssetGraph";
import { AppProvider } from "../store/AppContext";

const server = setupServer();
beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function renderPage() {
  return render(
    <MemoryRouter>
      <AppProvider>
        <AssetGraph />
      </AppProvider>
    </MemoryRouter>
  );
}

describe("AssetGraph page", () => {
  it("shows data when API returns nodes", async () => {
    server.use(
      http.get("/api/v1/asset-graph", () =>
        HttpResponse.json({
          nodes: [{ id: "1", type: "agent", name: "test-agent", properties: { namespace: "default" } }],
          edges: []
        })
      )
    );
    renderPage();
    await waitFor(() => expect(screen.getByText(/1 nodes, 0 edges/i)).toBeInTheDocument());
  });
});
