import { HttpResponse, http } from "msw";

export const handlers = [
  http.get("/api/v1/asset-graph", () => HttpResponse.json({ nodes: [], edges: [] })),
  http.get("/api/v1/attack-paths", () => HttpResponse.json({ paths: [], nodes: [] })),
  http.get("/api/v1/cluster-info", () =>
    HttpResponse.json({ cluster_id: "local", cluster_name: "local", namespaces: ["default"] })
  ),
  http.get("/api/v1/me", () =>
    HttpResponse.json({ sub: "tester", role: "admin", namespace: "", email: null, name: "Test User" })
  ),
  http.get("/api/v1/coverage-by-category", () =>
    HttpResponse.json({ namespace: "default", coverage_pct: 0, categories: [] })
  ),
  http.get("/api/v1/settings", () =>
    HttpResponse.json({
      namespace: "default",
      enforcement_mode: "block",
      trust_threshold: 0.7,
      violation_penalty: 0.05,
      rate_limit: 60
    })
  ),
  http.get("/api/v1/version", () => HttpResponse.json({ version: "0.1.0", license: "Apache-2.0" })),
  http.get("/api/v1/deployments", () => HttpResponse.json([]))
];
