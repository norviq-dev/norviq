import { HttpResponse, http } from "msw";

export const handlers = [
  http.get("/api/v1/asset-graph", () => HttpResponse.json({ nodes: [], edges: [] })),
  http.get("/api/v1/attack-paths", () => HttpResponse.json({ paths: [], nodes: [] }))
];
