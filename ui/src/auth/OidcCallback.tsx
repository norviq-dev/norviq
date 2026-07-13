// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

import { useEffect, useState } from "react";
import { handleCallback } from "./oidc";

/** Standalone /auth/callback handler: completes the PKCE exchange, then reloads into the app. */
export function OidcCallback() {
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    handleCallback()
      .then(() => window.location.replace("/"))
      .catch((e) => setError(String(e)));
  }, []);
  return (
    <div style={{ padding: 24, color: "var(--text-secondary)" }}>
      {error ? `Login failed: ${error}` : "Signing in…"}
    </div>
  );
}
