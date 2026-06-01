// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

import { useApp } from "../store/AppContext";

const RedTeam = () => {
  const { namespace } = useApp();

  return (
    <div style={{ padding: "2rem" }}>
      <h1 style={{ color: "#fff", marginBottom: "0.5rem" }}>Red Team</h1>
      <p style={{ color: "#888" }}>Showing: {namespace}</p>
      <div
        style={{
          background: "#141414",
          border: "1px solid #2A2A2A",
          borderRadius: "12px",
          padding: "2rem",
          marginTop: "1.5rem"
        }}
      >
        <h3 style={{ color: "#fff" }}>Automated Attack Suite</h3>
        <p style={{ color: "#888" }}>
          Run 25+ attack scenarios against your policies. Coming in Day 8.
        </p>
      </div>
    </div>
  );
};

export default RedTeam;
