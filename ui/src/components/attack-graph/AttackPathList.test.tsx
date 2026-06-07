import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AttackPathList } from "./AttackPathList";
import type { AttackPath } from "./types";

const paths: AttackPath[] = [
  {
    path_id: "p1",
    source_id: "a",
    target_id: "b",
    steps: [],
    risk_score: 0.8,
    severity: "high",
    mitre_techniques: [],
    blocked_by_policy: false
  }
];

describe("AttackPathList", () => {
  it("renders and selects path", () => {
    const onSelect = vi.fn();
    render(<AttackPathList paths={paths} onSelect={onSelect} />);
    fireEvent.click(screen.getByText(/p1/i));
    expect(onSelect).toHaveBeenCalledWith(paths[0]);
  });
});
