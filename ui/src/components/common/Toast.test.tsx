// SPDX-License-Identifier: Apache-2.0
// The shared feedback surface. Errors/warnings are STICKY (a partial outcome can't expire
// unseen); success/info auto-dismiss; the action button fires and dismisses.
import { render, screen, act } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { ToastProvider, useToast } from "./Toast";

function Trigger() {
  const { push } = useToast();
  return (
    <div>
      <button onClick={() => push({ kind: "success", message: "saved ok" })}>ok</button>
      <button onClick={() => push({ kind: "warning", message: "0 drafts created", detail: "AML.T0055 has no runtime-expressible rule" })}>warn</button>
      <button onClick={() => push({ kind: "info", message: "draft ready", actionLabel: "Open →", onAction: onAction })}>action</button>
    </div>
  );
}
const onAction = vi.fn();

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe("ToastProvider", () => {
  it("success auto-dismisses; warning is sticky with its full detail visible", () => {
    render(
      <ToastProvider>
        <Trigger />
      </ToastProvider>
    );
    act(() => { screen.getByText("ok").click(); });
    act(() => { screen.getByText("warn").click(); });
    expect(screen.getByTestId("toast-success")).toHaveTextContent("saved ok");
    expect(screen.getByTestId("toast-warning")).toHaveTextContent("no runtime-expressible rule");
    act(() => { vi.advanceTimersByTime(7000); });
    // success expired, the warning survives until explicitly dismissed
    expect(screen.queryByTestId("toast-success")).toBeNull();
    expect(screen.getByTestId("toast-warning")).toBeInTheDocument();
    act(() => { screen.getByLabelText("Dismiss notification").click(); });
    expect(screen.queryByTestId("toast-warning")).toBeNull();
  });

  it("the action button fires the callback and dismisses the toast", () => {
    render(
      <ToastProvider>
        <Trigger />
      </ToastProvider>
    );
    act(() => { screen.getByText("action").click(); });
    act(() => { screen.getByText("Open →").click(); });
    expect(onAction).toHaveBeenCalledTimes(1);
    expect(screen.queryByTestId("toast-info")).toBeNull();
  });
});
