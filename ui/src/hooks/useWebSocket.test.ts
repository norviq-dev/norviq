// SPDX-License-Identifier: Apache-2.0
import { renderHook, act } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useWebSocket } from "./useWebSocket";

class MockWS {
  static instances: MockWS[] = [];
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  url: string;
  constructor(url: string) {
    this.url = url;
    MockWS.instances.push(this);
  }
  close() {
    this.onclose?.();
  }
}

describe("useWebSocket (#5)", () => {
  beforeEach(() => {
    MockWS.instances = [];
    vi.stubGlobal("WebSocket", MockWS as unknown as typeof WebSocket);
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("does not connect when disabled", () => {
    renderHook(() => useWebSocket("ws://x/ws/audit", false));
    expect(MockWS.instances.length).toBe(0);
  });

  it("connects and reports connected on open", () => {
    const { result } = renderHook(() => useWebSocket("ws://x/ws/audit", true));
    expect(MockWS.instances.length).toBe(1);
    act(() => MockWS.instances[0].onopen?.());
    expect(result.current.connected).toBe(true);
  });

  it("reconnects with backoff after the socket closes", () => {
    const { result } = renderHook(() => useWebSocket("ws://x/ws/audit", true));
    act(() => MockWS.instances[0].onopen?.());
    act(() => MockWS.instances[0].onclose?.()); // disconnect → schedule reconnect (2s)
    expect(result.current.connected).toBe(false);
    expect(MockWS.instances.length).toBe(1);
    act(() => vi.advanceTimersByTime(2000)); // backoff window elapses
    expect(MockWS.instances.length).toBe(2); // a fresh socket was opened
  });

  it("accumulates messages newest-first", () => {
    const { result } = renderHook(() => useWebSocket<{ n: number }>("ws://x/ws/audit", true));
    act(() => MockWS.instances[0].onopen?.());
    act(() => MockWS.instances[0].onmessage?.({ data: JSON.stringify({ n: 1 }) }));
    act(() => MockWS.instances[0].onmessage?.({ data: JSON.stringify({ n: 2 }) }));
    expect(result.current.messages.map((m) => m.n)).toEqual([2, 1]);
  });
});
