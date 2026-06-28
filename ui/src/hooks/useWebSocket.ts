import { useEffect, useRef, useState } from "react";

/**
 * Subscribe to a websocket with automatic reconnect/backoff. Returns the most recent messages
 * (newest first, capped) plus a `connected` flag so callers can fall back to polling when the
 * socket is down.
 */
export function useWebSocket<T>(url: string, enabled: boolean) {
  const [messages, setMessages] = useState<T[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!enabled) {
      wsRef.current?.close();
      wsRef.current = null;
      setConnected(false);
      return;
    }

    let closed = false;
    let attempt = 0;
    let reconnectTimer: ReturnType<typeof setTimeout> | undefined;

    const scheduleReconnect = () => {
      if (closed) return;
      attempt += 1;
      const delay = Math.min(1000 * 2 ** Math.min(attempt, 4), 15000); // 2s,4s,8s,16s → capped 15s
      reconnectTimer = setTimeout(connect, delay);
    };

    const connect = () => {
      if (closed) return;
      let ws: WebSocket;
      try {
        ws = new WebSocket(url);
      } catch {
        scheduleReconnect();
        return;
      }
      wsRef.current = ws;

      ws.onopen = () => {
        attempt = 0;
        setConnected(true);
      };
      ws.onclose = () => {
        setConnected(false);
        scheduleReconnect();
      };
      ws.onerror = () => {
        setConnected(false);
        // onclose fires next and schedules the reconnect.
      };
      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data) as T;
          setMessages((prev) => [payload, ...prev].slice(0, 100));
        } catch {
          // Ignore malformed events.
        }
      };
    };

    connect();

    return () => {
      closed = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, [enabled, url]);

  return { messages, connected, clear: () => setMessages([]) };
}
