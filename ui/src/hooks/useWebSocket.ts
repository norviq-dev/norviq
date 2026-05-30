import { useEffect, useRef, useState } from "react";

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

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onerror = () => setConnected(false);
    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data) as T;
        setMessages((prev) => [payload, ...prev].slice(0, 100));
      } catch {
        // Ignore malformed events.
      }
    };

    return () => ws.close();
  }, [enabled, url]);

  return { messages, connected, clear: () => setMessages([]) };
}
