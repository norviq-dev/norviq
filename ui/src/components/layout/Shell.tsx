// Shell — the authenticated app layout: wraps routed page content with the sidebar and header, and
// mounts the toast provider so any page can surface async outcomes.

import { ReactNode, useEffect, useState } from "react";
import { Header } from "./Header";
import { Sidebar } from "./Sidebar";
import { ToastProvider } from "../common/Toast";
import { SystemHealthBanner } from "../common/SystemHealthBanner";

export function Shell({ children }: { children: ReactNode }) {
  const [isTablet, setIsTablet] = useState(() => window.innerWidth <= 1023);
  const [tabletMenuOpen, setTabletMenuOpen] = useState(() => window.innerWidth <= 1023);

  useEffect(() => {
    const onResize = () => {
      const tablet = window.innerWidth <= 1023;
      setIsTablet(tablet);
      setTabletMenuOpen(tablet);
    };
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  return (
    <ToastProvider>
      <div className="app">
        <Sidebar tabletOpen={tabletMenuOpen} onCloseTablet={() => setTabletMenuOpen(false)} />
        <div className="main main-content">
          <Header
            isTablet={isTablet}
            onMenuToggle={() => setTabletMenuOpen((v) => !v)}
            tabletMenuOpen={tabletMenuOpen}
            showMenuButton={false}
          />
          {/* Above the routed page, not inside it: an enforcement outage affects every screen, and a
              banner that only appeared on one of them would be missed for exactly as long as it matters. */}
          <SystemHealthBanner />
          <main className="content">{children}</main>
        </div>
      </div>
    </ToastProvider>
  );
}
