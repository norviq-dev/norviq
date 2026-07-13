import { ReactNode, useEffect, useState } from "react";
import { Header } from "./Header";
import { Sidebar } from "./Sidebar";
import { ToastProvider } from "../common/Toast";

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
          <main className="content">{children}</main>
        </div>
      </div>
    </ToastProvider>
  );
}
