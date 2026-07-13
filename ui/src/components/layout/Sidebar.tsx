import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import { sectionFromPath, useApp } from "../../store/AppContext";
import ExpandedPanel from "./ExpandedPanel";
import IconRail from "./IconRail";

export function Sidebar({
  tabletOpen,
  onCloseTablet
}: {
  tabletOpen: boolean;
  onCloseTablet: () => void;
}) {
  const location = useLocation();
  const { setActiveSection } = useApp();
  const [isLaptop, setIsLaptop] = useState(() => window.innerWidth >= 1024 && window.innerWidth <= 1439);
  const [isTablet, setIsTablet] = useState(() => window.innerWidth <= 1023);
  const [laptopPanelOpen, setLaptopPanelOpen] = useState(false);

  useEffect(() => {
    setActiveSection(sectionFromPath(location.pathname));
  }, [location.pathname, setActiveSection]);

  useEffect(() => {
    const onResize = () => {
      const laptop = window.innerWidth >= 1024 && window.innerWidth <= 1439;
      const tablet = window.innerWidth <= 1023;
      setIsLaptop(laptop);
      setIsTablet(tablet);
      if (!laptop) setLaptopPanelOpen(false);
    };
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  useEffect(() => {
    setLaptopPanelOpen(false);
    if (tabletOpen) onCloseTablet();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.pathname]);

  const showLaptopOverlay = isLaptop && laptopPanelOpen;

  return (
    <>
      {tabletOpen && !isTablet && <div className="sidebar-backdrop" onClick={onCloseTablet} />}
      <aside
        className={`sidebar2 ${tabletOpen || isTablet ? "tablet-open" : ""}`}
        onMouseEnter={() => {
          if (isLaptop) setLaptopPanelOpen(true);
        }}
        onMouseLeave={() => {
          if (isLaptop) setLaptopPanelOpen(false);
        }}
      >
        <IconRail
          onNavigate={() => {
            if (isLaptop) setLaptopPanelOpen(false);
            if (tabletOpen) onCloseTablet();
          }}
        />
        <ExpandedPanel
          overlay={showLaptopOverlay}
          onNavigate={() => {
            if (isLaptop) setLaptopPanelOpen(false);
            if (tabletOpen) onCloseTablet();
          }}
        />
      </aside>
    </>
  );
}
