// IconRail — the slim vertical navigation rail: the Norviq mark plus the top-level section icons that
// switch the active section and expand the sidebar panel.

import { BookOpen, Brain, Crosshair, HelpCircle, MessageCircle, Settings } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { Section, useApp } from "../../store/AppContext";

function NorviqMark({ size = 22 }: { size?: number }) {
  return (
    <svg viewBox="0 0 166 200" width={size * 0.83} height={size} fill="currentColor" aria-label="Norviq">
      <path d="M0 0 L77.5 72.3 L77.5 200 L74.3 197.2 L57.3 181 L57.3 87.4 L0 34.4 L0 0.4 Z" />
      <path d="M165.6 0 L166 34 L108.3 87.4 L108.3 180.6 L88.1 200 L88.1 72.3 L165.2 0.4 Z" />
    </svg>
  );
}

const SECTION_ICONS: Array<{ section: Section; title: string; icon: typeof Crosshair }> = [
  { section: "intelligence", title: "Overview", icon: Brain },
  { section: "security", title: "Security Operations", icon: Crosshair },
  { section: "settings", title: "Settings", icon: Settings }
];

const BOTTOM_ICONS = [
  {
    Icon: HelpCircle,
    title: "Support",
    onClick: () => window.open("https://norviq.dev/docs", "_blank", "noreferrer")
  },
  {
    Icon: MessageCircle,
    title: "Feedback",
    onClick: () => window.open("https://norviq.dev/docs", "_blank", "noreferrer")
  },
  {
    Icon: BookOpen,
    title: "Documentation",
    onClick: () => window.open("https://norviq.dev/docs", "_blank", "noreferrer")
  }
];

export default function IconRail({
  onNavigate
}: {
  onNavigate?: () => void;
}) {
  const navigate = useNavigate();
  const { activeSection, setActiveSection } = useApp();
  const defaultRouteBySection: Record<Section, string> = {
    intelligence: "/",
    security: "/policies/catalog",
    settings: "/settings/general"
  };

  return (
    <div className="icon-rail">
      <div className="rail-top">
        <button
          type="button"
          className="rail-logo"
          style={{ color: "var(--accent)" }}
          title="Go to Overview"
          onClick={() => {
            setActiveSection("intelligence");
            navigate("/");
            onNavigate?.();
          }}
        >
          <NorviqMark size={22} />
        </button>
        {SECTION_ICONS.map((item) => (
          <button
            key={item.title}
            type="button"
            className={`rail-icon${activeSection === item.section ? " active" : ""}`}
            title={item.title}
            onClick={() => {
              setActiveSection(item.section);
              navigate(defaultRouteBySection[item.section]);
              onNavigate?.();
            }}
          >
            <item.icon size={18} />
          </button>
        ))}
      </div>
      <div className="rail-bottom">
        {BOTTOM_ICONS.map(({ Icon, title, onClick }, idx) => (
          <button key={idx} type="button" className="rail-icon muted-rail" title={title} onClick={onClick}>
            <Icon size={17} />
          </button>
        ))}
      </div>
    </div>
  );
}
