import { CSSProperties, ReactNode } from "react";

type PanelProps = {
  title?: ReactNode;
  sub?: ReactNode;
  action?: ReactNode;
  pad?: boolean;
  className?: string;
  style?: CSSProperties;
  children?: ReactNode;
};

export function Panel({ title, sub, action, pad = true, className = "", style, children }: PanelProps) {
  return (
    <div className={`panel${pad ? " panel-pad" : ""}${className ? " " + className : ""}`} style={style}>
      {(title || action) && (
        <div className="panel-head">
          <div>
            {title && <div className="panel-title">{title}</div>}
            {sub && <div className="panel-sub">{sub}</div>}
          </div>
          {action}
        </div>
      )}
      {children}
    </div>
  );
}
