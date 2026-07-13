import { CSSProperties, ReactNode } from "react";

type PanelProps = {
  title?: ReactNode;
  sub?: ReactNode;
  action?: ReactNode;
  pad?: boolean;
  className?: string;
  style?: CSSProperties;
  children?: ReactNode;
  // Forward test/aria hooks to the root element (e.g. `data-testid`) without listing each explicitly.
  "data-testid"?: string;
};

export function Panel({ title, sub, action, pad = true, className = "", style, children, ...rest }: PanelProps) {
  return (
    <div className={`panel${pad ? " panel-pad" : ""}${className ? " " + className : ""}`} style={style} {...rest}>
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
