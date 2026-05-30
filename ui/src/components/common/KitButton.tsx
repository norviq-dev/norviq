import { ButtonHTMLAttributes, ReactNode } from "react";
import type { LucideIcon } from "lucide-react";

type Variant = "primary" | "secondary" | "outline" | "ghost" | "destructive" | "save";

type KitButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: Variant;
  size?: "sm";
  icon?: LucideIcon;
  children?: ReactNode;
};

export function KitButton({
  variant = "primary",
  size,
  icon: Icon,
  children,
  className = "",
  ...props
}: KitButtonProps) {
  return (
    <button
      className={`btn btn-${variant}${size === "sm" ? " btn-sm" : ""}${className ? " " + className : ""}`}
      {...props}
    >
      {Icon && <Icon size={15} />}
      {children}
    </button>
  );
}
