import type { ButtonHTMLAttributes, ReactNode } from "react";
import { cn } from "./cn";

export type StatTone = "neutral" | "accent" | "success" | "warning" | "danger";

const toneChip: Record<StatTone, string> = {
  neutral: "bg-surface-raised text-text-muted",
  accent: "bg-accent-soft text-accent",
  success: "bg-success-soft text-success",
  warning: "bg-warning-soft text-warning",
  danger: "bg-danger-soft text-danger",
};

const toneDot: Record<StatTone, string> = {
  neutral: "bg-text-subtle",
  accent: "bg-accent",
  success: "bg-success",
  warning: "bg-warning",
  danger: "bg-danger",
};

export interface StatTileProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "children" | "value"> {
  /** The big number (already formatted for the locale). */
  value: ReactNode;
  label: ReactNode;
  tone?: StatTone;
  /** Shown in a tone-colored chip; without it a tone dot marks the tile. */
  icon?: ReactNode;
  /** A short line under the label, for example "2 new since Monday". */
  detail?: ReactNode;
  /** Renders a button (for tiles that filter a list); otherwise a static tile. */
  interactive?: boolean;
}

/**
 * A big number with a label: security report tiles (Gefährdet / Mehrfach /
 * Schwach / Sicher), counts on dashboards.
 */
export function StatTile({
  value,
  label,
  tone = "neutral",
  icon,
  detail,
  interactive = false,
  className,
  type = "button",
  ...props
}: StatTileProps) {
  const body = (
    <>
      <div className="flex items-center justify-between gap-2">
        {icon ? (
          <span className={cn("flex size-8 items-center justify-center rounded-[9px] [&_svg]:size-4", toneChip[tone])}>
            {icon}
          </span>
        ) : (
          <span aria-hidden="true" className={cn("size-2 rounded-full", toneDot[tone])} />
        )}
      </div>
      <div className="mt-4 text-stat text-text tabular-nums">{value}</div>
      <div className="mt-1 text-sm font-medium text-text-muted">{label}</div>
      {detail && <div className="mt-0.5 text-xs text-text-subtle">{detail}</div>}
    </>
  );
  const base = "flex flex-col rounded-card border border-hairline bg-surface p-5 text-left shadow-card";
  if (!interactive) return <div className={cn(base, className)}>{body}</div>;
  return (
    <button
      type={type}
      className={cn(
        base,
        "transition-[background-color,border-color] duration-150 hover:border-border-strong hover:bg-surface-raised",
        "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus",
        className,
      )}
      {...props}
    >
      {body}
    </button>
  );
}
