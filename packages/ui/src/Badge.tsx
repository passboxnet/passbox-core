import type { HTMLAttributes } from "react";
import { cn } from "./cn";

export type BadgeTone = "neutral" | "accent" | "success" | "warning" | "danger" | "info";
/** `soft` (default) for status, `solid` for strong labels such as "Popular", `outline` for chips. */
export type BadgeVariant = "soft" | "solid" | "outline";

const soft: Record<BadgeTone, string> = {
  neutral: "bg-surface-raised text-text-muted ring-border",
  accent: "bg-accent-soft text-accent ring-accent/25",
  success: "bg-success-soft text-success ring-success/25",
  warning: "bg-warning-soft text-warning ring-warning/30",
  danger: "bg-danger-soft text-danger ring-danger/25",
  info: "bg-info-soft text-info ring-info/25",
};

const solid: Record<BadgeTone, string> = {
  neutral: "bg-surface-inverse text-text-inverse ring-transparent",
  accent: "bg-accent text-accent-contrast ring-transparent",
  success: "bg-success text-success-contrast ring-transparent",
  warning: "bg-warning text-warning-contrast ring-transparent",
  danger: "bg-danger text-danger-contrast ring-transparent",
  info: "bg-info-soft text-info ring-info/25",
};

const outline: Record<BadgeTone, string> = {
  neutral: "bg-transparent text-text-muted ring-border-strong",
  accent: "bg-transparent text-accent ring-accent/50",
  success: "bg-transparent text-success ring-success/50",
  warning: "bg-transparent text-warning ring-warning/60",
  danger: "bg-transparent text-danger ring-danger/50",
  info: "bg-transparent text-info ring-info/50",
};

const dots: Record<BadgeTone, string> = {
  neutral: "bg-text-subtle",
  accent: "bg-accent",
  success: "bg-success",
  warning: "bg-warning",
  danger: "bg-danger",
  info: "bg-info",
};

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: BadgeTone;
  variant?: BadgeVariant;
  /** A small status dot before the text. */
  dot?: boolean;
}

/** A small pill for status, counts and labels. `Pill` is the same component. */
export function Badge({ tone = "neutral", variant = "soft", dot = false, className, children, ...props }: BadgeProps) {
  const palette = variant === "solid" ? solid : variant === "outline" ? outline : soft;
  return (
    <span
      className={cn(
        "inline-flex h-5 items-center gap-1 rounded-full px-2 text-2xs font-semibold whitespace-nowrap tabular-nums ring-1 ring-inset [&_svg]:size-3",
        palette[tone],
        className,
      )}
      {...props}
    >
      {dot && <span aria-hidden="true" className={cn("size-1.5 rounded-full", dots[tone])} />}
      {children}
    </span>
  );
}

export const Pill = Badge;
export type PillProps = BadgeProps;

export function Kbd({ className, ...props }: HTMLAttributes<HTMLElement>) {
  return (
    <kbd
      className={cn(
        // Keyboard hints mean nothing on touch screens.
        "inline-flex h-5 min-w-5 items-center justify-center rounded-md border border-border-strong bg-surface px-1 font-sans text-2xs font-medium text-text-muted shadow-xs coarse:hidden",
        className,
      )}
      {...props}
    />
  );
}
