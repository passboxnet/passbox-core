import { forwardRef, type HTMLAttributes } from "react";
import { cn } from "./cn";

export type CardVariant = "default" | "raised" | "sunken" | "glass" | "outline";
export type CardPadding = "none" | "sm" | "md" | "lg";

export interface CardProps extends HTMLAttributes<HTMLDivElement> {
  variant?: CardVariant;
  padding?: CardPadding;
  /** Hover and focus styles for cards that are links or buttons (put the handler on the card itself). */
  interactive?: boolean;
}

const cardVariants: Record<CardVariant, string> = {
  default: "border border-border bg-surface shadow-card",
  raised: "border border-hairline bg-surface-raised shadow-raised",
  sunken: "bg-surface-sunken ring-1 ring-hairline ring-inset",
  glass: "glass shadow-overlay",
  outline: "border border-border",
};

const paddings: Record<CardPadding, string> = { none: "", sm: "p-3", md: "p-5", lg: "p-6 sm:p-8" };

/** A rounded surface (radius `card`, 20 px) for grouped content. */
export const Card = forwardRef<HTMLDivElement, CardProps>(function Card(
  { variant = "default", padding = "md", interactive = false, className, ...props },
  ref,
) {
  return (
    <div
      ref={ref}
      className={cn(
        "rounded-card",
        cardVariants[variant],
        paddings[padding],
        interactive &&
          "cursor-pointer transition-[background-color,border-color,box-shadow] duration-150 hover:border-border-strong hover:bg-surface-raised focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus",
        className,
      )}
      {...props}
    />
  );
});

export interface PanelProps extends HTMLAttributes<HTMLDivElement> {
  /** Force a theme for this panel's subtree (website panels alternate light and dark). */
  theme?: "light" | "dark";
  /** The thick soft bezel around website device panels. */
  bezel?: boolean;
}

/**
 * A large surface (radius `panel`, 24 px): the desktop window, website
 * "device" panels. With `theme` the subtree uses that theme's tokens.
 */
export const Panel = forwardRef<HTMLDivElement, PanelProps>(function Panel(
  { theme, bezel = false, className, children, ...props },
  ref,
) {
  const inner = (
    <div
      data-theme={theme}
      className={cn(
        "relative overflow-hidden rounded-panel bg-canvas text-text",
        bezel ? "shadow-highlight" : "border border-hairline shadow-raised",
        className,
      )}
      {...(bezel ? {} : { ref, ...props })}
    >
      {children}
    </div>
  );
  if (!bezel) return inner;
  return (
    <div
      ref={ref}
      className="rounded-[calc(var(--radius-panel)+0.625rem)] bg-[oklch(0.75_0.03_266/0.28)] p-2.5 shadow-overlay ring-1 ring-[oklch(1_0_0/0.18)] ring-inset backdrop-blur-sm"
      {...props}
    >
      {inner}
    </div>
  );
});
