import { type ButtonHTMLAttributes, forwardRef, type ReactNode } from "react";
import { cn } from "./cn";

/** Hues spread around the color wheel; picked deterministically per name (as in `Monogram`). */
const HUES = [262, 200, 160, 130, 85, 45, 20, 350, 310, 285];

function hueFor(seed: string): number {
  let hash = 0;
  for (const char of seed) hash = (hash * 31 + (char.codePointAt(0) ?? 0)) >>> 0;
  return HUES[hash % HUES.length] ?? 262;
}

/** Up to two initials: "Miriam Weber" → "MW", "m.weber@posteo.de" → "MW", "alice@x" → "A". */
export function initials(name: string): string {
  const local = name.trim().split("@")[0] ?? "";
  const parts = local.split(/[\s._-]+/).filter(Boolean);
  const letters = parts.length > 1 ? [parts[0], parts[parts.length - 1]] : [parts[0]];
  return (
    letters
      .map((part) => part?.charAt(0) ?? "")
      .join("")
      .toUpperCase() || "?"
  );
}

export type AvatarSize = "xs" | "sm" | "md" | "lg";

const sizes: Record<AvatarSize, string> = {
  xs: "size-6 text-[0.625rem]",
  sm: "size-8 text-[0.6875rem]",
  md: "size-9 text-xs",
  lg: "size-11 text-sm",
};

export interface AvatarProps {
  /** A person's name or email; initials and color are derived from it. */
  name: string;
  size?: AvatarSize;
  /** `signature`: the Passbox gradient (the signed-in account); `tint` (default): a hue per person. */
  tone?: "tint" | "signature";
  className?: string | undefined;
}

/** A round avatar with initials, for people (account, "Geteilt mit", members). Decorative. */
export function Avatar({ name, size = "md", tone = "tint", className }: AvatarProps) {
  const hue = hueFor(name.toLowerCase());
  return (
    <span
      aria-hidden="true"
      style={
        tone === "tint"
          ? {
              backgroundColor: `oklch(var(--pb-monogram-bg-l) 0.07 ${hue})`,
              color: `oklch(var(--pb-monogram-fg-l) 0.14 ${hue})`,
            }
          : undefined
      }
      className={cn(
        "inline-flex shrink-0 items-center justify-center rounded-full font-bold tracking-tight select-none",
        tone === "signature" && "bg-signature text-white shadow-highlight",
        sizes[size],
        className,
      )}
    >
      {initials(name)}
    </span>
  );
}

export interface FabProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "aria-label" | "children"> {
  /** Accessible name. */
  label: string;
  icon: ReactNode;
}

/**
 * The raised round "+" (signature element): the signature gradient, a glow
 * and a canvas-colored ring that separates it from what lies below.
 */
export const Fab = forwardRef<HTMLButtonElement, FabProps>(function Fab(
  { label, icon, className, type = "button", ...props },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      aria-label={label}
      className={cn(
        "flex size-14 shrink-0 items-center justify-center rounded-full bg-signature text-white shadow-glow ring-4 ring-canvas",
        "transition-[transform,filter] duration-150 ease-standard hover:brightness-110 active:scale-95",
        "focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-focus [&_svg]:size-6",
        className,
      )}
      {...props}
    >
      {icon}
    </button>
  );
});
