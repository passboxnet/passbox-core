import type { ReactNode } from "react";
import { cn } from "./cn";

/** Hues spread around the color wheel; picked deterministically per name. */
const HUES = [262, 200, 160, 130, 85, 45, 20, 350, 310, 285];

function hueFor(seed: string): number {
  let hash = 0;
  for (const char of seed) hash = (hash * 31 + (char.codePointAt(0) ?? 0)) >>> 0;
  return HUES[hash % HUES.length] ?? 262;
}

export type MonogramSize = "sm" | "md" | "lg" | "xl" | "2xl";

/** Box, corner radius (28 % of the box), text and icon size per step (shared with the image tiles). */
export const monogramSizes: Record<MonogramSize, string> = {
  sm: "size-6 rounded-[7px] text-2xs [&_svg]:size-3.5",
  md: "size-8 rounded-[9px] text-xs [&_svg]:size-4",
  lg: "size-10 rounded-[11px] text-sm [&_svg]:size-5",
  xl: "size-14 rounded-tile text-xl [&_svg]:size-7",
  "2xl": "size-18 rounded-[20px] text-2xl [&_svg]:size-9",
};

export interface MonogramProps {
  /** Text the initial and color are derived from. */
  name: string;
  size?: MonogramSize;
  /** Replaces the initial, for example with a category icon. */
  icon?: ReactNode;
  className?: string | undefined;
}

/** Colored initial (or icon) used for items, vaults and people. */
export function Monogram({ name, size = "md", icon, className }: MonogramProps) {
  const hue = hueFor(name.toLowerCase());
  return (
    <span
      aria-hidden="true"
      style={{
        backgroundColor: `oklch(var(--pb-monogram-bg-l) 0.06 ${hue})`,
        color: `oklch(var(--pb-monogram-fg-l) 0.14 ${hue})`,
      }}
      className={cn(
        "flex shrink-0 items-center justify-center font-semibold uppercase",
        monogramSizes[size],
        className,
      )}
    >
      {icon ?? (name.trim().charAt(0) || "?")}
    </span>
  );
}
