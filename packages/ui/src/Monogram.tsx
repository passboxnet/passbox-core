import type { ReactNode } from "react";
import { cn } from "./cn";

/** Hues spread around the color wheel; picked deterministically per name. */
const HUES = [262, 200, 160, 130, 85, 45, 20, 350, 310, 285];

function hueFor(seed: string): number {
  let hash = 0;
  for (const char of seed) hash = (hash * 31 + (char.codePointAt(0) ?? 0)) >>> 0;
  return HUES[hash % HUES.length] ?? 262;
}

export type MonogramSize = "sm" | "md" | "lg" | "xl";

const sizes: Record<MonogramSize, string> = {
  sm: "size-6 rounded-md text-2xs [&_svg]:size-3.5",
  md: "size-8 rounded-lg text-xs [&_svg]:size-4",
  lg: "size-10 rounded-lg text-sm [&_svg]:size-5",
  xl: "size-14 rounded-xl text-xl [&_svg]:size-7",
};

export interface MonogramProps {
  /** Text the initial and color are derived from. */
  name: string;
  size?: MonogramSize;
  /** Replaces the initial, for example with a category icon. */
  icon?: ReactNode;
  className?: string;
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
      className={cn("flex shrink-0 items-center justify-center font-semibold uppercase", sizes[size], className)}
    >
      {icon ?? (name.trim().charAt(0) || "?")}
    </span>
  );
}
