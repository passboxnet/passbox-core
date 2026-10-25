"use client";

import { useId } from "react";
import { cn } from "./cn";

export interface LogoProps {
  className?: string;
  withWordmark?: boolean;
}

/** The Passbox mark: a keyhole on the signature gradient tile (sources: packages/ui/brand). */
export function Logo({ className, withWordmark = true }: LogoProps) {
  // A unique gradient ID: with a fixed one, a hidden copy of the logo elsewhere
  // on the page (display: none) would leave every other copy without a fill.
  const gradient = `passbox-logo-${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
  return (
    <span className={cn("inline-flex items-center gap-2 font-bold tracking-[-0.02em]", className)}>
      <svg viewBox="0 0 32 32" aria-hidden="true" className="size-7 shrink-0">
        <defs>
          <linearGradient id={gradient} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="oklch(0.72 0.14 252)" />
            <stop offset="0.5" stopColor="oklch(0.55 0.23 263)" />
            <stop offset="1" stopColor="oklch(0.36 0.17 268)" />
          </linearGradient>
          <radialGradient id={`${gradient}-glow`} cx="0.22" cy="0.12" r="0.75">
            <stop offset="0" stopColor="white" stopOpacity="0.24" />
            <stop offset="1" stopColor="white" stopOpacity="0" />
          </radialGradient>
        </defs>
        <rect width="32" height="32" rx="9" fill={`url(#${gradient})`} />
        <rect width="32" height="32" rx="9" fill={`url(#${gradient}-glow)`} />
        <rect x="0.5" y="0.5" width="31" height="31" rx="8.5" fill="none" stroke="white" strokeOpacity="0.18" />
        <circle cx="16" cy="13.4" r="4.2" fill="white" />
        <path d="M14.2 16.2h3.6l1.1 6.9a.8.8 0 0 1-.8.9h-4.2a.8.8 0 0 1-.8-.9z" fill="white" />
      </svg>
      {withWordmark && <span className="text-[1.0625rem]">Passbox</span>}
    </span>
  );
}
