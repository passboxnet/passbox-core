import { cn } from "./cn";

export interface LogoProps {
  className?: string;
  withWordmark?: boolean;
}

/** The Passbox mark: a rounded box with a keyhole. */
export function Logo({ className, withWordmark = true }: LogoProps) {
  return (
    <span className={cn("inline-flex items-center gap-2 font-semibold tracking-tight", className)}>
      <svg viewBox="0 0 32 32" aria-hidden="true" className="size-7 shrink-0">
        <defs>
          <linearGradient id="passbox-logo" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="oklch(0.62 0.2 262)" />
            <stop offset="1" stopColor="oklch(0.45 0.2 268)" />
          </linearGradient>
        </defs>
        <rect width="32" height="32" rx="8" fill="url(#passbox-logo)" />
        <rect x="0.5" y="0.5" width="31" height="31" rx="7.5" fill="none" stroke="white" strokeOpacity="0.15" />
        <circle cx="16" cy="13.5" r="4" fill="white" />
        <path d="M14.2 16.5h3.6l1 7h-5.6z" fill="white" />
      </svg>
      {withWordmark && <span className="text-[17px]">Passbox</span>}
    </span>
  );
}
