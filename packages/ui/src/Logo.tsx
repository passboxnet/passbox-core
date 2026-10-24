import { cn } from "./cn";

export interface LogoProps {
  className?: string;
  withWordmark?: boolean;
}

/** The Passbox mark: a rounded box with a keyhole. */
export function Logo({ className, withWordmark = true }: LogoProps) {
  return (
    <span className={cn("inline-flex items-center gap-2 font-semibold tracking-tight", className)}>
      <svg viewBox="0 0 32 32" aria-hidden="true" className="size-7">
        <rect width="32" height="32" rx="9" className="fill-accent" />
        <circle cx="16" cy="13.5" r="4" className="fill-accent-contrast" />
        <path d="M14.2 16.5h3.6l1 7h-5.6z" className="fill-accent-contrast" />
      </svg>
      {withWordmark && <span className="text-lg">Passbox</span>}
    </span>
  );
}
