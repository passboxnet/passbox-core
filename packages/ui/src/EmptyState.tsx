import type { ReactNode } from "react";
import { cn } from "./cn";

export interface EmptyStateProps {
  icon: ReactNode;
  title: string;
  description?: ReactNode;
  action?: ReactNode;
  /** `brand` (default): the icon on the signature gradient inside dotted rings; `quiet`: a small tinted tile (search without results, inline lists). */
  tone?: "brand" | "quiet";
  className?: string;
}

/**
 * What an empty list or screen shows: the brand illustration (an icon tile
 * on the signature gradient, framed by dotted rings with corner dots — the
 * panel motif in miniature), a title and what to do next.
 */
export function EmptyState({ icon, title, description, action, tone = "brand", className }: EmptyStateProps) {
  return (
    <div className={cn("flex flex-col items-center px-6 py-12 text-center", className)}>
      {tone === "brand" ? (
        <div aria-hidden="true" className="relative mb-6 flex size-32 items-center justify-center">
          <span className="absolute inset-0 rounded-full border border-dotted border-border-strong" />
          <span className="absolute inset-4 rounded-full border border-dotted border-border-strong opacity-70" />
          <span className="absolute top-1/2 left-0 size-1.5 -translate-x-1/2 -translate-y-1/2 rounded-full bg-text-subtle" />
          <span className="absolute top-1/2 right-0 size-1.5 translate-x-1/2 -translate-y-1/2 rounded-full bg-text-subtle" />
          <span
            className="absolute inset-6 rounded-full opacity-60 blur-xl"
            style={{ background: "color-mix(in oklch, var(--color-sky) 45%, transparent)" }}
          />
          <span className="relative flex size-16 items-center justify-center rounded-[18px] bg-signature text-solar shadow-[0_3px_0_0_var(--color-marina-lip)] ring-1 ring-white/15 ring-inset [&_svg]:size-7">
            {icon}
          </span>
        </div>
      ) : (
        <div className="mb-5 flex size-14 items-center justify-center rounded-tile bg-accent-soft text-accent shadow-highlight ring-1 ring-info/20 ring-inset [&_svg]:size-6">
          {icon}
        </div>
      )}
      <h3 className="text-headline text-text">{title}</h3>
      {description && <p className="mt-1.5 max-w-xs text-sm text-text-muted">{description}</p>}
      {action && <div className="mt-6">{action}</div>}
    </div>
  );
}
