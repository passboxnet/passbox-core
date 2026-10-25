import type { ReactNode } from "react";
import { cn } from "./cn";

export interface EmptyStateProps {
  icon: ReactNode;
  title: string;
  description?: ReactNode;
  action?: ReactNode;
  className?: string;
}

/** What an empty list or screen shows: an icon tile, a title, what to do next. */
export function EmptyState({ icon, title, description, action, className }: EmptyStateProps) {
  return (
    <div className={cn("flex flex-col items-center px-6 py-12 text-center", className)}>
      <div className="mb-5 flex size-14 items-center justify-center rounded-tile bg-accent-soft text-accent shadow-highlight ring-1 ring-accent/15 ring-inset [&_svg]:size-6">
        {icon}
      </div>
      <h3 className="text-headline text-text">{title}</h3>
      {description && <p className="mt-1.5 max-w-xs text-sm text-text-muted">{description}</p>}
      {action && <div className="mt-6">{action}</div>}
    </div>
  );
}
