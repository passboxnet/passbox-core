import type { HTMLAttributes } from "react";
import { cn } from "./cn";

/**
 * A placeholder shape while content loads. Size it with classes
 * (`h-4 w-32`, `size-10 rounded-[11px]`). Hidden from screen readers; mark the
 * loading region with `aria-busy` instead.
 */
export function Skeleton({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      aria-hidden="true"
      className={cn(
        "animate-shimmer rounded-lg bg-surface-raised bg-[length:200%_100%]",
        "bg-[linear-gradient(90deg,transparent_25%,var(--pb-hairline)_50%,transparent_75%)]",
        className,
      )}
      {...props}
    />
  );
}
