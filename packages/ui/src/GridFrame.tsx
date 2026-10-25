import type { HTMLAttributes } from "react";
import { cn } from "./cn";

export interface GridFrameProps extends HTMLAttributes<HTMLDivElement> {
  /** Draw the dotted line and corner dots at the top (default) and/or bottom. */
  edges?: "top" | "bottom" | "both";
}

/**
 * The Passbox panel motif: dotted vertical guides at the content edges, a
 * dotted horizontal rule and small dots where they cross. Purely decorative;
 * use it to frame sections inside website panels and onboarding screens.
 */
export function GridFrame({ edges = "top", className, children, ...props }: GridFrameProps) {
  const rows = edges === "both" ? ["top-0", "bottom-0"] : [edges === "top" ? "top-0" : "bottom-0"];
  return (
    <div className={cn("relative px-6 sm:px-10", className)} {...props}>
      <div aria-hidden="true" className="pointer-events-none absolute inset-0">
        <span className="dotted-y absolute inset-y-0 left-6 sm:left-10" />
        <span className="dotted-y absolute inset-y-0 right-6 sm:right-10" />
        {rows.map((row) => (
          <span key={row} className={cn("absolute inset-x-0", row)}>
            <span className="dotted-x absolute inset-x-0" />
            <span className="absolute left-6 size-1.5 -translate-x-[2.5px] -translate-y-[2.5px] rounded-full bg-text-subtle sm:left-10" />
            <span className="absolute right-6 size-1.5 translate-x-[2.5px] -translate-y-[2.5px] rounded-full bg-text-subtle sm:right-10" />
          </span>
        ))}
      </div>
      <div className="relative">{children}</div>
    </div>
  );
}
