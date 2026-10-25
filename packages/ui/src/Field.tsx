import type { ReactNode } from "react";
import { cn } from "./cn";

export interface FieldProps {
  /** Small label above the value ("Username", "Password"). */
  label: ReactNode;
  /** The value; use `font-mono` for secrets and codes. */
  children: ReactNode;
  /** Icon buttons on the right: reveal, copy, open. */
  actions?: ReactNode;
  /** Separator line under the field (on by default; off for the last field of a group). */
  divider?: boolean;
  className?: string;
}

/**
 * A read-only field of an item: label, value and actions (reveal, copy).
 * Inputs for editing are `Input` and `PasswordInput`.
 */
export function Field({ label, children, actions, divider = true, className }: FieldProps) {
  return (
    <div className={cn("group flex items-center gap-3 py-3", divider && "border-b border-hairline", className)}>
      <div className="min-w-0 flex-1">
        <div className="text-xs font-medium text-text-subtle">{label}</div>
        <div className="mt-1 truncate text-[0.9375rem] text-text">{children}</div>
      </div>
      {actions && <div className="flex shrink-0 items-center gap-1">{actions}</div>}
    </div>
  );
}
