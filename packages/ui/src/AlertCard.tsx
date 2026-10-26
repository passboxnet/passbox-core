"use client";

import { AlertTriangle, CheckCircle2, Info, ShieldAlert, X } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "./cn";
import { useUiStrings } from "./UiStrings";

export type AlertTone = "info" | "success" | "warning" | "danger";

export interface AlertCardProps {
  tone?: AlertTone;
  /** `card` (default): soft card with an icon tile. `banner`: a solid inline strip, like "Time to update your password". */
  variant?: "card" | "banner";
  title: ReactNode;
  description?: ReactNode;
  /** A link or button ("See details", "Update now"). */
  action?: ReactNode;
  /** Shows a close button. */
  onDismiss?: () => void;
  icon?: ReactNode;
  className?: string;
}

const icons: Record<AlertTone, ReactNode> = {
  info: <Info />,
  success: <CheckCircle2 />,
  warning: <AlertTriangle />,
  danger: <ShieldAlert />,
};

const tile: Record<AlertTone, string> = {
  info: "bg-info-soft text-info",
  success: "bg-success-soft text-success",
  warning: "bg-warning-soft text-warning",
  danger: "bg-danger-soft text-danger",
};

const banner: Record<AlertTone, string> = {
  info: "bg-info-soft text-info-text",
  success: "bg-success text-success-contrast",
  warning: "bg-warning text-warning-contrast",
  danger: "bg-danger text-danger-contrast",
};

/**
 * A notice that needs attention: compromised passwords, an expiring
 * subscription, an available update. Danger and warning are announced to
 * screen readers (`role="alert"`), the others politely (`role="status"`).
 */
export function AlertCard({
  tone = "info",
  variant = "card",
  title,
  description,
  action,
  onDismiss,
  icon,
  className,
}: AlertCardProps) {
  const strings = useUiStrings();
  const role = tone === "danger" || tone === "warning" ? "alert" : "status";
  if (variant === "banner") {
    return (
      <div
        role={role}
        className={cn(
          "flex min-h-11 items-center gap-3 rounded-control px-4 py-2.5 text-[0.8125rem] font-medium [&_svg]:size-4 [&_svg]:shrink-0",
          banner[tone],
          className,
        )}
      >
        {icon ?? icons[tone]}
        <div className="min-w-0 flex-1">
          {title}
          {description && <span className="opacity-85"> · {description}</span>}
        </div>
        {action && (
          <div className="shrink-0 font-semibold [&_a]:underline-offset-2 [&_a:hover]:underline">{action}</div>
        )}
        {onDismiss && (
          <button
            type="button"
            onClick={onDismiss}
            aria-label={strings.close}
            className="-mr-1.5 flex size-7 items-center justify-center rounded-lg hover:bg-black/10 focus-visible:outline-2 focus-visible:outline-current coarse:size-11"
          >
            <X />
          </button>
        )}
      </div>
    );
  }
  return (
    <div
      role={role}
      className={cn("flex gap-4 rounded-card border border-hairline bg-surface p-5 shadow-card", className)}
    >
      <span
        className={cn("flex size-10 shrink-0 items-center justify-center rounded-[11px] [&_svg]:size-5", tile[tone])}
      >
        {icon ?? icons[tone]}
      </span>
      <div className="min-w-0 flex-1">
        <div className="text-[0.9375rem] font-semibold text-text">{title}</div>
        {description && <div className="mt-1 text-sm text-text-muted">{description}</div>}
        {action && <div className="mt-3 text-sm font-semibold text-accent">{action}</div>}
      </div>
      {onDismiss && (
        <button
          type="button"
          onClick={onDismiss}
          aria-label={strings.close}
          className="-mt-1 -mr-1 flex size-8 shrink-0 items-center justify-center rounded-lg text-text-subtle hover:bg-surface-raised hover:text-text focus-visible:outline-2 focus-visible:outline-focus coarse:size-11 [&_svg]:size-4"
        >
          <X />
        </button>
      )}
    </div>
  );
}
