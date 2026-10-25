"use client";

import { Toaster as Sonner, toast } from "sonner";

export interface ToasterProps {
  position?: "top-left" | "top-center" | "top-right" | "bottom-left" | "bottom-center" | "bottom-right";
  /** Milliseconds a toast stays visible. */
  duration?: number;
  /** Distance from the window edge, for example to keep clear of a toolbar. */
  offset?: string | number;
}

/** Mount once near the root. Use `toast()` anywhere to show a notification. */
export function Toaster({ position = "bottom-right", duration, offset }: ToasterProps = {}) {
  return (
    <Sonner
      position={position}
      {...(duration !== undefined ? { duration } : {})}
      {...(offset !== undefined ? { offset } : {})}
      toastOptions={{
        classNames: {
          toast:
            "!rounded-control !border !border-hairline !bg-surface-overlay !text-text !shadow-overlay !font-sans !text-[0.8125rem] !gap-2.5",
          description: "!text-text-muted",
          actionButton: "!rounded-full !bg-accent !text-accent-contrast !font-semibold",
          success: "[&_[data-icon]]:!text-success",
          error: "[&_[data-icon]]:!text-danger",
        },
      }}
    />
  );
}

export { toast };
