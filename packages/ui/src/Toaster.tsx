"use client";

import { Toaster as Sonner, toast } from "sonner";

/** Mount once near the root. Use `toast()` anywhere to show a notification. */
export function Toaster() {
  return (
    <Sonner
      position="bottom-right"
      toastOptions={{
        classNames: {
          toast:
            "!rounded-lg !border !border-border !bg-surface !text-text !shadow-overlay !font-sans !text-[13px] !gap-2.5",
          description: "!text-text-muted",
          success: "[&_[data-icon]]:!text-success",
          error: "[&_[data-icon]]:!text-danger",
        },
      }}
    />
  );
}

export { toast };
