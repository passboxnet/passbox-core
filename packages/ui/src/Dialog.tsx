"use client";

import * as RadixDialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import type { ReactNode } from "react";
import { Button } from "./Button";
import { cn } from "./cn";
import { useUiStrings } from "./UiStrings";

export interface DialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: ReactNode;
  children?: ReactNode;
  footer?: ReactNode;
  size?: "sm" | "md" | "lg";
  /** Shown before the title, for example the icon of the item the dialog is about. */
  icon?: ReactNode;
}

const widths = { sm: "max-w-sm", md: "max-w-lg", lg: "max-w-2xl" };

export function Dialog({ open, onOpenChange, title, description, children, footer, size = "md", icon }: DialogProps) {
  const strings = useUiStrings();
  return (
    <RadixDialog.Root open={open} onOpenChange={onOpenChange}>
      <RadixDialog.Portal>
        <RadixDialog.Overlay className="fixed inset-0 z-40 animate-fade-in bg-black/40 backdrop-blur-[2px]" />
        <RadixDialog.Content
          className={cn(
            "fixed top-1/2 left-1/2 z-50 max-h-[calc(100dvh-2rem)] w-[calc(100vw-2rem)] -translate-x-1/2 -translate-y-1/2 overflow-y-auto",
            "animate-scale-in rounded-card border border-border bg-surface shadow-overlay focus:outline-none",
            widths[size],
          )}
        >
          <div className="flex items-start justify-between gap-4 px-6 pt-5">
            {icon && <div className="shrink-0">{icon}</div>}
            <div className="min-w-0 flex-1">
              <RadixDialog.Title className="text-base font-semibold text-text">{title}</RadixDialog.Title>
              {description ? (
                <RadixDialog.Description className="mt-1 text-sm text-text-muted">
                  {description}
                </RadixDialog.Description>
              ) : (
                <RadixDialog.Description className="sr-only">{title}</RadixDialog.Description>
              )}
            </div>
            <RadixDialog.Close asChild>
              <Button variant="ghost" size="icon-sm" aria-label={strings.close}>
                <X />
              </Button>
            </RadixDialog.Close>
          </div>
          {children && <div className="px-6 py-4">{children}</div>}
          {footer && (
            <div className="flex flex-wrap justify-end gap-2 rounded-b-card border-t border-border bg-surface-raised px-6 py-3">
              {footer}
            </div>
          )}
        </RadixDialog.Content>
      </RadixDialog.Portal>
    </RadixDialog.Root>
  );
}

export interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: ReactNode;
  confirmLabel: string;
  /** Defaults to the localized "Cancel". */
  cancelLabel?: string;
  tone?: "default" | "danger";
  onConfirm: () => void;
  /** Extra buttons left of Cancel, for example "Show Emergency Kit". */
  extraActions?: ReactNode;
  size?: DialogProps["size"];
}

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  cancelLabel,
  tone = "default",
  onConfirm,
  extraActions,
  size = "sm",
}: ConfirmDialogProps) {
  const strings = useUiStrings();
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={title}
      description={description}
      size={size}
      footer={
        <>
          {extraActions}
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            {cancelLabel ?? strings.cancel}
          </Button>
          <Button
            variant={tone === "danger" ? "danger" : "primary"}
            onClick={() => {
              onConfirm();
              onOpenChange(false);
            }}
          >
            {confirmLabel}
          </Button>
        </>
      }
    />
  );
}
