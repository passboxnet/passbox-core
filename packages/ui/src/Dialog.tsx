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

const overlayClassName = "fixed inset-0 z-(--pb-z-scrim) animate-fade-in bg-scrim backdrop-blur-[3px]";

function Header({ title, description, icon }: Pick<DialogProps, "title" | "description" | "icon">) {
  const strings = useUiStrings();
  return (
    <div className="flex items-start justify-between gap-4 px-6 pt-6">
      {icon && <div className="shrink-0">{icon}</div>}
      <div className="min-w-0 flex-1">
        <RadixDialog.Title className="text-headline text-text">{title}</RadixDialog.Title>
        {description ? (
          <RadixDialog.Description className="mt-1 text-sm text-text-muted">{description}</RadixDialog.Description>
        ) : (
          <RadixDialog.Description className="sr-only">{title}</RadixDialog.Description>
        )}
      </div>
      <RadixDialog.Close asChild>
        <Button variant="ghost" size="icon-sm" aria-label={strings.close} className="-mt-1 -mr-2">
          <X />
        </Button>
      </RadixDialog.Close>
    </div>
  );
}

export function Dialog({ open, onOpenChange, title, description, children, footer, size = "md", icon }: DialogProps) {
  return (
    <RadixDialog.Root open={open} onOpenChange={onOpenChange}>
      <RadixDialog.Portal>
        <RadixDialog.Overlay className={overlayClassName} />
        <RadixDialog.Content
          className={cn(
            "fixed top-1/2 left-1/2 z-(--pb-z-modal) max-h-[calc(100dvh-2rem)] w-[calc(100vw-2rem)] -translate-x-1/2 -translate-y-1/2 overflow-y-auto",
            "animate-scale-in rounded-card border border-hairline bg-surface-overlay shadow-overlay focus:outline-none",
            widths[size],
          )}
        >
          <Header title={title} description={description} icon={icon} />
          {children ? <div className="px-6 py-5">{children}</div> : <div className="h-5" />}
          {footer && (
            <div className="flex flex-wrap justify-end gap-2 rounded-b-card border-t border-hairline px-6 py-4">
              {footer}
            </div>
          )}
        </RadixDialog.Content>
      </RadixDialog.Portal>
    </RadixDialog.Root>
  );
}

export interface SheetProps extends Omit<DialogProps, "size"> {
  /** `bottom` (mobile, default) slides up from the bottom edge; `right` is a side panel. */
  side?: "bottom" | "right";
}

/** A dialog attached to a screen edge: bottom sheet on phones, side panel on large screens. */
export function Sheet({ open, onOpenChange, title, description, children, footer, icon, side = "bottom" }: SheetProps) {
  return (
    <RadixDialog.Root open={open} onOpenChange={onOpenChange}>
      <RadixDialog.Portal>
        <RadixDialog.Overlay className={overlayClassName} />
        <RadixDialog.Content
          className={cn(
            "fixed z-(--pb-z-modal) flex flex-col overflow-hidden border-hairline bg-surface-overlay shadow-overlay focus:outline-none",
            side === "bottom"
              ? "inset-x-0 bottom-0 max-h-[92dvh] animate-sheet-in rounded-t-sheet border-t pb-[env(safe-area-inset-bottom)]"
              : "inset-y-0 right-0 w-full max-w-md animate-fade-in border-l",
          )}
        >
          {side === "bottom" && (
            <div aria-hidden="true" className="mx-auto mt-2.5 h-1 w-10 shrink-0 rounded-full bg-border-strong" />
          )}
          <Header title={title} description={description} icon={icon} />
          <div className="min-h-0 flex-1 overflow-y-auto px-6 py-5">{children}</div>
          {footer && (
            <div className="flex flex-wrap justify-end gap-2 border-t border-hairline px-6 py-4">{footer}</div>
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
