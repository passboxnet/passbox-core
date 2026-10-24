"use client";

import * as Dropdown from "@radix-ui/react-dropdown-menu";
import type { ComponentPropsWithoutRef, ReactNode } from "react";
import { cn } from "./cn";

export const Menu = Dropdown.Root;
export const MenuTrigger = Dropdown.Trigger;

export function MenuContent({ className, align = "end", ...props }: ComponentPropsWithoutRef<typeof Dropdown.Content>) {
  return (
    <Dropdown.Portal>
      <Dropdown.Content
        align={align}
        sideOffset={6}
        className={cn(
          "z-50 min-w-48 animate-scale-in rounded-lg border border-border bg-surface p-1 shadow-overlay",
          className,
        )}
        {...props}
      />
    </Dropdown.Portal>
  );
}

export interface MenuItemProps extends ComponentPropsWithoutRef<typeof Dropdown.Item> {
  icon?: ReactNode;
  shortcut?: ReactNode;
  tone?: "default" | "danger";
}

export function MenuItem({ icon, shortcut, tone = "default", className, children, ...props }: MenuItemProps) {
  return (
    <Dropdown.Item
      className={cn(
        "flex h-8 cursor-default select-none items-center gap-2.5 rounded-md px-2 text-[0.8125rem] outline-none coarse:h-11",
        "data-[highlighted]:bg-surface-sunken data-[disabled]:opacity-50 [&_svg]:size-4",
        tone === "danger" ? "text-danger" : "text-text",
        className,
      )}
      {...props}
    >
      {icon && <span className={cn("flex", tone === "danger" ? "text-danger" : "text-text-muted")}>{icon}</span>}
      <span className="flex-1">{children}</span>
      {shortcut && <span className="text-2xs text-text-subtle">{shortcut}</span>}
    </Dropdown.Item>
  );
}

export function MenuLabel({ className, ...props }: ComponentPropsWithoutRef<typeof Dropdown.Label>) {
  return <Dropdown.Label className={cn("px-2 py-1.5 text-2xs font-medium text-text-subtle", className)} {...props} />;
}

export function MenuSeparator() {
  return <Dropdown.Separator className="my-1 h-px bg-border" />;
}
