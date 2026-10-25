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
          "z-(--pb-z-popover) min-w-48 animate-scale-in rounded-control border border-hairline bg-surface-overlay p-1.5 shadow-overlay",
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
        "flex h-9 cursor-default select-none items-center gap-2.5 rounded-lg px-2.5 text-[0.8125rem] font-medium outline-none coarse:h-11",
        "data-[highlighted]:bg-surface-raised data-[disabled]:opacity-50 [&_svg]:size-4",
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
  return (
    <Dropdown.Label className={cn("px-2.5 py-1.5 text-2xs font-semibold text-text-subtle", className)} {...props} />
  );
}

export function MenuSeparator() {
  return <Dropdown.Separator className="my-1.5 h-px bg-hairline" />;
}
