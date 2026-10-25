"use client";

import { type HTMLAttributes, type KeyboardEvent, type ReactNode, useRef } from "react";
import { cn } from "./cn";

export interface TabItem<T extends string> {
  value: T;
  label: ReactNode;
  /** A count shown after the label. */
  count?: number;
  disabled?: boolean;
}

export interface TabsProps<T extends string> {
  value: T;
  onChange: (value: T) => void;
  items: Array<TabItem<T>>;
  /** Accessible name of the tab list. */
  label: string;
  /** Prefix for the tab and panel IDs; pair with `TabPanel` using the same prefix. */
  idPrefix: string;
  /** `underline` for page sections, `pill` for compact filters. */
  variant?: "underline" | "pill";
  className?: string;
}

export const tabId = (prefix: string, value: string) => `${prefix}-tab-${value}`;
export const tabPanelId = (prefix: string, value: string) => `${prefix}-panel-${value}`;

/** Tabs following the WAI-ARIA pattern: arrow keys, Home and End move between tabs. */
export function Tabs<T extends string>({
  value,
  onChange,
  items,
  label,
  idPrefix,
  variant = "underline",
  className,
}: TabsProps<T>) {
  const list = useRef<HTMLDivElement>(null);
  const enabled = items.filter((item) => !item.disabled);

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const index = enabled.findIndex((item) => item.value === value);
    let next: number | undefined;
    if (event.key === "ArrowRight") next = (index + 1) % enabled.length;
    else if (event.key === "ArrowLeft") next = (index - 1 + enabled.length) % enabled.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = enabled.length - 1;
    const target = next === undefined ? undefined : enabled[next];
    if (!target) return;
    event.preventDefault();
    onChange(target.value);
    list.current?.ownerDocument.getElementById(tabId(idPrefix, target.value))?.focus();
  };

  return (
    <div
      ref={list}
      role="tablist"
      aria-label={label}
      onKeyDown={onKeyDown}
      className={cn(
        "flex items-center",
        variant === "underline" ? "gap-5 border-b border-hairline" : "gap-1",
        className,
      )}
    >
      {items.map((item) => {
        const selected = item.value === value;
        return (
          <button
            key={item.value}
            id={tabId(idPrefix, item.value)}
            type="button"
            role="tab"
            aria-selected={selected}
            aria-controls={tabPanelId(idPrefix, item.value)}
            tabIndex={selected ? 0 : -1}
            disabled={item.disabled}
            onClick={() => onChange(item.value)}
            className={cn(
              "inline-flex shrink-0 items-center gap-1.5 text-[0.8125rem] font-semibold whitespace-nowrap transition-colors duration-150 disabled:opacity-50",
              "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus",
              variant === "underline"
                ? cn(
                    "-mb-px h-10 border-b-2 coarse:h-12",
                    selected ? "border-accent text-text" : "border-transparent text-text-muted hover:text-text",
                  )
                : cn(
                    "h-8 rounded-full px-3.5 coarse:h-11",
                    selected
                      ? "bg-accent text-accent-contrast"
                      : "text-text-muted hover:bg-surface-raised hover:text-text",
                  ),
            )}
          >
            {item.label}
            {item.count !== undefined && (
              <span
                className={cn(
                  "rounded-full px-1.5 text-2xs tabular-nums",
                  selected && variant === "pill" ? "bg-accent-contrast/20" : "bg-surface-raised text-text-subtle",
                )}
              >
                {item.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

export interface TabPanelProps extends HTMLAttributes<HTMLDivElement> {
  idPrefix: string;
  value: string;
}

export function TabPanel({ idPrefix, value, ...props }: TabPanelProps) {
  return (
    <div
      role="tabpanel"
      id={tabPanelId(idPrefix, value)}
      aria-labelledby={tabId(idPrefix, value)}
      // biome-ignore lint/a11y/noNoninteractiveTabindex: WAI-ARIA tabs: the panel is focusable when it has no focusable content
      tabIndex={0}
      {...props}
    />
  );
}
