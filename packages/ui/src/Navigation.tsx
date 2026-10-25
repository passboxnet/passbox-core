import { type ButtonHTMLAttributes, forwardRef, type ReactNode } from "react";
import { cn } from "./cn";

export type TagColor = "blue" | "violet" | "pink" | "red" | "orange" | "yellow" | "green" | "teal";

/** Background classes for the category dots (`tag-*` tokens). */
export const tagDotClassName: Record<TagColor, string> = {
  blue: "bg-tag-blue",
  violet: "bg-tag-violet",
  pink: "bg-tag-pink",
  red: "bg-tag-red",
  orange: "bg-tag-orange",
  yellow: "bg-tag-yellow",
  green: "bg-tag-green",
  teal: "bg-tag-teal",
};

/** Sidebar item styles, for router links. */
export function sidebarItemClassName({
  active = false,
  className,
}: {
  active?: boolean;
  className?: string | undefined;
} = {}) {
  return cn(
    "flex h-9 w-full items-center gap-3 rounded-[0.625rem] px-3 text-left text-[0.8125rem] font-medium transition-colors duration-150 coarse:h-11",
    "focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-focus [&_svg]:size-4 [&_svg]:shrink-0",
    active ? "bg-surface-raised text-text" : "text-text-muted hover:bg-surface-raised/60 hover:text-text",
    className,
  );
}

export interface SidebarItemProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  icon?: ReactNode;
  /** A colored category dot instead of (or in addition to) an icon. */
  dot?: TagColor;
  label: ReactNode;
  count?: number;
  active?: boolean;
}

/** A navigation entry in the sidebar: icon or colored dot, label, count. */
export const SidebarItem = forwardRef<HTMLButtonElement, SidebarItemProps>(function SidebarItem(
  { icon, dot, label, count, active = false, className, type = "button", ...props },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      aria-current={active ? "page" : undefined}
      className={sidebarItemClassName({ active, className })}
      {...props}
    >
      {icon && <span className={cn("flex", active ? "text-accent" : "text-text-subtle")}>{icon}</span>}
      {dot && <span aria-hidden="true" className={cn("ml-1 size-2 shrink-0 rounded-full", tagDotClassName[dot])} />}
      <span className="min-w-0 flex-1 truncate">{label}</span>
      {count !== undefined && <span className="text-xs text-text-subtle tabular-nums">{count}</span>}
    </button>
  );
});

/** List row styles, for router links. Selected rows are solid accent. */
export function listRowClassName({
  selected = false,
  className,
}: {
  selected?: boolean;
  className?: string | undefined;
} = {}) {
  return cn(
    "group flex w-full items-center gap-3 rounded-control px-3 py-2.5 text-left transition-colors duration-150",
    "focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-focus",
    selected
      ? "bg-accent text-accent-contrast shadow-glow focus-visible:outline-accent-contrast"
      : "text-text hover:bg-surface-raised",
    className,
  );
}

export interface ListRowProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "title"> {
  /** Favicon tile (`SiteIcon`) or `Monogram`. */
  leading?: ReactNode;
  title: ReactNode;
  subtitle?: ReactNode;
  /** Badges, a shield for risky items, a time. */
  trailing?: ReactNode;
  selected?: boolean;
}

/** A row in a list of items: icon tile, title (service) and subtitle (username). */
export const ListRow = forwardRef<HTMLButtonElement, ListRowProps>(function ListRow(
  { leading, title, subtitle, trailing, selected = false, className, type = "button", ...props },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      aria-current={selected ? "true" : undefined}
      className={listRowClassName({ selected, className })}
      {...props}
    >
      {leading}
      <span className="min-w-0 flex-1">
        <span className="block truncate text-sm font-semibold">{title}</span>
        {subtitle && (
          <span className={cn("block truncate text-xs", selected ? "text-accent-contrast" : "text-text-muted")}>
            {subtitle}
          </span>
        )}
      </span>
      {trailing && (
        <span
          className={cn("flex shrink-0 items-center gap-1.5", selected ? "text-accent-contrast" : "text-text-subtle")}
        >
          {trailing}
        </span>
      )}
    </button>
  );
});
