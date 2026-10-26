import { type ButtonHTMLAttributes, forwardRef, type ReactNode } from "react";
import { cn } from "./cn";
import { Spinner } from "./Spinner";

/** `onAccent`: icon buttons on a tinted surface such as the selected (Sky) list row. */
export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "subtle" | "soft" | "onAccent";
export type ButtonSize = "xs" | "sm" | "md" | "lg" | "icon" | "icon-sm" | "icon-lg";
/** `rounded` (default) for app chrome, `pill` for calls to action and marketing. */
export type ButtonShape = "rounded" | "pill";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  shape?: ButtonShape;
  loading?: boolean;
}

const variants: Record<ButtonVariant, string> = {
  primary:
    "bg-accent text-accent-contrast shadow-lip hover:bg-accent-hover hover:shadow-lip-glow active:translate-y-px active:bg-accent-pressed active:shadow-none",
  secondary:
    "border border-border-strong bg-surface text-text shadow-xs hover:border-text-subtle hover:bg-surface-raised active:bg-surface-sunken",
  ghost: "text-text-muted hover:bg-surface-raised hover:text-text active:bg-surface-sunken",
  subtle: "bg-surface-raised text-text hover:bg-border active:bg-border-strong",
  soft: "bg-accent-soft text-accent hover:bg-selection active:bg-selection",
  danger: "bg-danger text-danger-contrast shadow-xs hover:brightness-110 active:brightness-95",
  onAccent: "text-text-muted hover:bg-text/8 hover:text-text active:bg-text/12",
};

const sizes: Record<ButtonSize, string> = {
  // Touch screens (coarse pointers) get targets of at least 44 px.
  xs: "h-7 gap-1.5 rounded-lg px-2.5 text-xs coarse:h-11",
  sm: "h-8 gap-1.5 rounded-[0.625rem] px-3 text-[0.8125rem] coarse:h-11",
  md: "h-9 gap-2 rounded-control px-4 text-sm coarse:h-11",
  lg: "h-11 gap-2 rounded-control px-5 text-[0.9375rem] coarse:h-12",
  icon: "size-9 rounded-control coarse:size-11",
  "icon-sm": "size-7 rounded-lg coarse:size-11",
  "icon-lg": "size-12 rounded-card [&_svg]:size-5",
};

/** Button styles, for links that should look like buttons. */
export function buttonClassName({
  variant = "primary",
  size = "md",
  shape = "rounded",
  className,
}: {
  variant?: ButtonVariant;
  size?: ButtonSize;
  shape?: ButtonShape;
  className?: string | undefined;
} = {}): string {
  return cn(
    "inline-flex shrink-0 select-none items-center justify-center font-semibold whitespace-nowrap",
    "transition-[background-color,border-color,color,box-shadow,filter,translate] duration-150 ease-standard",
    "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus",
    "disabled:pointer-events-none disabled:opacity-50 aria-disabled:pointer-events-none aria-disabled:opacity-50",
    "[&_svg]:size-4 [&_svg]:shrink-0",
    variants[variant],
    sizes[size],
    shape === "pill" && "rounded-full",
    className,
  );
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  {
    variant = "primary",
    size = "md",
    shape = "rounded",
    loading = false,
    className,
    type = "button",
    disabled,
    children,
    ...props
  },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={buttonClassName({ variant, size, shape, className })}
      {...props}
    >
      {loading && <Spinner />}
      {children}
    </button>
  );
});

export interface IconButtonProps extends Omit<ButtonProps, "size" | "shape" | "children" | "aria-label"> {
  /** Accessible name (also the tooltip text when the app wraps it in `Tooltip`). */
  label: string;
  icon: ReactNode;
  size?: "sm" | "md" | "lg";
  /** `circle` for floating actions such as the raised "+" button. */
  shape?: ButtonShape | "circle";
}

const iconSizes = { sm: "icon-sm", md: "icon", lg: "icon-lg" } as const;

/** A square (or round) button with only an icon; `label` is required for screen readers. */
export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton(
  { label, icon, size = "md", shape = "rounded", variant = "ghost", className, ...props },
  ref,
) {
  return (
    <Button
      ref={ref}
      aria-label={label}
      variant={variant}
      size={iconSizes[size]}
      shape={shape === "circle" ? "pill" : shape}
      className={className}
      {...props}
    >
      {icon}
    </Button>
  );
});
