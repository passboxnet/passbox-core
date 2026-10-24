import { type ButtonHTMLAttributes, forwardRef } from "react";
import { cn } from "./cn";
import { Spinner } from "./Spinner";

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "subtle";
export type ButtonSize = "xs" | "sm" | "md" | "lg" | "icon" | "icon-sm";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
}

const variants: Record<ButtonVariant, string> = {
  primary: "bg-accent text-accent-contrast shadow-xs hover:bg-accent-hover",
  secondary: "border border-border-strong bg-surface text-text shadow-xs hover:bg-surface-raised",
  ghost: "text-text-muted hover:bg-surface-sunken hover:text-text",
  subtle: "bg-surface-sunken text-text hover:bg-border",
  danger: "bg-danger text-white shadow-xs hover:opacity-90",
};

const sizes: Record<ButtonSize, string> = {
  xs: "h-7 gap-1.5 rounded-md px-2 text-xs",
  sm: "h-8 gap-1.5 rounded-md px-3 text-[13px]",
  md: "h-9 gap-2 rounded-lg px-3.5 text-sm",
  lg: "h-11 gap-2 rounded-lg px-5 text-[15px]",
  icon: "size-9 rounded-lg",
  "icon-sm": "size-7 rounded-md",
};

/** Button styles, for links that should look like buttons. */
export function buttonClassName({
  variant = "primary",
  size = "md",
  className,
}: {
  variant?: ButtonVariant;
  size?: ButtonSize;
  className?: string | undefined;
} = {}): string {
  return cn(
    "inline-flex shrink-0 select-none items-center justify-center font-medium whitespace-nowrap transition-colors",
    "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent",
    "disabled:pointer-events-none disabled:opacity-50 aria-disabled:pointer-events-none aria-disabled:opacity-50",
    "[&_svg]:size-4 [&_svg]:shrink-0",
    variants[variant],
    sizes[size],
    className,
  );
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "primary", size = "md", loading = false, className, type = "button", disabled, children, ...props },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={buttonClassName({ variant, size, className })}
      {...props}
    >
      {loading && <Spinner />}
      {children}
    </button>
  );
});
