"use client";

import { useId } from "react";
import { cn } from "./cn";

export interface SegmentedControlProps<T extends string> {
  value: T;
  onChange: (value: T) => void;
  options: Array<{ value: T; label: string }>;
  label: string;
  className?: string;
}

/** A row of mutually exclusive options, built on native radio buttons. */
export function SegmentedControl<T extends string>({
  value,
  onChange,
  options,
  label,
  className,
}: SegmentedControlProps<T>) {
  const name = useId();
  return (
    <fieldset
      className={cn(
        "inline-grid auto-cols-fr grid-flow-col gap-0.5 rounded-full bg-surface-sunken p-1 ring-1 ring-hairline ring-inset",
        className,
      )}
    >
      <legend className="sr-only">{label}</legend>
      {options.map((option) => (
        <label
          key={option.value}
          className={cn(
            "flex h-8 cursor-pointer items-center justify-center rounded-full px-3.5 text-center text-[0.8125rem] font-semibold transition-colors duration-150 coarse:h-11",
            "has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-focus",
            value === option.value
              ? "bg-surface-overlay text-text shadow-card ring-1 ring-hairline"
              : "text-text-muted hover:text-text",
          )}
        >
          <input
            type="radio"
            name={name}
            value={option.value}
            checked={value === option.value}
            onChange={() => onChange(option.value)}
            className="sr-only"
          />
          {option.label}
        </label>
      ))}
    </fieldset>
  );
}
