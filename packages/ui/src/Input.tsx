"use client";

import { Eye, EyeOff } from "lucide-react";
import {
  forwardRef,
  type InputHTMLAttributes,
  type KeyboardEvent,
  type ReactNode,
  type TextareaHTMLAttributes,
  useId,
  useState,
} from "react";
import { cn } from "./cn";
import { useUiStrings } from "./UiStrings";

export const fieldClassName = cn(
  "w-full rounded-control border border-border-strong bg-field text-sm text-text shadow-xs transition-[border-color,box-shadow] duration-150",
  "placeholder:text-text-subtle hover:border-text-subtle",
  "focus:border-focus focus:outline-none focus:ring-4 focus:ring-focus/20",
  "disabled:cursor-not-allowed disabled:bg-surface-sunken disabled:opacity-70",
  "aria-invalid:border-danger aria-invalid:focus:ring-danger/20",
);

interface FieldWrapperProps {
  id: string;
  label: string | undefined;
  hint: ReactNode | undefined;
  error: string | undefined;
  hideLabel: boolean | undefined;
  labelAction?: ReactNode;
  children: ReactNode;
}

function FieldWrapper({ id, label, hint, error, hideLabel, labelAction, children }: FieldWrapperProps) {
  return (
    <div className="flex flex-col gap-1.5">
      {label && (
        <div className={cn("flex items-center justify-between", hideLabel && "sr-only")}>
          <label htmlFor={id} className="text-[0.8125rem] font-medium text-text">
            {label}
          </label>
          {labelAction}
        </div>
      )}
      {children}
      {error ? (
        <p id={`${id}-error`} className="text-xs text-danger">
          {error}
        </p>
      ) : (
        hint && (
          <p id={`${id}-hint`} className="text-xs text-text-muted">
            {hint}
          </p>
        )
      )}
    </div>
  );
}

export interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  hint?: ReactNode | undefined;
  error?: string | undefined;
  hideLabel?: boolean;
  labelAction?: ReactNode;
  /** Icon or text shown inside the field on the left. */
  leading?: ReactNode;
  /** Buttons shown inside the field on the right. */
  trailing?: ReactNode;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
  { label, hint, error, hideLabel, labelAction, leading, trailing, className, id, ...props },
  ref,
) {
  const generatedId = useId();
  const inputId = id ?? generatedId;
  const describedBy = error ? `${inputId}-error` : hint ? `${inputId}-hint` : undefined;
  return (
    <FieldWrapper id={inputId} label={label} hint={hint} error={error} hideLabel={hideLabel} labelAction={labelAction}>
      <div className="relative flex items-center">
        {leading && (
          <span className="pointer-events-none absolute left-3 flex text-text-subtle [&_svg]:size-4">{leading}</span>
        )}
        <input
          ref={ref}
          id={inputId}
          aria-describedby={describedBy}
          aria-invalid={error ? true : undefined}
          className={cn(
            fieldClassName,
            "h-10 px-3 coarse:h-12",
            leading ? "pl-9" : undefined,
            trailing ? "pr-20" : undefined,
            className,
          )}
          {...props}
        />
        {trailing && <span className="absolute right-1.5 flex items-center gap-0.5">{trailing}</span>}
      </div>
    </FieldWrapper>
  );
});

export interface PasswordInputProps extends Omit<InputProps, "type"> {
  /** Extra buttons next to the reveal toggle, for example a generator. */
  actions?: ReactNode;
}

/** Password field with a reveal toggle and a Caps Lock warning. */
export const PasswordInput = forwardRef<HTMLInputElement, PasswordInputProps>(function PasswordInput(
  { actions, hint, onKeyUp, className, ...props },
  ref,
) {
  const strings = useUiStrings();
  const [revealed, setRevealed] = useState(false);
  const [capsLock, setCapsLock] = useState(false);
  const handleKeyUp = (event: KeyboardEvent<HTMLInputElement>) => {
    setCapsLock(event.getModifierState("CapsLock"));
    onKeyUp?.(event);
  };
  return (
    <Input
      ref={ref}
      type={revealed ? "text" : "password"}
      onKeyUp={handleKeyUp}
      spellCheck={false}
      autoCapitalize="off"
      className={cn("font-mono tracking-tight", className)}
      hint={
        capsLock ? (
          <span className="font-medium text-warning-text" role="status">
            {strings.capsLockOn}
          </span>
        ) : (
          hint
        )
      }
      trailing={
        <>
          {actions}
          <button
            type="button"
            onClick={() => setRevealed((r) => !r)}
            aria-label={revealed ? strings.hidePassword : strings.showPassword}
            aria-pressed={revealed}
            className="flex size-7 items-center justify-center rounded-lg text-text-muted hover:bg-surface-raised hover:text-text coarse:size-10 [&_svg]:size-4"
          >
            {revealed ? <EyeOff /> : <Eye />}
          </button>
        </>
      }
      {...props}
    />
  );
});

export interface TextareaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  hint?: ReactNode | undefined;
  error?: string | undefined;
  hideLabel?: boolean;
}

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(function Textarea(
  { label, hint, error, hideLabel, className, id, ...props },
  ref,
) {
  const generatedId = useId();
  const inputId = id ?? generatedId;
  return (
    <FieldWrapper id={inputId} label={label} hint={hint} error={error} hideLabel={hideLabel}>
      <textarea
        ref={ref}
        id={inputId}
        aria-invalid={error ? true : undefined}
        className={cn(fieldClassName, "min-h-24 px-3 py-2 leading-relaxed", className)}
        {...props}
      />
    </FieldWrapper>
  );
});
