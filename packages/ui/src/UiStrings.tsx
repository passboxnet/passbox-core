"use client";

import { createContext, type ReactNode, useContext } from "react";

/**
 * Text the components render themselves (button labels, screen-reader
 * labels). Apps pass translated strings with `UiStringsProvider`; without a
 * provider the components use English.
 */
export interface UiStrings {
  close: string;
  cancel: string;
  showPassword: string;
  hidePassword: string;
  capsLockOn: string;
}

export const DEFAULT_UI_STRINGS: UiStrings = {
  close: "Close",
  cancel: "Cancel",
  showPassword: "Show password",
  hidePassword: "Hide password",
  capsLockOn: "Caps Lock is on",
};

const UiStringsContext = createContext<UiStrings>(DEFAULT_UI_STRINGS);

export function UiStringsProvider({ strings, children }: { strings: Partial<UiStrings>; children: ReactNode }) {
  return (
    <UiStringsContext.Provider value={{ ...DEFAULT_UI_STRINGS, ...strings }}>{children}</UiStringsContext.Provider>
  );
}

export function useUiStrings(): UiStrings {
  return useContext(UiStringsContext);
}
