"use client";

import { type ReactNode, useEffect, useState } from "react";
import { cn } from "./cn";
import { Monogram, type MonogramSize, monogramSizes } from "./Monogram";

/** Image URLs that loaded before: shown at once when a row mounts again. */
const loaded = new Set<string>();

export interface SiteIconProps {
  /** Image URL (a `data:` URL from the user's server, or a bundled asset). Nothing or `null`: the monogram. */
  src: string | null | undefined;
  /** Name the monogram is derived from (shown while loading and when there is no image). */
  name: string;
  /** Replaces the monogram's initial, for example with a category icon. */
  icon?: ReactNode;
  size?: MonogramSize;
  /** Alternative text. Empty (the default) when the name is shown next to the icon. */
  alt?: string;
  /** The image fills its square (an app icon); otherwise it gets some padding on the tile. */
  bleed?: boolean;
  className?: string | undefined;
}

/**
 * A website or service icon on a light rounded tile, with the tinted
 * monogram while it loads and when there is none or it fails to load.
 */
export function SiteIcon({ src, name, icon, size = "md", alt = "", bleed = false, className }: SiteIconProps) {
  const [state, setState] = useState<"loading" | "loaded" | "failed">(() =>
    src && loaded.has(src) ? "loaded" : "loading",
  );
  useEffect(() => {
    setState(src && loaded.has(src) ? "loaded" : "loading");
  }, [src]);

  if (!src || state === "failed") {
    const monogram = <Monogram name={name} size={size} icon={icon} className={alt ? undefined : className} />;
    return alt ? (
      <span role="img" aria-label={alt} className={cn("inline-flex shrink-0", className)}>
        {monogram}
      </span>
    ) : (
      monogram
    );
  }
  const ready = state === "loaded";
  const label = alt ? { role: "img" as const, "aria-label": alt } : { "aria-hidden": true as const };
  return (
    <span className={cn("relative block shrink-0", monogramSizes[size], className)} {...label}>
      {!ready && <Monogram name={name} size={size} icon={icon} className="absolute inset-0 size-full" />}
      <span
        style={{
          backgroundColor: "var(--pb-icon-tile, #fff)",
          boxShadow: "inset 0 0 0 1px var(--pb-icon-tile-ring, rgb(0 0 0 / 0.08))",
        }}
        className={cn(
          "absolute inset-0 flex items-center justify-center overflow-hidden rounded-[inherit]",
          !ready && "opacity-0",
        )}
      >
        <img
          src={src}
          alt=""
          draggable={false}
          decoding="async"
          referrerPolicy="no-referrer"
          onLoad={() => {
            loaded.add(src);
            setState("loaded");
          }}
          onError={() => setState("failed")}
          className={cn(
            "pointer-events-none select-none",
            bleed ? "size-full object-cover" : "size-[70%] object-contain",
          )}
        />
      </span>
    </span>
  );
}
