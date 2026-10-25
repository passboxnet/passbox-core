"use client";

import { brandIconInfo } from "@passbox/brand-icons";
import type { MonogramSize } from "./Monogram";
import { SiteIcon } from "./SiteIcon";

/*
 * Exported as `@passbox/ui/brand-icon` (not from the package index) so that
 * apps that do not show third-party services do not bundle the icons.
 */

export interface BrandIconProps {
  /** The service: ID (`okta`), host name (`okta.com`) or URL. */
  service: string;
  /** Overrides the service's name (alt text and monogram fallback). */
  name?: string;
  size?: MonogramSize;
  /** Hide from assistive technology when the service's name is written right next to the icon. */
  decorative?: boolean;
  className?: string | undefined;
}

/**
 * The bundled icon of a third-party service (see `@passbox/brand-icons`),
 * with a monogram for services without one. Never loads anything from the
 * service itself.
 */
export function BrandIcon({ service, name, size = "md", decorative = false, className }: BrandIconProps) {
  const info = brandIconInfo(service);
  const label = name ?? info?.name ?? service;
  return (
    <SiteIcon
      src={info?.url}
      name={label}
      size={size}
      alt={decorative ? "" : label}
      bleed={info?.bleed ?? false}
      className={className}
    />
  );
}
