import type { ItemData } from "../items";

/** Every format the importer understands. */
export type ImportFormat =
  | "passbox"
  | "chrome-csv"
  | "firefox-csv"
  | "safari-csv"
  | "bitwarden-json"
  | "bitwarden-csv"
  | "1password-1pux"
  | "1password-csv"
  | "keepass-csv"
  | "keepass-xml"
  | "passbolt-csv"
  | "lastpass-csv"
  | "dashlane-csv"
  | "dashlane-zip"
  | "protonpass-json"
  | "protonpass-csv"
  | "generic-csv";

/** One item ready to be created in a Passbox vault. */
export interface ImportedItem {
  data: ItemData;
  /**
   * The vault (1Password, Proton Pass, Passbox exports) or top-level folder
   * the item came from, if the source has one. Folders are also kept as tags.
   */
  sourceVault?: string;
}

/**
 * Something the user should know about: data the source did not export, or
 * that Passbox cannot store yet. `count` items were affected; `examples`
 * lists up to five of their titles.
 */
export interface ImportWarning {
  code: ImportWarningCode;
  count: number;
  examples: string[];
}

export type ImportWarningCode =
  /** The source does not export passkey private keys, so passkeys were not imported. */
  | "passkeys_not_exported"
  /** File attachments are not part of the export file and were not imported. */
  | "attachments_not_imported"
  /** Items in the source's trash or recycle bin were skipped. */
  | "trashed_skipped"
  /** Rows without a title, website, username, password or note were skipped. */
  | "empty_skipped"
  /** Item types Passbox has no category for (for example SSH keys) were imported as "other" items. */
  | "converted_to_other"
  /** Passkeys were imported. They work in the browser extension. */
  | "passkeys_imported"
  /** A one-time password value was not a valid setup key and was kept as a text field. */
  | "invalid_totp";

export interface ImportResult {
  format: ImportFormat;
  items: ImportedItem[];
  warnings: ImportWarning[];
}

/** Thrown when a file cannot be imported. `code` is stable for translation. */
export class ImportError extends Error {
  constructor(
    readonly code:
      | "unknown_format"
      | "encrypted_export"
      | "password_required"
      | "wrong_password"
      | "invalid_file"
      | "no_items"
      | "mapping_required",
    message: string,
  ) {
    super(message);
    this.name = "ImportError";
  }
}

/** Collects warnings while parsing. */
export class WarningCollector {
  private readonly map = new Map<ImportWarningCode, ImportWarning>();

  add(code: ImportWarningCode, title: string, count = 1): void {
    const warning = this.map.get(code) ?? { code, count: 0, examples: [] };
    warning.count += count;
    if (title && warning.examples.length < 5 && !warning.examples.includes(title)) warning.examples.push(title);
    this.map.set(code, warning);
  }

  list(): ImportWarning[] {
    return [...this.map.values()];
  }
}
