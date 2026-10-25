# Import and export

Passbox imports the export files of browsers and other password managers and exports your data as an encrypted Passbox file or as CSV. Everything happens on your device: the file is parsed in the browser (in a Web Worker), and each item is encrypted with its vault key before it is uploaded, like any other item.

- Web app: **Settings → Import and export**, or open `#/import` directly.
- Code: parsers in [`packages/client/src/import`](../packages/client/src/import), export in [`packages/client/src/export`](../packages/client/src/export), the export encryption in [`crates/core/src/export.rs`](../crates/core/src/export.rs), the UI in [`apps/web/src/import`](../apps/web/src/import) and [`apps/web/src/export`](../apps/web/src/export).
- The command-line client has no import or export yet (`pbx import` / `pbx export` are planned).

## Supported formats

The format is detected from the file content (ZIP entries, JSON keys, XML root element or CSV header row), so the source the user picks in the wizard only selects the instructions. Two sources force a format: **Excel/CSV** always shows the column mapping, **Passbolt** also accepts Passbolt's copies of other layouts.

| Source | File | What is imported | Not imported |
| --- | --- | --- | --- |
| Chrome, Edge, Brave, Opera, Vivaldi | CSV: `name,url,username,password[,note]` | logins, notes | — (browsers export nothing else) |
| Firefox | CSV: `url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged` | logins; HTTP realm and a differing form address as fields | sync metadata (`guid`, timestamps), `chrome://` entries |
| Safari, Apple Passwords | CSV: `Title,URL,Username,Password,Notes,OTPAuth` | logins with one-time passwords | passkeys (Apple does not export them) |
| Bitwarden | JSON (unencrypted) | logins (all URIs, TOTP, custom fields, password history, **passkeys**), secure notes, cards, identities, SSH keys (as "Other"), folders and collections as tags, favourites | items in the trash, attachments, encrypted (`"encrypted": true`) exports are refused with a hint |
| Bitwarden | CSV: `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp` | logins and notes, custom fields (`name: value` lines) | cards and identities (Bitwarden does not put them in CSV) |
| 1Password | 1PUX (ZIP with `export.data`) | every vault (optionally recreated by name), logins (all URLs, all section fields with their types, password history), passwords, cards, secure notes, identities, all other categories as "Other" with every field, tags, favourites, archived items (tag "Archived") | passkeys and attachments (1Password does not export them) |
| 1Password | CSV: `Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes` (also 1Password 7 CSV) | logins, tags, favourites | everything that is not a login |
| KeePassXC | CSV: `Group,Title,Username,Password,URL,Notes,TOTP,Icon,Last Modified,Created` | logins, groups as tags, TOTP | the recycle bin |
| KeePass 2 | CSV: `Account,Login Name,Password,Web Site,Comments` | logins | |
| KeePass 2, KeePassXC | XML (unencrypted "KeePass XML (2.x)") | logins, nested groups as tags (`Work/Servers`), entry tags, custom strings as fields (protected ones hidden), password history from the entry history, TOTP (`otp`, `TimeOtp-Secret-Base32`, `TOTP Seed`), **KeePassXC passkeys** (`KPEX_PASSKEY_*`) | the recycle bin, attachments. A `.kdbx` file must be exported first |
| Passbolt | CSV in every Passbolt layout: `csv-kdbx` (`Title,Username,URL,Password,Notes,Group,TOTP`), `csv-1password` (`Title,Username,Url,Password,Notes,Type`, where `Type` holds the folder), `csv-bitwarden` (`name,login_username,login_uri,login_password,notes,folder,login_totp`), `csv-lastpass`, `csv-chromium`, `csv-mozilla`, `csv-safari`, `csv-dashlane` | logins, folders as tags, TOTP | Passbolt's description field when the layout has none. Since Passbolt 5.10 an administrator must allow CSV exports; alternatively export KDBX, open it in KeePassXC and export XML |
| LastPass | CSV: `url,username,password,totp,extra,name,grouping,fav` | logins, secure notes (`http://sn`), "Credit Card" notes as cards, "Address" notes as identities, other note types as notes with their fields, folders (`Work\Tools` → `Work/Tools`) as tags, favourites | attachments |
| Dashlane | ZIP of CSV files or a single CSV | `credentials.csv` (logins, alternative usernames, TOTP, category as tag), `securenotes.csv`, `payments.csv` (cards), `personalInfo.csv` (identities) | IDs (`ids.csv`) and other files |
| Proton Pass | ZIP or JSON (unencrypted) | every vault, logins (email and username, all URLs, TOTP, extra fields), aliases (as logins tagged "Alias"), notes, cards, identities (with extra sections), Wi-Fi and SSH keys (as "Other"), pinned items as favourites | items in the trash, passkeys (exported in Proton's own format), attachments, PGP-encrypted exports |
| Proton Pass | CSV: `type,name,url,email,username,password,note,totp,createTime,modifyTime,vault` | logins, notes, aliases | |
| Excel, any CSV | CSV with a header row, comma, semicolon or tab, UTF-8 or Windows-1252 | anything mapped in the column step | |
| Passbox | `.pbx-export` | everything, including passkeys, password history and vault names | |

### Mapping rules

- **Logins** use the well-known fields `username`, `password`, `url` and `totp`. Further URLs become extra "Website" fields; the title falls back to the host name, then the username.
- **One-time passwords** are kept when they are an `otpauth://totp/` URI or a Base32 setup key (spaces and dashes are removed; `key=…` from older KeePass plugins is understood). Anything else (a six-digit code, HOTP) is kept as a hidden field and reported.
- **Cards** use `cardholder`, `card_number`, `card_expiry` (`MM/YYYY`) and `card_code`; brand and PIN become extra fields.
- **Identities** use stable field IDs (`first_name`, `last_name`, `email`, `phone`, `address`, `postal_code`, `city`, `country`, `company`, `job_title`, `ssn`, `passport_number`, …); see `IDENTITY_FIELDS` in [`build.ts`](../packages/client/src/import/build.ts).
- **Folders and groups** become one tag with the full path (`Work/Servers`). KeePass root groups ("Root", the database name) are dropped. Tags of the source are kept as tags.
- **Unknown data is kept**: columns or fields Passbox has no slot for become extra text fields (hidden when the source marks them as secret), and item types Passbox does not have yet are imported as "Other" with all their fields. Nothing is silently dropped except sync bookkeeping (Firefox `guid` and timestamps, KeePass icons and modification dates).
- **Not imported, and reported in the wizard:** items in the source's trash, attachments, passkeys that the source does not export, empty rows.
- URLs without a scheme get `https://`.

### Passkeys

Only Bitwarden JSON and KeePassXC XML export passkeys with their private key. Passbox imports them when they are ES256 (P-256) keys: Bitwarden's GUID credential IDs are converted to their 16 raw bytes, PEM keys from KeePassXC to PKCS#8 DER. 1Password, Apple and Proton Pass do not export usable passkeys; the wizard lists the affected items so users can keep them in the old app or register a new passkey.

### Generic CSV and column detection

`detectColumns(headers)` suggests a target for each column from English and German header names (for example *Bezeichnung*, *Benutzername*, *Kennwort*, *Webseite*, *Bemerkung*, *Ordner*). Exact names win over partial matches, each target is used once, a lone email column becomes the username, and columns that look secret (*PIN*, *Code*, *Geheim*) become hidden fields. Everything else becomes a visible extra field. The user can change every column in the mapping step; `mappingProblem` blocks mappings without any useful column or with a target used twice.

Columns the header rules do not recognize can get a suggestion in the mapping step (K6): **Suggest fields** uses value patterns on the device (URLs → website, email addresses → username, `otpauth://`/Base32 → one-time password, random strings → hidden field); with the AI feature switched on, **Suggest with AI** asks the configured model and sends only the headers and a pattern profile per column, never cell values. Suggestions are marked and can be undone. See [architecture/ai-gateway.md](architecture/ai-gateway.md#k6-smart-import-mapping-import-mapping-d1).

### Duplicates

An imported login is a duplicate of an existing one when the normalized host (lower case, without `www.`, ignoring path and scheme) and the username (case-insensitive) match. Other items match on category and title. Items in the trash are ignored. For each duplicate the user chooses **Skip** (default), **Update existing** (imported values replace existing ones, new fields are added, tags and passkeys are merged, a different note is appended, and the old password goes into the password history) or **Keep both**.

### Large imports

`PassboxClient.importItems` uploads items with up to six requests in flight, refreshes the item list every 200 items, yields to the event loop between batches and syncs once at the end. Server errors and dropped connections are retried with backoff, and the number of parallel requests halves while the server reports errors, then grows again. The wizard shows a progress bar and can stop the import.

Measured with a synthetic Chrome CSV against a local debug build of the server (`packages/client/src/import/import.integration.test.ts`, `PASSBOX_IMPORT_BENCH=10000`):

| Items | Server database | Parse | Duplicate check | Upload |
| --- | --- | --- | --- | --- |
| 10,000 | SQLite in memory | 0.18 s | 0.02 s | 17.8 s (≈560 items/s) |
| 10,000 | SQLite file | 0.18 s | 0.02 s | 47 s (≈210 items/s) |

The longest pause between two progress callbacks stayed below 30 ms on the in-memory database (no frozen UI); 40,000 items take a few minutes. With a SQLite file, parallel writes regularly fail with "database is locked" on the server; the client's retries absorb this, but the server should set a busy timeout and WAL mode.

## Export

Exports exclude items in the trash unless the user asks for them, and can be limited to some vaults. The dialog requires the master password again (checked locally: the derived key must decrypt the account key; no new sign-in).

### Encrypted export (`.pbx-export`, recommended)

A JSON envelope whose payload is encrypted with a password chosen for this file (independent of the account, so it can be imported into any Passbox account):

```json
{
  "format": "passbox-export",
  "version": 1,
  "kdf": { "algorithm": "argon2id", "salt": "<16 bytes, Base64url>", "memoryKib": 131072, "iterations": 3, "parallelism": 4 },
  "cipher": "xchacha20poly1305",
  "ciphertext": "<Base64url>"
}
```

- `key = HKDF-SHA256(Argon2id(password, salt, params), info = "passbox/v1/export")`.
- The ciphertext is the standard Passbox AEAD envelope (version, algorithm, 24-byte nonce, XChaCha20-Poly1305) with the header as associated data: `"passbox-export" 0 "1" 0 "argon2id" 0 m 0 t 0 p 0 salt 0 "xchacha20poly1305"`. Changing any header field, for example lowering the KDF cost, makes decryption fail.
- Decryption enforces `KdfParams::MINIMUM` (64 MiB, 3 passes) and a maximum (1 GiB, 64 passes, 16 lanes), so a crafted file can neither downgrade the derivation nor exhaust memory.
- The UI requires an export password with a strength score of at least 3.
- The decrypted payload is `{"format":"passbox-export-payload","version":1,"exportedAt":<ms>,"vaults":[{"name":…,"items":[<item data v1>…]}]}` with the complete item data, including passkeys and password history.

Code: [`crates/core/src/export.rs`](../crates/core/src/export.rs) (WebAssembly: `encryptExport`, `decryptExport`, `isExport`).

### CSV export (not encrypted)

Bitwarden's CSV layout (`folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp`), which Bitwarden, Proton Pass, 1Password, Passbolt and Passbox import. Logins keep all their website fields (comma-separated) and extra fields (`label: value` lines); cards, identities and other items become notes with their fields. The folder is the first tag (prefixed with the vault name when several vaults are exported). Passkeys, password history and further tags are not included. Values are written unchanged, so a spreadsheet program may interpret cells that start with `=`, `+`, `-` or `@` as formulas: do not open the file in Excel.

The dialog shows a strong warning and requires an explicit confirmation before it writes the file.

## Tests

- `pnpm --filter @passbox/client test`: parsers against the fixtures in [`packages/client/src/import/fixtures`](../packages/client/src/import/fixtures) (synthetic data only), format detection, duplicate detection, the encrypted export round trip through the WebAssembly core and the importer, and CSV export round trips.
- `cargo test -p passbox-core export`: the export envelope (round trip, wrong password, header authentication, KDF bounds, versions).
- `PASSBOX_TEST_SERVER_URL=… pnpm --filter @passbox/client test`: bulk import, duplicate update and master password check against a server; add `PASSBOX_IMPORT_BENCH=10000` for the benchmark.
- `pnpm e2e` (`e2e/tests/import.spec.ts`): imports the Chrome fixture in the web app, finds the items, re-imports to see the duplicates, and exports encrypted and CSV files from Settings.
