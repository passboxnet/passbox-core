# Item extras: history, icons, breaches, usage, health, bulk changes

Client features behind the item list and item detail screens of the apps
(created date, "Eintragsverlauf", website icons, "Kompromittierte
Passwörter", "Zuletzt verwendet" / "Letztes Auto-Ausfüllen", the per-item
"Sicherheits-Check" and multi-select). They exist in the Rust client
(`crates/client`, used by the CLI, desktop and through `crates/ffi` by iOS
and Android) and in the TypeScript client (`packages/client`, web and
extension). All FFI calls are blocking: run them on a background task
(Swift `Task.detached`, Kotlin `Dispatchers.IO`).

## Created date

The server sends `createdAt` (Unix ms) with every item in `/api/v1/sync`.
Clients expose it as `Item.created_at` (Rust), `Item.createdAt` (FFI, TS).
It is 0 (TS: 0 or absent) from servers that do not send it yet.

## Item history ("Eintragsverlauf")

Every update of an item keeps the replaced encrypted version on the server
(table `item_versions`, newest 20 per item, removed when the item is deleted
permanently or its vault is deleted). Re-encryptions after a key rotation are
versions too. The server cannot read them: each version stays bound to its
own revision and key epoch through the item's associated data
(`passbox/v1/item|vault|item|revision` or `passbox/v2/item|…|epoch`), so it
cannot pass off an old version as the current one either.

| | Call | Returns |
| --- | --- | --- |
| HTTP | `GET /api/v1/items/{id}/versions` | `{ versions: [{ revision, keyEpoch, encryptedData, updatedAt, updatedBy }] }`, newest first |
| Rust | `client.item_history(id)` | `Vec<ItemVersion { revision, updated_at, updated_by, data: Option<ItemData> }>` |
| FFI | `itemHistory(id)` | `[ItemVersion { revision, updatedAt, updatedBy?, data? }]` |
| TS | `client.itemHistory(id)` | `Promise<{ revision, updatedAt, updatedBy, data: ItemData \| null }[]>` |

`data` is empty when this device cannot decrypt the version, typically a
shared vault's version from before a key rotation that the account was not a
member for (it never received that epoch's key). Show such entries as
"Diese Version kann auf diesem Gerät nicht angezeigt werden" instead of
hiding them. `updatedBy` is the public session ID of the device that saved
the version; match it against `sessions()` to show a device name.

**Restoring** a version is a normal update with its data:
`updateItem(id, version.data)`. That saves it as a new version (so the restore
can be undone from the history too) and keeps the password history.

## Website icons

Apps never contact the websites in a vault. They ask their own server:
`GET /api/v1/icons/{domain}` (session required) fetches the icon over HTTPS
with strict protection against server-side request forgery and caches it.
See [self-hosting.md](../self-hosting.md#website-icons) for the rules and the
privacy note: the server learns which domains are in vaults. Admins can turn
it off (`PASSBOX_ICONS=off`, `/api/v1/meta` → `icons: false`).

| | Call | Returns |
| --- | --- | --- |
| Rust | `client.icon(domain)` | `Option<Vec<u8>>` (PNG, ICO, JPEG, GIF or WebP) |
| FFI | `icon(domain)` | `Data?` / `ByteArray?` |
| TS | `client.iconUrl(domain)` | `Promise<string \| null>` (`data:` URL for `<img>`; the CSP allows `data:` images) |
| TS | `api.icon(domain)`, `iconPath(domain)` | raw bytes and content type |

Pass the bare host name (`github.com`; punycode for international names in the
Rust client). The Rust client caches results in its store for 7 days ("no
icon" for a day) under keys `cache_icon_<domain with _ for .>`, and returns a
cached icon when offline. Apps keep store keys starting with `cache` in
files, not in the keychain (iOS `AppSecureStore` does this).

**User preference:** apps offer "Website-Icons anzeigen" (default on) and
show a monogram when it is off, when `meta.icons` is false or when there is
no icon. The preference is local to the app.

## Breach check ("Kompromittierte Passwörter")

Have I Been Pwned's range API with k-anonymity: only the first 5 hex
characters of the password's SHA-1 hash are sent, with `Add-Padding: true`;
matching happens on the device (`passbox_core::breach`).

| | Call | Returns |
| --- | --- | --- |
| Rust | `client.breach_check(password)` | `u64` (0 = not found) |
| Rust | `client.check_breached_items()` | `Vec<BreachedItem { item_id, count }>`, most breached first |
| FFI | `breachCheck(password)`, `breachedItems()` | `UInt64`, `[BreachedItem { itemId, count }]` |
| TS | `breachCount(password)`, `client.checkBreachedItems()` | `Promise<number>`, `Promise<{ itemId, count }[]>` |

`check_breached_items` covers logins outside the trash, sends one request per
hash prefix and keeps the results in memory until the vault locks. It is slow
for large vaults: run it in the background. Offline it fails with
`Network` ("Have I Been Pwned could not be reached"). The check is opt-in:
ask once and explain what is sent ("Nur die ersten 5 Zeichen eines
Prüfwerts Ihres Passworts werden an Have I Been Pwned gesendet – nie das
Passwort selbst.").

## Usage ("Zuletzt verwendet", "Letztes Auto-Ausfüllen")

A device-local map item ID → `{ lastUsedAt, lastAutofilledAt, useCount }`,
encrypted with the account key (`Keyring::encrypt_local`, purpose
`item-usage`) and never sent to the server. Times are Unix ms, 0 = never.

| | Call |
| --- | --- |
| Rust | `client.record_item_use(id, UsageKind::Copy \| Autofill \| Open)`, `item_usage(id)`, `item_usages()` |
| FFI | `recordItemUse(id, kind: .copy/.autofill/.open)`, `itemUsage(id)`, `itemUsages()` (map by item ID) |
| TS | `client.recordItemUse(id, "copy" \| "autofill" \| "open")`, `itemUsage(id)`, `itemUsages()` |

Every kind sets `lastUsedAt` and counts a use; `autofill` also sets
`lastAutofilledAt`. Call it when a field is copied, when the item is opened
and from the iOS AutoFill extension / Android Autofill service after filling.
The Rust client stores it under the store key `cache_usage`, the TS client in
`localStorage` (`passbox.usage.<accountId>`). Signing out deletes it.

## Per-item health ("Sicherheits-Check")

The same rules as the vault health (`health()`), for one item:

| | Call | Returns |
| --- | --- | --- |
| Rust | `client.item_health(id)` | `ItemHealth { problems: Vec<ItemProblem>, strength: Option<u8>, reused_with, breach_count: Option<u64> }` |
| FFI | `itemHealth(id)` | `ItemHealth { problems: [ItemProblem], strength?, reusedWith, breachCount? }` |
| TS | `client.itemHealth(id)` | `{ problems: ItemProblem[], strength, reusedWith, breachCount }` |

Problems, in this order: `weak` (score ≤ 1), `reused`, `insecure_url`
(`http://`), `missing_totp` (a login with a password but no one-time
password), `breached` (only known after a breach check in this session;
`breachCount` is `null`/`None` before). FFI enum cases: `.weak`, `.reused`,
`.insecureUrl`, `.missingTotp`, `.breached` (Kotlin `WEAK`, `REUSED`,
`INSECURE_URL`, `MISSING_TOTP`, `BREACHED`). Items in the trash and other
categories have no problems.

## Bulk changes (multi-select)

| | Call | Returns |
| --- | --- | --- |
| Rust | `client.trash_items(&ids)`, `client.set_favorite(&ids, favorite)` | `Vec<BulkFailure { item_id, error }>` |
| FFI | `trashItems(ids)`, `setFavorite(ids, favorite)` | `[BulkFailure { itemId, error }]` |
| TS | `client.trashItems(ids)`, `client.setFavorite(ids, favorite)` | `Promise<{ itemId, error }[]>` |

Items are written one after another with a single sync at the end; items
that already have the requested state are skipped. Failures (for example an
item changed on another device meanwhile) are reported per item and do not
stop the others. Losing the connection or the session stops the operation
with `Offline` / `Locked`. Trashed items can be restored for 30 days, so an
undo toast is enough confirmation.
