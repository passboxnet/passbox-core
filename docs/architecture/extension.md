# Browser extension

The Chrome extension ([passboxnet/browser-extension](https://github.com/passboxnet/browser-extension), Manifest V3) is a full Passbox client. It uses the same core (WebAssembly) and client logic (`@passbox/client`) as the web vault.

## Contexts

```
 web page ─┬─ MAIN world: webauthn.js      wraps navigator.credentials (passkeys)
           ├─ isolated world: content.js   field detection, inline icon, filling, submit detection
           └─ closed shadow root
                └─ chrome-extension:// iframes (frame.html): inline menu, save banner, passkey dialog
                                │
 toolbar popup (popup.html) ────┼──── runtime messages ────▶ service worker (background.js)
                                                              PassboxClient, keyring (WebAssembly)
                                                                    │
                                                    offscreen.html (clipboard only, created on demand)
```

- **Service worker:** owns the vault. It signs in, unlocks, syncs, decides what to fill, creates or signs passkeys and clears the clipboard. Nothing else holds keys or the item list.
- **Popup:** first-run server choice, sign-in, unlock, vault list with suggestions for the current site, item detail (copy, one-time codes, previous passwords, Fill, "Open website & fill", move to trash), trash, generator (password, passphrase, PIN) and settings.
- **Content script:** never asks for vault data. It receives only the values of the one item the user chose, for the document it runs in, and only for the fields the form visibly has.
- **Frames:** the inline menu, the save banner and the passkey dialog are extension pages in iframes. The page cannot read them (different origin).
- **Offscreen document:** created with reason `CLIPBOARD` to clear the clipboard, then closed.

## Message validation

The service worker trusts only what Chrome reports about a sender (`sender.id`, `sender.origin`, `sender.tab`, `sender.frameId`, `sender.documentId`), never what a message claims:

| Sender | Accepted when | May |
| --- | --- | --- |
| Popup | own extension, origin and path `/popup.html` | everything |
| Frame | own extension, origin and path `/frame.html`, inside a tab | act on the session whose random 128-bit ID it holds, only in that tab |
| Content script | own extension, a tab, an http(s) frame origin | report fields and submits, open a menu, forward WebAuthn calls |

Content scripts only accept messages from the service worker. Passbox does nothing on its own server's origin, so the web vault's master password is never captured.

Errors reach the popup and frames as message keys with parameters (`error.wrongMasterPassword`, `error.rateLimited` with `minutes`, …), so the UI shows them in the user's language.

## Autofill rules

- Fill only after an explicit user action: a click in the inline menu, Fill in the popup, the keyboard shortcut (Ctrl/Cmd+Shift+L), or "Open website & fill" (the login is filled once the chosen item's site has loaded in the new tab).
- Logins match by registrable domain (eTLD+1 from the Public Suffix List, private suffixes such as `github.io` included). IP addresses and `localhost` match by exact host; on loopback hosts an item URL with a port also needs the same port, because every port is a different local app. Items in the trash are never offered or filled.
- Each fill goes to exactly one document (`documentId`) whose origin matches the item; the content script checks the origin again before filling. A cross-origin iframe only gets a login that matches its own origin.
- Only visible fields count. A field is invisible when it or an ancestor has `display: none`, `visibility: hidden`, an opacity of almost 0, a `clip`/`clip-path` that leaves nothing, `content-visibility: hidden`, a box of at most one pixel, or a position left of or above the document. Before filling, the service worker asks the content script which fields the target form has and never sends the password when there is no visible password field; the menu then says "This form has no visible password field. Passbox filled in only the username."
- The user confirms before filling on http pages (other than loopback), before filling a login saved for `https://` into an `http://` page, and before filling into a frame whose site differs from the page around it ("In a frame on prize-winner.test", then "Fill into frame").
- On a page without a matching login that imitates a saved or well-known site (IDN homograph, look-alike characters, a typo of a saved domain), the menu shows "Careful: this is not paypal.com" and fills nothing; the save banner warns the same way. The check runs locally in the core (`checkLookalike`, see [security-analysis.md](security-analysis.md)).
- The menu shows hosts with the registrable domain in bold and the subdomains muted, truncated from the left, and marks site-level matches with "Saved for example.test".
- Values are set through the native value setter followed by `input` and `change` events, so React and Vue forms notice.

## Save prompts

- A submit counts only when the event is trusted (`isTrusted`) and the user pressed a pointer or key inside the same form within the five seconds before. Page scripts that fill a form and call `click()` or `requestSubmit()` cannot raise a prompt.
- The banner offers to save (with editable name, username and vault) or to update the password of the login with the same username. When the site already has logins with other usernames, it asks whether to update one of them or save a new login. "Not now" is the default button; "Never ask for this website" adds the registrable domain to a list the user can edit in Settings.
- An update says "Only update if you signed in successfully" and, when the saved login belongs to another host of the site, "Saved for example.test · you are on promo.example.test". The replaced password goes to the item's password history (by `@passbox/client`), and the banner offers "Undo" for ten seconds, which puts it back.

## Clipboard

The popup copies with `navigator.clipboard.writeText` and sends the service worker a SHA-256 of the value (never the value). The service worker keeps the hash in `chrome.storage.session` and clears the clipboard on a `chrome.alarms` alarm after 1, 2 or 5 minutes (setting; alarms have about one-minute granularity, so the copy says "in about 1 minute") and whenever the vault locks. Clearing runs in an offscreen document: it compares the clipboard with the hash when it can read it, and otherwise clears it anyway, because Passbox does not request the `clipboardRead` permission. The popup itself cannot clear: it closes as soon as the user clicks into the page to paste.

## Click-jacking

The page controls the iframe element and could make it transparent, cover it or move it under the pointer. Frames use Intersection Observer v2 (`trackVisibility`) and ignore clicks unless they have been visible, unobscured and untransformed for 300 ms. The icon and frames live in a closed shadow root, so page scripts cannot query them.

## Passkeys

The MAIN-world script wraps `navigator.credentials.create` and `get` for `publicKey` requests (conditional mediation stays with the browser) and forwards them through the content script. The service worker checks the RP ID against the frame's origin (see [cryptography.md](cryptography.md#passkeys-implemented)), shows the dialog in the top frame and answers with a credential, an error or "fallback". "Use device or security key instead" and requests Passbox cannot serve (no matching passkey, no ES256, cross-platform attachment requested, calls from iframes, where the browser enforces the `publickey-credentials-*` permissions policy) run the browser's original implementation.

The dialog headlines the verified RP ID ("Save a passkey for **example.com**?") and shows the page-supplied `rp.name` only as "The site calls itself “PayPal”". New logins are titled with the RP ID host, and the confirm button gets no automatic focus. The UV flag is set only when the master password was entered in the last five minutes; when the site requires user verification and the last entry is older, the dialog asks for the master password before signing.

## Accounts and servers

- First run asks "Choose your server" (there is no built-in default until a hosted service exists; a managed `serverUrl` policy skips the step). The address is checked with `GET /api/v1/meta` before it is saved. `http://` is accepted without asking only for loopback hosts; other http servers need the user to type "http".
- The Secret Key format is checked on the device before sign-in. A wrong password on the unlock screen says "Wrong master password" (with a Caps Lock hint), and rate limits say how many minutes to wait.
- Signing out (Settings or "Use a different account…" on the unlock screen) asks first, because it removes the Secret Key from this device, and offers "Show Emergency Kit". The kit (email, sign-in address, Secret Key) is shown only after the master password is entered again; while unlocked, the password is checked locally by opening the account key.
- With two-factor sign-in on, sign-in and unlock show a second step after the password: a code from the authenticator app or a recovery code, with "Remember this device for 30 days" (bound to the extension's device token). The pending login lives in the service worker; if the browser stops it before the code is entered, the popup goes back to the password. Security keys are registered for the web vault's domain, which the popup (a `chrome-extension://` page) cannot use, so accounts with only security keys use a recovery code here or remember the device after signing in once with one. Two-factor settings are managed in the web vault.
- Auto-lock offers the web vault's choices (1, 5, 15, 30, 60 minutes); the vault also locks when the screen locks and when the browser closes.
- Website icons of logins (popup, inline menu, save banner) come through the user's Passbox server, never from the websites: the service worker answers `popup.icon` / `frame.icon` with `client.iconUrl`, keeps the results in `chrome.storage.session` until the vault locks and returns nothing when "Show website icons" is off in Settings (see [item-extras.md](item-extras.md#website-icons)).
- Items that fail to decrypt are listed in a banner with details; nothing is deleted. Trashed items are purged after 30 days, best effort after each unlock.

## Shared vaults

The extension shows what families and teams share but does not manage them (that is the web vault's "Family & team"):

- The popup has a vault filter under the search when there is more than one vault: personal vaults, then shared vaults grouped by organization (`<optgroup>`), view-only ones marked. Items in shared vaults carry a people icon; suggestions for the current site are never filtered.
- `snapshot.sharingWarnings` (changed keys, unverifiable shared data) show a warning notice with a link to `#/sharing` in the web vault, where they are explained and resolved.
- View-only items (`ItemDetail.readOnly`) can be copied and filled; trash and password restore are hidden, and the service worker refuses those writes with `item.error.readOnly` (`Vault.writable`).
- The save banner lists only vaults the user may write to, shared ones as "Family vault · The Millers", and never offers to update a login from a view-only vault (a changed password there is for its managers). New logins default to the personal vault.
- The exported session is refreshed when a shared vault's key epoch changes, so a restarted service worker keeps the rotated key.

## Languages

All popup, frame and error strings come from `@passbox/i18n` (`common` plus the `extension` namespace, English and German). The language follows the browser and can be changed in Settings (stored as `locale` in `chrome.storage.local`). The manifest name and description, the shortcut description and the few labels the content script creates use `_locales/{en,de}/messages.json`.

## Permissions

`storage`, `activeTab`, `alarms` (auto-lock, periodic sync, clipboard clearing, the breach catalogue every six hours), `notifications` (one notification when a newly published breach concerns saved logins; the toolbar badge shows "!" until the popup alert is acknowledged), `idle` (lock when the screen locks), `offscreen` and `clipboardWrite` (clipboard clearing), content scripts on all http(s) pages (autofill), and optional host permissions for the server. When the server is chosen and at sign-in, the popup requests access to the server's host unless granted access already covers it.

## Tests

- `pnpm test` in passboxnet/browser-extension: unit tests for domain matching, field detection and visibility (jsdom fixtures), trusted submits, save and update decisions with undo, fill payloads, passkey user verification, server checks, error mapping and translation completeness.
- End-to-end tests load the built extension in Chromium and cover the first-run server step, sign-in, the inline menu, update with Undo, scripted submits, hidden fields, frames of other sites, clipboard clearing on lock, passkeys with and without user verification, shared family vaults in the popup filter, and the sign-out confirmation.

## Known limitations

- Pending save prompts live in service worker memory and are lost if the worker stops between submit and the next page.
- Tabs opened before the extension was installed need a reload to get the content script.
- Save prompts are only offered while the vault is unlocked.
- Passkeys inside iframes are left to the browser.
- Without `clipboardRead`, clearing cannot tell whether the user copied something else in the meantime and clears it too.
- Content-script labels (the field icon's name) follow the browser language, not the language setting.
