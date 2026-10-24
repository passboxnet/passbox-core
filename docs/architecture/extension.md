# Browser extension

The Chrome extension (`apps/extension`, Manifest V3) is a full Passbox client. It uses the same core (WebAssembly) and client logic (`@passbox/client`) as the web vault.

## Contexts

```
 web page ─┬─ MAIN world: webauthn.js      wraps navigator.credentials (passkeys)
           ├─ isolated world: content.js   field detection, inline icon, filling, submit detection
           └─ closed shadow root
                └─ chrome-extension:// iframes (frame.html): inline menu, save banner, passkey dialog
                                │
 toolbar popup (popup.html) ────┼──── runtime messages ────▶ service worker (background.js)
                                                              PassboxClient, keyring (WebAssembly)
```

- **Service worker:** owns the vault. It signs in, unlocks, syncs, decides what to fill and creates or signs passkeys. Nothing else holds keys or the item list.
- **Popup:** sign-in, unlock, vault list with suggestions for the current site, item detail (copy, one-time codes, Fill), generator, settings.
- **Content script:** never asks for vault data. It receives only the values of the one item the user chose, for the document it runs in.
- **Frames:** the inline menu, the save banner and the passkey dialog are extension pages in iframes. The page cannot read them (different origin).

## Message validation

The service worker trusts only what Chrome reports about a sender (`sender.id`, `sender.origin`, `sender.tab`, `sender.frameId`, `sender.documentId`), never what a message claims:

| Sender | Accepted when | May |
| --- | --- | --- |
| Popup | own extension, origin and path `/popup.html` | everything |
| Frame | own extension, origin and path `/frame.html`, inside a tab | act on the session whose random 128-bit ID it holds, only in that tab |
| Content script | own extension, a tab, an http(s) frame origin | report fields and submits, open a menu, forward WebAuthn calls |

Content scripts only accept messages from the service worker. Passbox does nothing on its own server's origin, so the web vault's master password is never captured.

## Autofill rules

- Fill only after an explicit user action: a click in the inline menu, Fill in the popup, or the keyboard shortcut (Ctrl/Cmd+Shift+L).
- Logins match by registrable domain (eTLD+1 from the Public Suffix List, private suffixes such as `github.io` included). IP addresses and `localhost` match by exact host.
- Each fill goes to exactly one document (`documentId`) whose origin matches the item; the content script checks the origin again before filling. A cross-origin iframe only gets a login that matches its own origin.
- On http pages (other than `localhost`) the user must confirm before filling.
- Values are set through the native value setter followed by `input` and `change` events, so React and Vue forms notice.

## Click-jacking

The page controls the iframe element and could make it transparent, cover it or move it under the pointer. Frames use Intersection Observer v2 (`trackVisibility`) and ignore clicks unless they have been visible, unobscured and untransformed for 300 ms. The icon and frames live in a closed shadow root, so page scripts cannot query them.

## Passkeys

The MAIN-world script wraps `navigator.credentials.create` and `get` for `publicKey` requests (conditional mediation stays with the browser) and forwards them through the content script. The service worker checks the RP ID against the frame's origin (see [cryptography.md](cryptography.md#passkeys-implemented)), shows the dialog in the top frame and answers with a credential, an error or "fallback". "Use device or security key instead" and requests Passbox cannot serve (no matching passkey, no ES256, cross-platform attachment requested, calls from iframes, where the browser enforces the `publickey-credentials-*` permissions policy) run the browser's original implementation.

## Permissions

`storage`, `activeTab`, `alarms` (auto-lock, periodic sync), `idle` (lock when the screen locks), content scripts on all http(s) pages (autofill), and optional host permissions for the server. At sign-in the popup requests access to the server's host unless granted access already covers it.

## Known limitations

- Conditional mediation (passkey autofill in username fields) is left to the browser.
- The clipboard is cleared after 90 seconds only while the popup stays open.
- Pending save prompts live in service worker memory and are lost if the worker stops between submit and the next page.
- Tabs opened before the extension was installed need a reload to get the content script.
- Save prompts are only offered while the vault is unlocked.
- Passkeys inside iframes are left to the browser.
