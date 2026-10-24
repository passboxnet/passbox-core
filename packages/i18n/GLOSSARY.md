# Glossary

German copy uses the formal "Sie" everywhere. Use these terms in every
client (web, desktop, extension, iOS, Android) and on the website.

| English | German |
|---|---|
| Vault | Tresor |
| Item / All items | Eintrag / Alle Einträge |
| Login (category) | Anmeldung |
| Secure note | Sichere Notiz |
| Credit card | Kreditkarte |
| Identity | Identität |
| Master password | Master-Passwort |
| Secret Key | Geheimschlüssel |
| Emergency Kit | Notfall-Kit |
| One-time password / 2FA | Zwei-Faktor-Code (2FA) |
| Watchtower / Security check | Sicherheits-Check |
| Weak / Reused / Unsecured website | Leicht zu erraten / Mehrfach verwendet / Unsichere Verbindung |
| Unlock / Lock | Entsperren / Sperren |
| Sign in / Sign out | Anmelden / Abmelden |
| Create account | Konto erstellen |
| Trash | Papierkorb |
| Restore / Undo | Wiederherstellen / Rückgängig |
| Previous passwords | Frühere Passwörter |
| Devices | Geräte |
| Activity | Aktivität |
| Auto-lock | Automatisch sperren |
| Password generator | Passwort-Generator |
| Favorites | Favoriten |
| Fill / Save to Passbox? / Not now | Ausfüllen / In Passbox speichern? / Jetzt nicht |
| Passkey | Passkey |

Plain language first: no "OPAQUE", "ciphertext", "revision", "account ID"
or "otpauth://" in default screens. Technical details go behind a
"Technical details" / "Technische Details" disclosure.

## Catalog layout

- `messages/<locale>/common.json`: actions, terms, strength and error
  messages shared by all clients.
- `messages/<locale>/<app>.json`: one namespace per app (`web`,
  `extension`, `website`). Keys are `area.thing`, for example
  `unlock.forgotPassword`.
- iOS (`Localizable.xcstrings`) and Android (`values-de/strings.xml`) keep
  native resources but use the same terms.
