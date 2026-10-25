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
| Two-factor sign-in | Zwei-Faktor-Anmeldung |
| Authenticator app | Authenticator-App |
| Security key | Sicherheitsschlüssel |
| Recovery code | Wiederherstellungscode |
| Account recovery code (Emergency Kit, `R1-…`) | Wiederherstellungscode für das Konto; where it could be mixed up with the two-factor codes: Zwei-Faktor-Wiederherstellungscode |
| Recovery through the organization | Wiederherstellung über die Organisation |
| Request code (compared by phone) | Anfragecode |
| Emergency access / Emergency contact | Notfallzugang / Notfallkontakt |
| Waiting period | Wartezeit |
| Add a device / Sign in with another device | Gerät hinzufügen / Mit einem anderen Gerät anmelden |
| Device code | Gerätecode |
| Remember this device | Dieses Gerät merken |
| Organization / Family / Team | Organisation / Familie / Team |
| Family & team (navigation) | Familie & Team |
| Organizer (family owner) / Owner (team) | Organisator / Eigentümer |
| Admin (team) / Co-organizer (family) | Administrator / Mitorganisator |
| Member / Family member / Guest | Mitglied / Familienmitglied / Gast |
| Invitation / Invite | Einladung / Einladen |
| Role | Rolle |
| Shared vault / Family vault | Geteilter Tresor / Familien-Tresor |
| Group | Gruppe |
| View / Edit / Manage (vault permissions) | Ansehen / Bearbeiten / Verwalten |
| Security code (fingerprint) | Sicherheitscode |
| Confirm (a member) | Bestätigen |
| Pause access / Lift pause | Zugriff pausieren / Pause aufheben |
| Developer (navigation) | Entwickler |
| Service account / Token | Dienstkonto / Token |
| Environment (item category, `.env` variables) | Umgebung |
| AI agent | KI-Agent |
| Approve / Deny (agent request) | Freigeben / Ablehnen |
| Revoke | Widerrufen |
| AI features / Model | KI-Funktionen / Modell |
| On this device / Your own server / Cloud provider (where a model runs) | Auf diesem Gerät / Eigener Server / Cloud-Anbieter |
| AI log | KI-Protokoll |
| Your plan (security copilot) | Ihr Plan |
| Urgent / Important / Recommended / When you have time | Dringend / Wichtig / Empfohlen / Wenn Sie Zeit haben |

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
