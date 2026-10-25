# Security analysis ("Sicherheits-Check")

The security check grades the whole vault and tells users what to fix
first. It goes beyond the classic weak/reused/breached trio: similar
passwords, lookalike (phishing) addresses, missing two-factor sign-in where
the site offers it, unused passkeys, expiring cards and documents, and email
addresses found in breaches. Everything is computed on the device; the few
optional lookups that need a third party go through the user's own server
and never include a password.

## Where it runs

```
 crates/core/src/analysis/           pure logic, no I/O (also built for WebAssembly)
 ├ mod.rs        analyze(items, options) → SecurityReport
 ├ similar.rs    password bases ("Sommer2023!" ≈ "Sommer2024!")
 ├ lookalike.rs  homographs, confusables, typos (check_host)
 ├ domain.rs     URL hosts, punycode (RFC 3492), registrable-domain heuristic
 ├ expiry.rs     expiry dates as people type them
 ├ breaches.rs   breached websites: catalogue, bundled snapshot, matching
 └ sites.rs      bundled 2fa.directory / Passkeys Directory snapshots
        │
        ├── crates/client  security_report(), dismiss_finding(), check_lookalike(),
        │                  breach routing, email monitoring, aliases ──► crates/ffi ──► iOS, Android
        └── crates/core-wasm analyzeSecurity(), checkLookalike(), siteSupport()
                           ──► packages/client securityReport() … ──► web, extension
```

Every client gets the same score and findings because they run the same
engine. The input is the decrypted item JSON (`{ id, createdAt, data }`),
the options and the results of the optional online checks.

## Findings

| Kind | Severity | When | Fix |
| --- | --- | --- | --- |
| `breached` | critical | The password appears in Have I Been Pwned (after a breach check in this session) | change password |
| `exposed_email` | high | Email monitoring found the login's address in a breach **of the same site** | change password |
| `breached_site` | high / medium / low / info | The login's website had a data breach (Have I Been Pwned's public catalogue) that became public **after the password was set** (see [Breached websites](#breached-websites)) | change password, link to the site's `/.well-known/change-password` |
| `lookalike` | high | The login's domain imitates another saved domain or a well-known site | check website |
| `reused` | high | Another login has the same password (groups) | change password |
| `weak` | high | zxcvbn score ≤ 1 (with German words and the account email as context) | change password |
| `similar` | medium | Distinct passwords with the same base, or the password is a small change of an earlier one of the same item | change password |
| `insecure_url` | medium | `http://` (not for IPs and `localhost`) | use https |
| `missing_two_factor` | medium | The site offers TOTP or security keys (2fa.directory) and the login has neither a one-time code nor a passkey | enable 2FA (with the site's instructions) |
| `expired` | medium | A card or document (any field labeled expiry / "Ablauf" / "Gültig bis") is past its date | renew |
| `expiring` | low | … within `expiringWithinDays` (default 60) | renew |
| `old` | low | Password set more than `oldAfterDays` ago (default 365; from the password history, else the creation date) | change password |
| `passkey_available` | low | The site supports passkey sign-in (Passkeys Directory) and the login has none | add passkey |
| `duplicate` | low | Same registrable domain and username (or same card number) in several items | review duplicates |
| `missing_url` | low | A login with a password but no website (no autofill, no phishing protection) | add website |
| `missing_username` | info | A login with a password but no username | add username |
| `totp_in_same_item` | info | Password and one-time code in one item: whoever opens the vault has both factors. A trade-off, shown as a tip, not scored | separate (optional) |

`old` follows NIST SP 800-63B: strong unique passwords do not need periodic
changes, so the finding is low severity and its text says so.

### Score

Every login with a password counts the same (items with other scored
findings count too). An item loses its share by the combined weights of its
open findings, `1 − Π(1 − w)` with critical 1.0, high 0.7, medium 0.35,
low 0.1, info 0; the score is `100 × (1 − Σ loss / items)`, rated excellent
(≥ 90), good (≥ 75), fair (≥ 50) or poor. Each category reports the points
it costs (`categories[].points`), which is the explanation the UIs show
("−18 Mehrfach verwendet"). `fixFirst` lists up to ten items by severity,
then by the points fixing them would gain.

### Dismissals

Dismissing a finding stores its code in the item (`securityIgnore: ["weak"]`),
so it is encrypted and synced like the item and older clients keep it.
Dismissed findings stay listed ("Ausgeblendet") but no longer count. Kinds
can also be turned off entirely per device (web settings; iOS keeps the
password-age limit in `AppSettings`).

## Lookalike detection (G17)

- **Homographs:** IDN labels are decoded from punycode and folded with a
  table of look-alike characters (Cyrillic, Greek, accented Latin, `0`/`o`,
  `1`/`l`, `rn`/`m`, `vv`/`w`, `cl`/`d`). Two different domains with the same
  "skeleton" read the same.
- **Mixed scripts:** a label mixing Latin with Cyrillic or Greek letters.
- **Typos:** one insert, delete, replace or swap from a saved domain with the
  same ending and a first label of at least five letters. The same name with
  another ending (`amazon.de`, `amazon.com`) is not flagged.
- **Well-known sites:** skeleton matches against the ~2,800 domains of the
  bundled directories (no typo matching there, to keep false alarms low).

The browser extension calls `checkLookalike(host)` when the inline menu
opens on a page **without** a matching login and when the save banner
appears; it then warns "Vorsicht: Das ist nicht paypal.com" and fills
nothing. The analysis flags saved logins whose own domain is a lookalike.
The registrable-domain heuristic in the core knows common two-level
suffixes and hosting platforms; the extension still matches logins with the
full Public Suffix List.

## Third-party data and what leaves the device

| Feature | What is sent | To whom | When |
| --- | --- | --- | --- |
| Analysis, similar passwords, lookalikes, expiry, duplicates | nothing | – | always local |
| 2FA / passkey hints | nothing (bundled snapshots, MIT and CC BY 4.0, see [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md); `scripts/update-site-directories.py` refreshes them) | – | always local |
| Leaked passwords (G6) | first 5 hex characters of each password's SHA-1 | the user's Passbox server, which asks `api.pwnedpasswords.com` with `Add-Padding: true` (default) – or Have I Been Pwned directly | only after the user starts the check |
| Email monitoring (G11) | the email addresses the user confirmed | the Passbox server, which sends them to `haveibeenpwned.com` with the operator's API key | after opt-in and confirmation by code, then every `PASSBOX_HIBP_CHECK_HOURS` |
| Email aliases (G10) | the website's domain as a note; the API key | the alias provider chosen by the user, directly from the device | when the user presses "Alias erstellen" |
| Breached websites | **nothing new**: the app downloads the same public catalogue as everyone else (`GET /api/v1/breaches/catalog`, no session) and matches it on the device | – (the server fetches the public list from Have I Been Pwned on its own schedule) | at unlock and every few hours |
| Organization report of breached websites | per breach title: logins in the organization's vaults still open and fixed (counts, no item IDs; sensitive breaches never) | the user's Passbox server, inside the existing security aggregate | at most daily, members of team organizations |

Nothing in this feature sends a password, a TOTP secret or a vault item to
a model or service (data class D4 in `docs/planning/ai-native.md` stays on
the device).

### Breach routing

Clients choose `auto` (default: through the Passbox server when
`/api/v1/meta` says `breachProxy: true` / the endpoint exists, otherwise
directly), `server` (never directly; fails if the server does not offer it)
or `direct`. The server proxy:

- `GET /api/v1/breach/range/{prefix}` with a session, 5 hex characters only;
- fetches the padded range (so the response size does not reveal matches),
  caches it in memory for 24 hours (2,048 prefixes), answers
  `Cache-Control: private, no-store`;
- 3,000 prefixes per account and hour; `PASSBOX_BREACH_PROXY=off` disables it.

The server learns which hash prefixes an account asked for. Each prefix is
shared by hundreds of passwords; we accept that in exchange for hiding users'
IP addresses from Have I Been Pwned.

### Email monitoring

`/api/v1/breach/emails` (list, add), `/{id}/verify`, `/{id}/check`,
`DELETE /{id}`. Adding mails a 6-digit code (30 minutes, 5 attempts, one
per minute, 10 per hour) to the address itself; only confirmed addresses
are ever sent to Have I Been Pwned. The first check runs at confirmation and
is shown, not mailed; later checks mail new breaches to the account owner
(`breach_monitor_alert`). Tables `breach_monitor_emails` and
`breach_monitor_results` (migration 0012) hold only addresses, breach
metadata and timestamps. The analysis turns results into `exposed_email`
findings for logins of the breached site that use the address.

### Breached websites

1Password calls it "compromised websites": the site of a saved login had a
data breach, and the password was not changed since. Passbox does this
without the server learning which sites anyone uses.

- **Catalogue.** The server fetches Have I Been Pwned's public breach list
  (`https://haveibeenpwned.com/api/v3/breaches`, no API key, CC BY 4.0) every
  `PASSBOX_BREACH_CATALOG_HOURS` (6) in the `worker:breach_catalog` job,
  with `If-None-Match` when Have I Been Pwned sent an `ETag`, and stores
  every entry with its flags in `site_breaches` (migration 0004; global,
  readable in every context, written only by the job). `GET
  /api/v1/breaches/catalog` serves the entries clients match against (a
  domain; not fabricated, not a spam list, not retired; sensitive ones
  flagged) with name, title, domain, dates, account count, data classes
  and flags, as one document with a strong `ETag` (its version, a hash of
  the content), gzip and `Cache-Control: public, no-cache`;
  `/catalog/version` is the cheap check. Everyone gets the same bytes,
  without a session. `PASSBOX_BREACH_CATALOG=off` (air-gapped servers)
  turns job and endpoints off.
- **Bundled snapshot.** `crates/core/data/site-breaches.tsv`
  (`scripts/update-breach-catalog.py`, same filter) is used until a client
  has downloaded a newer catalogue, offline, and with the catalogue off.
- **Matching** (`analysis::breaches`, all clients through the core): a
  login with a password and an http(s) website matches a breach when its
  registrable domain equals the breach's (a breach of a subdomain such as
  `forum.example.com` matches only that host and its children). When the
  current password was set is the newest password-history entry, else the
  item's creation date. Set before the breach was **published**
  (`AddedDate`) → affected; unknown → possibly affected; set after it on
  an item created before it → fixed (and resolved automatically); item
  created after it → not affected. The publication date is used instead
  of the breach date because breach dates are approximate and data is
  usually exposed until the breach is discovered. Limit: an imported
  item's creation date is the import, so an old password imported after
  a breach is not flagged.
- **Severity.** Passwords or other sign-in secrets exposed (`Passwords`,
  `Password hints`, `Historical passwords`, `Auth tokens`, security
  questions, PINs): high, possibly affected medium. Only other data
  (emails, names): low, possibly affected info (a tip, not scored).
  Findings carry `breaches` (titles), `breachNames`, `breachDate`,
  `dataClasses`, `possibly` and the site's change-password URL; the
  report's `breachedSites` lists each breach with the affected, possibly
  affected and fixed item IDs, `breachCatalog` the catalogue used.
- **Notifications** without server knowledge. Clients check the version
  at unlock and every six hours, download a newer catalogue and call
  `breachAlerts()`: open, not dismissed breaches published after the last
  acknowledged catalogue (initially the bundled snapshot's date, so old
  breaches show in the check but are not announced). Web: a banner and,
  once allowed, a browser notification while the tab is hidden; desktop: a
  system notification (Tauri notification plugin); extension: badge and
  notification; iOS: local notification from a `BGAppRefreshTask` or at
  unlock/activation, count on the tab; Android: JobScheduler job every six
  hours, notification (Android 13+ asks), count on the tab. Matching needs
  the decrypted vault, so background runs with a locked vault only
  download the catalogue; the alert follows at the next unlock. Sensitive
  breaches are never named in notifications. Email alerts stay with the
  opt-in email monitoring (G11): only confirmed addresses Have I Been
  Pwned reports for a breach are mailed.
- **Organizations.** Members' apps add per-breach counts of the logins in
  that organization's vaults (open, fixed; sensitive breaches left out) to
  the daily security aggregate (`siteBreaches` in `PUT
  /orgs/{id}/security-report`, stored in `org_security_reports`); admins
  see "12 Mitglieder betroffen, 8 behoben" per breach title in Reports.
  Personal vaults are never included.
- **Attribution.** Every UI that shows breach data names Have I Been Pwned
  with a link and the license (THIRD_PARTY_NOTICES.md).

### Email aliases (G10)

Providers: SimpleLogin, addy.io (both also self-hosted), Fastmail Masked
Email (JMAP), DuckDuckGo Email Protection, Firefox Relay. The API key is a
vault item (category "other", tag `alias-service`, fields `alias_provider`,
`alias_api_key`, optional `alias_base_url`, `alias_domain`), so it is
end-to-end encrypted and synced. Requests go from the device to the provider
over HTTPS; the Passbox server is not involved. Some providers do not allow
requests from web pages (CORS); the web generator then explains that the
extension or desktop app works.

## APIs

| | Call |
| --- | --- |
| Rust | `client.security_report(&ReportOptions)`, `dismiss_finding(id, kind, dismissed)`, `check_lookalike(host)`, `set_breach_mode(BreachMode)`, `email_monitoring()`, `add/verify/check/remove_monitored_email`, `alias_services()`, `add_alias_service(…)`, `create_alias(service_item, domain)` |
| FFI | `securityReport(options)`, `dismissFinding(itemId, kind, dismissed)`, `checkLookalike(host)`, `setBreachMode("auto"/"server"/"direct")`, `emailMonitoring()`, …, `defaultSecurityReportOptions()`; kinds, severities and fixes are string codes |
| WebAssembly | `analyzeSecurity(itemsJson, optionsJson)` (`siteBreaches` in the options), `bundledBreachCatalog()`, `checkLookalike(host, savedJson)`, `siteSupport(host)` |
| TS | `client.securityReport(options)`, `dismissFinding`, `checkLookalike`, `breachMode`, `checkBreachedItems(fetch?, onProgress?)`, `emailMonitoring()`, …, `createAlias` |

The older `health()` / `itemHealth()` stay for the per-item card and the
organization security aggregate.

## UIs

- **Web:** the Security check is a dashboard: score ring with what costs
  points, the breach check (with the route it takes), "Fix these first",
  category cards with drill-down (details, instructions link, fix button,
  Dismiss with Undo), dismissed findings, email monitoring and settings
  (route, password age, expiry warning, optional kinds). The generator has
  "Email alias".
- **Extension:** lookalike warning in the inline menu and the save banner.
- **iOS / Android:** the Sicherheits-Check shows the score with its reasons,
  "Zuerst beheben" and "Weitere Prüfungen" with a list per kind (swipe or
  button to dismiss and show again).

## Tests

- `cargo test -p passbox-core analysis` – engine, punycode, lookalikes,
  similar passwords, expiry dates, directories.
- `cargo test -p passbox-server --test api` – proxy (cache, validation, off
  switch) and monitoring (codes, isolation, periodic check, alert mail) with
  a fake Have I Been Pwned, on PostgreSQL.
- `cargo test -p passbox-client --test analysis` – report, dismissals, proxy
  routing and monitoring end to end; alias providers with a recording
  transport.
- `packages/client/src/analysis.test.ts`, extension `autofill.test.ts`,
  `e2e/tests/security.spec.ts`, PassboxKit `SecurityAnalysisTests`, Android
  `SecurityAnalysisTest` and the FFI integration test.
- Breached websites: core `breaches.rs` and `tests.rs` (dates, subdomains,
  password changed after the breach, unknown dates, severity, bundled
  snapshot); server `breach_catalog` in `tests/api/breach.rs` (fake Have I
  Been Pwned, filter, `ETag`/304, gzip, versions across instances,
  failures, off switch, row level security) and the organization counts in
  `tests/api/org_admin.rs`; client `breached_websites_from_the_server_catalogue`;
  TS `analysis.test.ts` and `breaches.integration.test.ts`; extension
  `breaches.test.ts`; `e2e/tests/breaches.spec.ts` (fake catalogue → banner
  and finding → new password → resolved); PassboxKit `BreachedSitesTests`;
  Android `breachedSitesExplainTheFinding` and the FFI integration test.
