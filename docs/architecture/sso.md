# Single sign-on, trusted devices and provisioning

> **Draft.** Not reviewed by cryptographers and not audited. Formats may still change before the first release that ships them.

This document describes waves E1 (sign-in with OpenID Connect), E2 (unlocking with SSO on trusted devices), E3 (SCIM 2.0 provisioning) and E4 (SAML, deferred: [ADR 0005](../adr/0005-saml-deferred.md)) as implemented. The planning sketch is in [docs/planning/feature-gap.md](../planning/feature-gap.md) §5.6 (German); where this document differs, this document is what the code does. Setting it up per identity provider: [self-hosting.md](../self-hosting.md#single-sign-on-sso).

| Part | Code |
| --- | --- |
| ID token verification, PKCE (feature `oidc`, server only) | [`crates/core/src/oidc.rs`](../../crates/core/src/oidc.rs) |
| Trusted device keys and grants | [`crates/core/src/trusted_device.rs`](../../crates/core/src/trusted_device.rs), WebAssembly in [`crates/core-wasm`](../../crates/core-wasm/src/lib.rs) |
| Server | [`crates/server/src/api/sso`](../../crates/server/src/api/sso) (`mod.rs` configuration, `oidc.rs` provider HTTP, `login.rs` flow and policy, `devices.rs` trusted devices), [`crates/server/src/api/scim`](../../crates/server/src/api/scim), migration [`0001_baseline.sql`](../../crates/server/migrations/0001_baseline.sql) |
| TypeScript client | [`packages/api-client/src/sso.ts`](../../packages/api-client/src/sso.ts), [`packages/client/src/sso.ts`](../../packages/client/src/sso.ts), `PassboxClient` (`ssoFor`, `startSso`, `redeemSso`, `signIn`/`unlock` with `ssoProof`, `unlockWithSso`, `trustThisDevice`, `approveDevice`, `requestDeviceApproval`, `checkDeviceApproval`, `sso`) |
| Web | [`apps/web/src/sso`](../../apps/web/src/sso): sign-in option, callback screen (`#/sso`), trusted devices in Settings, organization settings (`#/org-sso/{id}`) with SCIM |

## What SSO does and does not do

SSO proves **who someone is**. It never gives the server anything that decrypts data. Passbox stays end-to-end encrypted:

- **Without a trusted device**, an SSO sign-in yields a single-use *proof*. The client still runs the normal OPAQUE login with the master password and the Secret Key (on a new device) and sends the proof along. The organization's identity provider is then an additional gate, not a replacement for the master password.
- **On a trusted device (E2)**, the proof unlocks the account key that was sealed to that device's key. No master password is typed; the account key is then protected by the device key and the identity provider instead of Argon2id and the Secret Key. Organizations opt in to this.

## Configuration (per organization)

Owners and admins of a **team** organization configure one OIDC provider (`PUT /api/v1/orgs/{id}/sso`):

| Setting | Notes |
| --- | --- |
| issuer, client ID, client secret | The secret is encrypted with the server key `sso_key` (XChaCha20-Poly1305, associated data `passbox/v1/server/sso-client-secret|{org_id}`) and never returned. Like the two-factor key, `sso_key` sits in `server_secrets`: it protects against leaks of single tables or exports, not a full database copy. |
| token endpoint authentication | `client_secret_basic` (default), `client_secret_post` or `none` (public client; PKCE protects the code) |
| scopes, claims | `openid` is required; email, name and groups claims are configurable (dotted paths such as `realm_access.roles` work); `require_verified_email` (default on) requires `email_verified: true` |
| email domains | Each domain belongs to **one** organization on the instance while SSO is enabled (409 `sso_domain_taken` otherwise). Domain ownership is not verified (wave D7); on a shared instance the first organization claiming a domain gets it. A claimed domain only decides which sign-in is *offered*; it never signs in accounts that are not members of the organization. |
| `required` | Members (role `member`) must sign in with SSO; owners and admins can always use the master password, so a broken provider cannot lock the organization out. |
| `allowDeviceUnlock` | Members may trust devices (E2). |
| `reauthHours` (1–720, default 12) | How long a device that signed in with SSO is remembered for the `required` policy. |

Enabling fetches `{issuer}/.well-known/openid-configuration` and the JWKS and caches both. The discovery document's `issuer` must match what was entered (a trailing slash is forgiven; the document's value is stored and ID tokens must name it exactly), all endpoints must be `https://`, and the provider must offer an asymmetric ID token algorithm and S256 PKCE. Changing the issuer deletes the links to provider accounts.

**Checks for admins:** `POST …/sso/check` fetches discovery and JWKS and returns only parsed fields (endpoints, number of keys, algorithms) or an error code, never response bodies. `POST …/sso/test/start` + `…/test/result` run a real sign-in in a popup (`prompt=login`) and show the claims the provider sent and whether a real sign-in would succeed, without signing in or linking anything.

## The sign-in flow (E1)

```text
browser tab                      server                                 identity provider
  │ POST /sso/discover {email}     │  domain → organization (no account lookup)
  │ POST /sso/start {orgId}        │  state, nonce, PKCE verifier stored (10 min, single use);
  │ ◀── authorizationUrl, flowSecret   SHA-256(flowSecret) stored with the flow
  │ ── redirect ──────────────────────────────────────────────────────────▶  sign-in
  │                                │ ◀── GET /sso/callback?code&state ─────
  │                                │ ── POST token (code, verifier, client auth) ─▶
  │                                │ ◀── ID token: signature (JWKS) and claims checked in the core
  │ ◀── 303 {PASSBOX_PUBLIC_URL}/#/sso?ticket=…  (or ?error=<code>)
  │ POST /sso/redeem {ticket, flowSecret}   ticket: 5 min, single use, bound to the flow secret
  │ ◀── proof (10 min, single use) or status "no_account"
  │ OPAQUE login …/login/finish {ssoProof}   or   POST /sso/unlock {proof, deviceId}
```

- **ID token checks** (`passbox_core::oidc::verify_id_token`, OpenID Connect Core §3.1.3.7): only `RS256/384/512`, `PS256/384/512`, `ES256`, `ES384` (never `none` or HMAC); RSA keys of at least 2048 bits; the key is picked by `kid` (an unknown `kid` refetches the JWKS, at most six times a minute per organization; the cache is refreshed after an hour); `iss` exact; `aud` contains the client ID and `azp` equals it when present or when there are several audiences; `exp`, `iat` (at most 15 minutes old) and `nbf` with 2 minutes of clock skew; `nonce` equal (constant time); `sub` present. Tokens and JWKS are size limited. The ID token comes straight from the token endpoint over TLS and is verified anyway.
- **Mapping to an account:** a provider identity is linked by `(organization, issuer, sub)`. The first sign-in links by email: the email must be verified (unless the setting is off), its domain allowed, an account with that email must exist and be a member of the organization (not suspended). Later sign-ins use only the subject, so changing the email at the provider cannot move a link to another account. An account that is invited but not yet a member (for example provisioned by SCIM) joins on its first SSO sign-in: the invitation is accepted, and the member waits for confirmation like any other.
- **Why the ticket and the flow secret:** the redirect target is always the server's public URL, never a client-supplied address. The ticket only works together with the flow secret the starting tab kept in `sessionStorage`, so a ticket that ends up elsewhere (forwarded link, browser history, someone starting a flow and luring a victim through the provider) cannot be redeemed. The ticket travels in the URL fragment, which browsers do not send to servers or in `Referer`.
- **No account yet:** `redeem` answers `no_account` with the verified email; the web app explains how to create the account first. Just-in-time account creation is not implemented, because an account needs a master password and Secret Key created on the device.
- **`SSO required` at `login/finish`:** if the account is a `member` of an organization that requires SSO, a password login without a valid proof fails with `sso_required`, unless the device token presented at `login/start` signed in with SSO within `reauthHours` (`device_tokens.sso_until`, carried over when the token rotates). With several organizations requiring SSO, a proof from any of them satisfies the policy.
- **Second factor:** a login with a fresh or remembered SSO sign-in skips Passbox's own two-factor step. The identity provider is the authority for multi-factor authentication in that case; enforce MFA there.
- **Errors** end as `#/sso?error=<code>` (codes in `apps/web/src/sso/messages.ts`); provider responses are never shown or logged in full.

## Trusted devices (E2)

```text
device key  = X-Wing key pair (seed kept on the device)
sealed      = Seal(device_pk, account_key, purpose "trusted-device", context (account_id, device_id))
grant       = { account_id, device_id, device_key_hash, sealed_hash, approved_by, approved_at }
              signed with the account's Ed25519 key  (type tag passbox/v1/trusted-device-grant)
code        = 4 groups of five digits from SHA-256("passbox/v1/trusted-device-code\0" || device_pk)
```

- **Trusting this device:** an unlocked device (login in the last 10 minutes) creates a key pair, seals the account key to it and signs the grant (`approved_by` empty). The server checks the grant against the account's published key, the device key and the sealed bytes (`POST /account/trusted-devices`); the organization must allow it. At most 20 per account.
- **Unlocking:** after an SSO sign-in, `POST /sso/unlock {proof, deviceId}` returns a session and the sealed key with the grant and the account's key pairs. The core opens the account key with the device key, checks the grant (account, device, key hash, sealed hash), checks that the account key opens the account's key pairs, and that the grant is signed by the account's own signing key. A server can therefore neither hand a device a different key nor create a trusted device on its own.
- **A new device:** after an SSO sign-in it creates a key pair and asks for approval (`POST /sso/device-requests`, 30 minutes, at most 5 open per account). It shows the code of its public key. A device of the account that is unlocked (Settings → Trusted devices → Review) computes the code from the public key the server relays; the user compares them and approves, which seals the account key and signs the grant (`approved_by` = the approver's device ID). A server that swapped in its own key would have to find a key with the same 66-bit code within the request's lifetime. The waiting device polls with its request token and receives the session and the sealed key once. This is the same pattern as the device codes (C4) and the recovery request code (C1).
- **Admin path:** a member who lost all trusted devices and the master password uses organization recovery (C1); after setting a new master password the device can be trusted again.
- **Removing:** Settings → Trusted devices → Remove deletes the server's sealed copy; the device then needs the master password (and Secret Key). SCIM deprovisioning deletes all trusted devices of the account.
- **Browser storage:** the web app keeps the seed encrypted with an AES-GCM key that WebCrypto creates as **non-extractable**, both in IndexedDB (`apps/web/src/sso/deviceStore.ts`). The seed is decrypted into JavaScript memory briefly when unlocking (to pass it to WebAssembly).
- **Account without Secret Key on the device:** a device approved by another device never learns the Secret Key; it unlocks with SSO only (the unlock screen then offers only SSO). Signing in with the master password there needs the Emergency Kit.

### Threat model of SSO unlock

| An attacker who has … | can … |
| --- | --- |
| only the server or its database | nothing new: sealed keys need a device key; client secrets are encrypted (but see `sso_key` above) |
| control of the identity provider (or a provider admin) | sign in as any member, but decrypt only with a member's trusted device or master password. They *can* request device approval; the member must compare the code and approve. |
| a trusted device (unlocked computer, or a copy of the browser profile) **and** the member's identity provider account | unlock the vault. This is the accepted trade of SSO unlock (as with 1Password and Bitwarden trusted devices). In the browser the device key is not hardware-bound: non-extractable WebCrypto keys protect against scripts copying the key out, not against someone with access to the profile on disk. Organizations that need more should not enable SSO unlock, or use native apps with hardware-backed keys once available. |
| script running on the Passbox origin (XSS) while unlocked | already everything (as without SSO); while locked, it could use the WebCrypto key to decrypt the seed, but still needs a fresh SSO sign-in to get the sealed account key |
| a malicious server | relay a fake device request (the user must compare the code), withhold or delay unlocks, see metadata (who trusted which device when, IP addresses) |

Without the master password, the protection by Argon2id and the Secret Key does not apply on that path. That is a deliberate choice an organization makes with `allowDeviceUnlock` and is explained in the settings.

## Provisioning with SCIM 2.0 (E3)

Base URL `{PASSBOX_PUBLIC_URL}/api/v1/scim/v2`, authenticated with a bearer token per organization (`pbx_scim_…`, 256 bits, only the SHA-256 hash is stored, 1–730 days, at most 10 per organization, created by an owner or admin with a recent login, 600 requests per minute). The web app flags tokens that expire within 14 days.

Supported (RFC 7643/7644): `ServiceProviderConfig`, `ResourceTypes`, `Schemas`; `Users` and `Groups` with `GET` (list with `filter`, `startIndex`, `count` ≤ 200), `POST`, `GET /{id}`, `PUT`, `PATCH` (`add`, `replace`, `remove`, with and without `path`, value filters such as `emails[type eq "work"].value` and `members[value eq "…"]`, case-insensitive operation names and `"True"`/`"False"` strings as Microsoft Entra ID sends them), `DELETE`. Filters: `eq`, `ne`, `co`, `sw`, `ew`, `gt`/`ge`/`lt`/`le`, `pr`, `and`, `or`, `not`, parentheses. Errors use the SCIM error schema with `scimType`. Not supported: bulk, sorting, `/Me`, password changes, enterprise extension attributes (accepted and ignored).

What a user resource does in Passbox:

- **Create or activate:** if the email belongs to a member, the SCIM user is linked. Otherwise the server creates an organization invitation (30 days) and mails it. The person joins by accepting it, or by signing in through the organization's SSO, which accepts it. Then they are **pending confirmation**: an admin's unlocked client must check their key and seal the organization key for them, which the server cannot do. The SSO settings page lists these people with a **Confirm** button. Invitations created by provisioning carry no organization fingerprint in the link (the admin client did not create them), so the invitee trusts the organization's key on first use.
- **Deactivate (`active: false`) or `DELETE`:** the membership is suspended (the server stops serving the organization's vaults) and every session, device token (with remembered SSO and two-factor sign-ins), SSO proof, trusted device and device request of the account is deleted right away. Pending invitations are revoked. Reactivation restores the status the member had. `DELETE` also forgets the SCIM user; removing the member (with vault key rotation) is left to an admin, because rotation needs an admin client. The owner cannot be deactivated (`mutability`).
- **Groups** are stored with their members and shown to admins. Passbox groups hold sealed keys, so adding directory group members to Passbox groups needs an admin client and is not automatic yet.

`userName` is unique per organization (case-insensitive). A user's email is the primary `emails` value, or `userName` when it is an email.

## Server storage and limits

Migration `0001_baseline.sql`: `org_sso`, `sso_domains`, `sso_identities`, `sso_flows` (10 minutes), `sso_tickets` (5 minutes), `sso_proofs` (10 minutes), `device_tokens.sso_until`, `trusted_devices`, `trusted_device_requests`, `scim_tokens`, `scim_users`, `scim_groups`, `scim_group_members`. Secrets in flight (state, tickets, proofs, request tokens, SCIM tokens) are stored as SHA-256 hashes. The tables have forced row level security ([database-security.md](database-security.md)).

Talking to the provider: `ureq` with rustls and the platform certificate store on the blocking pool, 10 second timeout, no redirects, 256 KiB response limit. Only `https://` URLs (plus `http://` on `localhost`/`127.0.0.1`/`[::1]` when `PASSBOX_SSO_ALLOW_HTTP_LOOPBACK=1`, for development). Because organization admins choose the issuer URL, the server makes outbound requests on their behalf; it never returns response bodies, and the connection check is rate limited. On shared instances, restrict outbound traffic of the server at the network level if internal https services must not be probed.

Rate limits: `discover`, `redeem`, `unlock` and `device-requests` share the per-IP authentication limit; `start` 30 per IP and minute; the callback 60 per IP and minute; status polls 120 per IP and minute.

Events (`account_events`): `sso_authenticated`, `login_sso`, `login_sso_device`, `org_sso_updated`, `org_sso_removed`, `trusted_device_added`, `_removed`, `_requested`, `_approved`, `_denied`, `org_scim_token_created`, `_revoked`, `org_membership_deprovisioned`.

## Tests

- Core: RFC 7636 PKCE vector; RS256 and ES256 tokens; `none`, HMAC and unknown algorithms; wrong `kid`, key type, issuer, audience, `azp`, expiry, `iat`, `nbf`, nonce and `sub`; tampered payloads; JWKS parsing (`oidc::tests`). Trusted devices: unlock, approval by another device, foreign keys, grants and key pairs (`trusted_device::tests`).
- Server: `crates/server/tests/api/sso.rs` against an in-process mock provider (discovery, JWKS, token endpoint checking client authentication and PKCE, signed ID tokens): configuration and secrets, domain claims, discovery, the full flow, flow secret binding, single-use state and proofs, every rejection case, subject linking, `SSO required` with remembered devices, the connection test, trusted devices and approvals, SCIM (filters, paging, uniqueness, PATCH in Okta and Entra style, deprovisioning ending sessions, reactivation, groups, owner protection, token revocation) and SSO accepting a provisioned invitation.
- Web: `e2e/tests/sso.spec.ts` runs its own server and a mock provider: setup, connection check, test sign-in in a popup, SCIM token and a provisioned person, sign-in with SSO on a new device, trusting the browser and unlocking with SSO only.

## Not done yet

- **Native clients** (desktop app, extension, CLI, iOS, Android): the Rust client and FFI have no SSO calls yet. They need a loopback or custom-scheme redirect (RFC 8252) instead of `#/sso` on the server's origin, and hardware-backed device keys: Secure Enclave or Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` on Apple platforms, Android Keystore (StrongBox where available), TPM or the platform keystore on desktop. The core API (`TrustedDeviceKey`, `Keyring::trust_device`) is ready; the server endpoints are client-agnostic.
- WebAuthn PRF as the browser device key (hardware-bound where the authenticator supports it).
- Just-in-time account creation, mapping directory groups to Passbox groups, an optional confirmation service that confirms provisioned members automatically (planning §5.6), SAML (ADR 0005), domain verification (D7).
