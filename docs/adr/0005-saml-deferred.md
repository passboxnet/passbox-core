# ADR 0005: SAML 2.0 is deferred; single sign-on uses OpenID Connect

- Status: accepted
- Date: 2026-10-24

## Context

Wave E4 asks for SAML 2.0 for identity providers without OpenID Connect (older ADFS installations, some public-sector IdPs). Every provider Passbox targets first (Microsoft Entra ID, Google Workspace, Okta, Keycloak, authentik, ZITADEL, and ADFS since Windows Server 2016) also speaks OpenID Connect, which Passbox implements (wave E1, [sso.md](../architecture/sso.md)).

SAML is verified through XML Signature, which needs XML canonicalization (Exclusive C14N) and careful handling of signature wrapping, comments, namespaces and entity expansion. The Rust options in October 2026:

- **`samael`** (MIT) is the only maintained, reasonably complete SAML service provider crate. Signature verification needs its `xmlsec` feature, which links **libxml2, libxmlsec1 and OpenSSL** through C bindings. That breaks the static, OpenSSL-free builds Passbox relies on (musl container, cross-compiled ARM images, `cargo audit` without C advisories to track) and adds two large C libraries with a long history of parser vulnerabilities to the server's attack surface. It has not had an independent security audit.
- Pure-Rust XML parsers (`quick-xml`, `roxmltree`) exist, but there is no audited pure-Rust XML-DSig with canonicalization. Writing one in Passbox would mean owning exactly the code where SAML implementations have failed most often (signature wrapping, CVE-2017-11427 class comment truncation, `xmlsec` key confusion).

## Decision

Passbox does not implement SAML now. Single sign-on is OpenID Connect only. The documentation tells administrators to use their IdP's OIDC support, which also exists in ADFS 2016+ ("application groups").

## How it would be done

When a pure-Rust, audited XML-DSig implementation exists (or a customer funds an audit):

1. Server-side SP in a separate module behind the same `org_sso` configuration (new `protocol` column, `saml` settings: IdP metadata URL or XML, entity ID, ACS URL `{public_url}/api/v1/sso/saml/acs`).
2. SP-initiated flow only (`AuthnRequest` with a random ID stored like OIDC flows, HTTP-Redirect binding), responses via HTTP-POST binding to the ACS.
3. Verify strictly: exactly one assertion, signed (response and/or assertion) with the configured certificate only; reject unsigned assertions, `KeyInfo` certificates that are not configured, DTDs and entities; check `InResponseTo`, `Destination`, `Audience`, `NotBefore`/`NotOnOrAfter`, `Recipient`; map `NameID` (persistent) like OIDC `sub`.
4. Hand the result to the same ticket/proof machinery as OIDC, so `SSO required`, trusted devices and SCIM work unchanged.
5. Test against signature wrapping and comment injection corpora and a real ADFS and Shibboleth instance.

## Consequences

Organizations whose IdP speaks only SAML cannot use Passbox SSO yet; they can still use SCIM provisioning and master-password sign-in. The server keeps a small dependency footprint without C XML libraries.
