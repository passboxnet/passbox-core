# ADR 0002: MIT License and no feature gating for self-hosters

- Status: Accepted

## Context

The target audience ranges from individuals to large companies. Many of them want to run Passbox themselves. Copyleft or open-core licensing would protect a hosted business but makes adoption harder.

## Decision

All code is released under the MIT License. Self-hosted installations get every feature, including single sign-on, SCIM and administration. Revenue comes from the hosted service only:

| Plan | Monthly | Yearly |
| --- | --- | --- |
| Personal | 1 € per member | 10 € per member |
| Teams | 3 € per member | 30 € per member |

## Consequences

Anyone, including competitors, may host Passbox commercially. In exchange, there is no license friction for users and contributors, and no need for a contributor license agreement. Third-party dependencies must have MIT-compatible licenses.
