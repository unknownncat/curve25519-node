# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 2.x     | Yes       |
| < 2.0.0 | No        |

## Reporting a Vulnerability

Please use GitHub private vulnerability reporting whenever possible:

1. Go to the repository `Security` tab.
2. Click `Report a vulnerability`.
3. Submit impact details and a minimal proof-of-concept.

If private reporting is not available, open a public issue without sensitive details and request private contact.

## Scope

- Cryptographic flaws, incorrect input validation, and integrity/confidentiality issues are high priority.
- Include package version, runtime environment, and reproducible steps.

## Maintainer Security Checks

Before publishing a release, run:

```bash
npm run ci
npm run audit
npm run audit:prod
npm run release:check
```
