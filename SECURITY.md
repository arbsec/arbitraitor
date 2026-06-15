# Security Policy

## Reporting a Vulnerability

**Do not report vulnerabilities through public GitHub issues.**

Use [GitHub private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) to disclose security issues responsibly.

Please include:

- Description of the vulnerability and its impact.
- Steps to reproduce or proof of concept.
- Affected versions or commits.
- Suggested fix if available.

We will acknowledge receipt within 72 hours and aim to provide an initial assessment within 7 days.

## Security Invariants

Arbitraitor enforces the following non-negotiable security invariants. Any change that weakens them will be rejected:

1. **No early release:** No artifact byte reaches a downstream consumer before scanning and policy evaluation complete.
2. **Immutable identity:** Released bytes must hash to exactly the SHA-256 recorded in the verdict.
3. **Single retrieval:** The primary network response is not re-fetched between approval and execution.
4. **Bounded processing:** Every parser, decompressor, scanner, and recursive operation has explicit limits.
5. **Fail closed:** When enforcement is mandatory, inability to complete a required check blocks release.
6. **Plan-bound approval:** Approval binds the full execution plan, not just the artifact digest.

## Supported Versions

| Version | Supported |
|---------|-----------|
| < 1.0   | Security fixes only on latest `main` |

Arbitraitor is pre-1.0. Only the latest `main` branch receives security fixes.
