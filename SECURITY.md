# Security Policy

Security reports help protect WPAuditor users and the wider WordPress community. Please report suspected vulnerabilities privately so they can be investigated and corrected before technical details become public.

## Supported versions

Security updates are provided for the latest published WPAuditor release.

| Version | Security updates |
| --- | --- |
| Latest release | Supported |
| Older releases | Upgrade to the latest release before requesting support |

## Report a vulnerability privately

Email **[almas@wpauditor.app](mailto:almas@wpauditor.app?subject=WPAuditor%20Security%20Report)** with the subject:

```text
WPAuditor Security Report
```

Do not open a public GitHub issue for an unpatched vulnerability. Do not include secrets, private keys, credentials, personal information, live customer data, or destructive payloads in the report.

Please include:

- A concise description of the vulnerability and its likely impact
- The affected WPAuditor version
- WordPress and PHP versions used during testing
- Required roles, permissions, settings, and environment details
- Clear reproduction steps or a minimal proof of concept
- Relevant requests, responses, logs, screenshots, or stack traces with sensitive values removed
- Any suggested mitigation or fix
- Your preferred name and link for acknowledgment, if desired

If an attachment contains sensitive information, first email a short description and ask for an appropriate transfer method.

## What happens after a report

The report will be reviewed to reproduce the issue, determine its severity and affected versions, and prepare a correction when necessary. We aim to acknowledge complete reports within five business days. Complex reports may require additional time, but material status changes will be communicated through the reporting email thread.

Please allow time for investigation and coordinated remediation before publishing details. When appropriate, a release note or security advisory will describe the affected versions, impact, and upgrade guidance without exposing users prematurely.

## Scope

Examples of in-scope issues include:

- Authentication or authorization bypasses
- Missing capability or nonce checks that enable a meaningful attack
- Stored or reflected cross-site scripting
- SQL injection, command injection, unsafe deserialization, or remote code execution
- Arbitrary file reading, writing, uploading, deletion, restoration, or path traversal
- Exposure of logs, quarantine data, recovery values, or other protected information
- Security-control bypasses in Custom Login or API Access Control

Ordinary support requests, hardening recommendations without a demonstrated vulnerability, automated scanner output without validation, social engineering, denial-of-service traffic, and vulnerabilities that exist only in unsupported third-party software should use the normal support channel or the responsible project.

## Testing expectations

Test only on systems you own or have explicit permission to assess. Use the minimum access and data necessary to demonstrate the issue. Do not disrupt production services, access unrelated information, retain personal data, establish persistence, or perform destructive actions.

Good-faith research that follows this policy will be handled cooperatively. This policy does not authorize testing of third-party services, WordPress.org infrastructure, hosting providers, or sites belonging to other users.

## Public disclosure

Coordinate public disclosure through the reporting email thread. Please do not publish exploit details, demonstrations, or scanner output until affected users have had a reasonable opportunity to update.

Thank you for helping improve WPAuditor security.
