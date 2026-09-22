# WPAuditor Screenshot Guide

Store the public GitHub screenshots in this directory using these filenames:

| Filename | Screen | Recommended content |
| --- | --- | --- |
| `dashboard.png` | Dashboard | Event totals, severity summary, threat categories, targeted endpoints, and activity chart. |
| `security-events.png` | Security Events | Filtered events with one sanitized detail panel expanded. |
| `core-integrity.png` | Core File Integrity | A completed scan showing verified files and clearly labeled findings. |
| `file-forensics.png` | File Forensics | Results containing risk, confidence, evidence, hashes, and file context. |
| `quarantine-manager.png` | Quarantine Manager | Sanitized quarantined-file records and available actions. |
| `custom-login.png` | Custom Login | Configuration controls without displaying a real private path or recovery value. |
| `api-access-control.png` | API Access Control | XML-RPC and REST API controls with explanatory text visible. |

Brand artwork in this directory uses `social-preview.png` for repository sharing and `icon-512x512.png` as the high-resolution source icon.

## Capture standard

- Use a consistent viewport, theme, zoom level, and demonstration site.
- Recommended size: 1600 × 1000 pixels or another consistent 16:10 format.
- Crop browser tabs, address bars, bookmarks, operating-system chrome, and unrelated WordPress menus where practical.
- Use realistic demonstration data while removing real domains, usernames, email addresses, IP addresses, filesystem paths, tokens, nonces, cookies, recovery values, and license information.
- Prefer optimized PNG for interface text. Keep each image reasonably small without making text difficult to read.
- Do not alter results in a way that misrepresents the plugin's behavior.

## Suggested alt text

- `dashboard.png`: `WPAuditor WordPress security dashboard with event and threat summaries`
- `security-events.png`: `WPAuditor Security Events activity and suspicious request log`
- `core-integrity.png`: `WPAuditor WordPress Core File Integrity results`
- `file-forensics.png`: `WPAuditor File Forensics inspection results`
- `quarantine-manager.png`: `WPAuditor Quarantine Manager`
- `custom-login.png`: `WPAuditor Custom Login configuration`
- `api-access-control.png`: `WPAuditor REST API and XML-RPC access controls`

The root `README.md` displays these files as a compact gallery.
