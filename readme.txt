=== WPAuditor ===
Contributors: wpalmaszaman
Tags: security, activity log, audit log, file integrity, security scanner
Requires at least: 6.0
Tested up to: 7.1
Stable tag: 1.0.0
Requires PHP: 8.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Monitor security events, detect suspicious requests, verify core files, quarantine threats, and harden WordPress access.

== Description ==

WPAuditor provides security monitoring and investigation tools inside the WordPress administration area. It records important WordPress activity, highlights suspicious requests, checks files, verifies WordPress core integrity, and provides optional access-hardening controls.

WPAuditor Free does not require a license key or an external account.

= Security monitoring =

* Dashboard summaries for security events, severity, source addresses, threat categories, and targeted endpoints.
* Filterable Security Events view with timestamps, event categories, HTTP context, severity, and expandable details.
* Optional live refresh during an active investigation.
* MITRE ATT&CK and OWASP context for supported event types.
* Local logging of successful and failed logins, user and role changes, content changes, media activity, plugin activation or deactivation, and theme changes.
* Detection of suspicious requests associated with common web-application attacks, reconnaissance, sensitive-resource probes, and unsafe uploads.

= File investigation and response =

* File Forensics scans for suspicious uploads and sensitive-file exposure.
* Risk, severity, confidence, evidence, file type, modification time, and file-hash context when available.
* WordPress Core File Integrity checks against official WordPress.org checksums.
* Core results identify verified, modified, missing, unexpected, and unreadable files.
* Quarantine Manager can restore quarantined files or permanently delete them after review.

= Hardening =

* Optional Custom Login path, disabled by default.
* Optional XML-RPC blocking, disabled by default.
* Optional restriction of unauthenticated REST API access and public user endpoints, disabled by default.

= Log management =

* Local log health, size, entry count, and date-range information.
* Download the current event log.
* Manual cleanup by date range or deletion of all logs with confirmation.
* Automatic retention from 30 to 180 days using WordPress scheduled events.

= Important limitations =

WPAuditor Free observes and records suspicious activity. It does not automatically block attacking IP addresses. A detection is an indicator that requires review, not proof of compromise, and a clean scan cannot guarantee that a site is uncompromised.

Quarantining a required plugin, theme, or WordPress core file can break the site. Create a backup and confirm a recovery path before changing files. WPAuditor complements, but does not replace, secure hosting, updates, strong authentication, least-privilege access, and tested off-site backups.

For the complete user guide, see https://wpauditor.app/documentation.html

== Installation ==

1. In WordPress, go to Plugins > Add New > Upload Plugin.
2. Select the WPAuditor ZIP file and choose Install Now.
3. Deactivate WPAuditor Pro if it is active. The Free and Pro editions must not run simultaneously.
4. Activate WPAuditor.
5. Open WPAuditor > Settings and confirm that event logging is active and the WordPress timezone is correct.
6. Open WPAuditor > Dashboard to review activity.
7. Run File Forensics and Core Integrity before enabling optional hardening controls.

The web-server user must be able to write to the WordPress content and uploads locations used for protected log and quarantine storage. WordPress scheduled events must work for automatic log retention. A core integrity scan requires outbound HTTPS access to WordPress.org.

== Frequently Asked Questions ==

= Does WPAuditor Free automatically block attacks? =

No. WPAuditor Free detects and records suspicious activity for administrator review. It does not automatically block source IP addresses.

= Does WPAuditor require an account or license key? =

No. WPAuditor Free works without a license key or external WPAuditor account.

= Does a high-severity event prove that my site was compromised? =

No. Severity helps prioritize review. Investigate the related requests, accounts, files, timing, and actual outcome before taking destructive action.

= Where are events stored? =

Events are stored locally in protected storage within the WordPress content area. They are not sent to WPAuditor. Protect server and downloaded copies because logs can contain personal or confidential information.

= What does a core integrity scan send to WordPress.org? =

Only the installed WordPress version and locale are sent to the official WordPress.org checksum service when an administrator starts a scan. WPAuditor logs, site content, and user data are not included in that request.

= Why did my File Forensics results disappear? =

File Forensics results are intentionally temporary and associated with the administrator who ran the scan. Open File Forensics again to create a fresh result set.

= Should I quarantine every finding? =

No. Legitimate files can match suspicious characteristics. Compare the file with a trusted source, review recent site changes, create a backup, and quarantine only when you understand the impact.

= What happens when I restore a quarantined file? =

WPAuditor attempts to return it to its original location. If another file already exists there, WPAuditor avoids silently overwriting it and restores the item with a distinguishable name for manual review.

= Can Custom Login lock me out? =

An incompatible rewrite, cache, CDN, or security configuration can interfere with a custom login path. Test it in a private browser window before signing out. Store the private recovery information shown by WPAuditor securely and never publish it.

= Can XML-RPC or REST API restrictions break other features? =

Yes. Mobile publishing applications, remote-management services, WooCommerce, headless frontends, page builders, and other integrations may depend on these APIs. Test restrictions on a staging site and restore access if a required integration stops working.

= Can WPAuditor Free and WPAuditor Pro run together? =

No. Deactivate one edition before activating the other.

= What should I do if event logging needs attention? =

Check available disk space, filesystem ownership, and write permissions for the WordPress content area. Review the private server error log and reactivate the plugin after correcting the problem. Do not make the entire WordPress installation world-writable.

== External services ==

WPAuditor Free contacts the WordPress.org Core Checksum API only when an authorized administrator starts a WordPress Core File Integrity scan. The service supplies official file checksums used to compare the installed WordPress core files.

Data sent: the installed WordPress version and locale.

Service endpoint: https://api.wordpress.org/core/checksums/1.0/

WordPress.org privacy policy: https://wordpress.org/about/privacy/

WPAuditor Free does not include analytics, telemetry, advertising, license callbacks, Cloudflare synchronization, AI-provider connections, or an external plugin updater.

== Privacy ==

WPAuditor stores its event log locally. Depending on the activity recorded, logs can contain IP addresses, request URLs, user-agent strings, usernames, content titles, country information when available, and file paths.

Recognized password-like URL parameters, nonces, tokens, API keys, secrets, and Custom Login recovery values are redacted before logging. Redaction reduces risk but cannot guarantee that arbitrary custom application data never contains sensitive information.

Site administrators should:

* Disclose applicable security logging in their privacy notice.
* Select a retention period appropriate for their legal and operational requirements.
* Restrict WPAuditor access to trusted administrators.
* Protect downloaded logs and quarantined files.
* Review logs before sharing them with support or another party.
* Configure equivalent web-access protection when their server does not honor Apache or IIS protection files.

== Third-party libraries ==

WPAuditor includes Chart.js 4.5.1, licensed under the MIT License.

Project and human-readable source: https://github.com/chartjs/Chart.js/releases/tag/v4.5.1

License: https://github.com/chartjs/Chart.js/blob/v4.5.1/LICENSE.md

Country flag PNG images in includes/ui/assets/flags are sourced from Flagpedia.net and released for commercial and non-commercial use as public domain material.

Source and license information: https://flagpedia.net/download

== Screenshots ==

1. WPAuditor security dashboard with activity and threat summaries.
2. Security Events showing WordPress activity and detected requests.
3. WordPress Core File Integrity scan results.
4. File Forensics inspection results.
5. Quarantine Manager for isolated files.
6. Custom Login and API Access Control settings.

== Changelog ==

= 1.0.0 =

* Initial release of WPAuditor Free.
* Added the security dashboard and filterable event viewer.
* Added suspicious-request monitoring and security-framework context.
* Added File Forensics, WordPress Core File Integrity, and Quarantine Manager.
* Added Custom Login and API Access Control.
* Added log download, manual cleanup, and automatic retention settings.

== Upgrade Notice ==

= 1.0.0 =

Initial public release. Back up the site before installation and review all optional hardening controls before enabling them in production.
