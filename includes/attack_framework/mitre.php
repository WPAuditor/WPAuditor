<?php
if (!defined('ABSPATH')) exit; // Block direct access.

// File: mitre.php
// MITRE ATT&CK mapping and severity map for WPAuditor events.

function wpauditor_get_mitre_mapping(): array {
    return [
        // Web attacks.
        'SQL_INJECTION'         => ['tactic' => 'Initial Access', 'technique' => 'T1190'],
        'XSS'                   => ['tactic' => 'Initial Access', 'technique' => 'T1190'],
        'REMOTE_CODE_EXECUTION' => ['tactic' => 'Initial Access', 'technique' => 'T1190'],
        'LFI_RFI'               => ['tactic' => 'Initial Access', 'technique' => 'T1190'],
        'WORDPRESS_EXPLOITS'    => ['tactic' => 'Initial Access', 'technique' => 'T1190'],
        'COMMAND_INJECTION'     => ['tactic' => 'Initial Access', 'technique' => 'T1190'],
        'SSRF'                  => ['tactic' => 'Initial Access', 'technique' => 'T1190'],
        'XXE'                   => ['tactic' => 'Initial Access', 'technique' => 'T1190'],
        'PHP_OBJECT_INJECTION'  => ['tactic' => 'Initial Access', 'technique' => 'T1190'],

        // Credentials and identity.
        'SENSITIVE_FILES'       => ['tactic' => 'Reconnaissance', 'technique' => 'T1595'],
        'LOGIN_FAILED'          => null,
        'BRUTE_FORCE_ALERT'     => ['tactic' => 'Credential Access', 'technique' => 'T1110'],
        'LOGIN_SUCCESS'         => null,
        'PASSWORD_RESET'        => null,
        'ROLE_CHANGE'           => null,

        // Account lifecycle.
        'USER_REGISTER'         => null,
        'USER_DELETED'          => null,

        // Uploads and files.
        'RAW_UPLOAD_ATTEMPT'    => null,
        'FILE_UPLOAD'           => null,
        'SUSPICIOUS_UPLOADS'    => ['tactic' => 'Initial Access', 'technique' => 'T1190'],
        'MEDIA_UPLOADED'        => null,
        'MEDIA_DELETED'         => null,

        // Obfuscation and encoding.
        'OBFUSCATION_ENCODING'  => ['tactic' => 'Stealth', 'technique' => 'T1027'],
        'ENCODED_PAYLOAD'       => ['tactic' => 'Stealth', 'technique' => 'T1027'],

        // Recon and scanning.
        'TOOL_FINGERPRINTS'     => ['tactic' => 'Reconnaissance', 'technique' => 'T1595'],
        'WORDPRESS_RECON'       => ['tactic' => 'Reconnaissance', 'technique' => 'T1595'],
        'UNUSUAL_HTTP_METHOD'   => null,

        // Plugin/theme and site control.
        'PLUGIN_ACTIVATED'      => null,
        'THEME_SWITCH'          => null,
        'PLUGIN_DEACTIVATED'    => null,
        'SETTING_CHANGED'       => null,

        // Content integrity.
        'POST_CREATED'          => null,
        'POST_UPDATED'          => null,
        'POST_DELETED'          => null,

        // Defensive actions.
        'IP_BLOCKED'            => null,
    ];
}

// Get MITRE mapping for a single event key.
function wpauditor_get_mitre_for_event(string $key): ?array {
    $map = wpauditor_get_mitre_mapping();
    if (!array_key_exists($key, $map)) return null;
    return $map[$key];
}

// Build the canonical ATT&CK URL for a technique or sub-technique ID.
function wpauditor_get_mitre_technique_url(string $technique): string {
    $technique = strtoupper(trim($technique));
    if (!preg_match('/^(T\d{4})(?:\.(\d{3}))?$/', $technique, $matches)) return '';

    $url = 'https://attack.mitre.org/techniques/' . $matches[1] . '/';
    if (!empty($matches[2])) $url .= $matches[2] . '/';
    return $url;
}

// Map events to SOC-style severity (INFO/LOW/MEDIUM/HIGH/CRITICAL).
function wpauditor_map_severity(string $key): string {
    $map = [
        'SENSITIVE_FILES'       => 'MEDIUM',
        'SQL_INJECTION'         => 'HIGH',
        'XSS'                   => 'HIGH',
        'REMOTE_CODE_EXECUTION' => 'CRITICAL',
        'LFI_RFI'               => 'CRITICAL',
        'COMMAND_INJECTION'     => 'HIGH',
        'SSRF'                  => 'HIGH',
        'XXE'                   => 'CRITICAL',
        'PHP_OBJECT_INJECTION'  => 'HIGH',
        'WORDPRESS_EXPLOITS'    => 'HIGH',
        'OBFUSCATION_ENCODING'  => 'MEDIUM',
        'ENCODED_PAYLOAD'       => 'MEDIUM',
        'TOOL_FINGERPRINTS'     => 'LOW',
        'WORDPRESS_RECON'       => 'LOW',
        'UNUSUAL_HTTP_METHOD'   => 'MEDIUM',

        'RAW_UPLOAD_ATTEMPT'    => 'MEDIUM',
        'FILE_UPLOAD'           => 'INFO',
        'SUSPICIOUS_UPLOADS'    => 'HIGH',
        'FILE_FORENSICS_SCAN'       => 'INFO',
        'FILE_FORENSICS_SCAN_ERROR' => 'MEDIUM',
        'FILE_MONITORING_SCAN'       => 'INFO',
        'FILE_MONITORING_SCAN_ERROR' => 'MEDIUM',

        'LOGIN_FAILED'          => 'LOW',
        'LOGIN_SUCCESS'         => 'INFO',
        'BRUTE_FORCE_ALERT'     => 'HIGH',
        'PASSWORD_RESET'        => 'MEDIUM',

        'USER_REGISTER'         => 'INFO',
        'ROLE_CHANGE'           => 'MEDIUM',
        'USER_DELETED'          => 'MEDIUM',
        'PROFILE_UPDATED'       => 'INFO',

        'MEDIA_UPLOADED'        => 'INFO',
        'MEDIA_DELETED'         => 'INFO',

        'PLUGIN_ACTIVATED'      => 'INFO',
        'PLUGIN_DEACTIVATED'    => 'INFO',
        'THEME_SWITCH'          => 'INFO',

        'SETTING_CHANGED'       => 'MEDIUM',

        'POST_UPDATED'          => 'INFO',
        'POST_CREATED'          => 'INFO',
        'POST_DELETED'          => 'INFO',

        'IP_BLOCKED'            => 'HIGH',
    ];

    return $map[$key] ?? 'INFO';
}
?>
