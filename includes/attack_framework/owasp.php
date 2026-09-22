<?php
if (!defined('ABSPATH')) exit; // Block direct access.

// OWASP Top 10:2025 metadata and deterministic event mappings.
function wpauditor_get_owasp_2025_categories(): array {
    return [
        'A01:2025' => ['name' => 'Broken Access Control', 'url' => 'https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/'],
        'A02:2025' => ['name' => 'Security Misconfiguration', 'url' => 'https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/'],
        'A03:2025' => ['name' => 'Software Supply Chain Failures', 'url' => 'https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/'],
        'A04:2025' => ['name' => 'Cryptographic Failures', 'url' => 'https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/'],
        'A05:2025' => ['name' => 'Injection', 'url' => 'https://owasp.org/Top10/2025/A05_2025-Injection/'],
        'A06:2025' => ['name' => 'Insecure Design', 'url' => 'https://owasp.org/Top10/2025/A06_2025-Insecure_Design/'],
        'A07:2025' => ['name' => 'Authentication Failures', 'url' => 'https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/'],
        'A08:2025' => ['name' => 'Software or Data Integrity Failures', 'url' => 'https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/'],
        'A09:2025' => ['name' => 'Security Logging and Alerting Failures', 'url' => 'https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/'],
        'A10:2025' => ['name' => 'Mishandling of Exceptional Conditions', 'url' => 'https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/'],
    ];
}

// Map stable detector rule IDs to their primary CWE and OWASP category.
function wpauditor_get_owasp_2025_rule_mapping(): array {
    return [
        'WPA-RCE-001'     => ['owasp' => 'A05:2025', 'cwe' => 'CWE-78'],
        'WPA-RCE-002'     => ['owasp' => 'A05:2025', 'cwe' => 'CWE-98'],
        'WPA-RCE-003'     => ['owasp' => 'A05:2025', 'cwe' => 'CWE-95'],
        'WPA-RCE-004'     => ['owasp' => 'A05:2025', 'cwe' => 'CWE-95'],
        'WPA-RCE-005'     => ['owasp' => 'A05:2025', 'cwe' => 'CWE-78'],
        'WPA-LFI-001'     => ['owasp' => 'A01:2025', 'cwe' => 'CWE-22'],
        'WPA-LFI-002'     => ['owasp' => 'A05:2025', 'cwe' => 'CWE-98'],
        'WPA-LFI-003'     => ['owasp' => 'A05:2025', 'cwe' => 'CWE-98'],
        'WPA-LFI-004'     => ['owasp' => 'A01:2025', 'cwe' => 'CWE-22'],
        'WPA-SSRF-001'    => ['owasp' => 'A01:2025', 'cwe' => 'CWE-918'],
        'WPA-PHP-OBJ-001' => ['owasp' => 'A08:2025', 'cwe' => 'CWE-502'],
        'WPA-XXE-001'     => ['owasp' => 'A02:2025', 'cwe' => 'CWE-611'],
    ];
}

// Map detector rule families whose rules share the same CWE.
function wpauditor_get_owasp_2025_rule_prefix_mapping(): array {
    return [
        'WPA-SQLI-'   => ['owasp' => 'A05:2025', 'cwe' => 'CWE-89'],
        'WPA-XSS-'    => ['owasp' => 'A05:2025', 'cwe' => 'CWE-79'],
        'WPA-XXE-'    => ['owasp' => 'A02:2025', 'cwe' => 'CWE-611'],
        'WPA-CMDI-'   => ['owasp' => 'A05:2025', 'cwe' => 'CWE-78'],
        'WPA-LFI-'    => ['owasp' => 'A01:2025', 'cwe' => 'CWE-22'],
        'WPA-UPLOAD-' => ['owasp' => 'A06:2025', 'cwe' => 'CWE-434'],
        'WPA-PHP-OBJ-' => ['owasp' => 'A08:2025', 'cwe' => 'CWE-502'],
    ];
}

// Provide conservative category fallbacks for historical logs without a rule ID.
function wpauditor_get_owasp_2025_category_mapping(): array {
    return [
        'SQL_INJECTION'         => ['owasp' => 'A05:2025', 'cwe' => 'CWE-89'],
        'XSS'                   => ['owasp' => 'A05:2025', 'cwe' => 'CWE-79'],
        'REMOTE_CODE_EXECUTION' => ['owasp' => 'A05:2025', 'cwe' => 'CWE-94'],
        'COMMAND_INJECTION'     => ['owasp' => 'A05:2025', 'cwe' => 'CWE-78'],
        'SSRF'                  => ['owasp' => 'A01:2025', 'cwe' => 'CWE-918'],
        'XXE'                   => ['owasp' => 'A02:2025', 'cwe' => 'CWE-611'],
        'PHP_OBJECT_INJECTION'  => ['owasp' => 'A08:2025', 'cwe' => 'CWE-502'],
        'SUSPICIOUS_UPLOADS'    => ['owasp' => 'A06:2025', 'cwe' => 'CWE-434'],
    ];
}

// Resolve an event to OWASP metadata without changing the persisted log format.
function wpauditor_get_owasp_for_event(string $event, string $category = '', string $details = ''): ?array {
    $mapping = null;
    $rule_id = '';

    if (preg_match('/(?:^|\s)rule_id=([A-Z0-9-]+)/i', $details, $matches)) {
        $rule_id = strtoupper($matches[1]);
        $rule_map = wpauditor_get_owasp_2025_rule_mapping();
        $mapping = $rule_map[$rule_id] ?? null;

        if ($mapping === null) {
            foreach (wpauditor_get_owasp_2025_rule_prefix_mapping() as $prefix => $prefix_mapping) {
                if (strpos($rule_id, $prefix) === 0) {
                    $mapping = $prefix_mapping;
                    break;
                }
            }
        }
    }

    if ($mapping === null) {
        $category_map = wpauditor_get_owasp_2025_category_mapping();
        $category_key = strtoupper(trim($category));
        $event_key = strtoupper(trim($event));
        $mapping = $category_map[$category_key] ?? ($category_map[$event_key] ?? null);
    }

    if ($mapping === null) return null;

    $categories = wpauditor_get_owasp_2025_categories();
    $owasp_id = $mapping['owasp'];
    if (!isset($categories[$owasp_id])) return null;

    return [
        'id'      => $owasp_id,
        'name'    => $categories[$owasp_id]['name'],
        'url'     => $categories[$owasp_id]['url'],
        'cwe'     => $mapping['cwe'],
        'rule_id' => $rule_id,
    ];
}
