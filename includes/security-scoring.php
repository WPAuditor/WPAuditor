<?php
if (!defined('ABSPATH')) exit;

if (!function_exists('wpauditor_security_score_weights')) {
    function wpauditor_security_score_weights(): array {
        return ['critical' => 30, 'high' => 20, 'medium' => 10, 'low' => 5, 'info' => 5];
    }
}

if (!function_exists('wpauditor_security_score_event')) {
    function wpauditor_security_score_event(array $event): int {
        $event_type = strtoupper((string) ($event['event'] ?? $event['type'] ?? ''));
        $is_web_attack = $event_type === 'WEB_APP_ATTACK';
        $explicit_security_events = ['BRUTE_FORCE_ALERT', 'IP_SPOOF_ATTEMPT'];
        if (!$is_web_attack && !in_array($event_type, $explicit_security_events, true)) return 0;

        $weights = wpauditor_security_score_weights();
        $severity = strtolower((string) ($event['severity'] ?? 'info'));
        $base = $weights[$severity] ?? 0;
        $boost = 0;

        if ($is_web_attack) {
            // Legacy web attack events predate enforcement metadata and keep their prior score behavior.
            $enforcement = array_key_exists('enforcement', $event)
                ? strtolower((string) $event['enforcement'])
                : 'score';
            if (!in_array($enforcement, ['observe', 'score', 'block'], true) || $enforcement === 'observe') return 0;

            // Legacy attack events have no confidence value; treat them conservatively.
            $confidence = (int) ($event['confidence'] ?? 0);
            if ($confidence <= 0) $confidence = 60;
            if ($confidence < 50) return 0;
            if ($confidence < 70) $base = (int) floor($base * 0.5);
            if ($confidence >= 90) $boost += 10;
        }

        $uri = (string) ($event['uri'] ?? '');
        if ($uri !== '') {
            if (preg_match('#wp-config\.php|eval\(|base64#i', $uri)) {
                $boost += 20;
            }
            if (stripos($uri, '/wp-admin/') === false && preg_match('#(^|/)(admin|administrator)(/|$)#i', $uri)) {
                $boost += 20;
            }
        }

        if ($is_web_attack && in_array(strtoupper((string) ($event['category'] ?? '')), [
            'REMOTE_CODE_EXECUTION', 'COMMAND_INJECTION', 'LFI_RFI', 'SSRF',
            'SUSPICIOUS_UPLOADS', 'XXE', 'PHP_OBJECT_INJECTION',
        ], true)) {
            $boost += 10;
        }

        return max(0, $base + $boost);
    }
}
