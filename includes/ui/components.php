<?php
// WPAuditor shared admin UI components.

if (!defined('ABSPATH')) exit;

if (!function_exists('wpauditor_badge_html')) {
    function wpauditor_badge_html(string $label, string $type = 'status', string $tone = 'neutral'): string {
        $allowed_tones = [
            'status'   => ['success', 'warning', 'danger', 'neutral', 'info'],
            'severity' => ['critical', 'high', 'medium', 'low', 'info'],
        ];

        $type = array_key_exists($type, $allowed_tones) ? $type : 'status';
        $fallback_tone = $type === 'severity' ? 'info' : 'neutral';
        $tone = in_array($tone, $allowed_tones[$type], true) ? $tone : $fallback_tone;

        return sprintf(
            '<span class="wpa-%1$s-badge wpa-%1$s-badge--%2$s">%3$s</span>',
            esc_attr($type),
            esc_attr($tone),
            esc_html($label)
        );
    }
}

if (!function_exists('wpauditor_severity_badge_html')) {
    function wpauditor_severity_badge_html(string $severity): string {
        $tone = strtolower($severity);
        if (!in_array($tone, ['critical', 'high', 'medium', 'low', 'info'], true)) {
            $tone = 'info';
        }

        return wpauditor_badge_html(ucfirst($tone), 'severity', $tone);
    }
}
