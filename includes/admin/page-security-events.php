<?php
if (!defined('ABSPATH')) exit;

// Security Events browser.

if (!function_exists('wpauditor_security_events_page')) {
function wpauditor_security_events_page() {
    if (function_exists('wpauditor_soc_logs_page')) {
        wpauditor_soc_logs_page('security_events');
    }
}
}
