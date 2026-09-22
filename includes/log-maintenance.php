<?php
if (!defined('ABSPATH')) exit;

// Locked streaming operations preserve large log files and downloads without buffering.
// phpcs:disable WordPress.WP.AlternativeFunctions

/**
 * File: includes/log-maintenance.php
 * Log maintenance (always-loaded)
 */


if (!function_exists('wpauditor_prepare_log_storage')) {
    function wpauditor_prepare_log_storage(): bool {
        $dir = wpauditor_log_dir();
        if ($dir === '') return false;
        if (is_link(rtrim($dir, '/\\')) || (!is_dir($dir) && !wp_mkdir_p($dir))) return false;
        $files = [
            '.htaccess' => "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n",
            'web.config' => '<?xml version="1.0"?><configuration><system.webServer><security><authorization><remove users="*" roles="" verbs=""/><add accessType="Deny" users="*"/></authorization></security></system.webServer></configuration>',
            'index.php' => "<?php\n// Silence is golden.\n",
        ];
        foreach ($files as $name => $body) {
            $path = $dir . $name;
            if (is_link($path) || (!is_file($path) && @file_put_contents($path, $body, LOCK_EX) === false)) return false;
        }
        $log = wpauditor_get_log_path();
        if (is_link($log) || (!is_file($log) && @file_put_contents($log, '', LOCK_EX) === false)) return false;
        @chmod($log, 0640);
        return true;
    }
}
if (!function_exists('wpauditor_uploads_base_dir')) {
    function wpauditor_uploads_base_dir(): string {
        $uploads = wp_upload_dir(null, false);
        if (!empty($uploads['error']) || empty($uploads['basedir']) || !is_string($uploads['basedir'])) {
            return '';
        }
        return trailingslashit(wp_normalize_path($uploads['basedir']));
    }
}
if (!function_exists('wpauditor_storage_dir')) {
    function wpauditor_storage_dir(string $subdirectory): string {
        $base = wpauditor_uploads_base_dir();
        $subdirectory = sanitize_key($subdirectory);
        if ($base === '' || $subdirectory === '') return '';
        return trailingslashit($base . 'wpauditor/' . $subdirectory);
    }
}
if (!function_exists('wpauditor_wordpress_root')) {
    function wpauditor_wordpress_root(): string {
        // Core Integrity must inspect the actual WordPress installation, including subdirectory installs.
        $resolved = realpath(ABSPATH);
        $root = $resolved !== false ? $resolved : ABSPATH;
        return trailingslashit(wp_normalize_path($root));
    }
}
if (!function_exists('wpauditor_log_dir')) {
    function wpauditor_log_dir(): string {
        return wpauditor_storage_dir('logs');
    }
}

if (!function_exists('wpauditor_get_log_filename')) {
    function wpauditor_get_log_filename(): string {
        $fn = (string) get_option('wpauditor_free_log_file', '');

        // Preferred hidden format
        if ($fn && preg_match('/^\.WPA_[a-f0-9]{12}$/', $fn)) {
            return $fn;
        }

        $fn = '.WPA_' . strtolower(bin2hex(random_bytes(6)));
        update_option('wpauditor_free_log_file', $fn, false);
        return $fn;
    }
}

if (!function_exists('wpauditor_get_log_path')) {
    function wpauditor_get_log_path(): string {
        $dir = wpauditor_log_dir();
        if ($dir === '') return '';
        $fn  = basename(wpauditor_get_log_filename());
        return $dir . $fn;
    }
}

if (!function_exists('wpauditor_log_line_ts')) {
    function wpauditor_log_line_ts(string $line): ?int {
        if (!preg_match('/\[(\d{4}-\d{2}-\d{2}[^]]*)\]/', $line, $m)) return null;
        $ts = strtotime($m[1]);
        return $ts !== false ? $ts : null;
    }
}

if (!function_exists('wpauditor_safe_write_log')) {
    function wpauditor_safe_write_log(string $path, array $lines): bool {
        if (!wpauditor_prepare_log_storage()) return false;
        $payload = $lines
            ? implode("\n", array_map(static function($line) { return rtrim((string) $line, "\r\n"); }, $lines)) . "\n"
            : '';
        $handle = @fopen($path, 'c+b');
        if (!$handle || !flock($handle, LOCK_EX)) {
            if (is_resource($handle)) fclose($handle);
            return false;
        }
        rewind($handle);
        $ok = ftruncate($handle, 0);
        if ($ok && $payload !== '') $ok = fwrite($handle, $payload) === strlen($payload);
        fflush($handle);
        flock($handle, LOCK_UN);
        fclose($handle);
        return $ok;
    }
}

if (!function_exists('wpauditor_autoclean_reschedule')) {
    function wpauditor_autoclean_reschedule(): void {
        $hook = 'wpauditor_free_daily_autoclean';
        $has  = wp_next_scheduled($hook);

        if (!$has) wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', $hook);
    }
}

// Keep mandatory log retention scheduled
add_action('init', function () {
    if (get_option('wpauditor_free_auto_clean_enabled', null) !== null) {
        delete_option('wpauditor_free_auto_clean_enabled');
    }

    $stored_days = (int) get_option('wpauditor_free_auto_clean_days', 90);
    $retention_days = min(180, max(30, $stored_days));
    if ($stored_days !== $retention_days) {
        update_option('wpauditor_free_auto_clean_days', $retention_days);
    }

    wpauditor_autoclean_reschedule();
}, 20);

if (!function_exists('wpauditor_daily_autoclean_task')) {
    function wpauditor_daily_autoclean_task(): void {
        $path = wpauditor_get_log_path();
        if (!file_exists($path)) return;

        $days = min(180, max(30, (int) get_option('wpauditor_free_auto_clean_days', 90)));
        $cut  = time() - ($days * DAY_IN_SECONDS);

        $lines = @file($path, FILE_IGNORE_NEW_LINES);
        if ($lines === false) return;

        $kept = [];
        foreach ($lines as $line) {
            $ts = wpauditor_log_line_ts($line);
            if ($ts === null || $ts >= $cut) $kept[] = $line;
        }
        wpauditor_safe_write_log($path, $kept);
    }
}
add_action('wpauditor_free_daily_autoclean', 'wpauditor_daily_autoclean_task');

if (!function_exists('wpauditor_download_log_ajax')) {
    function wpauditor_download_log_ajax(): void {
        if (!current_user_can('manage_options')) wp_die('Unauthorized.');
        $nonce = isset($_GET['_wpnonce']) ? sanitize_text_field(wp_unslash($_GET['_wpnonce'])) : '';
        if (!wp_verify_nonce($nonce, 'wpauditor_download_log')) wp_die('Bad nonce.');

        $path = wpauditor_get_log_path();
        if (!file_exists($path)) wp_die('Log file not found.');

        while (ob_get_level()) { @ob_end_clean(); }
        nocache_headers();

        header('Content-Type: text/plain; charset=UTF-8');
        header('Content-Disposition: attachment; filename="' . basename(wpauditor_get_log_filename()) . '"');
        header('Content-Length: ' . (string) filesize($path));
        readfile($path);
        exit;
    }
}
add_action('wp_ajax_wpauditor_download_log', 'wpauditor_download_log_ajax');
