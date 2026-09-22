<?php
if (!defined('ABSPATH')) exit;

// Locked local log operations are required for retention and status reporting.
// phpcs:disable WordPress.WP.AlternativeFunctions

if (!function_exists('wpauditor_admin_page_settings')) {
    function wpauditor_admin_page_settings() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'wpauditor'));
        }

        $page_slug = isset($_GET['page']) ? sanitize_key(wp_unslash((string) $_GET['page'])) : 'wpauditor-settings';
        $base_url = add_query_arg(['page' => $page_slug], admin_url('admin.php'));
        $tabs = [
            'general'      => __('General', 'wpauditor'),
                                    'logs'         => __('Logs', 'wpauditor'),
        ];

        $active_tab = isset($_GET['tab']) ? sanitize_key(wp_unslash((string) $_GET['tab'])) : 'general';
        if ($active_tab === 'tz_integration') $active_tab = 'general';
        if ($active_tab === 'retention') $active_tab = 'logs';
        if (!isset($tabs[$active_tab])) $active_tab = 'general';

        $log_filename = function_exists('wpauditor_get_log_filename')
            ? (string) wpauditor_get_log_filename()
            : (basename((string) get_option('wpauditor_free_log_file', '')) ?: 'events.log');
        $log_path = function_exists('wpauditor_get_log_path')
            ? (string) wpauditor_get_log_path()
            : wpauditor_log_dir() . basename($log_filename);

        $timezone_name = (string) get_option('timezone_string', '');
        if (!$timezone_name) {
            $offset = (float) get_option('gmt_offset', 0);
            $sign = $offset >= 0 ? '+' : '-';
            $absolute = abs($offset);
            $hours = floor($absolute);
            $minutes = (int) round(($absolute - $hours) * 60);
            $timezone_name = sprintf('UTC%s%02d:%02d', $sign, $hours, $minutes);
        }
        $wpauditor_cron_jobs = [
            [
                'label'     => __('Log cleanup', 'wpauditor'),
                'hook'      => 'wpauditor_free_daily_autoclean',
                'frequency' => __('Daily', 'wpauditor'),
            ],
        ];
        $auto_clean_days = min(180, max(30, (int) get_option('wpauditor_free_auto_clean_days', 90)));
        $notices = [];
        $cleanup_from = '';
        $cleanup_to = '';

        $plugin_version = '1.6.0';
        if (defined('WPAUDITOR_MAIN_FILE') && function_exists('get_file_data')) {
            $plugin_data = get_file_data(WPAUDITOR_MAIN_FILE, ['Version' => 'Version'], 'plugin');
            if (!empty($plugin_data['Version'])) $plugin_version = (string) $plugin_data['Version'];
        }

        $parse_log_range = static function(string $from_raw, string $to_raw): array {
            if ($from_raw === '' && $to_raw === '') return [0, 0, false];

            try {
                $timezone = wp_timezone();
                $from = $from_raw !== ''
                    ? (new DateTimeImmutable($from_raw . ' 00:00:00', $timezone))->getTimestamp()
                    : 0;
                $to = $to_raw !== ''
                    ? (new DateTimeImmutable($to_raw . ' 23:59:59', $timezone))->getTimestamp()
                    : PHP_INT_MAX;
            } catch (Exception $exception) {
                return [0, 0, false];
            }

            return [$from, $to, $from <= $to];
        };
        if (
            isset($_POST['wpauditor_clean_by_date_submit'])
            && check_admin_referer('wpauditor_clean_by_date', 'wpauditor_clean_by_date_nonce')
        ) {
            $cleanup_from = isset($_POST['clean_from_date']) ? sanitize_text_field(wp_unslash($_POST['clean_from_date'])) : '';
            $cleanup_to = isset($_POST['clean_to_date']) ? sanitize_text_field(wp_unslash($_POST['clean_to_date'])) : '';
            [$from_timestamp, $to_timestamp, $valid_range] = $parse_log_range($cleanup_from, $cleanup_to);

            if (is_file($log_path) && $valid_range) {
                $kept = [];
                $removed = 0;
                foreach ((array) file($log_path, FILE_IGNORE_NEW_LINES) as $line) {
                    $timestamp = wpauditor_log_line_ts($line);
                    if ($timestamp !== null && $timestamp >= $from_timestamp && $timestamp <= $to_timestamp) {
                        $removed++;
                    } else {
                        $kept[] = $line;
                    }
                }

                $notices[] = wpauditor_safe_write_log($log_path, $kept)
// translators: Placeholders are replaced with the values described by the surrounding message.
                    ? ['success', sprintf(__('%d log entries were deleted.', 'wpauditor'), $removed)]
                    : ['error', __('WPAuditor could not update the log file.', 'wpauditor')];
            } else {
                $notices[] = ['error', __('Select a valid date range and try again.', 'wpauditor')];
            }
        }

        if (
            isset($_POST['wpauditor_delete_all_logs_submit'])
            && check_admin_referer('wpauditor_delete_all_logs', 'wpauditor_delete_all_logs_nonce')
        ) {
            $notices[] = is_file($log_path) && wpauditor_safe_write_log($log_path, [])
                ? ['success', __('All logs have been deleted.', 'wpauditor')]
                : ['warning', __('The log file was not found or could not be updated.', 'wpauditor')];
        }

        if (
            isset($_POST['wpauditor_auto_clean_settings_submit'])
            && check_admin_referer('wpauditor_auto_clean_settings', 'wpauditor_auto_clean_settings_nonce')
        ) {
            $auto_clean_days = isset($_POST['auto_clean_days']) ? absint(wp_unslash($_POST['auto_clean_days'])) : 90;
            $auto_clean_days = min(180, max(30, $auto_clean_days));
            update_option('wpauditor_free_auto_clean_days', $auto_clean_days);
            wpauditor_autoclean_reschedule();
            $notices[] = ['success', __('Log retention settings saved.', 'wpauditor')];
        }
        $log_exists = is_file($log_path);
        $log_writable = $log_exists && is_writable($log_path);
        ?>
        <div class="wrap wpa-admin-shell wpa-settings-page">
            <h1 class="wp-heading-inline"><?php esc_html_e('Settings', 'wpauditor'); ?></h1>
            <hr class="wp-header-end">

            <nav class="nav-tab-wrapper wpa-settings-tabs" aria-label="<?php esc_attr_e('Settings sections', 'wpauditor'); ?>">
                <?php foreach ($tabs as $key => $label) :
                    $url = add_query_arg(['tab' => $key], $base_url);
                    $class = 'nav-tab' . ($active_tab === $key ? ' nav-tab-active' : '');
                    ?>
                    <a href="<?php echo esc_url($url); ?>" class="<?php echo esc_attr($class); ?>" <?php echo $active_tab === $key ? 'aria-current="page"' : ''; ?>><?php echo esc_html($label); ?></a>
                <?php endforeach; ?>
            </nav>

            <?php foreach ($notices as $notice) : ?>
                <div class="notice notice-<?php echo esc_attr($notice[0]); ?> is-dismissible"><p><?php echo esc_html($notice[1]); ?></p></div>
            <?php endforeach; ?>

            <?php if ($active_tab === 'general') :
                $lines = $log_exists ? file($log_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
                $total_entries = is_array($lines) ? count($lines) : 0;
                $first_entry = $last_entry = __('Not available', 'wpauditor');
                if ($total_entries) {
                    if (preg_match('/\[(.*?)\]/', $lines[0], $match)) $first_entry = $match[1];
                    if (preg_match('/\[(.*?)\]/', $lines[$total_entries - 1], $match)) $last_entry = $match[1];
                }
                ?>
                <section class="wpa-settings-tab-panel">
                    <div class="wpa-settings-section-head">
                        <div>
                            <h2><?php esc_html_e('General', 'wpauditor'); ?></h2>
                        </div>
                    </div>
                    <table class="form-table" role="presentation">
                        <tbody>
                            <tr><th><?php esc_html_e('Plugin version', 'wpauditor'); ?></th><td><?php echo esc_html($plugin_version); ?></td></tr>
                            <tr>
                                <th><?php esc_html_e('Timezone', 'wpauditor'); ?></th>
                                <td>
                                    <strong><?php echo esc_html($timezone_name); ?></strong>
                                    <span aria-hidden="true"> &middot; </span>
                                    <a href="<?php echo esc_url(admin_url('options-general.php')); ?>"><?php esc_html_e('Change timezone', 'wpauditor'); ?></a>
                                    <p class="description"><?php esc_html_e('Confirm this matches your local time to keep event log timestamps accurate.', 'wpauditor'); ?></p>
                                </td>
                            </tr>
                            <tr>
                                <th><?php esc_html_e('Scheduled Jobs', 'wpauditor'); ?></th>
                                <td>
                                    <ul class="ul-disc">
                                        <?php foreach ($wpauditor_cron_jobs as $cron_job) :
                                            $next_run = wp_next_scheduled($cron_job['hook']);
                                            ?>
                                            <li>
                                                <strong><?php echo esc_html($cron_job['label']); ?>:</strong>
                                                <?php if ($next_run) : ?>
                                                    <?php echo esc_html(sprintf(
// translators: Placeholders are replaced with the values described by the surrounding message.
                                                        __('Scheduled, %1$s. Next: %2$s', 'wpauditor'),
                                                        $cron_job['frequency'],
                                                        wp_date('Y-m-d H:i:s', $next_run)
                                                    )); ?>
                                                <?php else : ?>
                                                    <?php echo esc_html(sprintf(
// translators: Placeholders are replaced with the values described by the surrounding message.
                                                        __('Not scheduled (%s)', 'wpauditor'),
                                                        $cron_job['frequency']
                                                    )); ?>
                                                <?php endif; ?>
                                            </li>
                                        <?php endforeach; ?>
                                    </ul>
                                </td>
                            </tr>
                            <tr><th><?php esc_html_e('Event logging', 'wpauditor'); ?></th><td><strong><?php echo $log_writable ? esc_html__('Active', 'wpauditor') : esc_html__('Needs attention', 'wpauditor'); ?></strong><p class="description"><code><?php echo esc_html($log_filename); ?></code></p></td></tr>
                            <tr><th><?php esc_html_e('File size', 'wpauditor'); ?></th><td><?php echo $log_exists ? esc_html(size_format((int) filesize($log_path))) : esc_html__('Not available', 'wpauditor'); ?></td></tr>
                            <tr><th><?php esc_html_e('Total entries', 'wpauditor'); ?></th><td><?php echo esc_html(number_format_i18n($total_entries)); ?></td></tr>
                            <tr><th><?php esc_html_e('First entry', 'wpauditor'); ?></th><td><?php echo esc_html($first_entry); ?></td></tr>
                            <tr><th><?php esc_html_e('Last entry', 'wpauditor'); ?></th><td><?php echo esc_html($last_entry); ?></td></tr>
                            <tr><th><?php esc_html_e('Log retention', 'wpauditor'); ?></th><td><?php // translators: %d is the number of retained days. ?><?php echo esc_html(sprintf(__('%d days', 'wpauditor'), $auto_clean_days)); ?></td></tr>
                        </tbody>
                    </table>
                </section>
            <?php elseif ($active_tab === 'logs') :
                $lines = $log_exists ? file($log_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
                $total_entries = is_array($lines) ? count($lines) : 0;
                $download_url = wp_nonce_url(admin_url('admin-ajax.php?action=wpauditor_download_log'), 'wpauditor_download_log');
                ?>
                <section class="wpa-settings-tab-panel">
                    <?php if (!$log_exists) : ?><div class="notice notice-error inline"><p><?php esc_html_e('Log file not found.', 'wpauditor'); ?></p></div><?php endif; ?>
                    <div class="wpa-settings-subsection-head">
                        <h3><?php esc_html_e('Manual Cleanup', 'wpauditor'); ?></h3>
                    </div>
                    <form method="post" action="<?php echo esc_url(add_query_arg(['tab' => 'logs'], $base_url)); ?>">
                        <?php wp_nonce_field('wpauditor_clean_by_date', 'wpauditor_clean_by_date_nonce'); ?>
                        <table class="form-table" role="presentation">
                            <tbody>
                                <tr>
                                    <th><?php esc_html_e('Date range', 'wpauditor'); ?></th>
                                    <td>
                                        <div class="wpa-settings-date-range">
                                            <label for="clean_from_date"><span><?php esc_html_e('From', 'wpauditor'); ?></span><input type="date" name="clean_from_date" id="clean_from_date" value="<?php echo esc_attr($cleanup_from); ?>"></label>
                                            <label for="clean_to_date"><span><?php esc_html_e('To', 'wpauditor'); ?></span><input type="date" name="clean_to_date" id="clean_to_date" value="<?php echo esc_attr($cleanup_to); ?>"></label>
                                            <button type="submit" name="wpauditor_clean_by_date_submit" class="button button-danger wpa-confirm-submit wpa-settings-date-delete" <?php disabled(!$log_exists || !$total_entries); ?> data-wpa-confirm-action="delete" data-wpa-confirm-eyebrow="<?php esc_attr_e('Log Management', 'wpauditor'); ?>" data-wpa-confirm-title="<?php esc_attr_e('Delete logs in this date range?', 'wpauditor'); ?>" data-wpa-confirm-description="<?php esc_attr_e('Permanently delete every matching security event from the current log file.', 'wpauditor'); ?>" data-wpa-confirm-note="<?php esc_attr_e('This action cannot be undone.', 'wpauditor'); ?>" data-wpa-confirm-label="<?php esc_attr_e('Delete Logs', 'wpauditor'); ?>" data-wpa-confirm-target-source="date-range"><?php esc_html_e('Delete', 'wpauditor'); ?></button>
                                        </div>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </form>

                    <hr>
                    <?php if ($log_exists) : ?>
                        <div class="notice notice-info inline wpa-settings-danger">
                            <p><strong><?php esc_html_e('Download all logs', 'wpauditor'); ?></strong></p>
                            <p><?php esc_html_e('Download every event from the current log file.', 'wpauditor'); ?></p>
                            <p class="wpa-settings-log-action"><a href="<?php echo esc_url($download_url); ?>" class="button wpa-settings-log-action-button"><?php esc_html_e('Download All Logs', 'wpauditor'); ?></a></p>
                        </div>
                    <?php endif; ?>

                    <div class="notice notice-error inline wpa-settings-danger">
                        <p><strong><?php esc_html_e('Delete all logs', 'wpauditor'); ?></strong></p>
                        <p><?php esc_html_e('This permanently removes every event from the current log file.', 'wpauditor'); ?></p>
                        <form class="wpa-settings-log-action" method="post" action="<?php echo esc_url(add_query_arg(['tab' => 'logs'], $base_url)); ?>">
                            <?php wp_nonce_field('wpauditor_delete_all_logs', 'wpauditor_delete_all_logs_nonce'); ?>
                            <button type="submit" name="wpauditor_delete_all_logs_submit" class="button button-danger wpa-confirm-submit wpa-settings-log-action-button" <?php disabled(!$log_exists || !$total_entries); ?> data-wpa-confirm-action="delete" data-wpa-confirm-eyebrow="<?php esc_attr_e('Log Management', 'wpauditor'); ?>" data-wpa-confirm-title="<?php esc_attr_e('Delete all WPAuditor logs?', 'wpauditor'); ?>" data-wpa-confirm-description="<?php esc_attr_e('Permanently remove every security event from the current log file.', 'wpauditor'); ?>" data-wpa-confirm-note="<?php esc_attr_e('This action cannot be undone.', 'wpauditor'); ?>" data-wpa-confirm-label="<?php esc_attr_e('Delete All Logs', 'wpauditor'); ?>" data-wpa-confirm-target-label="<?php esc_attr_e('Log entries', 'wpauditor'); ?>" data-wpa-confirm-target="<?php echo esc_attr(number_format_i18n($total_entries)); ?>"><?php esc_html_e('Delete All Logs', 'wpauditor'); ?></button>
                        </form>
                    </div>
                </section>

                <section class="wpa-settings-tab-panel">
                    <div class="wpa-settings-section-head">
                        <div>
                            <h2><?php esc_html_e('Retention Policy', 'wpauditor'); ?></h2>
                        </div>
                    </div>
                    <form method="post" action="<?php echo esc_url(add_query_arg(['tab' => 'logs'], $base_url)); ?>">
                        <?php wp_nonce_field('wpauditor_auto_clean_settings', 'wpauditor_auto_clean_settings_nonce'); ?>
                        <table class="form-table" role="presentation">
                            <tbody>
                                <tr>
                                    <th><label for="auto_clean_days"><?php esc_html_e('Retention period', 'wpauditor'); ?></label></th>
                                    <td>
                                        <div class="wpa-ads-range-field">
                                            <div class="wpa-ads-range-value-row">
                                                <output class="wpa-ads-range-output" for="auto_clean_days" aria-live="polite"><span id="auto_clean_days_value"><?php echo esc_html((string) $auto_clean_days); ?></span> <?php esc_html_e('days', 'wpauditor'); ?></output>
                                            </div>
                                            <input type="range" name="auto_clean_days" id="auto_clean_days" value="<?php echo esc_attr((string) $auto_clean_days); ?>" min="30" max="180" step="1" class="wpa-ads-range">
                                            <div class="wpa-ads-range-scale" aria-hidden="true">
                                                <span><?php esc_html_e('30 days', 'wpauditor'); ?></span>
                                                <span><?php esc_html_e('6 months', 'wpauditor'); ?></span>
                                            </div>
                                        </div>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                        <p class="submit"><button type="submit" name="wpauditor_auto_clean_settings_submit" class="button button-primary"><?php esc_html_e('Save Retention Policy', 'wpauditor'); ?></button></p>
                    </form>
                    <?php ob_start(); ?>
                    (function () {
                        const input = document.getElementById('auto_clean_days');
                        const output = document.getElementById('auto_clean_days_value');
                        if (!input || !output) return;
                        input.addEventListener('input', function () {
                            output.textContent = input.value;
                        });
                    })();
                    <?php
                    $retention_script = ob_get_clean();
                    wp_add_inline_script('wpauditor-admin-ui', $retention_script, 'after');
                    ?>
                </section>

            <?php endif; ?>
        </div>
        <?php
    }
}
