<?php
if (!defined('ABSPATH')) exit;
// Dashboard query values are read-only filters; mutations use dedicated nonce-protected handlers.
// phpcs:disable WordPress.Security.NonceVerification.Recommended

// Dashboard (SOC Logs).

if (!function_exists('wpauditor_country_name_from_cc')) {
    function wpauditor_country_name_from_cc(string $cc): string {
        $cc = strtoupper(trim($cc));

        $map = [
            'BD' => 'Bangladesh',
            'US' => 'United States',
            'GB' => 'United Kingdom',
            'IN' => 'India',
            'PK' => 'Pakistan',
            'CA' => 'Canada',
            'AU' => 'Australia',
            'DE' => 'Germany',
            'FR' => 'France',
            'IT' => 'Italy',
            'ES' => 'Spain',
            'NL' => 'Netherlands',
            'SE' => 'Sweden',
            'NO' => 'Norway',
            'DK' => 'Denmark',
            'RU' => 'Russia',
            'CN' => 'China',
            'JP' => 'Japan',
            'KR' => 'South Korea',
            'SG' => 'Singapore',
            'MY' => 'Malaysia',
            'TH' => 'Thailand',
            'VN' => 'Vietnam',
            'ID' => 'Indonesia',
            'PH' => 'Philippines',
            'SA' => 'Saudi Arabia',
            'AE' => 'United Arab Emirates',
            'TR' => 'Turkey',
            'IR' => 'Iran',
            'BR' => 'Brazil',
            'MX' => 'Mexico',
            'ZA' => 'South Africa',
            'XX' => 'Unknown',
            'T1' => 'Tor Network',
        ];

        $map = apply_filters('wpauditor_country_map', $map);
        return $map[$cc] ?? '';
    }
}

if (!function_exists('wpauditor_flag_url_from_cc')) {
    function wpauditor_flag_url_from_cc(string $cc): string {
        $cc = strtolower(trim($cc));

        if ($cc === 'unknown') {
            $flag_file = 'unknown.png';
        } else {
            if (!preg_match('/^[a-z]{2}$/', $cc)) return '';
            if ($cc === 'xx' || $cc === 't1') return '';
            $flag_file = $cc . '.png';
        }

        $plugin_root = dirname(__FILE__, 3);
        $file = $plugin_root . '/includes/ui/assets/flags/' . $flag_file;
        if (!file_exists($file)) return '';

        return plugins_url('includes/ui/assets/flags/' . $flag_file, $plugin_root . '/wpauditor.php');
    }
}

if (!function_exists('wpauditor_soc_logs_page')) {
function wpauditor_soc_logs_page($view = 'dashboard') {
    if (!current_user_can('manage_options')) wp_die(esc_html__('Permission denied.', 'wpauditor'));
    $view = ($view === 'security_events') ? 'security_events' : 'dashboard';
    $current_page_slug = ($view === 'security_events') ? 'wpauditor-security-events' : 'wpauditor-dashboard';
    $is_light_theme = function_exists('wpauditor_theme_get_user_preference') && wpauditor_theme_get_user_preference() === 'light';

    $wrap_class = ($view === 'dashboard') ? 'wrap wpa-admin-shell wpa-soc-dashboard' : 'wrap wpa-admin-shell wpa-security-events-page';
    echo '<div class="' . esc_attr($wrap_class) . '">';

    $log_filename = get_option('wpauditor_free_log_file');
    if (!$log_filename) {
        echo '<p class="wpa-error-text">Log file not found or not initialized. Please reactivate the plugin.</p>';
        return;
    }

    $log_file = wpauditor_get_log_path();
    if (!file_exists($log_file)) {
        echo '<p class="wpa-error-text">Log file does not exist: ' . esc_html($log_filename) . '</p>';
        return;
    }

    // Filters.
    $filter_event     = isset($_GET['event_type']) ? sanitize_text_field(wp_unslash($_GET['event_type'])) : '';
    $filter_start     = isset($_GET['start_date']) ? sanitize_text_field(wp_unslash($_GET['start_date'])) : '';
    $filter_end       = isset($_GET['end_date']) ? sanitize_text_field(wp_unslash($_GET['end_date'])) : '';
    $filter_severity  = isset($_GET['severity']) ? sanitize_text_field(wp_unslash($_GET['severity'])) : '';
    $filter_category  = isset($_GET['category']) ? sanitize_text_field(wp_unslash($_GET['category'])) : '';
    $filter_window    = isset($_GET['window']) ? sanitize_text_field(wp_unslash($_GET['window'])) : '';
    $page             = isset($_GET['paged']) ? max(1, absint(wp_unslash($_GET['paged']))) : 1;
    $per_page         = WPAUDITOR_ADMIN_ROWS_PER_PAGE;
    $refresh_nonce    = wp_create_nonce('wpauditor_soc_refresh');

    $now_ts    = current_time('timestamp');
    $today_ymd = wp_date('Y-m-d', $now_ts);

    // Quick window definitions.
    $window_defs = [
        'all' => ['label' => 'All',          'secs' => null],
        '45d' => ['label' => 'Last 45 days', 'secs' => 45 * 86400],
        '30d' => ['label' => 'Last 30 days', 'secs' => 30 * 86400],
        '7d'  => ['label' => 'Last 7 days',  'secs' =>  7 * 86400],
        '24h' => ['label' => 'Last 24h',     'secs' => 24 * 3600],
    ];
    if (!array_key_exists($filter_window, $window_defs) && $filter_window !== '') $filter_window = '';
    $allowed_severities = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    $filter_severity = strtoupper($filter_severity);
    if (!in_array($filter_severity, $allowed_severities, true)) $filter_severity = '';

    $safe_query_args = ['page' => $current_page_slug, 'paged' => $page];
    foreach ([
        'event_type' => $filter_event,
        'start_date' => $filter_start,
        'end_date'   => $filter_end,
        'severity'   => $filter_severity,
        'category'   => $filter_category,
        'window'     => $filter_window,
    ] as $query_key => $query_value) {
        if ($query_value !== '') $safe_query_args[$query_key] = $query_value;
    }

    // Resolve time bounds.
    $start_ts = null;
    $end_ts   = null;
    $date_range_error = '';

    // Default behavior: All (UI + logic).
    if ($filter_window === '' && $filter_start === '' && $filter_end === '') {
        $filter_window = 'all';
    }

    if ($filter_window && isset($window_defs[$filter_window])) {
        if ($filter_window === 'all') {
            $start_ts = 0;
            $end_ts   = $now_ts;

            // Keep date inputs empty for All
            $filter_start = '';
            $filter_end   = '';
        } else {
            $end_ts   = $now_ts;
            $start_ts = max(0, $end_ts - (int)$window_defs[$filter_window]['secs']);
            $filter_start = wp_date('Y-m-d', $start_ts);
            $filter_end   = wp_date('Y-m-d', $end_ts);
        }
    } else {
        // Custom date range (date-only). If empty → All.
        if ($filter_start === '' && $filter_end === '') {
            $start_ts = 0;
            $end_ts   = $now_ts;
            $filter_window = 'all';
        } else {
            $parse_filter_date = static function(string $value, bool $end_of_day): ?int {
                $date = DateTimeImmutable::createFromFormat('!Y-m-d', $value, wp_timezone());
                if (!$date || $date->format('Y-m-d') !== $value) return null;

                return $date->setTime($end_of_day ? 23 : 0, $end_of_day ? 59 : 0, $end_of_day ? 59 : 0)->getTimestamp();
            };

            $start_ts = $filter_start !== '' ? $parse_filter_date($filter_start, false) : null;
            $end_ts   = $filter_end !== '' ? $parse_filter_date($filter_end, true) : null;
            $filter_window = ''; // custom

            if (($filter_start !== '' && $start_ts === null) || ($filter_end !== '' && $end_ts === null)) {
                $date_range_error = __('Enter a valid From and To date.', 'wpauditor');
            } elseif ($start_ts !== null && $end_ts !== null && $start_ts > $end_ts) {
                $date_range_error = __('The From date must be earlier than or equal to the To date.', 'wpauditor');
            }
        }
    }

    if ($start_ts === null) $start_ts = 0;
    if ($end_ts === null) $end_ts = $now_ts;

    $lines = array_reverse(file($log_file, FILE_IGNORE_NEW_LINES));
    $logs = [];
    $event_types = [];
    $graph_data = [];
    $summary_counts = [];
    $event_summary_counts = [];

    // KPI accumulators.
    $severity_counts  = ['CRITICAL'=>0, 'HIGH'=>0, 'MEDIUM'=>0, 'LOW'=>0, 'INFO'=>0];
    $category_counts  = [];
    $endpoint_counts  = [];
    $unique_ip_map    = [];
    $attacker_ip_counts = [];
    $attacker_ip_ccs  = [];

    foreach ($lines as $line) {
        $re = '/\[(.*?)\]\s+\[(.*?)\]\s+IP=([^\s]+)\s+(?:cc=([A-Z0-9]{2})\s+)?method=(.*?)\s+uri=(.*?)\s+ua="((?:\\\"|[^"])*)"(?:\s+category=(.*?))?\s+severity=(\w+)(?:\s+mitre_tactic="([^"]+)"\s+mitre_technique=(T\d{4}(?:\.\d{3})?))?\s*(.*)?/i';

        if (preg_match($re, $line, $m)) {
            $timestamp   = $m[1];
            $event       = $m[2];
            $date        = substr($timestamp, 0, 10);
            $entry_time  = strtotime($timestamp);
            if ($entry_time === false) continue;

            if ($entry_time < $start_ts) continue;
            if ($entry_time > $end_ts) continue;

            $sev = strtoupper($m[9] ?? '');
            if ($filter_severity === 'CRITICAL_HIGH') {
                if (!in_array($sev, ['CRITICAL', 'HIGH'], true)) continue;
            } elseif ($filter_severity && $sev !== strtoupper($filter_severity)) {
                continue;
            }

            $cat = isset($m[8]) ? trim($m[8]) : '';
            if ($filter_category && $cat !== $filter_category) continue;

            // Keep event cards available while an event filter is active.
            $event_types[$event] = true;
            $event_summary_counts[$event] = ($event_summary_counts[$event] ?? 0) + 1;

            if ($filter_event && $event !== $filter_event) continue;

            $cc = strtoupper(trim($m[4] ?? ''));
            if (!preg_match('/^[A-Z0-9]{2}$/', $cc)) $cc = '';

            $ua_display = isset($m[7]) ? str_replace('\\"', '"', $m[7]) : '';
            $ip = trim((string) ($m[3] ?? ''));

            $logs[] = [
                'timestamp'       => $timestamp,
                'event'           => $event,
                'ip'              => $ip,
                'cc'              => $cc,
                'method'          => $m[5],
                'uri'             => $m[6],
                'ua'              => $ua_display,
                'category'        => $cat,
                'severity'        => $sev,
                'mitre_tactic'    => $m[10] ?? '',
                'mitre_technique' => $m[11] ?? '',
                'details'         => $m[12] ?? '',
            ];

            $graph_data[$event][$date] = ($graph_data[$event][$date] ?? 0) + 1;
            $summary_counts[$event] = ($summary_counts[$event] ?? 0) + 1;

            if (isset($severity_counts[$sev])) $severity_counts[$sev]++; else $severity_counts[$sev] = 1;
            if ($cat !== '') $category_counts[$cat] = ($category_counts[$cat] ?? 0) + 1;
            $endpoint_path = wp_parse_url((string) $m[6], PHP_URL_PATH);
            $endpoint_path = is_string($endpoint_path) && $endpoint_path !== '' ? $endpoint_path : '/';
            $endpoint_path = '/' . ltrim($endpoint_path, '/');
            $endpoint_path = preg_replace('#/+#', '/', $endpoint_path);
            $endpoint_path = strlen($endpoint_path) > 1 ? rtrim($endpoint_path, '/') : $endpoint_path;
            $endpoint_counts[$endpoint_path] = ($endpoint_counts[$endpoint_path] ?? 0) + 1;
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $unique_ip_map[$ip] = true;
                $attacker_ip_counts[$ip] = ($attacker_ip_counts[$ip] ?? 0) + 1;
                if ($cc !== '' && empty($attacker_ip_ccs[$ip])) {
                    $attacker_ip_ccs[$ip] = $cc;
                }
            }
        }
    }

    // KPI header.
    $total_filtered = count($logs);
    $unique_ip_total = count($unique_ip_map);
    $repeat_attacker_total = count(array_filter($attacker_ip_counts, static function($count): bool {
        return (int) $count > 1;
    }));
    $critical_high_total = (int) ($severity_counts['CRITICAL'] ?? 0) + (int) ($severity_counts['HIGH'] ?? 0);
    arsort($category_counts);
// translators: Placeholders are replaced with the values described by the surrounding message.
    arsort($endpoint_counts);
    arsort($attacker_ip_counts);
    arsort($event_summary_counts);
    $hot_categories = array_slice($category_counts, 0, 5, true);
    $top_targeted_endpoints = array_slice($endpoint_counts, 0, 5, true);

    $sev_colors = [
        'CRITICAL' => '#fb7185',
        'HIGH'     => '#fb923c',
        'MEDIUM'   => '#facc15',
        'LOW'      => '#4ade80',
        'INFO'     => '#60a5fa',
    ];

    $sev_order = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
    $all_dates = [];
    foreach ($graph_data as $counts) $all_dates = array_merge($all_dates, array_keys($counts));
    $all_dates = array_values(array_unique($all_dates));
    sort($all_dates);

    $series = [];
    foreach ($graph_data as $event => $counts) {
        $dataset = [];
        foreach ($all_dates as $d) { $dataset[] = (int)($counts[$d] ?? 0); }
        $series[$event] = $dataset;
    }

    $sev_chart_labels = ['Critical', 'High', 'Medium', 'Low', 'Info'];
    $sev_chart_counts = [
        (int) ($severity_counts['CRITICAL'] ?? 0),
        (int) ($severity_counts['HIGH'] ?? 0),
        (int) ($severity_counts['MEDIUM'] ?? 0),
        (int) ($severity_counts['LOW'] ?? 0),
        (int) ($severity_counts['INFO'] ?? 0),
    ];
    $sev_chart_colors = ['#fb7185', '#fb923c', '#facc15', '#4ade80', '#93c5fd'];
    $sev_chart_url_filters = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    $sev_chart_urls = array_map(static function($severity) use ($safe_query_args) {
        return esc_url_raw(add_query_arg(array_merge($safe_query_args, [
            'page'     => 'wpauditor-security-events',
            'severity' => $severity,
            'paged'    => 1,
        ]), admin_url('admin.php')));
    }, $sev_chart_url_filters);
    $hot_threat_labels = array_values(array_map('strval', array_keys($hot_categories)));
    $hot_threat_counts = array_values(array_map('intval', $hot_categories));
    $hot_threat_urls = array_values(array_map(static function($category_name) use ($safe_query_args) {
        return esc_url_raw(add_query_arg(array_merge($safe_query_args, [
            'page'     => 'wpauditor-security-events',
            'category' => $category_name,
            'paged'    => 1,
        ]), admin_url('admin.php')));
    }, array_keys($hot_categories)));

    if ($view === 'dashboard') {
    echo '<div class="wpa-page-head">';
    echo '<div class="wpa-page-heading-copy">';
    echo '<div class="wpa-page-title-row">';
    echo '<h1 class="wpa-page-title">Dashboard</h1>';
    echo '<span class="wpa-live-monitoring-badge">WPAuditor Free</span>';
    if (function_exists('wpauditor_render_priority_notification_bell')) {
        wpauditor_render_priority_notification_bell();
    }
    if (function_exists('wpauditor_render_theme_toggle')) {
        wpauditor_render_theme_toggle();
    }
    echo '</div>';
    echo '</div>';

    echo '<form method="get" class="wpa-dashboard-filter-form">';
    echo '<input type="hidden" name="page" value="wpauditor-dashboard">';
    if ($filter_event !== '') echo '<input type="hidden" name="event_type" value="' . esc_attr($filter_event) . '">';
    if ($filter_category !== '') echo '<input type="hidden" name="category" value="' . esc_attr($filter_category) . '">';
    echo '<label class="wpa-dashboard-filter-field"><span>Time range</span><select name="window" aria-label="Time range">';
    $dashboard_windows = ['24h', '7d', '30d', '45d', 'all'];
    foreach ($dashboard_windows as $window_key) {
        $window_label = $window_defs[$window_key]['label'] ?? $window_key;
        if ($window_key === '24h') $window_label = 'Last 24 hours';
        if ($window_key === 'all') $window_label = 'All time';
        echo '<option value="' . esc_attr($window_key) . '" ' . selected($filter_window, $window_key, false) . '>' . esc_html($window_label) . '</option>';
    }
    if ($filter_window === '') echo '<option value="" selected>Custom dates</option>';
    echo '</select></label>';
    echo '<label class="wpa-dashboard-filter-field"><span>Severity</span><select name="severity" aria-label="Severity">';
    echo '<option value="">All severities</option>';
    foreach (['CRITICAL','HIGH','MEDIUM','LOW','INFO'] as $severity_option) {
        echo '<option value="' . esc_attr($severity_option) . '" ' . selected($filter_severity, $severity_option, false) . '>' . esc_html(ucfirst(strtolower($severity_option))) . '</option>';
    }
    echo '</select></label>';
    echo '</form>';
    echo '</div>';

    if ($date_range_error !== '') {
        echo '<div class="notice notice-error inline"><p>' . esc_html($date_range_error) . '</p></div>';
    }

    $metric_event_args = [
        'page'       => 'wpauditor-security-events',
        'event_type' => $filter_event,
        'severity'   => $filter_severity,
        'category'   => $filter_category,
        'window'     => $filter_window,
        'start_date' => $filter_start,
        'end_date'   => $filter_end,
        'paged'      => 1,
    ];
    $metric_event_args = array_filter($metric_event_args, static function($value) {
        return $value !== '';
    });
    $threat_events_url = add_query_arg($metric_event_args, admin_url('admin.php'));
    $priority_events_url = add_query_arg(array_merge($metric_event_args, [
        'severity' => 'CRITICAL_HIGH',
    ]), admin_url('admin.php'));
    $repeat_sources_label = sprintf(
        // translators: %s is the number of repeat sources.
        _n('%s Repeat Source', '%s Repeat Sources', $repeat_attacker_total, 'wpauditor'),
        number_format_i18n($repeat_attacker_total)
    );

    echo '<section class="wpa-soc-metrics" aria-label="Key security metrics">';
    echo '<a class="wpa-soc-metric wpa-soc-metric-events" href="' . esc_url($threat_events_url) . '" aria-label="View security events">';
    echo '<div class="wpa-soc-metric-label">Security Events</div>';
    echo '<div class="wpa-soc-metric-value">' . esc_html(number_format_i18n($total_filtered)) . '</div>';
    echo '<div class="wpa-soc-metric-context"><span class="wpa-soc-metric-dot" aria-hidden="true"></span>Current Filtered View</div>';
    echo '</a>';
    echo '<a class="wpa-soc-metric wpa-soc-metric-priority" href="' . esc_url($priority_events_url) . '" aria-label="View critical and high severity events">';
    echo '<div class="wpa-soc-metric-label">Critical &amp; High Severity</div>';
    echo '<div class="wpa-soc-metric-value">' . esc_html(number_format_i18n($critical_high_total)) . '</div>';
    echo '<div class="wpa-soc-metric-context"><span class="wpa-soc-metric-dot" aria-hidden="true"></span>Needs Review</div>';
    echo '</a>';
    echo '<a class="wpa-soc-metric wpa-soc-metric-attackers" href="' . esc_url($threat_events_url) . '" aria-label="View events from unique sources">';
    echo '<div class="wpa-soc-metric-label">Unique Sources</div>';
    echo '<div class="wpa-soc-metric-value">' . esc_html(number_format_i18n($unique_ip_total)) . '</div>';
    echo '<div class="wpa-soc-metric-context"><span class="wpa-soc-metric-dot" aria-hidden="true"></span>' . esc_html($repeat_sources_label) . '</div>';
    echo '</a>';
    echo '</section>';

    echo '<div class="wpa-kpi-grid wpa-soc-analysis-grid">';

    echo '<div class="wpa-kpi-card wpa-kpi-card-hero">';
    echo '<div class="wpa-reference-panel-head"><div><div class="wpa-kpi-title">Threat Overview</div></div></div>';
    echo '<div class="wpa-severity-chart-wrap"><canvas id="wpaSeverityChart" aria-label="Severity distribution chart" data-labels="' . esc_attr(wp_json_encode($sev_chart_labels)) . '" data-counts="' . esc_attr(wp_json_encode($sev_chart_counts)) . '" data-colors="' . esc_attr(wp_json_encode($sev_chart_colors)) . '" data-urls="' . esc_attr(wp_json_encode($sev_chart_urls)) . '"></canvas></div>';
    echo '</div>';

    echo '<div class="wpa-kpi-card wpa-kpi-card-hot">';
    echo '<div class="wpa-reference-panel-head"><div><div class="wpa-kpi-title">Hot Events</div></div><a href="' . esc_url(admin_url('admin.php?page=wpauditor-security-events')) . '">View events</a></div>';
    if (!empty($hot_categories)) {
        echo '<div class="wpa-hot-chart-wrap"><canvas id="wpaHotThreatsChart" aria-label="Top threat categories horizontal bar chart" data-labels="' . esc_attr(wp_json_encode($hot_threat_labels)) . '" data-counts="' . esc_attr(wp_json_encode($hot_threat_counts)) . '" data-urls="' . esc_attr(wp_json_encode($hot_threat_urls)) . '"></canvas></div>';
    } else {
        echo '<p class="wpa-empty-state">No threat categories in this view.</p>';
    }

    echo '</div>';

    echo '<div class="wpa-kpi-card wpa-kpi-card-attackers">';
    echo '<div class="wpa-reference-panel-head"><div><div class="wpa-kpi-title">Top IPs</div></div><a href="' . esc_url(admin_url('admin.php?page=wpauditor-security-events')) . '">Security events</a></div>';
    if (!empty($attacker_ip_counts)) {
        $top_attackers = array_slice($attacker_ip_counts, 0, 5, true);
        $top_attacker_max = (int) max($top_attackers);
        echo '<div class="wpa-ipintel-list">';
        foreach ($top_attackers as $ip => $count) {
            $cc = strtoupper(trim((string) ($attacker_ip_ccs[$ip] ?? '')));
            $cc_ok = (bool) preg_match('/^[A-Z0-9]{2}$/', $cc);
            $country = $cc_ok ? wpauditor_country_name_from_cc($cc) : '';
            $is_localhost = in_array(strtolower(trim((string) $ip)), ['localhost', '127.0.0.1', '::1'], true);
            $flag_url = $is_localhost
                ? wpauditor_flag_url_from_cc('unknown')
                : (($cc_ok && preg_match('/^[A-Z]{2}$/', $cc)) ? wpauditor_flag_url_from_cc($cc) : '');
            $geo_label = $is_localhost ? 'Unknown' : ($country ? ($cc . ' - ' . $country) : ($cc_ok ? $cc : 'Unknown'));
            $bar_width = ($top_attacker_max > 0) ? max(10, (int) round(($count / $top_attacker_max) * 100)) : 0;

            echo '<div class="wpa-ipintel-row">';
            echo '<div class="wpa-ipintel-top">';
            echo '<div class="wpa-ipintel-main">';
            echo '<span class="wpa-ipintel-ip">' . esc_html($ip) . '</span>';
            echo '<span class="wpa-ipintel-geo">';
            if ($flag_url) {
                $flag_alt = $is_localhost ? 'Unknown location' : ($cc . ' flag');
                echo '<img src="' . esc_url($flag_url) . '" alt="' . esc_attr($flag_alt) . '" loading="lazy" referrerpolicy="no-referrer">';
            }
            echo '<span>' . esc_html($geo_label) . '</span>';
            echo '</span>';
            echo '</div>';
            echo '<span class="wpa-ipintel-count">' . intval($count) . '</span>';
            echo '</div>';
            echo '<span class="wpa-ipintel-bar"><span style="width:' . esc_attr($bar_width) . '%;"></span></span>';
            echo '</div>';
        }
        echo '</div>';
    } else {
        echo '<p class="wpa-empty-state">No source IP data found in this view.</p>';
    }
    echo '</div>';

    echo '<div class="wpa-kpi-card wpa-kpi-card-targets">';
    echo '<div class="wpa-reference-panel-head"><div><div class="wpa-kpi-title">Top Endpoints</div></div><a href="' . esc_url(admin_url('admin.php?page=wpauditor-security-events')) . '">Investigate</a></div>';
    if (!empty($top_targeted_endpoints)) {
        echo '<div class="wpa-targeted-endpoint-list">';
        foreach ($top_targeted_endpoints as $endpoint => $endpoint_count) {
            echo '<div class="wpa-targeted-endpoint-row"><code>' . esc_html($endpoint) . '</code><strong>' . esc_html(number_format_i18n($endpoint_count)) . '</strong></div>';
        }
        echo '</div>';
    } else {
        echo '<p class="wpa-empty-state">No endpoint data in the current filtered view.</p>';
    }
    echo '</div>';

    echo '</div>';

    $recent_events_url = add_query_arg([
        'page'     => 'wpauditor-security-events',
        'window'   => $filter_window,
        'severity' => $filter_severity,
    ], admin_url('admin.php'));
    $recent_logs = array_slice($logs, 0, 5);
    echo '<section class="wpa-recent-events" aria-label="Recent events">';
    echo '<div class="wpa-recent-events-head">';
    echo '<div><h2>Recent Events</h2></div>';
    echo '<a href="' . esc_url($recent_events_url) . '">Open all security events</a>';
    echo '</div>';
    echo '<div class="wpa-recent-events-list">';
    if ($recent_logs) {
        foreach ($recent_logs as $recent_event) {
            $recent_severity = strtolower((string) ($recent_event['severity'] ?? 'info'));
            if (!in_array($recent_severity, ['critical','high','medium','low','info'], true)) $recent_severity = 'info';
            $recent_title = ucwords(strtolower(str_replace(['_', '-'], ' ', (string) ($recent_event['event'] ?? 'Security event'))));
            $recent_ip = filter_var($recent_event['ip'] ?? '', FILTER_VALIDATE_IP) ? (string) $recent_event['ip'] : 'Unknown source';
            $recent_uri = wp_parse_url((string) ($recent_event['uri'] ?? '/'), PHP_URL_PATH);
            $recent_uri = is_string($recent_uri) && $recent_uri !== '' ? $recent_uri : '/';
            $recent_timestamp = strtotime((string) ($recent_event['timestamp'] ?? ''));
            $recent_age = $recent_timestamp ? human_time_diff($recent_timestamp, $now_ts) . ' ago' : (string) ($recent_event['timestamp'] ?? '');

            echo '<article class="wpa-recent-event">';
            echo wp_kses_post(wpauditor_severity_badge_html($recent_severity));
            echo '<div class="wpa-recent-event-copy">';
            echo '<strong>' . esc_html($recent_title) . '</strong>';
            echo '<span><code>' . esc_html($recent_ip) . '</code> targeted <code>' . esc_html($recent_uri) . '</code></span>';
            echo '</div>';
            echo '<time datetime="' . esc_attr((string) ($recent_event['timestamp'] ?? '')) . '">' . esc_html($recent_age) . '</time>';
            echo '</article>';
        }
    } else {
        echo '<p class="wpa-kpi-subtle">No recent security activity in the current filtered view.</p>';
    }
    echo '</div>';
    echo '</section>';

    // Event summary panels.
    echo '<div class="wpa-summary-panels">';
    foreach ($summary_counts as $type => $count) {
        echo '<div class="wpa-summary-panel">';
        echo '<strong class="wpa-summary-panel-count">'.intval($count)."</strong><br><span class=\"wpa-summary-panel-label\">".esc_html($type).'</span>';
        echo '</div>';
    }
    echo '</div>';

    // Chart data.
    $all_dates = [];
    foreach ($graph_data as $counts) $all_dates = array_merge($all_dates, array_keys($counts));
    $all_dates = array_values(array_unique($all_dates));
    sort($all_dates);

    $series = [];
    foreach ($graph_data as $event => $counts) {
        $dataset = [];
        foreach ($all_dates as $d) { $dataset[] = (int)($counts[$d] ?? 0); }
        $series[$event] = $dataset;
    }

    $activity_counts = array_fill(0, count($all_dates), 0);
    foreach ($series as $dataset) {
        foreach ($dataset as $index => $count) {
            $activity_counts[$index] += (int) $count;
        }
    }
    $activity_peak = $activity_counts ? max($activity_counts) : 0;
    $series = ['All events' => $activity_counts];

    $sub_line = 'All time';
    if ($filter_window !== 'all') {
        if ($filter_start !== '' || $filter_end !== '') {
            $sub_line = trim($filter_start) . ' → ' . trim($filter_end);
        }
    }

    echo '<div class="wpa-chart-card">
      <div class="wpa-chart-head">
        <div>
          <div class="wpa-chart-title">Activity</div>
        </div>
        <a href="' . esc_url(admin_url('admin.php?page=wpauditor-security-events')) . '">Open security events</a>
      </div>';

    echo '<div class="wpa-chart-toolbar">';

    foreach ($window_defs as $key => $meta) {
        $args = array_merge($safe_query_args, [
            'window' => $key,
            'paged'  => 1,
        ]);

        if ($key === 'all') {
            $args['start_date'] = '';
            $args['end_date']   = '';
        } else {
            $secs = (int)$meta['secs'];
            $start_calc = max(0, $now_ts - $secs);
            $args['start_date'] = wp_date('Y-m-d', $start_calc);
            $args['end_date']   = $today_ymd;
        }

        $url = esc_url(add_query_arg($args));
        $active = ($filter_window === $key) ? 'wpa-chip-active' : '';
        echo '<a class="wpa-chip ' . esc_attr($active) . '" href="' . esc_url($url) . '">' . esc_html($meta['label']) . '</a> ';
    }

    $custom_active = ($filter_window === '');
    $custom_label = 'Custom';
    if ($custom_active && $filter_start && $filter_end) {
        $custom_label = 'Custom: ' . $filter_start . ' → ' . $filter_end;
    }
    echo '<span class="wpa-chip '.($custom_active ? 'wpa-chip-active' : '').'">'.esc_html($custom_label).'</span>';

    echo '</div>';

    echo '  <div class="wpa-chart-wrap">
        <canvas id="socChart" data-labels="' . esc_attr(wp_json_encode($all_dates)) . '" data-series="' . esc_attr(wp_json_encode($series)) . '"></canvas>
      </div>
      <div class="wpa-activity-footer"><span class="wpa-activity-series"><span class="wpa-activity-dot" aria-hidden="true"></span>All events</span><span>Peak: ' . esc_html(number_format_i18n($activity_peak)) . ' events/day</span><span>' . esc_html($sub_line) . '</span></div>
    </div>';
    }

    if ($view === 'security_events') {
    echo '<div class="wpa-security-events-header">';
    echo '<h1 class="wpa-page-title">Security Events</h1>';
    echo '<h2 id="wpaLiveHead" class="wpa-live-head">';
    echo '  <span class="wpa-live-title">';
    echo '    <button type="button" id="wpaLiveToggle" class="wpa-live-toggle wpa-header-icon-button" aria-pressed="false" aria-label="Start live refresh" title="Start live refresh">';
    echo '      <svg class="wpa-live-play-icon" width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden="true">';
    echo '        <path d="M5 3.5L12 8L5 12.5V3.5Z" fill="currentColor"></path>';
    echo '      </svg>';
    echo '      <svg class="wpa-live-pause-icon" width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden="true">';
    echo '        <path d="M4.5 3.5H6.5V12.5H4.5V3.5ZM9.5 3.5H11.5V12.5H9.5V3.5Z" fill="currentColor"></path>';
    echo '      </svg>';
    echo '      <span class="screen-reader-text wpa-live-toggle-label">Start live refresh</span>';
    echo '    </button>';
    echo '  </span>';
    echo '</h2>';
    echo '</div>';

    if ($date_range_error !== '') {
        echo '<div class="notice notice-error inline"><p>' . esc_html($date_range_error) . '</p></div>';
    }

    // Event count cards.
    $event_summary_total = array_sum($event_summary_counts);
    $event_card_accents = ['blue', 'red', 'orange', 'green', 'purple', 'cyan'];
    $total_event_url = esc_url(add_query_arg([
        'page'       => $current_page_slug,
        'event_type' => '',
        'severity'   => $filter_severity,
        'category'   => $filter_category,
        'window'     => $filter_window,
        'start_date' => $filter_start,
        'end_date'   => $filter_end,
        'paged'      => 1,
    ], admin_url('admin.php')));

    echo '<section class="wpa-event-count-grid" aria-label="Event counts">';
    echo '<a class="wpa-event-count-card wpa-event-count-accent-blue' . ($filter_event === '' ? ' is-active' : '') . '" href="' . esc_url($total_event_url) . '">';
    echo '<strong>' . esc_html(number_format_i18n($event_summary_total)) . '</strong>';
    echo '<span>Total Events</span>';
    echo '</a>';

    $event_card_index = 0;
    foreach ($event_summary_counts as $event_name => $event_count) {
        $accent = $event_card_accents[$event_card_index % count($event_card_accents)];
        $event_url = esc_url(add_query_arg([
            'page'       => $current_page_slug,
            'event_type' => $event_name,
            'severity'   => $filter_severity,
            'category'   => $filter_category,
            'window'     => $filter_window,
            'start_date' => $filter_start,
            'end_date'   => $filter_end,
            'paged'      => 1,
        ], admin_url('admin.php')));
        $active_class = ($filter_event === $event_name) ? ' is-active' : '';

        echo '<a class="wpa-event-count-card wpa-event-count-accent-' . esc_attr($accent) . esc_attr($active_class) . '" href="' . esc_url($event_url) . '" title="Filter by ' . esc_attr($event_name) . '">';
        echo '<strong>' . esc_html(number_format_i18n($event_count)) . '</strong>';
        echo '<span>' . esc_html($event_name) . '</span>';
        echo '</a>';
        $event_card_index++;
    }
    echo '</section>';

    // Filter form.
    echo '<form method="get" id="wpaSocFilterForm" class="wpa-filter-bar">';
    echo '<input type="hidden" name="page" value="' . esc_attr($current_page_slug) . '" />';
    echo '<input type="hidden" name="window" id="wpaSocWindow" value="' . esc_attr($filter_window) . '" />';
    if ($filter_category !== '') {
        echo '<input type="hidden" name="category" value="' . esc_attr($filter_category) . '" />';
    }

    echo '<div class="wpa-filter-fields">';
    echo '<label class="wpa-filter-field" for="wpaEventType"><span>Event</span>';
    echo '<select id="wpaEventType" name="event_type"><option value="">All Events</option>';
    foreach (array_keys($event_types) as $event) {
        $event_label = ucwords(strtolower(str_replace('_', ' ', $event)));
        $event_label = str_replace(['Http', 'Sql', 'Xss', 'Php', 'Xml', 'Rpc', 'Api'], ['HTTP', 'SQL', 'XSS', 'PHP', 'XML', 'RPC', 'API'], $event_label);
        echo '<option value="' . esc_attr($event) . '" ' . selected($event, $filter_event, false) . '>' . esc_html($event_label) . '</option>';
    }
    echo '</select></label>';

    echo '<label class="wpa-filter-field" for="wpaSeverity"><span>Severity</span>';
    echo '<select id="wpaSeverity" name="severity"><option value="">All Severities</option>';
    $severity_filter_labels = [
        'CRITICAL_HIGH' => 'Critical & High',
        'CRITICAL'      => 'Critical',
        'HIGH'          => 'High',
        'MEDIUM'        => 'Medium',
        'LOW'           => 'Low',
        'INFO'          => 'Info',
    ];
    foreach ($severity_filter_labels as $lvl => $severity_label) {
        echo '<option value="' . esc_attr($lvl) . '" ' . selected($filter_severity, $lvl, false) . '>' . esc_html($severity_label) . '</option>';
    }
    echo '</select></label>';

    echo '<label class="wpa-filter-field" for="wpaStartDate"><span>From</span>';
    echo '<input type="date" id="wpaStartDate" name="start_date" value="' . esc_attr($filter_start) . '" max="' . esc_attr($filter_end) . '" />';
    echo '</label>';

    echo '<label class="wpa-filter-field" for="wpaEndDate"><span>To</span>';
    echo '<input type="date" id="wpaEndDate" name="end_date" value="' . esc_attr($filter_end) . '" min="' . esc_attr($filter_start) . '" />';
    echo '</label>';
    echo '</div>';

    $filters_active = $filter_event !== ''
        || $filter_severity !== ''
        || $filter_category !== ''
        || $filter_start !== ''
        || $filter_end !== ''
        || $filter_window !== 'all';
    $reset_url = esc_url(add_query_arg(['page' => $current_page_slug], admin_url('admin.php')));

    echo '<div class="wpa-filter-actions">';
    echo '<button type="submit" class="button button-primary">Apply Filters</button>';
    if ($filters_active) {
        echo '<a class="button" href="' . esc_url($reset_url) . '">Reset</a>';
    }
    echo '</div>';

    if ($filter_category !== '') {
        $clear_cat_url = esc_url(remove_query_arg(['category','paged']));
        echo '<div class="wpa-filter-context">';
        echo '<span>Category: <strong>' . esc_html($filter_category) . '</strong></span>';
        echo '<a href="' . esc_url($clear_cat_url) . '">Clear category</a>';
        echo '</div>';
    }
    echo '</form>';

    ob_start();
    ?>
    (function(){
        var start = document.getElementById('wpaStartDate');
        var end = document.getElementById('wpaEndDate');
        if (!start || !end) return;

        function validateDateRange(){
            start.max = end.value;
            end.min = start.value;
            end.setCustomValidity(start.value && end.value && start.value > end.value
                ? 'The To date must be later than or equal to the From date.'
                : '');
        }

        start.addEventListener('input', validateDateRange);
        end.addEventListener('input', validateDateRange);
        validateDateRange();
    })();
    <?php
    $date_range_script = ob_get_clean();
    wp_add_inline_script('wpauditor-admin-ui', $date_range_script, 'after');

    // Logs table + live header UI.
    $total_logs  = count($logs);
    $total_pages = max(1, (int)ceil($total_logs / $per_page));
    $start       = ($page - 1) * $per_page;
    $logs_page   = array_slice($logs, $start, $per_page);

    echo '<div id="wpaSecurityEventsResults">';
    echo '<div class="wpa-logs-container">';
    echo '<table class="widefat striped wpa-table">';
    echo '<thead><tr>
        <th>Timestamp</th><th>Event</th><th>Category</th><th>IP</th>
        <th>Method</th><th>Severity</th><th>URI</th><th>Actions</th>
    </tr></thead><tbody>';

    $row_idx = 0;
    foreach ($logs_page as $e) {
        $mitre_url = function_exists('wpauditor_get_mitre_technique_url')
            ? wpauditor_get_mitre_technique_url((string) $e['mitre_technique'])
            : '';
        $owasp = function_exists('wpauditor_get_owasp_for_event')
            ? wpauditor_get_owasp_for_event((string) $e['event'], (string) $e['category'], (string) $e['details'])
            : null;

        echo '<tr>';
        echo '<td>' . esc_html($e['timestamp']) . '</td>';
        echo '<td>' . esc_html($e['event']) . '</td>';
        echo '<td>' . esc_html($e['category']) . '</td>';

        $cc = strtoupper(trim((string)($e['cc'] ?? '')));
        $cc_ok = (bool) preg_match('/^[A-Z0-9]{2}$/', $cc);
        $country = $cc_ok ? wpauditor_country_name_from_cc($cc) : '';
        $is_localhost = in_array(strtolower(trim((string) $e['ip'])), ['localhost', '127.0.0.1', '::1'], true);
        $flag_url = $is_localhost
            ? wpauditor_flag_url_from_cc('unknown')
            : (($cc_ok && preg_match('/^[A-Z]{2}$/', $cc)) ? wpauditor_flag_url_from_cc($cc) : '');

        echo '<td>';
        echo '<div class="wpa-ipcell">';
        echo '<div><span class="wpa-copy" data-copy="'.esc_attr($e['ip']).'" title="Click to copy IP">'.esc_html($e['ip']).'</span></div>';
        if ($cc_ok || $is_localhost) {
            $title = $is_localhost ? 'Unknown location' : ($country ? ($cc . ' - ' . $country) : $cc);
            $copy_geo = $is_localhost ? 'Unknown location' : ($country ? ($cc . ' - ' . $country) : $cc);
            echo '<div class="wpa-geo wpa-copy" data-copy="'.esc_attr($copy_geo).'" title="'.esc_attr($title).'">';
            if ($flag_url) {
                $flag_alt = $is_localhost ? 'Unknown location' : ($cc . ' flag');
                echo '<img src="'.esc_url($flag_url).'" alt="'.esc_attr($flag_alt).'" loading="lazy" referrerpolicy="no-referrer">';
            }
            echo '<span class="wpa-cc">'.esc_html($is_localhost ? 'Unknown' : $cc).'</span>';
            if ($country && !$is_localhost) echo '<span class="wpa-country">'.esc_html($country).'</span>';
            echo '</div>';
        }
        echo '</div>';
        echo '</td>';

        echo '<td>' . esc_html($e['method']) . '</td>';
        echo '<td>' . wp_kses_post(wpauditor_severity_badge_html((string) $e['severity'])) . '</td>';

        echo '<td title="' . esc_attr($e['uri']) . '"><div class="wpa-truncate wpa-mono"><span class="wpa-copy" data-copy="'.esc_attr($e['uri']).'" title="Click to copy URI">'.esc_html($e['uri']) . '</span></div></td>';

        echo '<td>';
        echo '<button type="button" class="button button-small wpa-action-icon-btn wpa-expand-btn" data-target="' . esc_attr('wpa-expand-' . $row_idx) . '" aria-label="Expand log entry" aria-expanded="false" aria-controls="' . esc_attr('wpa-expand-' . $row_idx) . '" title="Expand">';
        echo '<span class="dashicons dashicons-arrow-down-alt2" aria-hidden="true"></span><span class="screen-reader-text">Expand</span>';
        echo '</button>';
        echo '</td>';
        echo '</tr>';

        echo '<tr id="' . esc_attr('wpa-expand-' . $row_idx) . '" class="wpa-expand-row" aria-hidden="true">';
        echo '<td colspan="8"><div class="wpa-expand-box">';
        echo '<div class="wpa-expanded-details">';
        echo '<div class="wpa-expanded-detail"><strong>Full URI</strong><br><code class="wpa-mono"><span class="wpa-copy" data-copy="'.esc_attr($e['uri']).'" title="Click to copy URI">'.esc_html($e['uri']).'</span></code></div>';
        echo '<div class="wpa-expanded-detail"><strong>Full Details</strong><br><code><span class="wpa-copy" data-copy="'.esc_attr($e['details']).'" title="Click to copy Details">'.esc_html($e['details']).'</span></code></div>';
        echo '<div class="wpa-expanded-detail"><strong>MITRE ATT&amp;CK</strong><br>'
            . ($e['mitre_technique'] && $mitre_url
                ? '<a href="'.esc_url($mitre_url).'" target="_blank" rel="noopener">'.esc_html($e['mitre_technique']).'</a><br><small class="wpa-subtle">' . esc_html($e['mitre_tactic']) . '</small>'
                : '<span class="wpa-subtle">N/A</span>')
            . '</div>';
        echo '<div class="wpa-expanded-detail"><strong>OWASP Top 10 (2025)</strong><br>'
            . ($owasp
                ? '<a href="'.esc_url($owasp['url']).'" target="_blank" rel="noopener">'.esc_html($owasp['id'] . ' - ' . $owasp['name']).'</a><br><small class="wpa-subtle">' . esc_html($owasp['cwe']) . '</small>'
                : '<span class="wpa-subtle">N/A</span>')
            . '</div>';
        echo '</div>';
        echo '<div class="wpa-subtle wpa-mt-8"><strong>User Agent</strong><br><span class="wpa-copy" data-copy="'.esc_attr($e['ua']).'" title="Click to copy User-Agent">'.esc_html($e['ua']).'</span></div>';
        echo '</div></td></tr>';
        $row_idx++;
    }
    echo '</tbody></table></div>';

    if ($total_pages > 1) {
        echo '<div class="tablenav-pages wpa-mt-20">';
        for ($i = 1; $i <= $total_pages; $i++) {
            $pagination_args = [
                'page'  => 'wpauditor-security-events',
                'paged' => $i,
            ];
            foreach (['event_type', 'start_date', 'end_date', 'severity', 'category', 'window'] as $filter_key) {
                if (!isset($_GET[$filter_key]) || !is_scalar($_GET[$filter_key])) continue;
                $pagination_args[$filter_key] = sanitize_text_field(wp_unslash((string) $_GET[$filter_key]));
            }
            $url = add_query_arg($pagination_args, admin_url('admin.php'));
            $class = ($i === $page) ? 'wpa-page-current' : '';
            echo '<a href="' . esc_url($url) . '" class="' . esc_attr($class) . '">' . esc_html((string) $i) . '</a> ';
        }
        echo '</div>';
    }
    echo '</div>';
    }

    echo '</div>'; // .wrap

    $chartjs_ver = '4.5.1';
    $chartjs_path = plugin_dir_path(WPAUDITOR_MAIN_FILE) . 'includes/ui/assets/chart.umd.min.js';
    $chartjs_url = plugins_url('includes/ui/assets/chart.umd.min.js', WPAUDITOR_MAIN_FILE);
    $chartjs_asset_ver = file_exists($chartjs_path) ? (string) filemtime($chartjs_path) : $chartjs_ver;

    wp_register_script('wpauditor_chartjs', $chartjs_url, [], $chartjs_asset_ver, true);
    wp_enqueue_script('wpauditor_chartjs');

    $labels_json = wp_json_encode($all_dates);
    $series_json = wp_json_encode($series);
    $colors_json = wp_json_encode($is_light_theme ? [
      "#3858e9","#008a20","#7047a3","#007cba","#008a8c","#646970",
      "#5b5bd6","#b26200","#d63638","#996800","#2271b1","#50575e",
      "#4f46a5","#006b1a","#8a4b00","#b32d2e","#3858e9","#007cba",
      "#7047a3","#008a8c","#646970","#996800","#b26200","#d63638"
    ] : [
      "#76b7f2","#a3be8c","#b48ead","#81a1c1","#8fbcbb","#8d98b7",
      "#b2cbce","#ddc6ba","#c5e0fb","#cab7d8","#f8d6d1","#bedbdd",
      "#88c0d0","#81a1c1","#5e81ac","#4c566a","#a3be8c","#8fbcbb",
      "#d08770","#ebcb8b","#e5e9f0","#d8dee9","#bf616a","#b48ead"
    ]);
    $sev_chart_labels = ['Critical', 'High', 'Medium', 'Low', 'Info'];
    $sev_chart_counts = [
        (int) ($severity_counts['CRITICAL'] ?? 0),
        (int) ($severity_counts['HIGH'] ?? 0),
        (int) ($severity_counts['MEDIUM'] ?? 0),
        (int) ($severity_counts['LOW'] ?? 0),
        (int) ($severity_counts['INFO'] ?? 0),
    ];
    $sev_chart_colors = ['#fb7185', '#fb923c', '#facc15', '#4ade80', '#93c5fd'];
    $sev_chart_url_filters = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    $sev_labels_json = wp_json_encode($sev_chart_labels);
    $sev_counts_json = wp_json_encode($sev_chart_counts);
    $sev_chart_colors_json = wp_json_encode($sev_chart_colors);
    $sev_urls_json = wp_json_encode(array_map(static function($severity) use ($safe_query_args) {
        return esc_url_raw(add_query_arg(array_merge($safe_query_args, [
            'page'     => 'wpauditor-security-events',
            'severity' => $severity,
            'paged'    => 1,
        ]), admin_url('admin.php')));
    }, $sev_chart_url_filters));
    $targeted_endpoint_labels_json = wp_json_encode(array_values(array_map('strval', array_keys($top_targeted_endpoints))));
    $targeted_endpoint_counts_json = wp_json_encode(array_values(array_map('intval', $top_targeted_endpoints)));
    $hot_threat_labels_json = wp_json_encode(array_values(array_map('strval', array_keys($hot_categories))));
    $hot_threat_counts_json = wp_json_encode(array_values(array_map('intval', $hot_categories)));
    $hot_threat_urls_json = wp_json_encode(array_values(array_map(static function($category_name) use ($safe_query_args) {
        return esc_url_raw(add_query_arg(array_merge($safe_query_args, [
            'page'     => 'wpauditor-security-events',
            'category' => $category_name,
            'paged'    => 1,
        ]), admin_url('admin.php')));
    }, array_keys($hot_categories))));
    $refresh_nonce_json = wp_json_encode($refresh_nonce);
    $refresh_view_json = wp_json_encode($view);
    $inline_js = <<<'JS'
(function(){
  const LS_TYPE = "wpa_soc_chart_type_v2";
  const LS_STACK = "wpa_soc_chart_stacked_v1";
  const LS_LIVE = "wpa_auto_refresh"; // keep same key for compatibility
  const WPA_REFRESH_NONCE = __WPA_REFRESH_NONCE__;
  const WPA_REFRESH_VIEW = __WPA_REFRESH_VIEW__;
  const WPA_REFRESH_INTERVAL = 10000;
  const WPA_NATIVE_FONT_FAMILY = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif';
  const WPA_SOC_DARK = !document.body.classList.contains("wpauditor-theme-light");
  const WPA_CHART_TEXT_COLOR = WPA_SOC_DARK ? "#dce7f5" : "#374151";
  const WPA_CHART_MUTED_COLOR = WPA_SOC_DARK ? "#91a3bb" : "#6b7280";
  const WPA_CHART_GRID_COLOR = WPA_SOC_DARK ? "rgba(148,163,184,0.16)" : "rgba(0,0,0,0.06)";
  const WPA_CHART_VALUE_COLOR = WPA_SOC_DARK ? "#f8fafc" : "#1d2327";
  const WPA_CHART_ACCENT_BORDER = WPA_SOC_DARK ? "#2271b1" : "#2846cc";

  function readCanvasData(canvas, key, fallback){
    if (!canvas) return fallback;
    try {
      var value = canvas.getAttribute("data-" + key);
      return value ? JSON.parse(value) : fallback;
    } catch(e) {
      return fallback;
    }
  }

  function hexToRgba(hex, a){
    var h = (hex || "").replace("#","");
    if (h.length !== 6) return "rgba(0,0,0,"+a+")";
    var r = parseInt(h.slice(0,2),16);
    var g = parseInt(h.slice(2,4),16);
    var b = parseInt(h.slice(4,6),16);
    return "rgba("+r+","+g+","+b+","+a+")";
  }

  function getSavedType(){
    var t = (localStorage.getItem(LS_TYPE) || "line").toLowerCase();
    return (t === "line") ? "line" : "bar";
  }
  function getSavedStacked(){
    var v = localStorage.getItem(LS_STACK);
    if (v === null) return true;
    return (v === "1");
  }
  function setSavedType(t){ localStorage.setItem(LS_TYPE, t); }
  function setSavedStacked(on){ localStorage.setItem(LS_STACK, on ? "1" : "0"); }

  function buildDatasets(type, stacked, series){
    var baseColors = __WPA_COLORS__;

    var entries = Object.entries(series || {});
    return entries.map(function(pair, i){
      var name = pair[0];
      var data = pair[1];
      var c = baseColors[i % baseColors.length];

      if (type === "line") {
        return {
          label: name,
          data: data,
          borderColor: hexToRgba(c, 0.95),
          backgroundColor: hexToRgba(c, 0.18),
          borderWidth: 2,
          tension: 0.35,
          fill: true,
          pointRadius: 2,
          pointHoverRadius: 4
        };
      }

      return {
        label: name,
        data: data,
        backgroundColor: hexToRgba(c, 0.60),
        borderColor: hexToRgba(c, 0.95),
        borderWidth: 1,
        borderRadius: 7,
        borderSkipped: false,
        maxBarThickness: 22,
        stack: stacked ? "events" : undefined
      };
    });
  }

  function renderChart(type, stacked){
    var canvas = document.getElementById("socChart");
    if (!canvas || typeof Chart === "undefined") return;

    var series = readCanvasData(canvas, "series", __WPA_SERIES__);
    var labels = readCanvasData(canvas, "labels", __WPA_LABELS__);
    if (!series || !Object.keys(series).length) return;

    if (window.wpaSocChart) { try { window.wpaSocChart.destroy(); } catch(e){} }

    var isLine = (type === "line");
    var useStacked = isLine ? false : !!stacked;
    var datasets = buildDatasets(type, useStacked, series);

    window.wpaSocChart = new Chart(canvas.getContext("2d"), {
      type: type,
      data: { labels: labels, datasets: datasets },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        normalized: true,
        animation: { duration: 550, easing: "easeOutQuart" },
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: {
            display: false,
            position: "bottom",
            labels: {
              usePointStyle: true,
              pointStyle: isLine ? "circle" : "rectRounded",
              boxWidth: 10,
              padding: 14,
              font: { size: 12 }
            }
          },
          tooltip: {
            backgroundColor: "rgba(17,24,39,0.92)",
            borderColor: "rgba(255,255,255,0.15)",
            borderWidth: 1,
            padding: 10,
            cornerRadius: 10,
            callbacks: {
              title: function(items){
                return items && items[0] && items[0].label ? ("Date: " + items[0].label) : "";
              },
              label: function(item){
                return (item.dataset.label + ": " + item.parsed.y);
              }
            }
          }
        },
        scales: {
          x: { stacked: useStacked, grid: { display: false }, ticks: { autoSkip: true, maxRotation: 0, font: { size: 11 } } },
          y: { stacked: useStacked, beginAtZero: true, grid: { color: WPA_CHART_GRID_COLOR }, ticks: { precision: 0, font: { size: 11 } }, title: { display: true, text: "Events", color: WPA_CHART_MUTED_COLOR } }
        }
      }
    });
  }

  function renderSeverityChart(){
    var canvas = document.getElementById("wpaSeverityChart");
    if (!canvas || typeof Chart === "undefined") return;

    var labels = readCanvasData(canvas, "labels", __WPA_SEVERITY_LABELS__);
    var counts = readCanvasData(canvas, "counts", __WPA_SEVERITY_COUNTS__);
    var colors = readCanvasData(canvas, "colors", __WPA_SEVERITY_COLORS__);
    var urls = readCanvasData(canvas, "urls", __WPA_SEVERITY_URLS__);
    if (!Array.isArray(labels) || !Array.isArray(counts) || !labels.length) return;

    if (window.wpaSeverityChart) { try { window.wpaSeverityChart.destroy(); } catch(e){} }

    var centerLabelPlugin = {
      id: "wpaSeverityCenterLabel",
      afterDraw: function(chart){
        var meta = chart.getDatasetMeta(0);
        var arc = meta && meta.data && meta.data[0] ? meta.data[0] : null;
        if (!arc) return;

        var x = arc.x;
        var y = arc.y;
        var ctx = chart.ctx;
        var visibleTotal = chart.data.datasets[0].data.reduce(function(total, value, index){
          return chart.getDataVisibility(index) ? total + (Number(value) || 0) : total;
        }, 0);
        var visibleTotalLabel = new Intl.NumberFormat().format(visibleTotal);

        ctx.save();
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillStyle = WPA_CHART_VALUE_COLOR;
        ctx.font = "400 30px " + WPA_NATIVE_FONT_FAMILY;
        ctx.fillText(visibleTotalLabel, x, y - 6);
        ctx.fillStyle = WPA_CHART_MUTED_COLOR;
        ctx.font = "400 10px " + WPA_NATIVE_FONT_FAMILY;
        ctx.fillText("events", x, y + 16);
        ctx.restore();
      }
    };

    window.wpaSeverityChart = new Chart(canvas.getContext("2d"), {
      type: "doughnut",
      data: {
        labels: labels,
        datasets: [{
          data: counts,
          backgroundColor: colors,
          borderColor: colors,
          borderWidth: 0,
          spacing: 0,
          hoverOffset: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "60%",
        animation: { duration: 500, easing: "easeOutQuart" },
        onClick: function(evt, elements){
          if (!elements || !elements.length) return;
          var index = elements[0].index;
          if (typeof urls[index] === "string" && urls[index]) window.location.href = urls[index];
        },
        plugins: {
          legend: {
            display: true,
            position: window.matchMedia("(max-width: 782px)").matches ? "bottom" : "right",
            labels: {
              usePointStyle: true,
              pointStyle: "circle",
              boxWidth: 8,
              boxHeight: 8,
              padding: 14,
              color: WPA_CHART_MUTED_COLOR,
              font: { size: 11, weight: "400", family: WPA_NATIVE_FONT_FAMILY },
              generateLabels: function(chart){
                var legendLabels = Chart.overrides.doughnut.plugins.legend.labels.generateLabels(chart);
                return legendLabels.map(function(label){
                  var value = Number(chart.data.datasets[0].data[label.index]) || 0;
                  label.text += ": " + new Intl.NumberFormat().format(value);
                  return label;
                });
              }
            }
          },
          tooltip: {
            backgroundColor: "rgba(17,24,39,0.92)",
            borderColor: "rgba(255,255,255,0.15)",
            borderWidth: 1,
            padding: 10,
            cornerRadius: 10,
            callbacks: {
              label: function(context){
                var value = context.parsed || 0;
                return context.label + ": " + value;
              }
            }
          }
        }
      },
      plugins: [centerLabelPlugin]
    });
  }

  function wrapChartLabel(label, maxLength){
    var words = String(label || "").trim().split(/\s+/);
    var lines = [];
    var current = "";

    words.forEach(function(word){
      if (word.length > maxLength) {
        if (current) {
          lines.push(current);
          current = "";
        }
        for (var start = 0; start < word.length; start += maxLength) {
          lines.push(word.slice(start, start + maxLength));
        }
        return;
      }

      var candidate = current ? current + " " + word : word;
      if (candidate.length > maxLength && current) {
        lines.push(current);
        current = word;
      } else {
        current = candidate;
      }
    });

    if (current) lines.push(current);
    return lines.length ? lines : [String(label || "")];
  }

  function renderHotThreatsChart(){
    var canvas = document.getElementById("wpaHotThreatsChart");
    if (!canvas || typeof Chart === "undefined") return;

    var labels = readCanvasData(canvas, "labels", __WPA_THREAT_LABELS__);
    var counts = readCanvasData(canvas, "counts", __WPA_THREAT_COUNTS__);
    var urls = readCanvasData(canvas, "urls", __WPA_THREAT_URLS__);
    if (!Array.isArray(labels) || !Array.isArray(counts) || !labels.length) return;

    if (window.wpaHotThreatsChart) {
      try { window.wpaHotThreatsChart.destroy(); } catch(e){}
    }

    var valueLabelPlugin = {
      id: "wpaHotThreatValues",
      afterDatasetsDraw: function(chart){
        var meta = chart.getDatasetMeta(0);
        if (!meta || !meta.data) return;

        var ctx = chart.ctx;
        ctx.save();
        ctx.font = "400 11px " + WPA_NATIVE_FONT_FAMILY;
        ctx.textBaseline = "middle";

        meta.data.forEach(function(bar, index){
          var label = new Intl.NumberFormat().format(Number(counts[index]) || 0);
          var labelWidth = ctx.measureText(label).width;
          var roomOnRight = chart.chartArea.right - bar.x;
          var placeInside = roomOnRight < labelWidth + 12;

          ctx.textAlign = placeInside ? "right" : "left";
          ctx.fillStyle = placeInside ? "#ffffff" : WPA_CHART_VALUE_COLOR;
          ctx.fillText(label, placeInside ? bar.x - 6 : bar.x + 6, bar.y);
        });

        ctx.restore();
      }
    };

    window.wpaHotThreatsChart = new Chart(canvas.getContext("2d"), {
      type: "bar",
      data: {
        labels: labels,
        datasets: [{
          label: "Events",
          data: counts,
          backgroundColor: "#3858e9",
          borderWidth: 0,
          borderRadius: 6,
          borderSkipped: false,
          maxBarThickness: 18
        }]
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 440, easing: "easeOutQuart" },
        interaction: { mode: "nearest", intersect: true },
        layout: { padding: { right: 34 } },
        onClick: function(evt, elements){
          if (!elements || !elements.length) return;
          var index = elements[0].index;
          if (typeof urls[index] === "string" && urls[index]) window.location.href = urls[index];
        },
        onHover: function(evt, elements){
          var target = evt && evt.native ? evt.native.target : null;
          if (target) target.style.cursor = elements && elements.length ? "pointer" : "default";
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "rgba(17,24,39,0.94)",
            borderColor: "rgba(255,255,255,0.15)",
            borderWidth: 1,
            padding: 10,
            cornerRadius: 10,
            callbacks: {
              title: function(items){
                return items && items.length ? labels[items[0].dataIndex] : "Threat category";
              },
              label: function(context){
                return "Events: " + (context.parsed.x || 0);
              }
            }
          }
        },
        scales: {
          x: {
            beginAtZero: true,
            ticks: { precision: 0, color: WPA_CHART_MUTED_COLOR },
            grid: { color: WPA_CHART_GRID_COLOR },
            border: { display: false }
          },
          y: {
            ticks: {
              autoSkip: false,
              color: WPA_CHART_TEXT_COLOR,
              font: { size: 11, weight: "400", family: WPA_NATIVE_FONT_FAMILY },
              callback: function(value){
                return wrapChartLabel(this.getLabelForValue(value), 20);
              }
            },
            grid: { display: false },
            border: { display: false }
          }
        }
      },
      plugins: [valueLabelPlugin]
    });
  }

  function renderTargetedEndpointsChart(){
    var canvas = document.getElementById("wpaTargetedEndpointsChart");
    if (!canvas || typeof Chart === "undefined") return;

    var labels = __WPA_ENDPOINT_LABELS__;
    var counts = __WPA_ENDPOINT_COUNTS__;
    if (!Array.isArray(labels) || !Array.isArray(counts) || !labels.length) return;

    if (window.wpaTargetedEndpointsChart) {
      try { window.wpaTargetedEndpointsChart.destroy(); } catch(e){}
    }

    var valueLabelPlugin = {
      id: "wpaTargetedEndpointValues",
      afterDatasetsDraw: function(chart){
        var meta = chart.getDatasetMeta(0);
        if (!meta || !meta.data) return;

        var ctx = chart.ctx;
        ctx.save();
        ctx.font = "400 11px " + WPA_NATIVE_FONT_FAMILY;
        ctx.textBaseline = "middle";

        meta.data.forEach(function(bar, index){
          var label = new Intl.NumberFormat().format(Number(counts[index]) || 0);
          var labelWidth = ctx.measureText(label).width;
          var roomOnRight = chart.chartArea.right - bar.x;
          var placeInside = roomOnRight < labelWidth + 12;

          ctx.textAlign = placeInside ? "right" : "left";
          ctx.fillStyle = placeInside ? "#ffffff" : WPA_CHART_VALUE_COLOR;
          ctx.fillText(label, placeInside ? bar.x - 6 : bar.x + 6, bar.y);
        });

        ctx.restore();
      }
    };

    window.wpaTargetedEndpointsChart = new Chart(canvas.getContext("2d"), {
      type: "bar",
      data: {
        labels: labels,
        datasets: [{
          label: "Events",
          data: counts,
          backgroundColor: "#3858e9",
          borderColor: WPA_CHART_ACCENT_BORDER,
          borderWidth: 1,
          borderRadius: 6,
          borderSkipped: false,
          maxBarThickness: 18
        }]
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 440, easing: "easeOutQuart" },
        interaction: { mode: "nearest", intersect: true },
        layout: { padding: { right: 34 } },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "rgba(17,24,39,0.94)",
            borderColor: "rgba(255,255,255,0.15)",
            borderWidth: 1,
            padding: 10,
            cornerRadius: 10,
            callbacks: {
              title: function(items){
                return items && items.length ? labels[items[0].dataIndex] : "Endpoint";
              },
              label: function(context){
                return "Events: " + (context.parsed.x || 0);
              }
            }
          }
        },
        scales: {
          x: {
            beginAtZero: true,
            ticks: { precision: 0, color: WPA_CHART_MUTED_COLOR },
            grid: { color: WPA_CHART_GRID_COLOR },
            border: { display: false }
          },
          y: {
            ticks: {
              autoSkip: false,
              color: WPA_CHART_TEXT_COLOR,
              font: { size: 11, weight: "400", family: WPA_NATIVE_FONT_FAMILY },
              callback: function(value){
                return wrapChartLabel(this.getLabelForValue(value), 20);
              }
            },
            grid: { display: false },
            border: { display: false }
          }
        }
      },
      plugins: [valueLabelPlugin]
    });
  }

  function initChartControls(){
    var typeSel = document.getElementById("wpaChartType");
    var stackedChk = document.getElementById("wpaChartStacked");
    var stackedLabel = stackedChk ? stackedChk.closest(".wpa-toggle") : null;

    function setStackedDisabled(disabled){
      if (!stackedChk) return;
      stackedChk.disabled = !!disabled;
      if (stackedLabel) stackedLabel.classList.toggle("is-disabled", !!disabled);
    }

    var type = getSavedType();
    var stacked = getSavedStacked();

    if (typeSel) typeSel.value = type;
    if (stackedChk) stackedChk.checked = stacked;

    function syncUI(){
      var t = typeSel ? typeSel.value : "bar";
      if (t === "line") {
        // forced off for line
        setSavedStacked(false);
        if (stackedChk) stackedChk.checked = false;
        setStackedDisabled(true);
      } else {
        setStackedDisabled(false);
        if (stackedChk) stackedChk.checked = getSavedStacked();
      }
    }

    syncUI();
    renderChart(type, stacked);

    if (typeSel) {
      typeSel.addEventListener("change", function(){
        var t = (typeSel.value === "line") ? "line" : "bar";
        setSavedType(t);

        if (t === "line") {
          syncUI();
          renderChart("line", false);
          return;
        }

        syncUI();
        renderChart("bar", getSavedStacked());
      });
    }

    if (stackedChk) {
      stackedChk.addEventListener("change", function(){
        var t = typeSel ? typeSel.value : "bar";
        if (t === "line") return;
        var s = !!stackedChk.checked;
        setSavedStacked(s);
        renderChart("bar", s);
      });
    }
  }

  var refreshInFlight = false;

  function destroyDashboardCharts(){
    ["wpaSocChart", "wpaSeverityChart", "wpaHotThreatsChart", "wpaTargetedEndpointsChart"].forEach(function(key){
      if (!window[key]) return;
      try { window[key].destroy(); } catch(e) {}
      window[key] = null;
    });
  }

  async function refreshDynamicRegions(){
    if (refreshInFlight || document.visibilityState !== "visible") return;

    var root = document.querySelector(WPA_REFRESH_VIEW === "dashboard" ? ".wpa-soc-dashboard" : ".wpa-security-events-page");
    if (!root) return;

    refreshInFlight = true;
    root.setAttribute("aria-busy", "true");

    try {
      var form = new URLSearchParams();
      form.set("action", "wpauditor_soc_refresh");
      form.set("nonce", WPA_REFRESH_NONCE);
      form.set("view", WPA_REFRESH_VIEW);

      var currentParams = new URLSearchParams(window.location.search);
      ["event_type", "start_date", "end_date", "severity", "category", "window", "paged"].forEach(function(key){
        if (currentParams.has(key)) form.set(key, currentParams.get(key));
      });

      var response = await fetch(ajaxurl, {
        method: "POST",
        credentials: "same-origin",
        headers: {"Content-Type":"application/x-www-form-urlencoded; charset=UTF-8"},
        body: form.toString()
      });
      var json = await response.json();
      if (!response.ok || !json || !json.success || !json.data || typeof json.data.html !== "string") {
        throw new Error((json && json.data && json.data.message) || "Live refresh failed.");
      }

      var nextDocument = new DOMParser().parseFromString(json.data.html, "text/html");
      var selectors = WPA_REFRESH_VIEW === "dashboard"
        ? [".wpa-soc-metrics", ".wpa-soc-analysis-grid", ".wpa-recent-events", ".wpa-summary-panels", ".wpa-chart-card"]
        : [".wpa-event-count-grid", "#wpaSecurityEventsResults"];

      if (WPA_REFRESH_VIEW === "dashboard") destroyDashboardCharts();

      selectors.forEach(function(selector){
        // Preserve the reviewed state while mode confirmation is open or submitting.
        var current = document.querySelector(selector);
        var next = nextDocument.querySelector(selector);
        if (current && next) current.replaceWith(document.importNode(next, true));
      });


      if (WPA_REFRESH_VIEW === "dashboard") {
        renderChart(getSavedType(), getSavedStacked());
        renderSeverityChart();
        renderHotThreatsChart();
        renderTargetedEndpointsChart();
      }
    } catch (error) {
      if (window.console && typeof window.console.warn === "function") {
        console.warn("WPAuditor live refresh:", error);
      }
    } finally {
      root.removeAttribute("aria-busy");
      refreshInFlight = false;
    }
  }

  function initOtherBehaviors(){

    function setLogDisclosureState(btn, row, open){
      if (!btn || !row) return;
      row.style.display = open ? "table-row" : "none";
      row.setAttribute("aria-hidden", open ? "false" : "true");
      btn.setAttribute("aria-expanded", open ? "true" : "false");
      btn.setAttribute("aria-label", open ? "Collapse log entry" : "Expand log entry");
      btn.setAttribute("title", open ? "Collapse" : "Expand");
      btn.innerHTML = open
        ? '<span class="dashicons dashicons-arrow-up-alt2" aria-hidden="true"></span><span class="screen-reader-text">Collapse</span>'
        : '<span class="dashicons dashicons-arrow-down-alt2" aria-hidden="true"></span><span class="screen-reader-text">Expand</span>';
    }

    // Apply dashboard filters as soon as either selection changes.
    var dashboardFilterForm = document.querySelector(".wpa-dashboard-filter-form");
    if (dashboardFilterForm) {
      dashboardFilterForm.querySelectorAll('select[name="window"], select[name="severity"]').forEach(function(select){
        select.addEventListener("change", function(){
          if (typeof dashboardFilterForm.requestSubmit === "function") dashboardFilterForm.requestSubmit();
          else dashboardFilterForm.submit();
        });
      });
    }

    // Keep window pills in sync when custom dates change
    var win = document.getElementById("wpaSocWindow");
    var sd  = document.getElementById("wpaStartDate");
    var ed  = document.getElementById("wpaEndDate");
    function clearWindow(){ if (win) win.value = ""; }
    if (sd) sd.addEventListener("change", clearWindow);
    if (ed) ed.addEventListener("change", clearWindow);

    // Expand/collapse rows, including rows inserted by live refresh.
    document.addEventListener("click", function(event){
        var btn = event.target.closest(".wpa-expand-btn");
        if (!btn) return;
        var targetId = btn.getAttribute("data-target");
        var row = document.getElementById(targetId);
        if (!row) return;
        var isOpen = btn.getAttribute("aria-expanded") === "true";
        setLogDisclosureState(btn, row, !isOpen);
    });

    // Live refresh toggle
    var refreshInterval = null;

    function startAutoRefresh(){
      if (refreshInterval) clearInterval(refreshInterval);
      refreshInterval = setInterval(refreshDynamicRegions, WPA_REFRESH_INTERVAL);
    }

    function stopAutoRefresh(){
      if (refreshInterval) clearInterval(refreshInterval);
      refreshInterval = null;
    }

    function setLive(on){
      if (WPA_REFRESH_VIEW === "security_events") {
        localStorage.setItem(LS_LIVE, on ? "on" : "off");
      }

      var head = document.getElementById("wpaLiveHead");
      if (head) head.classList.toggle("is-live", !!on);

      var liveToggle = document.getElementById("wpaLiveToggle");
      if (liveToggle) {
        var liveLabel = on ? "Stop live refresh" : "Start live refresh";
        liveToggle.classList.toggle("is-active", !!on);
        liveToggle.setAttribute("aria-pressed", on ? "true" : "false");
        liveToggle.setAttribute("aria-label", liveLabel);
        liveToggle.setAttribute("title", liveLabel);
        var screenReaderLabel = liveToggle.querySelector(".wpa-live-toggle-label");
        if (screenReaderLabel) screenReaderLabel.textContent = liveLabel;
      }

      if (on) startAutoRefresh();
      else stopAutoRefresh();
    }

    var liveToggle = document.getElementById("wpaLiveToggle");
    if (liveToggle) {
      liveToggle.addEventListener("click", function(){
        setLive(this.getAttribute("aria-pressed") !== "true");
      });
      setLive(localStorage.getItem(LS_LIVE) === "on");
    } else if (WPA_REFRESH_VIEW === "dashboard") {
      startAutoRefresh();
    }

    // Copy-to-clipboard, including values inserted by live refresh.
    document.addEventListener("click", async function(event){
        var el = event.target.closest(".wpa-copy");
        if (!el) return;
        var text = el.dataset.copy || el.textContent;
        try {
          await navigator.clipboard.writeText(text);
          var oldTitle = el.getAttribute("title") || "";
          el.setAttribute("title","Copied!");
          el.style.opacity = "0.75";
          setTimeout(function(){
            el.setAttribute("title", oldTitle || "Click to copy");
            el.style.opacity = "1";
          }, 900);
        } catch(e){ console.warn(e); }
    });

  }

  function boot(){
    if (typeof Chart !== "undefined") {
      Chart.defaults.font.family = WPA_NATIVE_FONT_FAMILY;
      Chart.defaults.font.weight = "400";
      Chart.defaults.color = WPA_CHART_MUTED_COLOR;
      Chart.defaults.borderColor = WPA_CHART_GRID_COLOR;
    }
    initChartControls();
    renderSeverityChart();
    renderHotThreatsChart();
    renderTargetedEndpointsChart();
    initOtherBehaviors();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
JS;

    $inline_js = strtr($inline_js, [
        '__WPA_REFRESH_NONCE__'   => (string) $refresh_nonce_json,
        '__WPA_REFRESH_VIEW__'    => (string) $refresh_view_json,
        '__WPA_COLORS__'          => (string) $colors_json,
        '__WPA_SERIES__'          => (string) $series_json,
        '__WPA_LABELS__'          => (string) $labels_json,
        '__WPA_SEVERITY_LABELS__' => (string) $sev_labels_json,
        '__WPA_SEVERITY_COUNTS__' => (string) $sev_counts_json,
        '__WPA_SEVERITY_COLORS__' => (string) $sev_chart_colors_json,
        '__WPA_SEVERITY_URLS__'   => (string) $sev_urls_json,
        '__WPA_THREAT_LABELS__'   => (string) $hot_threat_labels_json,
        '__WPA_THREAT_COUNTS__'   => (string) $hot_threat_counts_json,
        '__WPA_THREAT_URLS__'     => (string) $hot_threat_urls_json,
        '__WPA_ENDPOINT_LABELS__' => (string) $targeted_endpoint_labels_json,
        '__WPA_ENDPOINT_COUNTS__' => (string) $targeted_endpoint_counts_json,
    ]);

    wp_add_inline_script('wpauditor_chartjs', $inline_js, 'after');
}
}

if (!function_exists('wpauditor_soc_refresh_ajax')) {
function wpauditor_soc_refresh_ajax() {
    check_ajax_referer('wpauditor_soc_refresh', 'nonce');

    if (!current_user_can('manage_options')) {
        wp_send_json_error(['message' => 'You are not allowed to refresh WPAuditor data.'], 403);
    }

    $view = isset($_POST['view']) ? sanitize_key(wp_unslash($_POST['view'])) : 'dashboard';
    $view = ($view === 'security_events') ? 'security_events' : 'dashboard';

    $_GET = [];
    $_GET['page'] = ($view === 'security_events') ? 'wpauditor-security-events' : 'wpauditor-dashboard';

    foreach (['event_type', 'start_date', 'end_date', 'severity', 'category', 'window'] as $filter_key) {
        if (!isset($_POST[$filter_key]) || !is_scalar($_POST[$filter_key])) continue;
        $_GET[$filter_key] = sanitize_text_field(wp_unslash((string) $_POST[$filter_key]));
    }

    if (isset($_POST['paged'])) {
        $_GET['paged'] = max(1, absint(wp_unslash($_POST['paged'])));
    }

    ob_start();
    wpauditor_soc_logs_page($view);
    $html = (string) ob_get_clean();

    wp_send_json_success(['html' => $html]);
}
}
add_action('wp_ajax_wpauditor_soc_refresh', 'wpauditor_soc_refresh_ajax');
?>
