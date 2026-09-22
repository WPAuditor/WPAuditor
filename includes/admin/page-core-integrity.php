<?php
if (!defined('ABSPATH')) exit;
// Status, filter, and pagination query values only control this read-only report view.
// phpcs:disable WordPress.Security.NonceVerification.Recommended

function wpauditor_core_integrity_transient_key($version, $locale) {
    return 'wpauditor_free_wp_checksums_' . sanitize_key((string) $version) . '_' . sanitize_key((string) $locale);
}

function wpauditor_core_integrity_scan_marker_key() {
    return 'wpauditor_free_core_integrity_fresh_' . get_current_user_id();
}

function wpauditor_core_integrity_scan_key($scan_id, $user_id = null) {
    $user_id = $user_id === null ? get_current_user_id() : absint($user_id);
    return 'wpauditor_free_core_scan_' . $user_id . '_' . sanitize_key((string) $scan_id);
}

function wpauditor_core_integrity_normalize_relative_path($path) {
    $path = ltrim(wp_normalize_path((string) $path), '/');

    if ($path === '' || strpos($path, "\0") !== false || preg_match('#(^|/)\.\.(/|$)#', $path)) {
        return '';
    }

    return $path;
}

function wpauditor_core_integrity_path_key($path) {
    $path = wpauditor_core_integrity_normalize_relative_path($path);
    return DIRECTORY_SEPARATOR === '\\' ? strtolower($path) : $path;
}

// Keep only core directories and root files listed in the official checksum manifest.
function wpauditor_core_integrity_filter_checksums(array $checksums): array {
    return array_filter($checksums, static function ($path): bool {
        $path = wpauditor_core_integrity_normalize_relative_path($path);
        if ($path === '') return false;

        return strpos($path, '/') === false
            || str_starts_with($path, 'wp-admin/')
            || str_starts_with($path, 'wp-includes/');
    }, ARRAY_FILTER_USE_KEY);
}

function wpauditor_core_integrity_count_files(): int {
    $total = 0;

    foreach (['wp-admin', 'wp-includes'] as $core_directory) {
        $directory_path = realpath(wpauditor_wordpress_root() . $core_directory);
        if ($directory_path === false || !is_dir($directory_path)) continue;

        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($directory_path, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::LEAVES_ONLY
            );

            foreach ($iterator as $file_info) {
                if ($file_info->isFile()) $total++;
            }
        } catch (UnexpectedValueException $exception) {
            // Continue with any other readable core directory.
        }
    }

    return $total;
}

function wpauditor_core_integrity_find_unexpected_files(
    array $expected_paths,
    ?callable $progress_callback = null,
    ?int $progress_total = null
) {
    $expected_lookup = [];
    foreach ($expected_paths as $path) {
        $path_key = wpauditor_core_integrity_path_key($path);
        if ($path_key !== '') {
            $expected_lookup[$path_key] = true;
        }
    }

    $unexpected = [];
    $progress_total = $progress_total ?? ($progress_callback ? wpauditor_core_integrity_count_files() : 0);
    $progress_completed = 0;
    foreach (['wp-admin', 'wp-includes'] as $core_directory) {
        $directory_path = realpath(wpauditor_wordpress_root() . $core_directory);
        if ($directory_path === false || !is_dir($directory_path)) {
            continue;
        }

        $normalized_root = trailingslashit(wp_normalize_path($directory_path));

        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($directory_path, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::LEAVES_ONLY
            );

            foreach ($iterator as $file_info) {
                if (!$file_info->isFile()) {
                    continue;
                }

                if ($progress_callback) {
                    $progress_callback($progress_completed, $progress_total);
                    $progress_completed++;
                }

                $absolute_path = wp_normalize_path($file_info->getPathname());
                if (strpos($absolute_path, $normalized_root) !== 0) {
                    continue;
                }

                $relative_inside_directory = ltrim(substr($absolute_path, strlen($normalized_root)), '/');
                $relative_path = wpauditor_core_integrity_normalize_relative_path($core_directory . '/' . $relative_inside_directory);
                $path_key = wpauditor_core_integrity_path_key($relative_path);

                if ($relative_path === '' || isset($expected_lookup[$path_key])) {
                    continue;
                }

                $actual_hash = is_readable($file_info->getPathname()) ? @md5_file($file_info->getPathname()) : false;
                $unexpected[] = [
                    'path'     => $relative_path,
                    'status'   => 'Unexpected',
                    'expected' => '-',
                    'actual'   => $actual_hash !== false ? $actual_hash : __('Unreadable', 'wpauditor'),
                ];
            }
        } catch (UnexpectedValueException $exception) {
            // Continue with any other readable core directory.
        }
    }

    if ($progress_callback) $progress_callback($progress_total, $progress_total);
    return $unexpected;
}

function wpauditor_handle_core_integrity_scan() {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You are not allowed to run this integrity scan.', 'wpauditor'), '', ['response' => 403]);
    }


    check_admin_referer('wpauditor_core_integrity_scan');

    global $wp_version;
    $locale = get_locale();
    delete_transient(wpauditor_core_integrity_transient_key($wp_version, $locale));
    set_transient(wpauditor_core_integrity_scan_marker_key(), 1, MINUTE_IN_SECONDS);

    wp_safe_redirect(admin_url('admin.php?page=wpauditor-core-integrity'));
    exit;
}
add_action('admin_post_wpauditor_core_integrity_scan', 'wpauditor_handle_core_integrity_scan');

function wpauditor_admin_page_core_integrity() {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You are not allowed to view this page.', 'wpauditor'), '', ['response' => 403]);
    }


    global $wp_version;

    echo '<div class="wrap wpa-admin-shell wpa-scanner-page wpa-core-integrity-page">';
    echo '<h1>' . esc_html__('WordPress Core File Integrity', 'wpauditor') . '</h1>';

    $action_status = isset($_GET['wpauditor_status']) ? sanitize_key(wp_unslash($_GET['wpauditor_status'])) : '';
    $action_ok = isset($_GET['ok']) ? absint(wp_unslash($_GET['ok'])) : 0;
    $action_fail = isset($_GET['fail']) ? absint(wp_unslash($_GET['fail'])) : 0;
    if ($action_status === 'quarantined') {
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html(sprintf(
// translators: Placeholders are replaced with the values described by the surrounding message.
            __('Quarantine complete: %1$d succeeded, %2$d failed. Run a new scan after reviewing the updated integrity results.', 'wpauditor'),
            $action_ok,
            $action_fail
        )) . '</p></div>';
    } elseif ($action_status === 'rate_limited') {
        echo '<div class="notice notice-warning is-dismissible"><p>' . esc_html__('The action was rate limited. Wait briefly and try again.', 'wpauditor') . '</p></div>';
    } elseif ($action_status === 'no_files') {
        echo '<div class="notice notice-warning is-dismissible"><p>' . esc_html__('Select at least one available modified or unexpected file.', 'wpauditor') . '</p></div>';
    } elseif ($action_status === 'qdir_error') {
        echo '<div class="notice notice-error"><p>' . esc_html__('The protected quarantine directory could not be prepared. Check filesystem permissions and try again.', 'wpauditor') . '</p></div>';
    } elseif ($action_status === 'invalid_action') {
        echo '<div class="notice notice-error"><p>' . esc_html__('The requested file action was invalid. Refresh the page and try again.', 'wpauditor') . '</p></div>';
    } elseif ($action_status === 'invalid_nonce') {
        echo '<div class="notice notice-error"><p>' . esc_html__('The security token expired. Refresh the page and try again.', 'wpauditor') . '</p></div>';
    }

    wpauditor_render_loader(
        'wpauditor-core-integrity-loader',
        __('Verifying WordPress core files...', 'wpauditor'),
        true
    );
    echo '<div id="wpauditor-core-integrity-result" class="wpa-hidden">';

    if (ob_get_level() > 0) {
        @ob_flush();
    }
    flush();

    $finish_render = static function () {
        echo '</div>';
        wp_add_inline_script(
            'wpauditor-admin-ui',
            'document.addEventListener("DOMContentLoaded",function(){var loader=document.getElementById("wpauditor-core-integrity-loader");var result=document.getElementById("wpauditor-core-integrity-result");if(loader)loader.style.display="none";if(result)result.classList.remove("wpa-hidden");});',
            'after'
        );
        echo '</div>';
    };

    $fresh_scan = (bool) get_transient(wpauditor_core_integrity_scan_marker_key());
    if ($fresh_scan) {
        delete_transient(wpauditor_core_integrity_scan_marker_key());
    }

    $locale = get_locale();
    $transient_key = wpauditor_core_integrity_transient_key($wp_version, $locale);
    $checksums = get_transient($transient_key);

    if (!is_array($checksums) || empty($checksums)) {
        $url = add_query_arg(
            [
                'version' => (string) $wp_version,
                'locale'  => (string) $locale,
            ],
            'https://api.wordpress.org/core/checksums/1.0/'
        );

        $server_name = isset($_SERVER['SERVER_NAME']) ? strtolower(sanitize_text_field(wp_unslash($_SERVER['SERVER_NAME']))) : '';
        $home = strtolower(home_url('/'));
        $is_local_dev = (
            (defined('WP_LOCAL_DEV') && WP_LOCAL_DEV)
            || strpos($server_name, 'localhost') !== false
            || strpos($server_name, '127.0.0.1') !== false
            || strpos($server_name, '::1') !== false
            || strpos($home, 'localhost') !== false
            || strpos($home, '127.0.0.1') !== false
        );

        $common_args = [
            'headers'     => [
                'User-Agent' => WPAUDITOR_USER_AGENT,
                'Accept'     => 'application/json',
            ],
            'timeout'     => 15,
            'httpversion' => '1.1',
            'blocking'    => true,
            'sslverify'   => true,
        ];

        $response = wp_remote_get($url, $common_args);

        if ((is_wp_error($response) || (int) wp_remote_retrieve_response_code($response) !== 200) && $is_local_dev) {
            $fallback_args = $common_args;
            $fallback_args['timeout'] = 20;
            $fallback_args['httpversion'] = '1.0';
            $fallback_args['sslverify'] = false;
            $response = wp_remote_get($url, $fallback_args);
        }

        if (is_wp_error($response) || (int) wp_remote_retrieve_response_code($response) !== 200) {
            echo '<div class="notice notice-error"><p>' . esc_html__('Failed to retrieve WordPress checksums. Please check the server connection or try again later.', 'wpauditor') . '</p></div>';
            if ($fresh_scan && function_exists('wpauditor_log_event')) {
                wpauditor_log_event('CORE_INTEGRITY_SCAN_ERROR', 'WordPress core integrity scan could not retrieve official checksums', ['category' => 'FILE_INTEGRITY']);
            }
            $finish_render();
            return;
        }

        $data = json_decode(wp_remote_retrieve_body($response), true);
        $checksums = isset($data['checksums']) && is_array($data['checksums']) ? $data['checksums'] : [];
        if (!empty($checksums)) {
            set_transient($transient_key, $checksums, HOUR_IN_SECONDS);
        }
    }

    // Filter both cached and newly fetched manifests before counting or scanning files.
    $checksums = wpauditor_core_integrity_filter_checksums($checksums);
    if (empty($checksums)) {
        echo '<div class="notice notice-error"><p>' . esc_html__('WordPress.org did not provide core checksums for this WordPress version and locale.', 'wpauditor') . '</p></div>';
        if ($fresh_scan && function_exists('wpauditor_log_event')) {
            wpauditor_log_event('CORE_INTEGRITY_SCAN_ERROR', 'WordPress.org returned no core checksums for this version and locale', ['category' => 'FILE_INTEGRITY']);
        }
        $finish_render();
        return;
    }

    $results = [];
    $expected_paths = [];
    $checksum_total = count($checksums);
    $core_file_total = wpauditor_core_integrity_count_files();
    $progress_total = $checksum_total + $core_file_total;
    $progress_completed = 0;
    $last_progress_percent = -1;
    $emit_progress = static function (int $completed) use (
        $progress_total,
        &$last_progress_percent
    ): void {
        $percent = $progress_total > 0
            ? (int) floor((max(0, min($completed, $progress_total)) / $progress_total) * 100)
            : 100;
        if ($percent === $last_progress_percent) return;
        $last_progress_percent = $percent;
        wpauditor_emit_loader_progress('wpauditor-core-integrity-loader', $completed, $progress_total);
    };

    foreach ($checksums as $rel_path => $expected_hash) {
        $emit_progress($progress_completed);
        $progress_completed++;

        $rel_path = wpauditor_core_integrity_normalize_relative_path($rel_path);
        $expected_hash = strtolower(trim((string) $expected_hash));

        if ($rel_path === '' || !preg_match('/^[a-f0-9]{32}$/', $expected_hash)) {
            continue;
        }

        $expected_paths[] = $rel_path;
        $abs_path = wpauditor_wordpress_root() . str_replace('/', DIRECTORY_SEPARATOR, $rel_path);

        if (!file_exists($abs_path)) {
            $results[] = [
                'path'     => $rel_path,
                'status'   => 'Missing',
                'expected' => $expected_hash,
                'actual'   => '-',
            ];
            continue;
        }

        if (!is_file($abs_path) || !is_readable($abs_path)) {
            $results[] = [
                'path'     => $rel_path,
                'status'   => 'Unreadable',
                'expected' => $expected_hash,
                'actual'   => __('Unreadable', 'wpauditor'),
            ];
            continue;
        }

        $actual_hash = @md5_file($abs_path);
        if ($actual_hash === false) {
            $results[] = [
                'path'     => $rel_path,
                'status'   => 'Unreadable',
                'expected' => $expected_hash,
                'actual'   => __('Unreadable', 'wpauditor'),
            ];
            continue;
        }

        $results[] = [
            'path'     => $rel_path,
            'status'   => hash_equals($expected_hash, strtolower($actual_hash)) ? 'Verified' : 'Modified',
            'expected' => $expected_hash,
            'actual'   => strtolower($actual_hash),
        ];
    }

    $emit_progress($checksum_total);
    $unexpected_progress = static function (int $completed) use ($emit_progress, $checksum_total): void {
        $emit_progress($checksum_total + $completed);
    };
    $results = array_merge(
        $results,
        wpauditor_core_integrity_find_unexpected_files(
            $expected_paths,
            $unexpected_progress,
            $core_file_total
        )
    );
    $emit_progress($progress_total);

    $priority = [
        'Modified'   => 0,
        'Unexpected' => 1,
        'Unreadable' => 2,
        'Missing'    => 3,
        'Verified'   => 4,
    ];
    usort($results, static function ($a, $b) use ($priority) {
        $status_order = ($priority[$a['status']] ?? 99) <=> ($priority[$b['status']] ?? 99);
        return $status_order !== 0 ? $status_order : strcasecmp($a['path'], $b['path']);
    });

    $summary = [
        'All'        => count($results),
        'Modified'   => 0,
        'Missing'    => 0,
        'Unexpected' => 0,
        'Unreadable' => 0,
        'Verified'   => 0,
    ];
    foreach ($results as $result) {
        if (isset($summary[$result['status']])) {
            $summary[$result['status']]++;
        }
    }

    // Store trusted evidence only for files eligible for quarantine.
    $scan_id = '';
    $quarantine_paths = [];
    $quarantine_findings = [];
    foreach ($results as $result) {
        if (!in_array($result['status'], ['Modified', 'Unexpected'], true)) {
            continue;
        }

        $relative_path = wpauditor_core_integrity_normalize_relative_path($result['path']);
        $absolute_path = wpauditor_wordpress_root() . str_replace('/', DIRECTORY_SEPARATOR, $relative_path);
        if ($relative_path === '' || !is_file($absolute_path) || is_link($absolute_path)) {
            continue;
        }

        $sha256 = @hash_file('sha256', $absolute_path);
        $size = @filesize($absolute_path);
        $modified_ts = @filemtime($absolute_path);
        if ($sha256 === false || $size === false || $modified_ts === false) {
            continue;
        }

        $path_key = wpauditor_core_integrity_path_key($relative_path);
        $quarantine_paths[$path_key] = true;
        $quarantine_findings[] = [
            'relative_path' => $relative_path,
            'sha256'        => $sha256,
            'size'          => (int) $size,
            'modified_ts'   => (int) $modified_ts,
            'finding_id'    => substr(hash('sha256', $relative_path . '|' . $sha256), 0, 32),
            'detectors'     => ['core_integrity'],
            'rules'         => [strtolower($result['status']) . '_core_file'],
            'evidence'      => [$result['status'] . ' WordPress core integrity finding'],
            'score'         => $result['status'] === 'Modified' ? 90 : 80,
            'severity'      => $result['status'] === 'Modified' ? 'Critical' : 'High',
            'confidence'    => 'High',
        ];
    }

    if ($quarantine_findings) {
        $scan_id = md5(wp_generate_uuid4() . '|' . microtime(true));
        $scan_payload = [
            'created_at' => current_time('mysql'),
            'results'    => $quarantine_findings,
        ];
        if (!set_transient(wpauditor_core_integrity_scan_key($scan_id), $scan_payload, 30 * MINUTE_IN_SECONDS)) {
            $scan_id = '';
            $quarantine_paths = [];
        }
    }

    if ($fresh_scan && function_exists('wpauditor_log_event')) {
        $details = sprintf(
            'WordPress core integrity scan completed; checked:%d modified:%d missing:%d unexpected:%d unreadable:%d',
            $summary['All'],
            $summary['Modified'],
            $summary['Missing'],
            $summary['Unexpected'],
            $summary['Unreadable']
        );
        wpauditor_log_event('CORE_INTEGRITY_SCAN', $details, ['category' => 'FILE_INTEGRITY']);
    }

    echo '<div class="wpa-forensics-scan-meta wpa-core-integrity-meta">';
// translators: Placeholders are replaced with the values described by the surrounding message.
    echo '<strong>' . esc_html(sprintf(__('WordPress %s', 'wpauditor'), $wp_version)) . '</strong>';
// translators: Placeholders are replaced with the values described by the surrounding message.
    echo '<span>' . esc_html(sprintf(__('Locale: %s', 'wpauditor'), $locale)) . '</span>';
    if ($fresh_scan) {
        echo '<span class="wpa-core-integrity-fresh">' . esc_html__('Fresh scan completed', 'wpauditor') . '</span>';
    }
    echo '</div>';

    $summary_classes = [
        'All'        => 'all',
        'Modified'   => 'modified',
        'Missing'    => 'missing',
        'Unexpected' => 'unexpected',
        'Unreadable' => 'unreadable',
        'Verified'   => 'verified',
    ];
    $summary_labels = [
        'All'        => __('Files checked', 'wpauditor'),
        'Modified'   => __('Modified', 'wpauditor'),
        'Missing'    => __('Missing', 'wpauditor'),
        'Unexpected' => __('Unexpected', 'wpauditor'),
        'Unreadable' => __('Unreadable', 'wpauditor'),
        'Verified'   => __('Verified', 'wpauditor'),
    ];
    echo '<div class="wpa-forensics-summary wpa-core-integrity-summary" aria-label="' . esc_attr__('Integrity scan summary', 'wpauditor') . '">';
    foreach ($summary as $status => $count) {
        echo '<div class="wpa-forensics-summary-card wpa-core-summary-' . esc_attr($summary_classes[$status]) . '">';
        echo '<strong>' . esc_html((string) $count) . '</strong><span>' . esc_html($summary_labels[$status]) . '</span>';
        echo '</div>';
    }
    echo '</div>';

    $allowed_filters = ['modified', 'missing', 'unexpected', 'unreadable'];
    $status_filter = isset($_GET['integrity_status']) ? sanitize_key(wp_unslash($_GET['integrity_status'])) : '';
    if (!in_array($status_filter, $allowed_filters, true)) {
        $status_filter = '';
    }
    $search = isset($_GET['s']) ? sanitize_text_field(wp_unslash($_GET['s'])) : '';

    echo '<form method="get" class="wpa-forensics-filter-form wpa-core-integrity-filter-form">';
    echo '<input type="hidden" name="page" value="wpauditor-core-integrity">';
    echo '<label><span>' . esc_html__('Status', 'wpauditor') . '</span>';
    echo '<select name="integrity_status">';
    echo '<option value="">' . esc_html__('All statuses', 'wpauditor') . '</option>';
    foreach ($allowed_filters as $filter) {
        echo '<option value="' . esc_attr($filter) . '" ' . selected($status_filter, $filter, false) . '>' . esc_html(ucfirst($filter)) . '</option>';
    }
    echo '</select></label>';
    echo '<label class="wpa-forensics-search"><span>' . esc_html__('Search evidence', 'wpauditor') . '</span>';
    echo '<input type="search" name="s" value="' . esc_attr($search) . '" placeholder="' . esc_attr__('File path or MD5 hash', 'wpauditor') . '"></label>';
    echo '<div class="wpa-forensics-filter-actions">';
    echo '<button type="submit" class="button">' . esc_html__('Apply Filters', 'wpauditor') . '</button>';
    echo '<a class="button" href="' . esc_url(admin_url('admin.php?page=wpauditor-core-integrity')) . '">' . esc_html__('Clear', 'wpauditor') . '</a>';
    echo '</div>';
    echo '</form>';

    // Keep the investigation table focused on findings; verified files remain summarized above.
    $results = array_values(array_filter($results, static function ($result) {
        return $result['status'] !== 'Verified';
    }));

    if ($status_filter !== '' || $search !== '') {
        $results = array_values(array_filter($results, static function ($result) use ($status_filter, $search) {
            if ($status_filter !== '' && strtolower($result['status']) !== $status_filter) {
                return false;
            }
            if ($search !== '') {
                $haystack = implode(' ', [$result['path'], $result['expected'], $result['actual']]);
                if (stripos($haystack, $search) === false) {
                    return false;
                }
            }
            return true;
        }));
    }

    $per_page = WPAUDITOR_ADMIN_ROWS_PER_PAGE;
    $total_items = count($results);
    $current_page = isset($_GET['paged']) ? max(1, absint(wp_unslash($_GET['paged']))) : 1;
    $total_pages = max(1, (int) ceil($total_items / $per_page));
    if ($current_page > $total_pages) {
        $current_page = $total_pages;
    }
    $offset = ($current_page - 1) * $per_page;
    $paged_results = array_slice($results, $offset, $per_page);

    $selectable_on_page = 0;
    $row_action_forms = [];
    foreach ($paged_results as $row) {
        if ($scan_id !== '' && isset($quarantine_paths[wpauditor_core_integrity_path_key($row['path'])])) {
            $selectable_on_page++;
        }
    }

    echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" id="wpa-core-integrity-action-form">';
    echo '<input type="hidden" name="action" value="wpauditor_file_action">';
    wp_nonce_field('wpauditor_file_action', 'wpauditor_nonce');
    echo '<input type="hidden" name="wpauditor_operation" value="quarantine">';
    echo '<input type="hidden" name="wpauditor_scan_type" value="core-integrity">';
    echo '<input type="hidden" name="wpauditor_scan_id" value="' . esc_attr($scan_id) . '">';
// translators: Placeholders are replaced with the values described by the surrounding message.
    echo '<div class="wpa-forensics-result-count">' . esc_html(sprintf(_n('%d file shown', '%d files shown', $total_items, 'wpauditor'), $total_items)) . '</div>';
    echo '<table class="widefat striped wpa-scanner-table wpa-forensics-table">';
    echo '<thead><tr><th class="wpa-col-select"><label class="screen-reader-text" for="wpa-core-integrity-select-all">' . esc_html__('Select all available findings on this page', 'wpauditor') . '</label><input type="checkbox" id="wpa-core-integrity-select-all" title="' . esc_attr__('Select all available findings on this page', 'wpauditor') . '" ' . disabled($selectable_on_page, 0, false) . '></th>';
    echo '<th>' . esc_html__('File', 'wpauditor') . '</th><th>' . esc_html__('Status', 'wpauditor') . '</th><th>' . esc_html__('Expected MD5', 'wpauditor') . '</th><th>' . esc_html__('Actual MD5', 'wpauditor') . '</th><th class="wpa-forensics-col-actions">' . esc_html__('Actions', 'wpauditor') . '</th></tr></thead><tbody>';

    $status_tones = [
        'Modified'   => 'danger',
        'Unexpected' => 'warning',
        'Unreadable' => 'danger',
        'Missing'    => 'danger',
        'Verified'   => 'success',
    ];

    if (empty($paged_results)) {
        echo '<tr><td colspan="6">' . esc_html__('No core integrity findings match the current filters.', 'wpauditor') . '</td></tr>';
    } else {
        foreach ($paged_results as $row) {
            $status_tone = $status_tones[$row['status']] ?? 'neutral';
            echo '<tr>';
            echo '<td>';
            $path_key = wpauditor_core_integrity_path_key($row['path']);
            if ($scan_id !== '' && isset($quarantine_paths[$path_key])) {
// translators: Placeholders are replaced with the values described by the surrounding message.
                echo '<input type="checkbox" class="wpa-core-integrity-row-check" name="files[]" value="' . esc_attr($row['path']) . '" aria-label="' . esc_attr(sprintf(__('Select %s for quarantine', 'wpauditor'), $row['path'])) . '">';
            } else {
                echo '<span class="dashicons dashicons-minus" title="' . esc_attr__('This file is not eligible for quarantine', 'wpauditor') . '"></span>';
            }
            echo '</td>';
            echo '<td><code>' . esc_html($row['path']) . '</code></td>';
            echo '<td>' . wp_kses_post(wpauditor_badge_html((string) $row['status'], 'status', $status_tone)) . '</td>';
            echo '<td><code>' . esc_html($row['expected']) . '</code></td>';
            echo '<td><code>' . esc_html($row['actual']) . '</code></td>';
            echo '<td>';
            if ($scan_id !== '' && isset($quarantine_paths[$path_key])) {
                $row_form_id = 'wpa-core-integrity-row-action-' . count($row_action_forms);
                $row_action_forms[$row_form_id] = $row['path'];
// translators: Placeholders are replaced with the values described by the surrounding message.
                echo '<button type="submit" form="' . esc_attr($row_form_id) . '" class="button button-secondary button-small wpa-confirm-submit" aria-label="' . esc_attr(sprintf(__('Quarantine %s', 'wpauditor'), $row['path'])) . '" data-wpa-confirm-action="quarantine" data-wpa-confirm-title="' . esc_attr__('Quarantine this core file?', 'wpauditor') . '" data-wpa-confirm-description="' . esc_attr__('Quarantining a WordPress core file can immediately break the site.', 'wpauditor') . '" data-wpa-confirm-note="' . esc_attr__('Continue only after verifying the finding and confirming that you have a recovery path.', 'wpauditor') . '" data-wpa-confirm-label="' . esc_attr__('Quarantine File', 'wpauditor') . '" data-wpa-confirm-target-label="' . esc_attr__('File', 'wpauditor') . '" data-wpa-confirm-target="' . esc_attr($row['path']) . '">' . esc_html__('Quarantine', 'wpauditor') . '</button>';
            } else {
                echo '<span class="wpa-muted">' . esc_html__('Unavailable', 'wpauditor') . '</span>';
            }
            echo '</td>';
            echo '</tr>';
        }
    }

    echo '</tbody></table>';

    if ($total_pages > 1) {
        echo '<div class="tablenav"><div class="tablenav-pages">';
        echo wp_kses_post(paginate_links([
            'base'      => add_query_arg('paged', '%#%'),
            'format'    => '',
            'prev_text' => __('&laquo; Prev', 'wpauditor'),
            'next_text' => __('Next &raquo;', 'wpauditor'),
            'total'     => $total_pages,
            'current'   => $current_page,
        ]));
        echo '</div></div>';
    }

    echo '<p class="submit wpa-flex-actions">';
    echo '<button type="submit" class="button button-secondary wpa-confirm-submit" id="wpa-core-integrity-quarantine" data-wpa-confirm-action="quarantine" data-wpa-confirm-eyebrow="' . esc_attr__('WordPress Core File Integrity', 'wpauditor') . '" data-wpa-confirm-title="' . esc_attr__('Quarantine selected core files?', 'wpauditor') . '" data-wpa-confirm-description="' . esc_attr__('Quarantining a WordPress core file can immediately break the site.', 'wpauditor') . '" data-wpa-confirm-note="' . esc_attr__('Continue only after verifying the finding and confirming that you have a recovery path.', 'wpauditor') . '" data-wpa-confirm-label="' . esc_attr__('Quarantine Files', 'wpauditor') . '" data-wpa-confirm-target-source="selected" data-wpa-confirm-target-unit="file" ' . disabled($selectable_on_page, 0, false) . '>' . esc_html__('Quarantine Selected Files', 'wpauditor') . '</button>';
    echo '<span id="wpa-core-integrity-selected-count" class="wpa-muted"></span>';
    echo '</p></form>';

    // Separate row forms keep bulk selections out of single-file submissions.
    $row_nonce = wp_create_nonce('wpauditor_file_action');
    foreach ($row_action_forms as $row_form_id => $relative) {
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" id="' . esc_attr($row_form_id) . '" hidden>';
        echo '<input type="hidden" name="action" value="wpauditor_file_action">';
        echo '<input type="hidden" name="wpauditor_nonce" value="' . esc_attr($row_nonce) . '">';
        echo '<input type="hidden" name="wpauditor_operation" value="quarantine">';
        echo '<input type="hidden" name="wpauditor_scan_id" value="' . esc_attr($scan_id) . '">';
        echo '<input type="hidden" name="wpauditor_scan_type" value="core-integrity">';
        echo '<input type="hidden" name="files[]" value="' . esc_attr($relative) . '">';
        echo '</form>';
    }

    ?>
    <?php ob_start(); ?>
    (function(){
        const selectAll = document.getElementById('wpa-core-integrity-select-all');
        const checks = Array.from(document.querySelectorAll('.wpa-core-integrity-row-check'));
        const quarantine = document.getElementById('wpa-core-integrity-quarantine');
        const selectedCount = document.getElementById('wpa-core-integrity-selected-count');

        function selected(){ return checks.filter(function(check){ return check.checked; }); }
        function updateSelected(){
            const count = selected().length;
            if (selectedCount) selectedCount.textContent = count ? count + ' selected' : '';
            if (selectAll) {
                selectAll.checked = checks.length > 0 && count === checks.length;
                selectAll.indeterminate = count > 0 && count < checks.length;
            }
        }

        if (selectAll) {
            selectAll.addEventListener('change', function(){
                checks.forEach(function(check){ check.checked = selectAll.checked; });
                updateSelected();
            });
        }
        checks.forEach(function(check){ check.addEventListener('change', updateSelected); });

        if (quarantine) {
            quarantine.addEventListener('click', function(event){
                if (!selected().length) {
                    event.preventDefault();
                    window.alert('<?php echo esc_js(__('Select at least one available modified or unexpected file.', 'wpauditor')); ?>');
                    return;
                }
            });
        }
    })();
    <?php
    $core_integrity_script = ob_get_clean();
    wp_add_inline_script('wpauditor-admin-ui', $core_integrity_script, 'after');
    ?>
    <?php

    $finish_render();
}
