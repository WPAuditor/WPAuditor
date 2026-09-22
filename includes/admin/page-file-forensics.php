<?php
if (!defined('ABSPATH')) exit;
// Status, filter, and pagination query values only control this read-only report view.
// phpcs:disable WordPress.Security.NonceVerification.Recommended

// Build a user-scoped transient key for short-lived scan results
function wpauditor_file_forensics_scan_key(string $scan_id, int $user_id = 0): string {
    $user_id = $user_id ?: get_current_user_id();
    return 'wpauditor_free_forensics_' . $user_id . '_' . sanitize_key($scan_id);
}

// Run an explicit scan and redirect to the persistent result view
function wpauditor_handle_file_forensics_scan(): void {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You do not have permission to run this scan.', 'wpauditor'));
    }
    check_admin_referer('wpauditor_run_file_forensics', 'wpauditor_forensics_nonce');

    $scope = isset($_POST['scan_scope'])
        ? sanitize_key(wp_unslash($_POST['scan_scope']))
        : 'all';
    if (!in_array($scope, ['all', 'uploads', 'sensitive'], true)) {
        $scope = 'all';
    }

    $progress_id = isset($_POST['wpauditor_progress_id'])
        ? sanitize_key(wp_unslash($_POST['wpauditor_progress_id']))
        : '';
    $progress_reporter = preg_match('/^[a-f0-9]{32}$/', $progress_id)
        ? wpauditor_scan_progress_reporter($progress_id)
        : null;

    $started = microtime(true);

    try {
        $results = WPAuditor_Scanner::scan_file_forensics($scope, $progress_reporter);
    } catch (Throwable $exception) {
        wpauditor_event(
            'FILE_FORENSICS_SCAN_ERROR',
            'scope=' . $scope . ' scan_failed=1',
            ['category' => 'FILE_FORENSICS']
        );
        wp_safe_redirect(add_query_arg([
            'page'              => 'wpauditor-file-forensics',
            'wpauditor_status'  => 'scan_failed',
        ], admin_url('admin.php')));
        exit;
    }

    $summary = [
        'total'     => count($results),
        'critical'  => 0,
        'high'      => 0,
        'medium'    => 0,
        'low'       => 0,
        'info'      => 0,
        'uploads'   => 0,
        'sensitive' => 0,
        'correlated'=> 0,
    ];

    foreach ($results as $result) {
        $severity = strtolower((string) ($result['severity'] ?? 'info'));
        if (!isset($summary[$severity])) $severity = 'info';
        $summary[$severity]++;

        $detectors = (array) ($result['detectors'] ?? [$result['detector'] ?? '']);
        if (in_array('uploads', $detectors, true)) $summary['uploads']++;
        if (in_array('sensitive', $detectors, true)) $summary['sensitive']++;
        if (count(array_filter($detectors)) > 1) $summary['correlated']++;
    }

    // Keep transient payloads bounded on sites with exceptionally large result sets
    $result_limit = 500;
    $stored_results = array_slice($results, 0, $result_limit);
    $scan_id = str_replace('-', '', wp_generate_uuid4());
    $duration_ms = (int) round((microtime(true) - $started) * 1000);
    $payload = [
        'scan_id'        => $scan_id,
        'scope'          => $scope,
        'created_at'     => current_time('mysql'),
        'duration_ms'    => $duration_ms,
        'summary'        => $summary,
        'results'        => $stored_results,
        'truncated'      => count($results) > $result_limit,
        'result_limit'   => $result_limit,
    ];

    $stored = set_transient(
        wpauditor_file_forensics_scan_key($scan_id),
        $payload,
        30 * MINUTE_IN_SECONDS
    );

    if (!$stored) {
        wpauditor_event(
            'FILE_FORENSICS_SCAN_ERROR',
            'scope=' . $scope . ' result_store_failed=1',
            ['category' => 'FILE_FORENSICS']
        );
        wp_safe_redirect(add_query_arg([
            'page'             => 'wpauditor-file-forensics',
            'wpauditor_status' => 'scan_store_failed',
        ], admin_url('admin.php')));
        exit;
    }

    wpauditor_event(
        'FILE_FORENSICS_SCAN',
        'scan_id=' . $scan_id .
        ' scope=' . $scope .
        ' findings=' . (int) $summary['total'] .
        ' critical=' . (int) $summary['critical'] .
        ' high=' . (int) $summary['high'] .
        ' duration_ms=' . $duration_ms .
        ' truncated=' . ($payload['truncated'] ? '1' : '0'),
        ['category' => 'FILE_FORENSICS']
    );

    wp_safe_redirect(add_query_arg([
        'page'    => 'wpauditor-file-forensics',
        'scan_id' => $scan_id,
    ], admin_url('admin.php')));
    exit;
}
add_action('admin_post_wpauditor_run_file_forensics', 'wpauditor_handle_file_forensics_scan');

// Render a severity badge using the shared UI component
function wpauditor_file_forensics_severity_badge(string $severity): string {
    return wpauditor_severity_badge_html($severity);
}

// Render the unified File Forensics workspace
function wpauditor_admin_page_file_forensics(string $default_scope = 'all') {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You do not have permission to access this page.', 'wpauditor'));
    }

    $scope_labels = [
        'all'       => __('Complete forensic scan', 'wpauditor'),
        'uploads'   => __('Upload threats only', 'wpauditor'),
        'sensitive' => __('Sensitive exposure only', 'wpauditor'),
    ];

    if (!isset($scope_labels[$default_scope])) $default_scope = 'all';

    $scan_id = isset($_GET['scan_id']) ? sanitize_key(wp_unslash($_GET['scan_id'])) : '';
    $status = isset($_GET['wpauditor_status']) ? sanitize_key(wp_unslash($_GET['wpauditor_status'])) : '';
    $payload = false;
    if ($scan_id !== '' && preg_match('/^[a-f0-9]{32}$/', $scan_id)) {
        $payload = get_transient(wpauditor_file_forensics_scan_key($scan_id));
    }
    echo '<div class="wrap wpa-admin-shell wpa-scanner-page wpa-file-forensics-page">';
    echo '<h1>' . esc_html__('File Forensics', 'wpauditor') . '</h1>';

    // Start a complete scan immediately when File Forensics is opened from the menu.
    if ($scan_id === '' && $status === '') {
        $progress_id = str_replace('-', '', wp_generate_uuid4());
        wpauditor_render_loader(
            'wpauditor-file-forensics-loader',
            __('Running a complete forensic scan...', 'wpauditor'),
            true
        );
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" id="wpa-forensics-auto-scan">';
        echo '<input type="hidden" name="action" value="wpauditor_run_file_forensics">';
        echo '<input type="hidden" name="scan_scope" value="' . esc_attr($default_scope) . '">';
        echo '<input type="hidden" name="wpauditor_progress_id" value="' . esc_attr($progress_id) . '">';
        wp_nonce_field('wpauditor_run_file_forensics', 'wpauditor_forensics_nonce');
        echo '</form>';
        wpauditor_render_progressive_scan_script(
            'wpa-forensics-auto-scan',
            'wpauditor-file-forensics-loader',
            $progress_id
        );
        echo '</div>';
        return;
    }

    $ok = isset($_GET['ok']) ? absint(wp_unslash($_GET['ok'])) : 0;
    $fail = isset($_GET['fail']) ? absint(wp_unslash($_GET['fail'])) : 0;
    if ($status === 'quarantined') {
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html(sprintf(
// translators: Placeholders are replaced with the values described by the surrounding message.
            __('Quarantine complete: %1$d succeeded, %2$d failed. Run a new scan to refresh the evidence list.', 'wpauditor'),
            $ok,
            $fail
        )) . '</p></div>';
    } elseif ($status === 'rate_limited') {
        echo '<div class="notice notice-warning is-dismissible"><p>' . esc_html__('The action was rate limited. Wait briefly and try again.', 'wpauditor') . '</p></div>';
    } elseif ($status === 'no_files') {
        echo '<div class="notice notice-warning is-dismissible"><p>' . esc_html__('Select at least one available file.', 'wpauditor') . '</p></div>';
    } elseif ($status === 'qdir_error') {
        echo '<div class="notice notice-error"><p>' . esc_html__('The protected quarantine directory could not be prepared. Check filesystem permissions and try again.', 'wpauditor') . '</p></div>';
    } elseif ($status === 'invalid_action') {
        echo '<div class="notice notice-error"><p>' . esc_html__('The requested file action was invalid. Refresh the page and try again.', 'wpauditor') . '</p></div>';
    } elseif ($status === 'invalid_nonce') {
        echo '<div class="notice notice-error"><p>' . esc_html__('The security token expired. Refresh the page and try again.', 'wpauditor') . '</p></div>';
    } elseif ($status === 'scan_failed') {
        echo '<div class="notice notice-error"><p>' . esc_html__('The scan could not be completed. Check PHP resource limits and the server error log, then open File Forensics to try again.', 'wpauditor') . '</p></div>';
    } elseif ($status === 'scan_store_failed') {
        echo '<div class="notice notice-error"><p>' . esc_html__('The scan completed, but its short-lived results could not be stored. Check database availability and try again.', 'wpauditor') . '</p></div>';
    }

    if ($scan_id !== '' && $payload === false) {
        echo '<div class="notice notice-warning"><p>' . esc_html__('These scan results have expired or are unavailable. Run a new scan to continue the investigation.', 'wpauditor') . '</p></div>';
    }

    if (!is_array($payload)) {
        echo '<div class="wpa-forensics-empty">';
        echo '<h2>' . esc_html__('No scan loaded', 'wpauditor') . '</h2>';
        echo '<p>' . esc_html__('Open File Forensics from the menu to run a new complete scan. Results remain available to your user account for 30 minutes for filtering and pagination.', 'wpauditor') . '</p>';
        echo '</div>';
        echo '</div>';
        return;
    }

    $summary = is_array($payload['summary'] ?? null) ? $payload['summary'] : [];
    $results = is_array($payload['results'] ?? null) ? $payload['results'] : [];
    $scope = isset($scope_labels[$payload['scope'] ?? '']) ? $payload['scope'] : 'all';

    echo '<div class="wpa-forensics-scan-meta">';
    echo '<strong>' . esc_html($scope_labels[$scope]) . '</strong>';
// translators: Placeholders are replaced with the values described by the surrounding message.
    echo '<span>' . esc_html(sprintf(__('Completed %1$s in %2$s seconds', 'wpauditor'), (string) ($payload['created_at'] ?? ''), number_format_i18n(((int) ($payload['duration_ms'] ?? 0)) / 1000, 2))) . '</span>';
    echo '<span>' . esc_html__('Results expire after 30 minutes.', 'wpauditor') . '</span>';
    echo '</div>';

    $cards = [
        'total'     => __('Total findings', 'wpauditor'),
        'critical'  => __('Critical', 'wpauditor'),
        'high'      => __('High', 'wpauditor'),
        'uploads'   => __('Upload threats', 'wpauditor'),
        'sensitive' => __('Sensitive exposure', 'wpauditor'),
        'correlated'=> __('Correlated', 'wpauditor'),
    ];
    echo '<div class="wpa-forensics-summary" aria-label="' . esc_attr__('Scan summary', 'wpauditor') . '">';
    foreach ($cards as $key => $label) {
        echo '<div class="wpa-forensics-summary-card wpa-forensics-summary-' . esc_attr($key) . '">';
        echo '<strong>' . esc_html((string) ((int) ($summary[$key] ?? 0))) . '</strong>';
        echo '<span>' . esc_html($label) . '</span>';
        echo '</div>';
    }
    echo '</div>';

    if (!empty($payload['truncated'])) {
        echo '<div class="notice notice-warning"><p>' . esc_html(sprintf(
// translators: Placeholders are replaced with the values described by the surrounding message.
            __('The scan found %1$d items. The highest-risk %2$d findings are retained in this short-lived view. Use a narrower scan for complete review.', 'wpauditor'),
            (int) ($summary['total'] ?? 0),
            (int) ($payload['result_limit'] ?? 500)
        )) . '</p></div>';
    }

    $detector_filter = isset($_GET['detector']) ? sanitize_key(wp_unslash($_GET['detector'])) : '';
    $severity_filter = isset($_GET['severity']) ? sanitize_key(wp_unslash($_GET['severity'])) : '';
    $search = isset($_GET['s']) ? sanitize_text_field(wp_unslash($_GET['s'])) : '';
    if (!in_array($detector_filter, ['', 'uploads', 'sensitive', 'correlated'], true)) $detector_filter = '';
    if (!in_array($severity_filter, ['', 'critical', 'high', 'medium', 'low', 'info'], true)) $severity_filter = '';

    $filtered = array_values(array_filter($results, static function ($finding) use ($detector_filter, $severity_filter, $search): bool {
        $detectors = (array) ($finding['detectors'] ?? [$finding['detector'] ?? '']);
        if ($detector_filter === 'correlated' && count(array_filter($detectors)) < 2) return false;
        if (in_array($detector_filter, ['uploads', 'sensitive'], true) && !in_array($detector_filter, $detectors, true)) return false;
        if ($severity_filter !== '' && strtolower((string) ($finding['severity'] ?? 'info')) !== $severity_filter) return false;

        if ($search !== '') {
            $haystack = implode(' ', [
                (string) ($finding['relative_path'] ?? ''),
                (string) ($finding['reason'] ?? ''),
                implode(' ', (array) ($finding['rules'] ?? [])),
                (string) ($finding['sha256'] ?? ''),
            ]);
            if (stripos($haystack, $search) === false) return false;
        }

        return true;
    }));

    echo '<form method="get" class="wpa-forensics-filter-form">';
    echo '<input type="hidden" name="page" value="wpauditor-file-forensics">';
    echo '<input type="hidden" name="scan_id" value="' . esc_attr($scan_id) . '">';
    echo '<label><span>' . esc_html__('Detector', 'wpauditor') . '</span><select name="detector">';
    $detector_options = [
        ''           => __('All detectors', 'wpauditor'),
        'uploads'    => __('Upload threats', 'wpauditor'),
        'sensitive'  => __('Sensitive exposure', 'wpauditor'),
        'correlated' => __('Correlated findings', 'wpauditor'),
    ];
    foreach ($detector_options as $value => $label) {
        echo '<option value="' . esc_attr($value) . '" ' . selected($detector_filter, $value, false) . '>' . esc_html($label) . '</option>';
    }
    echo '</select></label>';
    echo '<label><span>' . esc_html__('Severity', 'wpauditor') . '</span><select name="severity">';
    $severity_options = ['' => __('All severities', 'wpauditor'), 'critical' => 'Critical', 'high' => 'High', 'medium' => 'Medium', 'low' => 'Low', 'info' => 'Info'];
    foreach ($severity_options as $value => $label) {
        echo '<option value="' . esc_attr($value) . '" ' . selected($severity_filter, $value, false) . '>' . esc_html($label) . '</option>';
    }
    echo '</select></label>';
    echo '<label class="wpa-forensics-search"><span>' . esc_html__('Search evidence', 'wpauditor') . '</span><input type="search" name="s" value="' . esc_attr($search) . '" placeholder="' . esc_attr__('Path, rule, reason, or SHA-256', 'wpauditor') . '"></label>';
    echo '<div class="wpa-forensics-filter-actions"><button type="submit" class="button">' . esc_html__('Apply Filters', 'wpauditor') . '</button>';
    echo '<a class="button" href="' . esc_url(add_query_arg(['page' => 'wpauditor-file-forensics', 'scan_id' => $scan_id], admin_url('admin.php'))) . '">' . esc_html__('Clear', 'wpauditor') . '</a></div>';
    echo '</form>';

    if (!$filtered) {
        $message = $results
            ? __('No findings match the current filters.', 'wpauditor')
            : __('No suspicious upload or sensitive exposure findings were detected in this scan.', 'wpauditor');
        echo '<div class="notice notice-success"><p>' . esc_html($message) . '</p></div>';
        echo '</div>';
        return;
    }

    $per_page = WPAUDITOR_ADMIN_ROWS_PER_PAGE;
    $total_items = count($filtered);
    $current_page = isset($_GET['paged']) ? max(1, absint(wp_unslash($_GET['paged']))) : 1;
    $total_pages = (int) ceil($total_items / $per_page);
    if ($current_page > max(1, $total_pages)) $current_page = max(1, $total_pages);
    $paged_results = array_slice($filtered, ($current_page - 1) * $per_page, $per_page);
    $row_action_forms = [];

    echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" id="wpa-forensics-action-form">';
    echo '<input type="hidden" name="action" value="wpauditor_file_action">';
    wp_nonce_field('wpauditor_file_action', 'wpauditor_nonce');
    echo '<input type="hidden" name="wpauditor_operation" id="wpauditor_operation" value="quarantine">';
    echo '<input type="hidden" name="wpauditor_scan_id" value="' . esc_attr($scan_id) . '">';
    echo '<input type="hidden" name="wpauditor_scan_type" value="file-forensics">';
// translators: Placeholders are replaced with the values described by the surrounding message.
    echo '<div class="wpa-forensics-result-count">' . esc_html(sprintf(_n('%d finding shown', '%d findings shown', $total_items, 'wpauditor'), $total_items)) . '</div>';
    echo '<table class="widefat striped wpa-scanner-table wpa-forensics-table">';
    echo '<thead><tr>';
    echo '<th class="wpa-col-select"><label class="screen-reader-text" for="wpa-forensics-select-all">' . esc_html__('Select all available files on this page', 'wpauditor') . '</label><input type="checkbox" id="wpa-forensics-select-all" title="' . esc_attr__('Select all available files on this page', 'wpauditor') . '"></th>';
    echo '<th>' . esc_html__('File', 'wpauditor') . '</th>';
    echo '<th class="wpa-forensics-col-finding">' . esc_html__('Forensic evidence', 'wpauditor') . '</th>';
    echo '<th class="wpa-forensics-col-risk">' . esc_html__('Risk', 'wpauditor') . '</th>';
    echo '<th class="wpa-forensics-col-type">' . esc_html__('Type', 'wpauditor') . '</th>';
    echo '<th class="wpa-col-modified">' . esc_html__('Modified', 'wpauditor') . '</th>';
    echo '<th class="wpa-forensics-col-actions">' . esc_html__('Actions', 'wpauditor') . '</th>';
    echo '</tr></thead><tbody>';

    foreach ($paged_results as $finding) {
        $relative = (string) ($finding['relative_path'] ?? '');
        $absolute = (string) ($finding['path'] ?? '');
        $available = $absolute !== '' && is_file($absolute) && !is_link($absolute);
        $detectors = array_values(array_filter((array) ($finding['detectors'] ?? [$finding['detector'] ?? ''])));
        $evidence = array_values(array_filter((array) ($finding['evidence'] ?? [])));
        $rules = array_values(array_filter((array) ($finding['rules'] ?? [])));
        $sha = (string) ($finding['sha256'] ?? '');

        echo '<tr>';
        echo '<td>';
        if ($available) {
// translators: Placeholders are replaced with the values described by the surrounding message.
            echo '<input type="checkbox" class="wpa-forensics-row-check" name="files[]" value="' . esc_attr($relative) . '" aria-label="' . esc_attr(sprintf(__('Select %s for quarantine', 'wpauditor'), $relative)) . '">';
        } else {
            echo '<span class="dashicons dashicons-minus" title="' . esc_attr__('File is no longer available', 'wpauditor') . '"></span>';
        }
        echo '</td>';
        echo '<td class="wpa-file-path"><code>' . esc_html($relative) . '</code>';
        echo '<div class="wpa-forensics-file-meta">' . esc_html(size_format((float) ($finding['size'] ?? 0)));
        if ($sha !== '') {
            echo ' &middot; <code class="wpa-copy" data-copy="' . esc_attr($sha) . '" title="' . esc_attr__('Click to copy full SHA-256', 'wpauditor') . '">SHA-256 ' . esc_html(substr($sha, 0, 12)) . '&hellip;</code>';
        } else {
            echo ' &middot; ' . esc_html__('SHA-256 skipped or unavailable', 'wpauditor');
        }
        echo '</div></td>';

        echo '<td class="wpa-forensics-evidence">';
        echo '<div class="wpa-forensics-detectors">';
        foreach ($detectors as $detector) {
            $detector_labels = [
                'uploads'    => __('Upload threat', 'wpauditor'),
                'sensitive'  => __('Sensitive exposure', 'wpauditor'),
            ];
            $label = $detector_labels[$detector] ?? ucfirst($detector);
            echo '<span class="wpa-forensics-detector wpa-forensics-detector-' . esc_attr($detector) . '">' . esc_html($label) . '</span>';
        }
        echo '</div>';
        if ($evidence) {
            echo '<strong>' . esc_html($evidence[0]) . '</strong>';
        }
        if (count($evidence) > 1 || $rules) {
// translators: Placeholders are replaced with the values described by the surrounding message.
            echo '<details><summary>' . esc_html(sprintf(_n('%d matched signal', '%d matched signals', count($rules), 'wpauditor'), count($rules))) . '</summary><ul>';
            foreach ($evidence as $index => $item) {
                $rule = $rules[$index] ?? '';
                echo '<li>' . esc_html($item);
                if ($rule !== '') echo '<br><code>' . esc_html($rule) . '</code>';
                echo '</li>';
            }
            echo '</ul></details>';
        }
        echo '</td>';

        echo '<td class="wpa-forensics-risk">' . wp_kses_post(wpauditor_file_forensics_severity_badge((string) ($finding['severity'] ?? 'Info')));
// translators: Placeholders are replaced with the values described by the surrounding message.
        echo '<strong>' . esc_html(sprintf(__('%d/100', 'wpauditor'), (int) ($finding['score'] ?? 0))) . '</strong>';
// translators: Placeholders are replaced with the values described by the surrounding message.
        echo '<span>' . esc_html(sprintf(__('%s confidence', 'wpauditor'), (string) ($finding['confidence'] ?? 'Low'))) . '</span></td>';
        echo '<td><code>' . esc_html((string) ($finding['ext'] ?: __('none', 'wpauditor'))) . '</code><br><span class="wpa-muted">' . esc_html((string) ($finding['mime'] ?? 'unknown')) . '</span></td>';
        echo '<td>' . esc_html((string) ($finding['modified'] ?? '')) . '</td>';
        echo '<td>';
        if ($available) {
            $row_form_id = 'wpa-forensics-row-action-' . count($row_action_forms);
            $row_action_forms[$row_form_id] = $relative;
// translators: Placeholders are replaced with the values described by the surrounding message.
            echo '<button type="submit" form="' . esc_attr($row_form_id) . '" class="button button-secondary button-small wpa-confirm-submit" aria-label="' . esc_attr(sprintf(__('Quarantine %s', 'wpauditor'), $relative)) . '" data-wpa-confirm-action="quarantine" data-wpa-confirm-title="' . esc_attr__('Quarantine this file?', 'wpauditor') . '" data-wpa-confirm-description="' . esc_attr__('Move this file into protected quarantine.', 'wpauditor') . '" data-wpa-confirm-note="' . esc_attr__('This may affect site functionality. The file can be restored later from Quarantine Manager.', 'wpauditor') . '" data-wpa-confirm-label="' . esc_attr__('Quarantine File', 'wpauditor') . '" data-wpa-confirm-target-label="' . esc_attr__('File', 'wpauditor') . '" data-wpa-confirm-target="' . esc_attr($relative) . '">' . esc_html__('Quarantine', 'wpauditor') . '</button>';
        } else {
            echo '<span class="wpa-muted">' . esc_html__('Unavailable', 'wpauditor') . '</span>';
        }
        echo '</td>';
        echo '</tr>';
    }

    echo '</tbody></table>';

    if ($total_pages > 1) {
        $page_url = add_query_arg(array_filter([
            'page'     => 'wpauditor-file-forensics',
            'scan_id'  => $scan_id,
            'detector' => $detector_filter,
            'severity' => $severity_filter,
            's'        => $search,
            'paged'    => '%#%',
        ], static fn($value) => $value !== ''), admin_url('admin.php'));
        echo '<div class="tablenav"><div class="tablenav-pages">' . wp_kses_post(paginate_links([
            'base'      => $page_url,
            'format'    => '',
            'prev_text' => __('&laquo; Previous', 'wpauditor'),
            'next_text' => __('Next &raquo;', 'wpauditor'),
            'total'     => $total_pages,
            'current'   => $current_page,
        ])) . '</div></div>';
    }

    echo '<p class="submit wpa-flex-actions">';
    echo '<button type="submit" class="button button-secondary wpa-confirm-submit" id="wpa-forensics-quarantine" data-wpa-confirm-action="quarantine" data-wpa-confirm-eyebrow="' . esc_attr__('File Forensics', 'wpauditor') . '" data-wpa-confirm-title="' . esc_attr__('Quarantine selected files?', 'wpauditor') . '" data-wpa-confirm-description="' . esc_attr__('Move the selected files into protected quarantine.', 'wpauditor') . '" data-wpa-confirm-note="' . esc_attr__('Files can be restored later from Quarantine Manager.', 'wpauditor') . '" data-wpa-confirm-label="' . esc_attr__('Quarantine Files', 'wpauditor') . '" data-wpa-confirm-target-source="selected" data-wpa-confirm-target-unit="file">' . esc_html__('Quarantine Selected Files', 'wpauditor') . '</button>';
    echo '<span id="wpa-forensics-selected-count" class="wpa-muted"></span>';
    echo '</p>';
    echo '</form>';

    // Separate row forms keep bulk selections out of single-file submissions.
    $row_nonce = wp_create_nonce('wpauditor_file_action');
    foreach ($row_action_forms as $row_form_id => $relative) {
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" id="' . esc_attr($row_form_id) . '" hidden>';
        echo '<input type="hidden" name="action" value="wpauditor_file_action">';
        echo '<input type="hidden" name="wpauditor_nonce" value="' . esc_attr($row_nonce) . '">';
        echo '<input type="hidden" name="wpauditor_operation" value="quarantine">';
        echo '<input type="hidden" name="wpauditor_scan_id" value="' . esc_attr($scan_id) . '">';
        echo '<input type="hidden" name="wpauditor_scan_type" value="file-forensics">';
        echo '<input type="hidden" name="files[]" value="' . esc_attr($relative) . '">';
        echo '</form>';
    }

    ?>
    <?php ob_start(); ?>
    (function(){
        const selectAll = document.getElementById('wpa-forensics-select-all');
        const checks = Array.from(document.querySelectorAll('.wpa-forensics-row-check'));
        const quarantine = document.getElementById('wpa-forensics-quarantine');
        const selectedCount = document.getElementById('wpa-forensics-selected-count');

        function updateSelected(){
            const count = checks.filter(function(check){ return check.checked; }).length;
            if (selectedCount) selectedCount.textContent = count ? count + ' selected' : '';
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
                const count = checks.filter(function(check){ return check.checked; }).length;
                if (!count) {
                    event.preventDefault();
                    window.alert('<?php echo esc_js(__('Select at least one available file.', 'wpauditor')); ?>');
                    return;
                }
            });
        }

        document.querySelectorAll('.wpa-copy').forEach(function(element){
            element.addEventListener('click', function(){
                const value = this.dataset.copy || '';
                if (value && navigator.clipboard) navigator.clipboard.writeText(value);
            });
        });
    })();
    <?php
    $forensics_script = ob_get_clean();
    wp_add_inline_script('wpauditor-admin-ui', $forensics_script, 'after');
    ?>
    <?php

    echo '</div>';
}
