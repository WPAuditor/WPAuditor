<?php
if (!defined('ABSPATH')) exit;

// Quarantine uses atomic local moves and permission changes after normalized path validation.
// phpcs:disable WordPress.WP.AlternativeFunctions,WordPress.PHP.DevelopmentFunctions.error_log_error_log

// Secure file actions (quarantine/restore/delete) use a dedicated admin-post route.
add_action('admin_post_wpauditor_file_action', 'wpauditor_handle_admin_actions');

function wpauditor_handle_admin_actions() {
    // Admin POST only
    $request_method = isset($_SERVER['REQUEST_METHOD'])
        ? strtoupper(sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD'])))
        : '';
    if ($request_method !== 'POST') {
        wp_die(esc_html__('Invalid request method.', 'wpauditor'), '', ['response' => 405]);
    }
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You do not have permission to manage quarantined files.', 'wpauditor'), '', ['response' => 403]);
    }

    $operation = isset($_POST['wpauditor_operation']) && is_string($_POST['wpauditor_operation'])
        ? sanitize_key(wp_unslash($_POST['wpauditor_operation']))
        : '';
    if (!in_array($operation, ['quarantine', 'restore', 'delete'], true)) {
        wpauditor_event('SECURITY_BLOCKED', "Unknown file operation={$operation}");
        wpauditor_safe_redirect(add_query_arg('wpauditor_status', 'invalid_action', wpauditor_file_action_return_url()));
    }

    // Nonce
    if (
        !isset($_POST['wpauditor_nonce']) ||
        !is_string($_POST['wpauditor_nonce']) ||
        !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['wpauditor_nonce'])), 'wpauditor_file_action')
    ) {
        wpauditor_event('SECURITY_BLOCKED', 'Invalid nonce for file action');
        wpauditor_safe_redirect(add_query_arg('wpauditor_status', 'invalid_nonce', wpauditor_file_action_return_url()));
    }

    // Per-user cooldown
    $uid = get_current_user_id();
    $key = 'wpauditor_free_action_cooldown_' . $uid;
    if (get_transient($key)) {
        wpauditor_event('RATE_LIMIT', 'Blocked burst action');
        wpauditor_safe_redirect(add_query_arg('wpauditor_status', 'rate_limited', wpauditor_file_action_return_url()));
    }
    set_transient($key, 1, 2);

    // Files list
    // Each array item is unslashed here and sanitized on the following line.
    // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
    $posted_files = isset($_POST['files']) && is_array($_POST['files'])
        ? map_deep(wp_unslash($_POST['files']), 'sanitize_text_field')
        : [];
    $files = array_values(array_map('sanitize_text_field', array_filter($posted_files, 'is_string')));
    if (!$files) {
        wpauditor_safe_redirect(add_query_arg('wpauditor_status', 'no_files', wpauditor_file_action_return_url()));
    }

    // Batch cap
    $MAX_FILES = 100;
    if (count($files) > $MAX_FILES) {
        $files = array_slice($files, 0, $MAX_FILES);
    }

    // Load trusted context from the current user's short-lived scan
    $forensic_findings = [];
    $scan_type = isset($_POST['wpauditor_scan_type']) && is_string($_POST['wpauditor_scan_type'])
        ? sanitize_key(wp_unslash($_POST['wpauditor_scan_type']))
        : '';
    $scan_id = isset($_POST['wpauditor_scan_id']) && is_string($_POST['wpauditor_scan_id'])
        ? sanitize_key(wp_unslash($_POST['wpauditor_scan_id']))
        : '';
    if ($scan_id !== '' && preg_match('/^[a-f0-9]{32}$/', $scan_id)) {
        $scan_payload = false;
        if ($scan_type === 'file-monitoring' && function_exists('wpauditor_monitoring_scan_key')) {
            $scan_payload = get_transient(wpauditor_monitoring_scan_key($scan_id, $uid));
        } elseif ($scan_type === 'file-forensics') {
            $scan_payload = get_transient('wpauditor_free_forensics_' . $uid . '_' . $scan_id);
        } elseif ($scan_type === 'core-integrity') {
            $scan_payload = get_transient('wpauditor_free_core_scan_' . $uid . '_' . $scan_id);
        } elseif ($scan_type === '') {
            // Keep existing File Forensics forms backward compatible
            $scan_payload = get_transient('wpauditor_free_forensics_' . $uid . '_' . $scan_id);
        }

        if (is_array($scan_payload) && is_array($scan_payload['results'] ?? null)) {
            foreach ($scan_payload['results'] as $finding) {
                $finding_path = isset($finding['relative_path'])
                    ? wpauditor_sanitize_rel((string) $finding['relative_path'])
                    : '';
                if ($finding_path !== '') {
                    $forensic_findings[strtolower(wp_normalize_path($finding_path))] = $finding;
                }
            }
        }
    }

    // Prepare quarantine directory
    $qdir = wpauditor_get_quarantine_dir();
    if (!wpauditor_ensure_quarantine_dir($qdir)) {
        wpauditor_event('QUARANTINE_ERROR', 'Failed to prepare quarantine directory');
        wpauditor_safe_redirect(add_query_arg('wpauditor_status', 'qdir_error', wpauditor_file_action_return_url()));
    }

    $results = ['ok' => 0, 'fail' => 0];

    if ($operation === 'quarantine') {
        foreach ($files as $user_path) {
            $user_path = wpauditor_sanitize_rel($user_path);
            $resolved  = wpauditor_secure_resolve_inside_abspath($user_path);
            if (!$resolved) {
                $results['fail']++;
                wpauditor_event('SECURITY_BLOCKED', "Quarantine reject path={$user_path}");
                continue;
            }

            // Skip items already in quarantine
            if (wpauditor_is_path_inside($resolved, $qdir)) {
                $results['fail']++;
                wpauditor_event('SECURITY_BLOCKED', "Quarantine reject (already quarantined) path={$user_path}");
                continue;
            }

            if (!is_file($resolved) || is_link($resolved)) {
                $results['fail']++;
                wpauditor_event('QUARANTINE_SKIP', "Not a regular file path={$user_path}");
                continue;
            }

            // Size cap
            $MAX_BYTES = 64 * 1024 * 1024;
            $fsize = @filesize($resolved);
            if ($fsize === false || $fsize > $MAX_BYTES) {
                $results['fail']++;
                wpauditor_event('QUARANTINE_SKIP', "Size cap exceeded path={$user_path} size={$fsize}");
                continue;
            }

            $hash   = @hash_file('sha256', $resolved) ?: '';
            $rel    = wpauditor_rel_from_abspath($resolved);
            $finding = $forensic_findings[strtolower(wp_normalize_path($rel))] ?? [];

            // Scan-backed actions must refer to an unchanged file from that trusted result set
            if ($scan_type !== '' && !$finding) {
                $results['fail']++;
                wpauditor_event('SECURITY_BLOCKED', "Quarantine reject (missing scan evidence) path={$user_path}");
                continue;
            }
            if ($finding) {
                $expected_hash = (string) ($finding['sha256'] ?? '');
                $expected_size = isset($finding['size']) ? (int) $finding['size'] : null;
                $expected_mtime = isset($finding['modified_ts']) ? (int) $finding['modified_ts'] : null;
                $current_mtime = @filemtime($resolved);
                $is_stale = $expected_hash !== ''
                    ? !hash_equals($expected_hash, $hash)
                    : ($expected_size !== null && $expected_size !== (int) $fsize) ||
                        ($expected_mtime !== null && $current_mtime !== false && $expected_mtime !== (int) $current_mtime);

                if ($is_stale) {
                    $results['fail']++;
                    wpauditor_event(
                        'SECURITY_BLOCKED',
                        "Quarantine reject (file changed after scan) path={$user_path} scan_id={$scan_id}"
                    );
                    continue;
                }
            }

            $qid    = wpauditor_make_qid($resolved, $hash);
            $qfile  = $qdir . DIRECTORY_SEPARATOR . $qid . '.qua';
            $qmeta  = $qdir . DIRECTORY_SEPARATOR . $qid . '.json';

            // Avoid overwriting an existing QID
            if (file_exists($qfile) || file_exists($qmeta)) {
                $qid   = $qid . '-' . wp_generate_password(6, false, false);
                $qfile = $qdir . DIRECTORY_SEPARATOR . $qid . '.qua';
                $qmeta = $qdir . DIRECTORY_SEPARATOR . $qid . '.json';
            }

            // Move into quarantine
            if (@rename($resolved, $qfile)) {
                $meta = [
                    'qid'            => $qid,
                    'original_path'  => $rel,
                    'original_name'  => basename($resolved),
                    'size'           => (int)$fsize,
                    'sha256'         => $hash,
                    'quarantined_at' => current_time('mysql'),
                    'by'             => wp_get_current_user()->user_login,
                    'fingerprint'    => substr(hash('sha1', $rel . '|' . $hash), 0, 20),
                    'scan_type'      => $scan_type,
                    'scan_id'        => $scan_id,
                    'finding_id'     => sanitize_key((string) ($finding['finding_id'] ?? '')),
                    'detectors'      => array_values(array_filter(array_map('sanitize_key', (array) ($finding['detectors'] ?? [])))),
                    'rules'          => array_values(array_filter(array_map('sanitize_text_field', (array) ($finding['rules'] ?? [])))),
                    'evidence'       => array_values(array_filter(array_map('sanitize_text_field', (array) ($finding['evidence'] ?? [])))),
                    'risk_score'     => max(0, min(100, (int) ($finding['score'] ?? 0))),
                    'risk_severity'  => sanitize_text_field((string) ($finding['severity'] ?? '')),
                    'confidence'     => sanitize_text_field((string) ($finding['confidence'] ?? '')),
                ];
                $meta_json = wp_json_encode($meta, JSON_UNESCAPED_SLASHES);
                $meta_written = is_string($meta_json)
                    ? @file_put_contents($qmeta, $meta_json, LOCK_EX)
                    : false;
                if ($meta_written === false) {
                    @unlink($qmeta);
                    // phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected -- Restore the verified source after a failed metadata write.
                    $rolled_back = @rename($qfile, $resolved);
                    $results['fail']++;
                    wpauditor_event(
                        'QUARANTINE_ERROR',
                        "Metadata write failed file={$rel} rollback=" . ($rolled_back ? 'ok' : 'failed')
                    );
                    continue;
                }
                @chmod($qfile, 0600);
                @chmod($qmeta, 0600);

                $results['ok']++;
                $detector_log = implode(',', $meta['detectors']);
                $event_category = $scan_type === 'file-monitoring'
                    ? 'FILE_MONITORING'
                    : ($scan_type === 'core-integrity' ? 'FILE_INTEGRITY' : 'FILE_FORENSICS');
                wpauditor_event(
                    'FILE_QUARANTINED',
                    "qid={$qid} file={$rel}" .
                    ($meta['finding_id'] ? " finding_id={$meta['finding_id']}" : '') .
                    ($detector_log ? " detector={$detector_log}" : '') .
                    ($meta['risk_severity'] ? " risk={$meta['risk_severity']}" : ''),
                    $meta['finding_id'] ? ['category' => $event_category] : []
                );
            } else {
                $results['fail']++;
                wpauditor_event('QUARANTINE_ERROR', "Move failed file={$rel}");
            }
        }

        wpauditor_finish_and_redirect('quarantined', $results);
    }

    elseif ($operation === 'restore') {
        // Restore accepts QIDs only
        foreach ($files as $qid_raw) {
            $qid = sanitize_file_name($qid_raw);
            if (!$qid) { $results['fail']++; continue; }

            $qfile = $qdir . DIRECTORY_SEPARATOR . $qid . '.qua';
            $qmeta = $qdir . DIRECTORY_SEPARATOR . $qid . '.json';

            if (!is_file($qfile) || !is_file($qmeta)) {
                $results['fail']++;
                wpauditor_event('RESTORE_ERROR', "Missing quarantine artifacts qid={$qid}");
                continue;
            }

            $meta = json_decode(@file_get_contents($qmeta), true) ?: [];
            $rel  = isset($meta['original_path']) ? (string)$meta['original_path'] : '';
            if ($rel === '' || !wpauditor_is_safe_rel($rel)) {
                $results['fail']++;
                wpauditor_event('RESTORE_ERROR', "Invalid original_path qid={$qid}");
                continue;
            }

            $wordpress_root = wpauditor_wordpress_root();
            $target_abs = wpauditor_join_and_normalize($wordpress_root, $rel);
            $resolved   = wpauditor_secure_resolve_inside_abspath($rel);
            if (!$resolved) {
                $parent = dirname($target_abs);
                if (!wpauditor_is_path_inside($parent, $wordpress_root)) {
                    $results['fail']++;
                    wpauditor_event('RESTORE_ERROR', "Parent outside ABSPATH qid={$qid}");
                    continue;
                }
                if (!is_dir($parent)) {
                    if (!wp_mkdir_p($parent)) {
                        $results['fail']++;
                        wpauditor_event('RESTORE_ERROR', "Failed to create parent qid={$qid}");
                        continue;
                    }
                }
                $dest = $target_abs;
            } else {
                if (is_file($resolved) || is_link($resolved)) {
                    $results['fail']++;
                    wpauditor_event('RESTORE_ERROR', "Destination exists qid={$qid}");
                    continue;
                }
                $dest = $resolved;
            }

            // phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected -- Restore only to the normalized, verified original WordPress path.
            if (@rename($qfile, $dest)) {
                @unlink($qmeta);
                @chmod($dest, 0640);
                $results['ok']++;
                wpauditor_event('FILE_RESTORED', "qid={$qid} to=" . wpauditor_rel_from_abspath($dest));
            } else {
                $results['fail']++;
                wpauditor_event('RESTORE_ERROR', "Move failed qid={$qid}");
            }
        }

        wpauditor_finish_and_redirect('restored', $results);
    }

    elseif ($operation === 'delete') {
        // Delete supports quarantine items only
        foreach ($files as $qid_raw) {
            $qid = sanitize_file_name($qid_raw);
            if (!$qid) { $results['fail']++; continue; }

            $qfile = $qdir . DIRECTORY_SEPARATOR . $qid . '.qua';
            $qmeta = $qdir . DIRECTORY_SEPARATOR . $qid . '.json';

            $ok1 = $ok2 = true;
            if (is_file($qfile)) $ok1 = @unlink($qfile);
            if (is_file($qmeta)) $ok2 = @unlink($qmeta);

            if ($ok1 || $ok2) {
                $results['ok']++;
                wpauditor_event('QUARANTINE_DELETED', "qid={$qid}");
            } else {
                $results['fail']++;
                wpauditor_event('DELETE_ERROR', "qid={$qid}");
            }
        }

        wpauditor_finish_and_redirect('deleted', $results);
    }

    else {
        wpauditor_event('SECURITY_BLOCKED', "Unknown file operation={$operation}");
        wpauditor_safe_redirect(add_query_arg('wpauditor_status', 'invalid_action', wpauditor_file_action_return_url()));
    }
}

// Log wrapper
function wpauditor_event($type, $details, array $context = []) {
    if (function_exists('wpauditor_log_event')) {
        wpauditor_log_event($type, $details, $context);
    } else {
        error_log("[WPAuditor] {$type} :: {$details}");
    }
}

// Safe redirect helper
function wpauditor_safe_redirect($url) {
    wp_safe_redirect($url);
    exit;
}

// Return actions to the page that submitted them, with a safe admin fallback.
function wpauditor_file_action_return_url(): string {
    $referer = wp_get_referer();
    return $referer ?: admin_url('admin.php?page=wpauditor-quarantine-manager');
}

// Quarantine directory path
function wpauditor_get_quarantine_dir(): string {
    return rtrim(wpauditor_storage_dir('quarantine'), '/\\');
}

// Ensure quarantine dir exists and is shielded
function wpauditor_ensure_quarantine_dir(string $qdir): bool {
    if ($qdir === '') return false;
    if (is_link($qdir)) return false;
    if (!is_dir($qdir)) {
        if (!wp_mkdir_p($qdir)) return false;
        @chmod($qdir, 0750);
    }

    $ht = $qdir . DIRECTORY_SEPARATOR . '.htaccess';
    if (is_link($ht)) return false;
    $apache_rules = "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n";
    $current_apache_rules = is_file($ht) ? trim((string) @file_get_contents($ht)) : '';
    if (!is_file($ht) || $current_apache_rules === 'Deny from all') {
        if (@file_put_contents($ht, $apache_rules, LOCK_EX) === false) return false;
        @chmod($ht, 0640);
    }

    $web_config = $qdir . DIRECTORY_SEPARATOR . 'web.config';
    if (is_link($web_config)) return false;
    if (!file_exists($web_config)) {
        $iis_rules = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration><system.webServer><security><authorization><remove users=\"*\" roles=\"\" verbs=\"\" /><add accessType=\"Deny\" users=\"*\" /></authorization></security></system.webServer></configuration>\n";
        if (@file_put_contents($web_config, $iis_rules, LOCK_EX) === false) return false;
        @chmod($web_config, 0640);
    }

    $ix = $qdir . DIRECTORY_SEPARATOR . 'index.php';
    if (is_link($ix)) return false;
    if (!file_exists($ix)) {
        if (@file_put_contents($ix, "<?php // Silence is golden.\n", LOCK_EX) === false) return false;
        @chmod($ix, 0640);
    }

    return true;
}

// Sanitize a user-supplied relative path
function wpauditor_sanitize_rel(string $p): string {
    $p = wp_unslash($p);
    $p = str_replace(["\0"], '', $p);
    $p = trim($p);
    $p = wp_normalize_path($p);
    $p = ltrim($p, '/');
    return $p;
}

// Validate relative path syntax
function wpauditor_is_safe_rel(string $rel): bool {
    if ($rel === '') return false;
    if (str_starts_with($rel, '/')) return false;
    if (preg_match('#(^|/)\.\.(?:/|$)#', $rel)) return false;
    if (strpos($rel, "\0") !== false) return false;
    return true;
}

// Join base + rel and normalize
function wpauditor_join_and_normalize(string $base, string $rel): string {
    $joined = rtrim($base, DIRECTORY_SEPARATOR . '/\\') . DIRECTORY_SEPARATOR . ltrim($rel, DIRECTORY_SEPARATOR . '/\\');
    return wp_normalize_path($joined);
}

// Resolve rel against ABSPATH and ensure it stays inside
function wpauditor_secure_resolve_inside_abspath(string $rel) {
    if (!wpauditor_is_safe_rel($rel)) return false;

    $wordpress_root = wpauditor_wordpress_root();
    $candidate = wpauditor_join_and_normalize($wordpress_root, $rel);
    $real      = @realpath($candidate);
    if ($real === false) return false;

    $abs_norm  = $wordpress_root;
    $real_norm = wp_normalize_path($real);

    if (!wpauditor_is_path_inside($real_norm, $abs_norm)) {
        return false;
    }
    return $real;
}

// Check if child is inside parent
function wpauditor_is_path_inside(string $child, string $parent): bool {
    $p = rtrim(wp_normalize_path($parent), '/') . '/';
    $c = wp_normalize_path($child);
    return str_starts_with($c, $p);
}

// Generate quarantine ID
function wpauditor_make_qid(string $abs_path, string $sha256): string {
    $hint = sanitize_title(basename($abs_path));
    $core = substr(hash('sha1', wp_normalize_path($abs_path) . '|' . $sha256), 0, 16);
    return $hint ? ($hint . '-' . $core) : $core;
}

// Convert absolute path under ABSPATH to relative
function wpauditor_rel_from_abspath(string $abs): string {
    $abs_norm = wp_normalize_path($abs);
    $base     = wpauditor_wordpress_root();
    if (str_starts_with($abs_norm, $base)) {
        return ltrim(substr($abs_norm, strlen($base)), '/');
    }
    return basename($abs_norm);
}

// Redirect with status and counters
function wpauditor_finish_and_redirect(string $status, array $results): void {
    $url = add_query_arg([
        'wpauditor_status' => $status,
        'ok'               => (string)$results['ok'],
        'fail'             => (string)$results['fail'],
    ], wpauditor_file_action_return_url());

    wpauditor_safe_redirect($url);
}
