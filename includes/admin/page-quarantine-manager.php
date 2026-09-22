<?php
if (!defined('ABSPATH')) exit;
// Status and pagination query values only control this read-only report view.
// phpcs:disable WordPress.Security.NonceVerification.Recommended
// Local metadata reads are restricted to the plugin quarantine directory.
// phpcs:disable WordPress.WP.AlternativeFunctions

// WPAuditor Quarantine Manager (QID-only UI)
function wpauditor_admin_page_quarantine_manager() {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'wpauditor'));
    }

    $qdir = wpauditor_get_quarantine_dir();

    echo '<div class="wrap wpa-admin-shell wpa-quarantine-page">';
	echo '<h1> Quarantine Manager</h1><br>';

    // Notices from actions-handler.php
    $status = isset($_GET['wpauditor_status']) ? sanitize_key(wp_unslash($_GET['wpauditor_status'])) : '';
    $ok     = isset($_GET['ok']) ? absint(wp_unslash($_GET['ok'])) : null;
    $fail   = isset($_GET['fail']) ? absint(wp_unslash($_GET['fail'])) : null;

    if ($status) {
        $msg = '';
        // translators: 1: number of successful actions, 2: number of failed actions.
        if ($status === 'restored')        $msg = sprintf(__('Restore complete — %1$d ok, %2$d failed.', 'wpauditor'), (int)$ok, (int)$fail);
        // translators: 1: number of successful actions, 2: number of failed actions.
        elseif ($status === 'deleted')     $msg = sprintf(__('Delete complete — %1$d ok, %2$d failed.', 'wpauditor'), (int)$ok, (int)$fail);
        // translators: 1: number of successful actions, 2: number of failed actions.
        elseif ($status === 'quarantined') $msg = sprintf(__('Quarantine complete — %1$d ok, %2$d failed.', 'wpauditor'), (int)$ok, (int)$fail);
        elseif ($status === 'rate_limited') $msg = __('Action rate limited — please try again.', 'wpauditor');
        elseif ($status === 'qdir_error')   $msg = __('Quarantine directory is not ready.', 'wpauditor');
        elseif ($status === 'invalid_action') $msg = __('Invalid action.', 'wpauditor');
        elseif ($status === 'invalid_nonce') $msg = __('The security token expired. Refresh the page and try again.', 'wpauditor');
        elseif ($status === 'no_files') $msg = __('Select at least one quarantined file.', 'wpauditor');

        if ($msg) echo '<div class="notice notice-info is-dismissible"><p>' . esc_html($msg) . '</p></div>';
    }

    // Quarantine directory check
    if (!is_dir($qdir)) {
        echo '<div class="notice notice-warning"><p>' . esc_html__('Quarantine directory not found.', 'wpauditor') . '</p></div>';
        echo '</div>';
        return;
    }

    // Gather items (each *.qua has optional .json sidecar)
    $items = [];
    $files = glob($qdir . DIRECTORY_SEPARATOR . '*.qua');
    if ($files === false) $files = [];

    foreach ($files as $qfile) {
        if (!is_file($qfile)) continue;

        $qid   = basename($qfile, '.qua');
        $metaF = $qdir . DIRECTORY_SEPARATOR . $qid . '.json';

        $size  = @filesize($qfile);
        $mtime = @filemtime($qfile);

        // Defaults; metadata may override
        $meta = [
            'qid'            => $qid,
            'original_path'  => '',
            'original_name'  => '',
            'size'           => ($size !== false ? (int)$size : null),
            'sha256'         => '',
            'quarantined_at' => ($mtime ? gmdate('Y-m-d H:i:s', $mtime) : ''),
            'by'             => '',
            'fingerprint'    => '',
            'scan_id'        => '',
            'finding_id'     => '',
            'detectors'      => [],
            'rules'          => [],
            'evidence'       => [],
            'risk_score'     => 0,
            'risk_severity'  => '',
            'confidence'     => '',
        ];

        if (is_file($metaF)) {
            $raw = @file_get_contents($metaF);
            $j   = $raw ? json_decode($raw, true) : null;
            if (is_array($j)) {
                $meta = array_merge($meta, array_intersect_key($j, $meta));
            }
        }

        $size_hr = ($meta['size'] !== null) ? size_format((float)$meta['size']) : __('Unknown', 'wpauditor');

        $items[] = [
            'qid'            => $qid,
            'file'           => basename($qfile),
            'size_bytes'     => $meta['size'],
            'size_hr'        => $size_hr,
            'sha256'         => (string)$meta['sha256'],
            'original_path'  => (string)$meta['original_path'],
            'original_name'  => (string)$meta['original_name'],
            'quarantined_at' => (string)$meta['quarantined_at'],
            'by'             => (string)$meta['by'],
            'fingerprint'    => (string)$meta['fingerprint'],
            'scan_id'        => (string)$meta['scan_id'],
            'finding_id'     => (string)$meta['finding_id'],
            'detectors'      => is_array($meta['detectors']) ? $meta['detectors'] : [],
            'rules'          => is_array($meta['rules']) ? $meta['rules'] : [],
            'evidence'       => is_array($meta['evidence']) ? $meta['evidence'] : [],
            'risk_score'     => (int)$meta['risk_score'],
            'risk_severity'  => (string)$meta['risk_severity'],
            'confidence'     => (string)$meta['confidence'],
        ];
    }

    // Sort newest first
    usort($items, function ($a, $b) {
        $ta = strtotime($a['quarantined_at'] ?: '1970-01-01 00:00:00');
        $tb = strtotime($b['quarantined_at'] ?: '1970-01-01 00:00:00');
        if ($ta === $tb) return strcmp($b['qid'], $a['qid']);
        return $tb <=> $ta;
    });

    if (empty($items)) {
        echo '<div class="notice notice-success"><p>' . esc_html__('No quarantined files found.', 'wpauditor') . '</p></div>';
        echo '</div>';
        return;
    }

    // Pagination
    $per_page     = WPAUDITOR_ADMIN_ROWS_PER_PAGE;
    $total_items  = count($items);
    $current_page = isset($_GET['paged']) ? max(1, absint(wp_unslash($_GET['paged']))) : 1;
    $total_pages  = (int)ceil($total_items / $per_page);
    $offset       = ($current_page - 1) * $per_page;
    $paged_items  = array_slice($items, $offset, $per_page);

    // Search controls
    echo '<div class="wpa-search-controls">';
    echo '<input type="search" id="wpa-qsearch" class="regular-text" placeholder="' . esc_attr__('Search (QID, path, hash, user)…', 'wpauditor') . '" />';
    echo '<button type="button" class="button" id="wpa-qsearch-clear">' . esc_html__('Clear', 'wpauditor') . '</button>';
    echo '</div>';

    // Bulk form posts to actions handler
    echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" id="wpa-qform">';
    echo '<input type="hidden" name="action" value="wpauditor_file_action">';
    wp_nonce_field('wpauditor_file_action', 'wpauditor_nonce');

    echo '<table class="widefat striped" id="wpa-qtable">';
    echo '<thead><tr>';
    echo '<th class="wpa-col-select-narrow"><label class="screen-reader-text" for="wpa-select-all">' . esc_html__('Select all quarantined files on this page', 'wpauditor') . '</label><input type="checkbox" id="wpa-select-all" title="' . esc_attr__('Select All', 'wpauditor') . '"></th>';
    echo '<th>' . esc_html__('QID', 'wpauditor') . '</th>';
    echo '<th>' . esc_html__('Original Path', 'wpauditor') . '</th>';
    echo '<th>' . esc_html__('Forensic Finding', 'wpauditor') . '</th>';
    echo '<th>' . esc_html__('Size', 'wpauditor') . '</th>';
    echo '<th>' . esc_html__('SHA256', 'wpauditor') . '</th>';
    echo '<th>' . esc_html__('Quarantined At', 'wpauditor') . '</th>';
    echo '<th>' . esc_html__('By', 'wpauditor') . '</th>';
// translators: Placeholders are replaced with the values described by the surrounding message.
    echo '</tr></thead><tbody>';

    foreach ($paged_items as $row) {
        $qid    = $row['qid'];
        $op     = $row['original_path'] ?: __('Unknown', 'wpauditor');
// translators: Placeholders are replaced with the values described by the surrounding message.
        $sha    = $row['sha256'] ?: __('Unknown', 'wpauditor');
        $qtime  = $row['quarantined_at'] ?: __('Unknown', 'wpauditor');
        $by     = $row['by'] ?: __('Unknown', 'wpauditor');
        $detectors = array_values(array_filter(array_map('sanitize_key', (array)$row['detectors'])));
        $finding_label = $detectors
            ? implode(', ', array_map(static function ($detector) {
                return $detector === 'uploads' ? __('Upload threat', 'wpauditor') : __('Sensitive exposure', 'wpauditor');
            }, $detectors))
            : __('Legacy quarantine item', 'wpauditor');

        echo '<tr>';
        // translators: %s is the original path of the quarantined file.
        echo '<td><input type="checkbox" name="files[]" value="' . esc_attr($qid) . '" class="wpa-rowcheck" aria-label="' . esc_attr(sprintf(__('Select quarantined file %s', 'wpauditor'), $op)) . '"></td>';

        // Click-to-copy fields
        echo '<td><code class="wpa-copy" data-copy="' . esc_attr($qid) . '" title="' . esc_attr__('Click to copy', 'wpauditor') . '">' . esc_html($qid) . '</code></td>';
        echo '<td><code class="wpa-copy" data-copy="' . esc_attr($op)  . '" title="' . esc_attr__('Click to copy', 'wpauditor') . '">' . esc_html($op)  . '</code></td>';
        echo '<td><strong>' . esc_html($finding_label) . '</strong>';
        if ($row['finding_id']) echo '<br><code>' . esc_html($row['finding_id']) . '</code>';
        // translators: %d is the number of matching detection rules.
        if ($row['rules']) echo '<br><span class="wpa-muted">' . esc_html(sprintf(_n('%d matched rule', '%d matched rules', count($row['rules']), 'wpauditor'), count($row['rules']))) . '</span>';
        echo '</td>';
        echo '<td>' . esc_html($row['size_hr']) . '</td>';
        echo '<td><code class="wpa-copy" data-copy="' . esc_attr($sha) . '" title="' . esc_attr__('Click to copy', 'wpauditor') . '">' . esc_html($sha) . '</code></td>';

        echo '<td>' . esc_html($qtime) . '</td>';
        echo '<td>' . esc_html($by) . '</td>';
        echo '</tr>';
    }

    echo '</tbody></table>';

    // Pagination links
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

    // Bulk actions
    echo '<p class="submit wpa-flex-actions">';
    echo '<input type="hidden" name="wpauditor_operation" id="wpauditor_operation" value="">';
    echo '<button type="submit" class="button button-primary wpa-confirm-submit" id="wpa-btn-restore" data-wpa-confirm-action="restore" data-wpa-confirm-eyebrow="' . esc_attr__('Quarantine Manager', 'wpauditor') . '" data-wpa-confirm-title="' . esc_attr__('Restore selected files?', 'wpauditor') . '" data-wpa-confirm-description="' . esc_attr__('Restore the selected quarantined files to their original locations.', 'wpauditor') . '" data-wpa-confirm-note="' . esc_attr__('If an original file already exists, the restored file receives a .restored suffix.', 'wpauditor') . '" data-wpa-confirm-label="' . esc_attr__('Restore Files', 'wpauditor') . '" data-wpa-confirm-target-source="selected" data-wpa-confirm-target-unit="file">' . esc_html__('Restore Selected', 'wpauditor') . '</button>';
    echo '<button type="submit" class="button button-delete wpa-confirm-submit" id="wpa-btn-delete" data-wpa-confirm-action="delete" data-wpa-confirm-eyebrow="' . esc_attr__('Quarantine Manager', 'wpauditor') . '" data-wpa-confirm-title="' . esc_attr__('Delete selected files?', 'wpauditor') . '" data-wpa-confirm-description="' . esc_attr__('Permanently delete the selected items from protected quarantine.', 'wpauditor') . '" data-wpa-confirm-note="' . esc_attr__('This action cannot be undone.', 'wpauditor') . '" data-wpa-confirm-label="' . esc_attr__('Delete Files', 'wpauditor') . '" data-wpa-confirm-target-source="selected" data-wpa-confirm-target-unit="file">' . esc_html__('Delete Selected', 'wpauditor') . '</button>';
    echo '<span id="wpa-selected-count" class="wpa-muted"></span>';
    echo '</p>';

    echo '</form>';

    // JS: select-all, bulk actions, search, and click-to-copy feedback
    ?>
    <?php ob_start(); ?>
    (function(){
        const $ = (sel, ctx=document) => ctx.querySelector(sel);
        const $$ = (sel, ctx=document) => Array.from(ctx.querySelectorAll(sel));

        const selAll = $('#wpa-select-all');
        const checks = $$('input.wpa-rowcheck');
        const actInp = $('#wpauditor_operation');
        const btnDel = $('#wpa-btn-delete');
        const btnRes = $('#wpa-btn-restore');
        const count  = $('#wpa-selected-count');

        function updateCount(){
            const n = checks.filter(c => c.checked).length;
            count.textContent = n ? (n + ' selected') : '';
        }
        if (selAll) selAll.addEventListener('change', () => { checks.forEach(c => c.checked = selAll.checked); updateCount(); });
        checks.forEach(c => c.addEventListener('change', updateCount));
        updateCount();

        function hasSelection(){ return checks.some(c => c.checked); }

        btnRes.addEventListener('click', (e) => {
            if (!hasSelection()) { e.preventDefault(); alert('Select at least one item.'); return; }
            actInp.value = 'restore';
        });

        btnDel.addEventListener('click', (e) => {
            if (!hasSelection()) { e.preventDefault(); alert('Select at least one item.'); return; }
            actInp.value = 'delete';
        });

        // Click-to-copy feedback
        document.querySelectorAll(".wpa-copy").forEach(function(el){
            el.addEventListener("click", async function(){
                var text = this.dataset.copy || this.textContent;
                try {
                    await navigator.clipboard.writeText(text);
                    var oldTitle = this.getAttribute("title") || "";
                    this.setAttribute("title","Copied!");
                    this.style.opacity = "0.75";
                    setTimeout(()=>{ this.setAttribute("title", oldTitle || "Click to copy"); this.style.opacity = "1"; }, 900);
                } catch(e){ console.warn(e); }
            });
        });

        // Client-side search/filter
        const qInput = $('#wpa-qsearch');
        const qClear = $('#wpa-qsearch-clear');
        const rows   = $$('#wpa-qtable tbody tr');

        function filterRows() {
            const q = (qInput.value || '').toLowerCase().trim();
            rows.forEach(tr => {
                const txt = tr.textContent.toLowerCase();
                tr.style.display = (!q || txt.indexOf(q) !== -1) ? '' : 'none';
            });
        }
        if (qInput) qInput.addEventListener('input', filterRows);
        if (qClear) qClear.addEventListener('click', () => { qInput.value=''; filterRows(); qInput.focus(); });
    })();
    <?php
    $quarantine_script = ob_get_clean();
    wp_add_inline_script('wpauditor-admin-ui', $quarantine_script, 'after');
    ?>
    <?php

    echo '</div>';
}
