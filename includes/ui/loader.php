<?php
if (!defined('ABSPATH')) exit;
// The embedded loader script reads URL parameters for display state only.
// phpcs:disable WordPress.Security.NonceVerification.Recommended

function wpauditor_render_loader($id = 'wpauditor-loader', $message = 'Scanning, please wait...', $show_progress = false) {
    ?>
    <div id="<?php echo esc_attr($id); ?>" class="wpauditor-loader">
        <div
            class="wpauditor-spinner<?php echo $show_progress ? ' wpauditor-spinner-has-progress' : ''; ?>"
            <?php if ($show_progress) : ?>
                role="progressbar"
                aria-valuemin="0"
                aria-valuemax="100"
                aria-valuenow="0"
            <?php endif; ?>
        >
            <?php if ($show_progress) : ?>
                <span class="wpauditor-spinner-progress">0%</span>
            <?php endif; ?>
        </div>
        <p class="wpauditor-loader-message"><?php echo esc_html($message); ?></p>
    </div>
    <?php
}

function wpauditor_scan_progress_key(string $progress_id, int $user_id = 0): string {
    $user_id = $user_id ?: get_current_user_id();
    return 'wpauditor_progress_' . $user_id . '_' . sanitize_key($progress_id);
}

function wpauditor_scan_progress_reporter(string $progress_id): callable {
    $progress_id = sanitize_key($progress_id);
    $last_percent = -1;

    return static function (int $completed, int $total) use ($progress_id, &$last_percent): void {
        if ($progress_id === '') return;

        $percent = $total > 0
            ? (int) floor((max(0, min($completed, $total)) / $total) * 100)
            : 100;

        if ($percent === $last_percent) return;
        $last_percent = $percent;
        set_transient(wpauditor_scan_progress_key($progress_id), $percent, 10 * MINUTE_IN_SECONDS);
    };
}

function wpauditor_ajax_scan_progress(): void {
    if (!current_user_can('manage_options')) {
        wp_send_json_error(['message' => __('Permission denied.', 'wpauditor')], 403);
    }

    check_ajax_referer('wpauditor_scan_progress', 'nonce');

    $progress_id = isset($_GET['progress_id'])
        ? sanitize_key(wp_unslash($_GET['progress_id']))
        : '';

    if (!preg_match('/^[a-f0-9]{32}$/', $progress_id)) {
        wp_send_json_error(['message' => __('Invalid scan progress identifier.', 'wpauditor')], 400);
    }

    $percent = get_transient(wpauditor_scan_progress_key($progress_id));
    wp_send_json_success(['percent' => $percent === false ? 0 : max(0, min(100, (int) $percent))]);
}
add_action('wp_ajax_wpauditor_scan_progress', 'wpauditor_ajax_scan_progress');

function wpauditor_render_progressive_scan_script(
    string $form_id,
    string $loader_id,
    string $progress_id
): void {
    echo '<span class="wpa-progressive-scan-config" hidden'
        . ' data-form-id="' . esc_attr($form_id) . '"'
        . ' data-loader-id="' . esc_attr($loader_id) . '"'
        . ' data-progress-id="' . esc_attr(sanitize_key($progress_id)) . '"'
        . ' data-ajax-url="' . esc_url(admin_url('admin-ajax.php')) . '"'
        . ' data-nonce="' . esc_attr(wp_create_nonce('wpauditor_scan_progress')) . '"></span>';
}

function wpauditor_emit_loader_progress(string $loader_id, int $completed, int $total): void {
    $percent = $total > 0
        ? (int) floor((max(0, min($completed, $total)) / $total) * 100)
        : 100;
    $loader_json = wp_json_encode($loader_id);
    $percent_json = wp_json_encode($percent . '%');
    $aria_json = wp_json_encode((string) $percent);
    wp_add_inline_script(
        'wpauditor-admin-ui',
        "(function(){var loader=document.getElementById({$loader_json});if(!loader)return;var progress=loader.querySelector('.wpauditor-spinner-progress');var spinner=loader.querySelector('.wpauditor-spinner');if(progress)progress.textContent={$percent_json};if(spinner)spinner.setAttribute('aria-valuenow',{$aria_json});}());",
        'after'
    );
}

if (!function_exists('wpauditor_render_action_confirmation_dialog')) {
    function wpauditor_render_action_confirmation_dialog(): void {
        static $rendered = false;

        if ($rendered) return;
        $rendered = true;
        $current_page = isset($_GET['page']) && is_string($_GET['page'])
            ? sanitize_key(wp_unslash($_GET['page']))
            : '';
        $show_target = true;
        ?>
        <div id="wpaActionConfirmDialog" class="wpa-confirm-dialog wpa-confirm-dialog-simple" data-action="danger" hidden>
            <div
                class="wpa-confirm-dialog-panel"
                role="alertdialog"
                aria-modal="true"
                aria-labelledby="wpaActionConfirmTitle"
                aria-describedby="wpaActionConfirmDescription"
            >
                <div class="wpa-confirm-dialog-head">
                    <span id="wpaActionConfirmIcon" class="wpa-confirm-dialog-icon" aria-hidden="true" hidden><span class="dashicons dashicons-shield"></span></span>
                    <div>
                        <h2 id="wpaActionConfirmTitle"><?php esc_html_e('Continue with this action?', 'wpauditor'); ?></h2>
                    </div>
                    <button id="wpaActionConfirmClose" type="button" class="wpa-confirm-dialog-close" aria-label="<?php esc_attr_e('Close confirmation', 'wpauditor'); ?>" hidden><span class="dashicons dashicons-no-alt" aria-hidden="true"></span></button>
                </div>
                <div class="wpa-confirm-dialog-body">
                    <?php if ($show_target): ?>
                        <p class="wpa-confirm-dialog-target" id="wpaActionConfirmTarget" hidden>
                            <span id="wpaActionConfirmTargetLabel"></span>
                            <code id="wpaActionConfirmTargetValue"></code>
                        </p>
                    <?php endif; ?>
                    <p id="wpaActionConfirmDescription"></p>
                    <p class="wpa-confirm-dialog-simple-note" id="wpaActionConfirmNote"><?php esc_html_e('This action takes effect immediately after confirmation.', 'wpauditor'); ?></p>
                </div>
                <div class="wpa-confirm-dialog-actions">
                    <button type="button" class="button wpa-confirm-dialog-cancel"><?php esc_html_e('Cancel', 'wpauditor'); ?></button>
                    <button type="button" class="button button-primary wpa-confirm-dialog-confirm"><?php esc_html_e('Confirm', 'wpauditor'); ?></button>
                </div>
            </div>
        </div>
        <?php ob_start(); ?>
        (function(){
          function initActionConfirmation(){
            var dialog = document.getElementById("wpaActionConfirmDialog");
            if (!dialog || dialog.dataset.initialized === "1") return;
            dialog.dataset.initialized = "1";

            var title = document.getElementById("wpaActionConfirmTitle");
            var description = document.getElementById("wpaActionConfirmDescription");
            var target = document.getElementById("wpaActionConfirmTarget");
            var targetLabel = document.getElementById("wpaActionConfirmTargetLabel");
            var targetValue = document.getElementById("wpaActionConfirmTargetValue");
            var note = document.getElementById("wpaActionConfirmNote");
            var icon = document.getElementById("wpaActionConfirmIcon");
            var closeButton = document.getElementById("wpaActionConfirmClose");
            var cancelButton = dialog.querySelector(".wpa-confirm-dialog-cancel");
            var confirmButton = dialog.querySelector(".wpa-confirm-dialog-confirm");
            var resolver = null;
            var lastFocus = null;

            function focusableElements(){
              return Array.prototype.slice.call(dialog.querySelectorAll("button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])")).filter(function(element){ return !element.hidden; });
            }

            function finish(result, restoreFocus){
              dialog.hidden = true;
              document.body.classList.remove("wpa-confirm-dialog-open");
              var pendingResolver = resolver;
              resolver = null;
              if (restoreFocus && lastFocus && typeof lastFocus.focus === "function") lastFocus.focus();
              if (pendingResolver) pendingResolver(result);
            }

            function selectedTarget(form, trigger){
              var source = trigger.dataset.wpaConfirmTargetSource || "";
              if (!form || !source) return {label: "", value: ""};

              if (source === "selected") {
                var selected = Array.prototype.slice.call(form.querySelectorAll('input[type="checkbox"]:checked')).filter(function(field){ return !!field.name; });
                var unit = trigger.dataset.wpaConfirmTargetUnit || "item";
                return {
                  label: trigger.dataset.wpaConfirmTargetLabel || "Selection",
                  value: selected.length + " selected " + unit + (selected.length === 1 ? "" : "s")
                };
              }

              if (source === "date-range") {
                var from = form.elements.namedItem("clean_from_date");
                var to = form.elements.namedItem("clean_to_date");
                var fromValue = from && from.value ? from.value : "Start";
                var toValue = to && to.value ? to.value : "Today";
                return {label: trigger.dataset.wpaConfirmTargetLabel || "Date range", value: fromValue + " to " + toValue};
              }

              if (source === "field") {
                var field = form.elements.namedItem(trigger.dataset.wpaConfirmTargetField || "");
                return {
                  label: trigger.dataset.wpaConfirmTargetLabel || "Target",
                  value: field && field.value ? field.value : ""
                };
              }

              return {label: "", value: ""};
            }

            function optionsFromTrigger(trigger, form){
              var dynamicTarget = selectedTarget(form, trigger);
              return {
                action: trigger.dataset.wpaConfirmAction || "danger",
                eyebrow: trigger.dataset.wpaConfirmEyebrow || "Confirm action",
                title: trigger.dataset.wpaConfirmTitle || "Continue with this action?",
                description: trigger.dataset.wpaConfirmDescription || "Review this action before continuing.",
                note: trigger.dataset.wpaConfirmNote || "This action takes effect immediately after confirmation.",
                confirmLabel: trigger.dataset.wpaConfirmLabel || "Confirm",
                targetLabel: dynamicTarget.label || trigger.dataset.wpaConfirmTargetLabel || "",
                target: dynamicTarget.value || trigger.dataset.wpaConfirmTarget || "",
                icon: trigger.dataset.wpaConfirmIcon || ""
              };
            }

            window.wpauditorConfirm = function(options){
              options = options || {};
              if (resolver) finish(false, false);

              var action = options.action || "danger";
              var ipStyle = options.style === "ip";
              dialog.classList.toggle("wpa-confirm-dialog-simple", !ipStyle);
              dialog.classList.toggle("wpa-confirm-dialog-ip", ipStyle);
              icon.hidden = !ipStyle;
              closeButton.hidden = !ipStyle;
              dialog.dataset.action = action;
              title.textContent = options.title || "Continue with this action?";
              description.textContent = options.description || "Review this action before continuing.";
              note.textContent = options.note || "This action takes effect immediately after confirmation.";
              confirmButton.textContent = options.confirmLabel || "Confirm";
              if (target) {
                if (targetLabel) targetLabel.textContent = options.targetLabel || "";
                if (targetValue) targetValue.textContent = options.target || "";
                target.hidden = !options.target;
              }
              lastFocus = document.activeElement;
              dialog.hidden = false;
              document.body.classList.add("wpa-confirm-dialog-open");
              window.requestAnimationFrame(function(){ cancelButton.focus(); });

              return new Promise(function(resolve){ resolver = resolve; });
            };

            document.addEventListener("submit", function(event){
              if (event.defaultPrevented) return;
              var form = event.target;
              var submitter = event.submitter || document.activeElement;
              if (!submitter || !submitter.classList || !submitter.classList.contains("wpa-confirm-submit")) return;
              if (form.dataset.wpaActionConfirmed === "1") {
                delete form.dataset.wpaActionConfirmed;
                return;
              }

              event.preventDefault();
              event.stopPropagation();
              window.wpauditorConfirm(optionsFromTrigger(submitter, form)).then(function(confirmed){
                if (!confirmed) return;
                form.dataset.wpaActionConfirmed = "1";
                if (typeof form.requestSubmit === "function") form.requestSubmit(submitter);
                else HTMLFormElement.prototype.submit.call(form);
              });
            });

            closeButton.addEventListener("click", function(){ finish(false, true); });
            cancelButton.addEventListener("click", function(){ finish(false, true); });
            confirmButton.addEventListener("click", function(){ finish(true, false); });
            dialog.addEventListener("click", function(event){
              if (event.target === dialog) finish(false, true);
            });

            document.addEventListener("keydown", function(event){
              if (dialog.hidden) return;
              if (event.key === "Escape") {
                event.preventDefault();
                finish(false, true);
                return;
              }
              if (event.key !== "Tab") return;

              var focusable = focusableElements();
              if (!focusable.length) return;
              var first = focusable[0];
              var last = focusable[focusable.length - 1];
              if (event.shiftKey && document.activeElement === first) {
                event.preventDefault();
                last.focus();
              } else if (!event.shiftKey && document.activeElement === last) {
                event.preventDefault();
                first.focus();
              }
            });
          }

          if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initActionConfirmation);
          else initActionConfirmation();
        })();
        <?php
        $confirmation_script = ob_get_clean();
        wp_add_inline_script('wpauditor-admin-ui', $confirmation_script, 'after');
        ?>
        <?php
    }
}

add_action('admin_footer', function (): void {
    $page = isset($_GET['page']) && is_string($_GET['page']) ? sanitize_key(wp_unslash($_GET['page'])) : '';
    if (strpos($page, 'wpauditor') !== 0) return;
    wpauditor_render_action_confirmation_dialog();
}, 20);
