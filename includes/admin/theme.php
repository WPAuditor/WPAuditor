<?php
// WPAuditor per-user admin theme controls.

if (!defined('ABSPATH')) exit;
// Admin page query values select presentation assets and never change state.
// phpcs:disable WordPress.Security.NonceVerification.Recommended

if (!defined('WPAUDITOR_ADMIN_THEME_META')) {
    define('WPAUDITOR_ADMIN_THEME_META', 'wpauditor_free_admin_theme');
}

if (!function_exists('wpauditor_theme_is_admin_page')) {
    function wpauditor_theme_is_admin_page(): bool {
        $page = isset($_GET['page']) && is_string($_GET['page'])
            ? sanitize_key(wp_unslash($_GET['page']))
            : '';

        return $page === 'wpauditor-securitylog' || $page === 'wpauditor' || strpos($page, 'wpauditor-') === 0 || strpos($page, 'wpauditor_') === 0;
    }
}

if (!function_exists('wpauditor_theme_get_user_preference')) {
    function wpauditor_theme_get_user_preference(int $user_id = 0): string {
        $user_id = $user_id > 0 ? $user_id : get_current_user_id();
        if ($user_id <= 0) return 'dark';

        $theme = sanitize_key((string) get_user_meta($user_id, WPAUDITOR_ADMIN_THEME_META, true));
        return in_array($theme, ['light', 'dark'], true) ? $theme : 'dark';
    }
}

if (!function_exists('wpauditor_theme_body_class')) {
    function wpauditor_theme_body_class(string $classes): string {
        if (!wpauditor_theme_is_admin_page()) return $classes;

        return $classes . ' wpauditor-theme-' . wpauditor_theme_get_user_preference();
    }
}
add_filter('admin_body_class', 'wpauditor_theme_body_class');

if (!function_exists('wpauditor_theme_enqueue_assets')) {
    function wpauditor_theme_enqueue_assets(): void {
        if (!wpauditor_theme_is_admin_page() || !current_user_can('manage_options')) return;

        $style_path = plugin_dir_path(WPAUDITOR_MAIN_FILE) . 'includes/ui/theme/wpa-theme.css';
        wp_enqueue_style(
            'wpauditor-theme',
            plugins_url('includes/ui/theme/wpa-theme.css', WPAUDITOR_MAIN_FILE),
            ['wpauditor-components'],
            file_exists($style_path) ? (string) filemtime($style_path) : '1.0.0'
        );

        $page = isset($_GET['page']) && is_string($_GET['page'])
            ? sanitize_key(wp_unslash($_GET['page']))
            : '';
        if ($page !== 'wpauditor-dashboard') return;

        $script_path = plugin_dir_path(WPAUDITOR_MAIN_FILE) . 'includes/ui/theme/wpa-theme.js';
        wp_enqueue_script(
            'wpauditor-theme',
            plugins_url('includes/ui/theme/wpa-theme.js', WPAUDITOR_MAIN_FILE),
            [],
            file_exists($script_path) ? (string) filemtime($script_path) : '1.0.0',
            true
        );
        wp_localize_script('wpauditor-theme', 'wpauditorTheme', [
            'ajaxUrl'  => admin_url('admin-ajax.php'),
            'nonce'    => wp_create_nonce('wpauditor_save_theme'),
            'theme'    => wpauditor_theme_get_user_preference(),
            'strings'  => [
                'dark'          => __('Dark', 'wpauditor'),
                'light'         => __('Light', 'wpauditor'),
                'switchToDark'  => __('Switch to Dark theme', 'wpauditor'),
                'switchToLight' => __('Switch to Light theme', 'wpauditor'),
                'saveFailed'    => __('The theme preference could not be saved.', 'wpauditor'),
            ],
        ]);
    }
}
add_action('admin_enqueue_scripts', 'wpauditor_theme_enqueue_assets');

if (!function_exists('wpauditor_theme_save_ajax')) {
    function wpauditor_theme_save_ajax(): void {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('You are not allowed to change this preference.', 'wpauditor')], 403);
        }

        check_ajax_referer('wpauditor_save_theme', 'nonce');
        $theme = isset($_POST['theme']) ? sanitize_key(wp_unslash($_POST['theme'])) : '';
        if (!in_array($theme, ['light', 'dark'], true)) {
            wp_send_json_error(['message' => __('Invalid theme preference.', 'wpauditor')], 400);
        }

        update_user_meta(get_current_user_id(), WPAUDITOR_ADMIN_THEME_META, $theme);
        wp_send_json_success(['theme' => $theme]);
    }
}
add_action('wp_ajax_wpauditor_save_theme', 'wpauditor_theme_save_ajax');

if (!function_exists('wpauditor_render_theme_toggle')) {
    function wpauditor_render_theme_toggle(): void {
        if (!current_user_can('manage_options')) return;

        $theme = wpauditor_theme_get_user_preference();
        $is_light = $theme === 'light';
        $switch_label = $is_light ? __('Switch to Dark theme', 'wpauditor') : __('Switch to Light theme', 'wpauditor');
        ?>
        <div class="wpa-theme-control" id="wpaThemeControl" data-theme="<?php echo esc_attr($theme); ?>">
            <button
                type="button"
                class="wpa-theme-toggle wpa-header-icon-button"
                id="wpaThemeToggle"
                role="switch"
                aria-checked="<?php echo $is_light ? 'true' : 'false'; ?>"
                aria-label="<?php echo esc_attr__('Light theme', 'wpauditor'); ?>"
                title="<?php echo esc_attr($switch_label); ?>"
            >
                <span class="wpa-theme-icon" aria-hidden="true">
                    <svg class="wpa-theme-icon-sun" viewBox="0 0 24 24" focusable="false">
                        <circle cx="12" cy="12" r="3.5"></circle>
                        <path d="M12 2.5v2M12 19.5v2M4.5 12h-2M21.5 12h-2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M18.7 5.3l-1.4 1.4M6.7 17.3l-1.4 1.4"></path>
                    </svg>
                    <svg class="wpa-theme-icon-moon" viewBox="0 0 24 24" focusable="false">
                        <path d="M20.5 14.2A8.5 8.5 0 0 1 9.8 3.5a8.6 8.6 0 1 0 10.7 10.7Z"></path>
                    </svg>
                </span>
            </button>
            <span class="screen-reader-text" id="wpaThemeLive" aria-live="polite"></span>
        </div>
        <?php
    }
}
