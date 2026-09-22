<?php
// WPAuditor Free plugin bootstrap.

/**
 * Plugin Name: WPAuditor
 * Description: The security visibility layer for WordPress. Logs activity, detects basic threats, checks core integrity, and provides file forensics, quarantine, and login/API hardening.
 * Version: 1.0.0
 * Requires at least: 6.0
 * Requires PHP: 8.0
 * Author: WPAuditor
 * Author URI: https://wpauditor.app
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: wpauditor
 */

if (!defined('ABSPATH')) exit;
// Admin page query values select menus and styles and never change state.
// phpcs:disable WordPress.Security.NonceVerification.Recommended

// Keep the two editions from loading the same runtime simultaneously.
$wpauditor_active_plugins = (array) get_option('active_plugins', []);
$wpauditor_network_plugins = is_multisite() ? (array) get_site_option('active_sitewide_plugins', []) : [];
$wpauditor_pro_active = in_array('wpauditor-pro/wpauditor-pro.php', $wpauditor_active_plugins, true)
    || isset($wpauditor_network_plugins['wpauditor-pro/wpauditor-pro.php'])
    || defined('WPAUDITOR_MAIN_FILE');

if ($wpauditor_pro_active) {
    add_action('admin_notices', function () {
        if (!current_user_can('activate_plugins')) return;
        $screen = function_exists('get_current_screen') ? get_current_screen() : null;
        if (!$screen || $screen->id !== 'plugins') return;
        echo '<div class="notice notice-warning"><p>'
            . esc_html__('WPAuditor Free is paused while WPAuditor Pro is active. Deactivate Pro before using Free.', 'wpauditor')
            . '</p></div>';
    });
    return;
}

define('WPAUDITOR_MAIN_FILE', __FILE__);
define('WPAUDITOR_USER_AGENT', 'WPAuditor Free (+https://wpauditor.app)');
define('WPAUDITOR_MENU_ICON_URL', plugins_url('includes/ui/32x32.png', __FILE__));
define('WPAUDITOR_ADMIN_ROWS_PER_PAGE', 50);

$wpauditor_free_path = plugin_dir_path(__FILE__);
require_once $wpauditor_free_path . 'includes/log-maintenance.php';
require_once $wpauditor_free_path . 'includes/security-scoring.php';
require_once $wpauditor_free_path . 'includes/event-logger.php';
require_once $wpauditor_free_path . 'includes/admin/theme.php';
require_once $wpauditor_free_path . 'includes/scanner/scanner-core.php';
require_once $wpauditor_free_path . 'includes/scanner/actions-handler.php';
require_once $wpauditor_free_path . 'includes/ui/loader.php';
require_once $wpauditor_free_path . 'includes/ui/components.php';
require_once $wpauditor_free_path . 'includes/admin/change-login-url.php';
require_once $wpauditor_free_path . 'includes/admin/page-api-access-control.php';

if (is_admin()) {
    require_once $wpauditor_free_path . 'includes/admin/page-file-forensics.php';
    require_once $wpauditor_free_path . 'includes/admin/page-core-integrity.php';
    require_once $wpauditor_free_path . 'includes/admin/page-quarantine-manager.php';
    require_once $wpauditor_free_path . 'includes/admin/page-dashboard.php';
    require_once $wpauditor_free_path . 'includes/admin/page-security-events.php';
    require_once $wpauditor_free_path . 'includes/admin/page-settings.php';
}

register_activation_hook(__FILE__, function () {
    if (!wpauditor_prepare_log_storage()) {
        wp_die(esc_html__('WPAuditor Free could not create protected log storage.', 'wpauditor'));
    }
});

register_deactivation_hook(__FILE__, function () {
    wp_clear_scheduled_hook('wpauditor_free_daily_autoclean');
});

add_action('admin_menu', function () {
    global $submenu;

    $cap = 'manage_options';
    add_menu_page('WPAuditor Free - Dashboard', 'WPAuditor', $cap, 'wpauditor-dashboard', 'wpauditor_soc_logs_page', WPAUDITOR_MENU_ICON_URL);
    add_submenu_page('wpauditor-dashboard', 'Dashboard', 'Dashboard', $cap, 'wpauditor-dashboard', 'wpauditor_soc_logs_page');
    add_submenu_page('wpauditor-dashboard', 'Security Events', 'Security Events', $cap, 'wpauditor-security-events', 'wpauditor_security_events_page');
    add_submenu_page('wpauditor-dashboard', 'File Forensics', 'File Forensics', $cap, 'wpauditor-file-forensics', 'wpauditor_admin_page_file_forensics');
    add_submenu_page('wpauditor-dashboard', 'Core Integrity', 'Core Integrity', $cap, 'wpauditor-core-integrity', 'wpauditor_admin_page_core_integrity');
    add_submenu_page('wpauditor-dashboard', 'Quarantine Manager', 'Quarantine Manager', $cap, 'wpauditor-quarantine-manager', 'wpauditor_admin_page_quarantine_manager');
    add_submenu_page('wpauditor-dashboard', 'Custom Login', 'Custom Login', $cap, 'wpauditor-change-login', 'wpauditor_settings_hardening_loginurl_render');
    add_submenu_page('wpauditor-dashboard', 'API Access Control', 'API Access Control', $cap, 'wpauditor-api-access-control', 'wpauditor_admin_page_api_access_control');
    add_submenu_page('wpauditor-dashboard', 'Settings', 'Settings', $cap, 'wpauditor-settings', 'wpauditor_admin_page_settings');

    if (isset($submenu['wpauditor-dashboard']) && is_array($submenu['wpauditor-dashboard'])) {
        $submenu['wpauditor-dashboard'][] = [
            esc_html__('Get Pro', 'wpauditor') . ' <span class="wpa-pro-menu-badge">' . esc_html__('PRO', 'wpauditor') . '</span>',
            $cap,
            esc_url('https://wpauditor.app/plans.html'),
            esc_html__('Get WPAuditor Pro', 'wpauditor'),
            'wpauditor-get-pro-menu',
        ];
    }
}, 9);

add_action('admin_enqueue_scripts', function () {
    if (!current_user_can('manage_options')) return;

    $page = isset($_GET['page']) && is_string($_GET['page']) ? sanitize_key(wp_unslash($_GET['page'])) : '';

    $assets = plugin_dir_path(WPAUDITOR_MAIN_FILE) . 'includes/ui/assets/';
    wp_enqueue_style('wpauditor-tokens', plugins_url('includes/ui/assets/css/tokens.css', WPAUDITOR_MAIN_FILE), [], filemtime($assets . 'css/tokens.css'));
    wp_enqueue_style('wpauditor-admin', plugins_url('includes/ui/assets/wpa.css', WPAUDITOR_MAIN_FILE), ['wpauditor-tokens'], filemtime($assets . 'wpa.css'));
    wp_enqueue_style('wpauditor-components', plugins_url('includes/ui/assets/css/components.css', WPAUDITOR_MAIN_FILE), ['wpauditor-admin'], filemtime($assets . 'css/components.css'));

    $admin_ui_path = $assets . 'admin-ui.js';
    wp_enqueue_script(
        'wpauditor-admin-ui',
        plugins_url('includes/ui/assets/admin-ui.js', WPAUDITOR_MAIN_FILE),
        [],
        file_exists($admin_ui_path) ? (string) filemtime($admin_ui_path) : '1.0.0',
        true
    );
    wp_localize_script('wpauditor-admin-ui', 'wpauditorAdminUi', [
        'forensicTools'          => __('Forensic Tools', 'wpauditor'),
        'hardening'              => __('Hardening', 'wpauditor'),
        'selectAtLeastOneFile'   => __('Select at least one available file.', 'wpauditor'),
        'selectAtLeastOneCore'   => __('Select at least one available modified or unexpected file.', 'wpauditor'),
        'selectAtLeastOneItem'   => __('Select at least one item.', 'wpauditor'),
        'dateRangeError'         => __('The To date must be later than or equal to the From date.', 'wpauditor'),
        'copied'                 => __('Copied!', 'wpauditor'),
        'copyTitle'              => __('Click to copy', 'wpauditor'),
    ]);
});

add_filter('admin_body_class', function ($classes) {
    $page = isset($_GET['page']) && is_string($_GET['page']) ? sanitize_key(wp_unslash($_GET['page'])) : '';
    $pages = ['wpauditor-dashboard', 'wpauditor-security-events', 'wpauditor-file-forensics', 'wpauditor-core-integrity', 'wpauditor-quarantine-manager', 'wpauditor-change-login', 'wpauditor-api-access-control', 'wpauditor-settings'];
    if (in_array($page, $pages, true)) $classes .= ' wpauditor-admin-page wpauditor-page-' . sanitize_html_class($page);
    return $classes;
});

add_filter('plugin_action_links_' . plugin_basename(WPAUDITOR_MAIN_FILE), function ($links) {
    $links[] = '<a href="' . esc_url(admin_url('admin.php?page=wpauditor-settings')) . '">' . esc_html__('Settings', 'wpauditor') . '</a>';
    return $links;
});
