<?php
if (!defined('ABSPATH')) exit;

// Block XML-RPC when the access control is enabled
if ((int) get_option('wpauditor_free_xmlrpc_disabled', 0)) {
    add_filter('xmlrpc_enabled', '__return_false');
    add_filter('xmlrpc_methods', '__return_empty_array', PHP_INT_MAX);
    add_filter('pings_open', '__return_false', PHP_INT_MAX);

    add_filter('wp_headers', function ($headers) {
        foreach (array_keys($headers) as $header_name) {
            if (strtolower((string) $header_name) === 'x-pingback') {
                unset($headers[$header_name]);
            }
        }

        return $headers;
    }, PHP_INT_MAX);

    add_action('init', function () {
        if (!defined('XMLRPC_REQUEST') || !XMLRPC_REQUEST) return;

        status_header(403);
        nocache_headers();

        if (!headers_sent()) {
            header('Content-Type: text/plain; charset=' . get_option('blog_charset'));
        }

        echo esc_html__('XML-RPC services are disabled on this site.', 'wpauditor');
        exit;
    }, 0);
}

// Restrict unauthenticated REST API access when enabled
if ((int) get_option('wpauditor_free_restapi_disabled', 0)) {
    add_filter('rest_authentication_errors', function ($result) {
        if (!empty($result)) return $result;

        if (!is_user_logged_in()) {
            return new WP_Error(
                'wpauditor_rest_disabled',
                __('REST API access is restricted for unauthenticated requests by WPAuditor.', 'wpauditor'),
                ['status' => 401]
            );
        }

        return $result;
    }, 0);

    // Remove public user endpoints to reduce enumeration
    add_filter('rest_endpoints', function ($endpoints) {
        unset($endpoints['/wp/v2/users']);

        foreach ($endpoints as $route => $handlers) {
            if (preg_match('#^/wp/v2/users(?:/|\()#', $route)) {
                unset($endpoints[$route]);
            }
        }

        return $endpoints;
    }, 999);
}

// Render the combined API access controls
function wpauditor_admin_page_api_access_control() {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('Sorry, you are not allowed to manage these settings.', 'wpauditor'));
    }

    $updated = '';

    // Handle the XML-RPC control independently
    $request_method = isset($_SERVER['REQUEST_METHOD'])
        ? strtoupper(sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD'])))
        : '';
    if ($request_method === 'POST' && isset($_POST['wpauditor_toggle_xmlrpc'])) {
        check_admin_referer('wpauditor_toggle_xmlrpc_action');

        $action = sanitize_key(wp_unslash($_POST['wpauditor_toggle_xmlrpc']));
        if (in_array($action, ['enable', 'disable'], true)) {
            $current = (int) get_option('wpauditor_free_xmlrpc_disabled', 0);
            $desired = $action === 'disable' ? 1 : 0;

            if ($desired !== $current) {
                update_option('wpauditor_free_xmlrpc_disabled', $desired, false);
                $updated = 'xmlrpc';
            }
        }
    }

    // Handle the REST API control independently
    if ($request_method === 'POST' && isset($_POST['wpauditor_toggle_restapi'])) {
        check_admin_referer('wpauditor_toggle_restapi_action');

        $action = sanitize_key(wp_unslash($_POST['wpauditor_toggle_restapi']));
        if (in_array($action, ['enable', 'disable'], true)) {
            $current = (int) get_option('wpauditor_free_restapi_disabled', 0);
            $desired = $action === 'disable' ? 1 : 0;

            if ($desired !== $current) {
                update_option('wpauditor_free_restapi_disabled', $desired, false);
                $updated = 'restapi';
            }
        }
    }

    $xmlrpc_disabled = (int) get_option('wpauditor_free_xmlrpc_disabled', 0);
    $restapi_disabled = (int) get_option('wpauditor_free_restapi_disabled', 0);
    ?>
    <div class="wrap wpa-admin-shell wpa-api-access-page">
        <h1><?php esc_html_e('API Access Control', 'wpauditor'); ?></h1>
        <br>

        <?php if ($updated): ?>
            <div class="notice notice-success is-dismissible">
                <p><?php esc_html_e('API access setting updated.', 'wpauditor'); ?></p>
            </div>
        <?php endif; ?>

        <div class="postbox wpa-panel wpa-copy-width">
            <h2><?php esc_html_e('XML-RPC Access', 'wpauditor'); ?></h2>

            <div class="notice <?php echo $xmlrpc_disabled ? 'notice-success' : 'notice-warning'; ?> inline">
                <p>
                    <?php if ($xmlrpc_disabled): ?>
                        <strong><?php esc_html_e('Blocked', 'wpauditor'); ?></strong> &mdash;
                        <?php esc_html_e('WordPress XML-RPC requests are blocked.', 'wpauditor'); ?>
                    <?php else: ?>
                        <strong><?php esc_html_e('Available', 'wpauditor'); ?></strong> &mdash;
                        <?php esc_html_e('WordPress XML-RPC is available to remote clients.', 'wpauditor'); ?>
                    <?php endif; ?>
                </p>
            </div>

            <form method="post" action="" class="wpa-mt-12">
                <?php wp_nonce_field('wpauditor_toggle_xmlrpc_action'); ?>
                <?php if ($xmlrpc_disabled): ?>
                    <button type="submit" name="wpauditor_toggle_xmlrpc" value="enable" class="button">
                        <?php esc_html_e('Allow XML-RPC', 'wpauditor'); ?>
                    </button>
                <?php else: ?>
                    <button type="submit" name="wpauditor_toggle_xmlrpc" value="disable" class="button button-primary">
                        <?php esc_html_e('Block XML-RPC', 'wpauditor'); ?>
                    </button>
                <?php endif; ?>
            </form>
        </div>

        <div class="postbox wpa-panel wpa-copy-width">
            <h2><?php esc_html_e('REST API Access', 'wpauditor'); ?></h2>

            <div class="notice <?php echo $restapi_disabled ? 'notice-success' : 'notice-warning'; ?> inline">
                <p>
                    <?php if ($restapi_disabled): ?>
                        <strong><?php esc_html_e('Restricted', 'wpauditor'); ?></strong> &mdash;
                        <?php esc_html_e('Unauthenticated REST requests are blocked and WordPress user endpoints are removed.', 'wpauditor'); ?>
                    <?php else: ?>
                        <strong><?php esc_html_e('Public', 'wpauditor'); ?></strong> &mdash;
                        <?php esc_html_e('The WordPress REST API is available to unauthenticated requests.', 'wpauditor'); ?>
                    <?php endif; ?>
                </p>
            </div>

            <form method="post" action="" class="wpa-mt-12">
                <?php wp_nonce_field('wpauditor_toggle_restapi_action'); ?>
                <?php if ($restapi_disabled): ?>
                    <button type="submit" name="wpauditor_toggle_restapi" value="enable" class="button">
                        <?php esc_html_e('Allow Public REST API', 'wpauditor'); ?>
                    </button>
                <?php else: ?>
                    <button type="submit" name="wpauditor_toggle_restapi" value="disable" class="button button-primary">
                        <?php esc_html_e('Restrict REST API', 'wpauditor'); ?>
                    </button>
                <?php endif; ?>
            </form>
        </div>
    </div>
    <?php
}

// Preserve the former page callbacks for compatibility
function wpauditor_admin_page_disable_xmlrpc() {
    wpauditor_admin_page_api_access_control();
}

function wpauditor_admin_page_disable_restapi() {
    wpauditor_admin_page_api_access_control();
}
