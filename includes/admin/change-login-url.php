<?php
if (!defined('ABSPATH')) exit; // Block direct access.

// The public login form follows WordPress core and cannot use an authenticated admin nonce.
// phpcs:disable WordPress.Security.NonceVerification.Missing

class WPA_Login_Rename {
    // Settings keys.
    const OPT_SLUG     = 'wpauditor_free_login_slug';
    const OPT_BYPASS   = 'wpauditor_free_login_bypass_key';
    const DEFAULT_SLUG = 'kitchen-key';
    const QV_BYPASS    = 'wpa-login-bypass';
    const OPT_DISABLED = 'wpauditor_free_login_rename_disabled';

    // Bootstrap (respects global disable and local disabled flag).
    public static function bootstrap() {
        if (defined('WPAUDITOR_DISABLE_LOGIN_RENAME') && WPAUDITOR_DISABLE_LOGIN_RENAME) return;
        if (get_option(self::OPT_DISABLED, 1)) return;

        // Ensure options first.
        add_action('init', [__CLASS__, 'ensure_options'], 0);

        // Request handling order.
        add_action('init', [__CLASS__, 'maybe_intercept_request'], 1);
        add_action('init', [__CLASS__, 'guard_wp_admin'], 2);
        add_action('init', [__CLASS__, 'block_core_login_endpoint'], 3);

        // Rewrite generated wp-login.php links.
        add_filter('site_url', [__CLASS__, 'filter_site_url'], 10, 4);
        add_filter('network_site_url', [__CLASS__, 'filter_site_url'], 10, 4);

        // add_action('login_init', [__CLASS__, 'maybe_allow_core_login_by_bypass'], 0);
    }

    // Ensure required options exist (disabled flag, slug, bypass key).
    public static function ensure_options() {
        if (get_option(self::OPT_DISABLED, null) === null) {
            update_option(self::OPT_DISABLED, 1, false);
        }
        if (!get_option(self::OPT_SLUG)) {
            update_option(self::OPT_SLUG, self::DEFAULT_SLUG, false);
        }
        self::get_bypass_key();
    }

    // Get active slug (trim slashes, fallback to default).
    public static function get_slug() {
        $slug = trim(get_option(self::OPT_SLUG, self::DEFAULT_SLUG));
        $slug = ltrim($slug, '/'); $slug = rtrim($slug, '/');
        if ($slug === '') $slug = self::DEFAULT_SLUG;
        return $slug;
    }

    // Get or create bypass key.
    public static function get_bypass_key() {
        $k = get_option(self::OPT_BYPASS, '');
        if (!$k) {
            $k = wp_generate_password(24, false, false);
            update_option(self::OPT_BYPASS, $k, false);
        }
        return $k;
    }

    // Reserved (no-op unless bypass is valid).
    public static function maybe_allow_core_login_by_bypass() {
        if (self::has_valid_bypass()) return;
    }

    // Replace wp-login.php in generated URLs with custom slug.
    public static function filter_site_url($url, $path, $scheme, $blog_id) {
        if (get_option(self::OPT_DISABLED, 1)) return $url;
        if (is_string($url) && strpos($url, 'wp-login.php') !== false) {
            $parts = wp_parse_url($url);
            if (!$parts) return $url;
            $query = isset($parts['query']) ? $parts['query'] : '';
            parse_str($query, $args);
            $custom = home_url('/' . self::get_slug() . '/', $scheme ?: 'login');
            if (!empty($args)) $custom = add_query_arg($args, $custom);
            return $custom;
        }
        return $url;
    }

    // If request path matches custom slug, load core login controller.
    public static function maybe_intercept_request() {
        if (get_option(self::OPT_DISABLED, 1)) return;
        if (is_admin() && !defined('DOING_AJAX')) return;
        $req_path = self::current_path();
        if ($req_path === self::get_slug()) {
            self::load_wp_login();
        }
    }

    // Block direct wp-login.php unless bypass query is valid.
    public static function block_core_login_endpoint() {
        if (get_option(self::OPT_DISABLED, 1)) return;
        if (self::has_valid_bypass()) return;   // fixed
        $path = self::current_path();
        if ($path === 'wp-login.php') self::send_404();
    }

    // Block /wp-admin/* for logged-out users (except ajax/post endpoints).
    public static function guard_wp_admin() {
        if (get_option(self::OPT_DISABLED, 1)) return;
        if (is_user_logged_in()) return;
        $script = isset($GLOBALS['pagenow']) ? $GLOBALS['pagenow'] : '';
        if ($script === 'admin-ajax.php' || $script === 'admin-post.php') return;
        $path = self::current_path();
        if (strpos($path, 'wp-admin') === 0) self::send_404();
    }

    // Load native login controller with 200 OK.
    protected static function load_wp_login() {
        global $pagenow;
        $pagenow = 'wp-login.php';
        status_header(200);
        nocache_headers();

        // Initialize expected wp-login.php variables.
        if (!isset($user_login)) {
            $user_login = '';
        }
        if (!isset($user_identity)) {
            $user_identity = '';
        }
        if (!isset($error) || !($error instanceof WP_Error)) {
            $error = new WP_Error();
        }

        // Sanitize/normalize POST data wp-login.php reads.
        if (isset($_POST['log'])) {
            $_POST['log'] = sanitize_user( wp_unslash( $_POST['log'] ) );
        }
        if (isset($_POST['pwd'])) {
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- WordPress authentication requires the exact password value.
            $_POST['pwd'] = wp_unslash( $_POST['pwd'] );
        }
        if (isset($_POST['rememberme'])) {
            $_POST['rememberme'] = sanitize_key( wp_unslash( $_POST['rememberme'] ) );
        }

        require_once ABSPATH . 'wp-login.php';
        exit;
    }

    // Send a generic 404 to hide core endpoints.
    protected static function send_404() {
        status_header(404);
        nocache_headers();
        wp_die(
            esc_html__('The page you are looking for could not be found.', 'wpauditor'),
            esc_html__('Not Found', 'wpauditor'),
            ['response' => 404]
        );
    }

    // Check if request contains a valid bypass key.
    protected static function has_valid_bypass() {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- This timing-safe secret is authentication for a read-only route decision.
        $key = isset($_GET[self::QV_BYPASS]) ? sanitize_text_field(wp_unslash($_GET[self::QV_BYPASS])) : '';
        return $key && hash_equals(self::get_bypass_key(), $key);
    }

    // Get current request path relative to home (no querystring).
    protected static function current_path() {
        $uri = isset($_SERVER['REQUEST_URI']) ? esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
        $uri = strtok($uri, '?');
        $home_path = trim(wp_parse_url(home_url('/'), PHP_URL_PATH), '/');
        $req_path = trim($uri, '/');
        if ($home_path && strpos($req_path, $home_path) === 0) {
            $req_path = ltrim(substr($req_path, strlen($home_path)), '/');
        }
        return $req_path;
    }
}

// Initialize login renamer (if enabled).
WPA_Login_Rename::bootstrap();

// Render WPAuditor → Hardening → Change Login URL admin page.
function wpauditor_settings_hardening_loginurl_render() {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You do not have permission to access this page. - WPAuditor', 'wpauditor'));
    }

    // Reset to native /wp-login.php.
    if ( isset($_POST['wpa_login_reset']) && check_admin_referer('wpa_harden_loginurl') ) {
        update_option(WPA_Login_Rename::OPT_DISABLED, 1, false);
        add_settings_error('wpa_loginurl', 'reset', __('Login URL reset: using native /wp-login.php (feature disabled).', 'wpauditor'), 'updated');
    }

    // Re-enable feature.
    if ( isset($_POST['wpa_login_enable']) && check_admin_referer('wpa_harden_loginurl') ) {
        update_option(WPA_Login_Rename::OPT_DISABLED, 0, false);
        add_settings_error('wpa_loginurl', 'enabled', __('Custom Login slug /kitchen-key is active.', 'wpauditor'), 'updated');
    }

    // Save slug and optional bypass regeneration.
    if ( isset($_POST['wpa_hardening_loginurl_save']) && check_admin_referer('wpa_harden_loginurl') ) {
        $errors   = [];
        $slug_raw = isset($_POST['wpa_login_slug']) ? sanitize_text_field(wp_unslash($_POST['wpa_login_slug'])) : '';
        $slug     = sanitize_title_with_dashes($slug_raw);
        $slug     = trim($slug, "/ \t\n\r\0\x0B");

        // Reserved slug checks.
        $reserved = ['wp-login.php','wp-admin','wp-admin/','admin','login','wp-login'];
        if ($slug === '') {
            $errors[] = __('Please provide a non-empty slug.', 'wpauditor');
        } elseif (in_array($slug, $reserved, true) || strpos($slug, 'wp-admin') === 0) {
            $errors[] = __('This slug is reserved. Choose something unique (e.g., secure-portal).', 'wpauditor');
        } elseif (preg_match('~[^a-z0-9\-]~', $slug)) {
            $errors[] = __('Only lowercase letters, numbers, and hyphens are allowed.', 'wpauditor');
        }

        if (empty($errors)) {
            update_option(WPA_Login_Rename::OPT_SLUG, $slug, false);
            add_settings_error('wpa_loginurl', 'ok', __('Login URL updated.', 'wpauditor'), 'updated');

            if (!empty($_POST['wpa_login_regen_bypass'])) {
                update_option(WPA_Login_Rename::OPT_BYPASS, wp_generate_password(24, false, false), false);
                add_settings_error('wpa_loginurl', 'regen', __('Emergency bypass key regenerated.', 'wpauditor'), 'updated');
            }
        } else {
            foreach ($errors as $e) {
                add_settings_error('wpa_loginurl', 'err_' . md5($e), $e, 'error');
            }
        }
    }

    // Output settings messages.
    settings_errors('wpa_loginurl');

    // Current values.
    $disabled    = (int) get_option(WPA_Login_Rename::OPT_DISABLED, 1);
    $slug        = WPA_Login_Rename::get_slug();
    $bypass_key  = WPA_Login_Rename::get_bypass_key();
    $login_url   = home_url('/' . $slug . '/');
    $bypass_url  = add_query_arg(WPA_Login_Rename::QV_BYPASS, rawurlencode($bypass_key), home_url('/wp-login.php'));
    ?>
    <div class="wrap wpa-admin-shell wpa-login-url-page">
      <h1 class="wp-heading-inline"><?php esc_html_e('Custom Login', 'wpauditor'); ?></h1>
<br>

      <hr class="wp-header-end">

      <?php if ($disabled): ?>
        <div class="notice notice-warning"><p>
          <?php
            $msg = __('Feature is currently <strong>DISABLED</strong>. WordPress is using the native /wp-login.php.', 'wpauditor');
            echo wp_kses( $msg, array( 'strong' => array() ) );
          ?>
        </p></div>
      <?php endif; ?>

      <form method="post">
        <?php wp_nonce_field('wpa_harden_loginurl'); ?>

        <table class="form-table" role="presentation">
          <tr>
            <th scope="row"><label for="wpa_login_slug"><?php esc_html_e('Custom Login Slug', 'wpauditor'); ?></label></th>
            <td>
              <input type="text" class="regular-text" id="wpa_login_slug" name="wpa_login_slug"
                     value="<?php echo esc_attr($slug); ?>" placeholder="secure-portal" <?php disabled($disabled); ?> />
              <p class="description">
                <?php esc_html_e('Once enabled, your login page will be set to kitchen-key/ by default. You can now access your login at:', 'wpauditor'); ?>
                <code><?php echo esc_html(trailingslashit($login_url)); ?></code>
              </p>
            </td>
          </tr>

          <?php if (!$disabled): ?>
          <tr>
            <th scope="row"><?php esc_html_e('Emergency Bypass URL', 'wpauditor'); ?></th>
            <td>
              <code><?php echo esc_html($bypass_url); ?></code>
              <p class="description">
                <?php esc_html_e('Use this one-time emergency link to access the native /wp-login.php if you get locked out. Share very carefully.', 'wpauditor'); ?>
              </p>
              <label>
                <input type="checkbox" name="wpa_login_regen_bypass" value="1" />
                <?php esc_html_e('Regenerate bypass key on save', 'wpauditor'); ?>
              </label>
            </td>
          </tr>
          <?php endif; ?>
        </table>

        <p class="submit wpa-flex-actions">
          <?php if ($disabled): ?>
            <button type="submit" name="wpa_login_enable" value="1" class="button button-primary">
              <?php esc_html_e('Enable Custom Login', 'wpauditor'); ?>
            </button>
          <?php else: ?>
            <button type="submit" name="wpa_hardening_loginurl_save" value="1" class="button button-primary">
              <?php esc_html_e('Save Changes', 'wpauditor'); ?>
            </button>
            <button type="submit" name="wpa_login_reset" value="1" class="button wpa-confirm-submit" data-wpa-confirm-action="reset" data-wpa-confirm-eyebrow="<?php esc_attr_e('Custom Login URL', 'wpauditor'); ?>" data-wpa-confirm-title="<?php esc_attr_e('Reset to the default login URL?', 'wpauditor'); ?>" data-wpa-confirm-description="<?php esc_attr_e('Disable the custom login path and restore the native WordPress login URL.', 'wpauditor'); ?>" data-wpa-confirm-note="<?php esc_attr_e('The default /wp-login.php address will become available immediately.', 'wpauditor'); ?>" data-wpa-confirm-label="<?php esc_attr_e('Reset Login URL', 'wpauditor'); ?>" data-wpa-confirm-target-label="<?php esc_attr_e('Login path', 'wpauditor'); ?>" data-wpa-confirm-target="/wp-login.php">
              <?php esc_html_e('Reset to Default (/wp-login.php)', 'wpauditor'); ?>
            </button>
          <?php endif; ?>

          <?php if (!$disabled): ?>
            <a class="button" target="_blank" rel="noopener" href="<?php echo esc_url($login_url); ?>">
              <?php esc_html_e('Open Login', 'wpauditor'); ?>
            </a>
          <?php endif; ?>
        </p>
      </form>
    </div>
    <?php
}
