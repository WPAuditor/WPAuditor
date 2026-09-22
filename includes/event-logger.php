<?php
if (!defined('ABSPATH')) exit;

if (!function_exists('wpauditor_server_text')) {
    function wpauditor_server_text(string $key, string $default = '', int $max_length = 4096): string {
        if (!isset($_SERVER[$key]) || !is_scalar($_SERVER[$key])) return $default;
        $value = sanitize_text_field(wp_unslash((string) $_SERVER[$key]));
        return substr($value, 0, max(1, $max_length));
    }
}

// Request inspection must examine raw request fields before WordPress alters them; all persisted values are normalized below.
// phpcs:disable WordPress.Security.NonceVerification.Missing,WordPress.Security.NonceVerification.Recommended,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash
// Append-only, locked local writes preserve security log record boundaries.
// phpcs:disable WordPress.WP.AlternativeFunctions

// MITRE ATT&CK mapping
include __DIR__ . '/attack_framework/mitre.php';

// OWASP Top 10 mapping
include __DIR__ . '/attack_framework/owasp.php';

// Web attack patterns
include __DIR__ . '/patterns/webapp.php';

// Bounded request normalization and contextual attack detection
include __DIR__ . '/detection/request-normalizer.php';
include __DIR__ . '/detection/attack-detector.php';

// WordPress hook listeners
include __DIR__ . '/patterns/wphooks.php';

if (!function_exists('wpauditor_clean_ip')) {
    function wpauditor_clean_ip($ip) {
        if (!is_string($ip)) return '';
        $ip = trim($ip);
        if ($ip === '') return '';

        // Handle bracketed IPv6 like: [2001:db8::1]:1234
        if ($ip[0] === '[') {
            if (!preg_match('/^\[([^\]]+)\](?::([0-9]{1,5}))?$/D', $ip, $parts)) return '';
            if (isset($parts[2]) && ((int) $parts[2] < 1 || (int) $parts[2] > 65535)) return '';
            $ip = $parts[1];
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return '';
        } else {
            // Strip port for IPv4:port (single colon)
            if (strpos($ip, ':') !== false && substr_count($ip, ':') === 1) {
                [$maybe_ip, $maybe_port] = explode(':', $ip, 2);
                if ($maybe_ip !== '' && ctype_digit($maybe_port)) {
                    if (strlen($maybe_port) > 5 || (int) $maybe_port < 1 || (int) $maybe_port > 65535) return '';
                    $ip = $maybe_ip;
                }
            }
        }

        if (!filter_var($ip, FILTER_VALIDATE_IP)) return '';
        // Canonicalize equivalent addresses, including IPv4-mapped IPv6.
        $packed = inet_pton($ip);
        if (strlen($packed) === 16 && substr($packed, 0, 12) === str_repeat("\0", 10) . "\xff\xff") {
            return inet_ntop(substr($packed, 12));
        }
        return inet_ntop($packed);
    }
}

if (!function_exists('wpauditor_is_public_ip')) {
    function wpauditor_is_public_ip($ip) {
        $ip = wpauditor_clean_ip($ip);
        if ($ip === '') return false;
        return (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }
}

if (!function_exists('wpauditor_ip_in_cidr')) {
    function wpauditor_ip_in_cidr($ip, $cidr) {
        $ip = wpauditor_clean_ip($ip);
        if ($ip === '') return false;

        $cidr = trim((string)$cidr);
        if ($cidr === '' || strpos($cidr, '/') === false) return false;

        [$subnet, $maskBits] = explode('/', $cidr, 2);
        if (!ctype_digit($maskBits)) return false;
        $subnet = wpauditor_clean_ip($subnet);
        $maskBits = (int)$maskBits;
        if ($subnet === '' || $maskBits < 0) return false;

        $ipBin  = @inet_pton($ip);
        $netBin = @inet_pton($subnet);
        if ($ipBin === false || $netBin === false) return false;

        $len = strlen($ipBin);
        if ($len !== strlen($netBin)) return false;

        $maxBits = $len * 8;
        if ($maskBits > $maxBits) return false;

        $bytes = intdiv($maskBits, 8);
        $bits  = $maskBits % 8;

        if ($bytes > 0) {
            if (substr($ipBin, 0, $bytes) !== substr($netBin, 0, $bytes)) return false;
        }
        if ($bits === 0) return true;

        $mask = chr((0xFF << (8 - $bits)) & 0xFF);
        return (($ipBin[$bytes] & $mask) === ($netBin[$bytes] & $mask));
    }
}

if (!function_exists('wpauditor_get_cloudflare_ranges_cached')) {
    function wpauditor_get_cloudflare_ranges_cached() {
        // Cloudflare-published proxy ranges bundled for trustworthy client IP handling.
        return [
            'v4' => ['173.245.48.0/20','103.21.244.0/22','103.22.200.0/22','103.31.4.0/22','141.101.64.0/18','108.162.192.0/18','190.93.240.0/20','188.114.96.0/20','197.234.240.0/22','198.41.128.0/17','162.158.0.0/15','104.16.0.0/13','104.24.0.0/14','172.64.0.0/13','131.0.72.0/22'],
            'v6' => ['2400:cb00::/32','2606:4700::/32','2803:f800::/32','2405:b500::/32','2405:8100::/32','2a06:98c0::/29','2c0f:f248::/32'],
        ];
    }
}
if (!function_exists('wpauditor_is_cloudflare_proxy')) {
    function wpauditor_is_cloudflare_proxy($remoteIp) {
        $remoteIp = wpauditor_clean_ip($remoteIp);
        if ($remoteIp === '') return false;

        // Cloudflare ranges
        $ranges = wpauditor_get_cloudflare_ranges_cached();
        if (empty($ranges['v4']) && empty($ranges['v6'])) return false;

        $list = (strpos($remoteIp, ':') !== false) ? $ranges['v6'] : $ranges['v4'];
        foreach ($list as $cidr) {
            if (wpauditor_ip_in_cidr($remoteIp, $cidr)) return true;
        }
        return false;
    }
}

if (!function_exists('wpauditor_is_trusted_proxy')) {
    function wpauditor_is_trusted_proxy($remoteIp) {
        $remoteIp = wpauditor_clean_ip($remoteIp);
        if ($remoteIp === '') return false;
        $custom = apply_filters('wpauditor_trusted_proxies', []);
        if (is_array($custom)) {
            foreach ($custom as $cidr) {
                if (is_string($cidr) && wpauditor_ip_in_cidr($remoteIp, $cidr)) return true;
            }
        }
        return wpauditor_is_cloudflare_proxy($remoteIp);
    }
}

if (!function_exists('wpauditor_get_client_ip')) {
    function wpauditor_get_client_ip() {
        static $spoof_logged = false;

        $remote = wpauditor_clean_ip(wpauditor_server_text('REMOTE_ADDR', '', 64));
        if ($remote === '') return '';

        $has_cf  = isset($_SERVER['HTTP_CF_CONNECTING_IP']);
        $has_xff = isset($_SERVER['HTTP_X_FORWARDED_FOR']);

        $trusted = wpauditor_is_trusted_proxy($remote);

        // Spoof attempt: proxy headers present but REMOTE_ADDR is NOT trusted
        if (!$trusted && ($has_cf || $has_xff)) {
            if (!$spoof_logged && function_exists('wpauditor_log_event')) {
                $spoof_logged = true;

                $cf  = wpauditor_clean_ip(wpauditor_server_text('HTTP_CF_CONNECTING_IP', '', 64));
                $xff = wpauditor_server_text('HTTP_X_FORWARDED_FOR', '', 4096);
                $details = 'remote=' . $remote
                         . ' cf=' . ($cf ?: '-')
                         . ' xff=' . substr($xff, 0, 300);

                // IMPORTANT: pass ip in context to avoid recursion
                wpauditor_log_event('IP_SPOOF_ATTEMPT', $details, [
                    'ip'       => $remote,
                    'category' => 'SECURITY',
                    'ua'       => wpauditor_server_text('HTTP_USER_AGENT', 'UNKNOWN', 2000),
                    'method'   => strtoupper(sanitize_key(wpauditor_server_text('REQUEST_METHOD', 'UNKNOWN', 16))),
                    'uri'      => wpauditor_server_text('REQUEST_URI', '', 4000),
                ]);
            }
            return $remote;
        }

        // Only a direct Cloudflare peer may assert CF-Connecting-IP.
        if ($trusted && $has_cf && wpauditor_is_cloudflare_proxy($remote)) {
            $cf = wpauditor_clean_ip(wpauditor_server_text('HTTP_CF_CONNECTING_IP', '', 64));
            if ($cf && wpauditor_is_public_ip($cf)) return $cf;
            // If CF header exists but is not a valid public IP, do NOT fall back to XFF.
            return $remote;
        }

        // Walk right to left; never cross an untrusted or malformed hop.
        if ($trusted && $has_xff) {
            $xff = wpauditor_server_text('HTTP_X_FORWARDED_FOR', '', 4096);
            if ($xff === '') return $remote;
            $parts = explode(',', $xff);
            if (count($parts) > 32) return $remote;
            for ($i = count($parts) - 1; $i >= 0; $i--) {
                $candidate = wpauditor_clean_ip($parts[$i]);
                if (!$candidate) return $remote;
                if (wpauditor_is_trusted_proxy($candidate)) continue;
                return wpauditor_is_public_ip($candidate) ? $candidate : $remote;
            }
        }

        return $remote;
    }
}
// Sanitize log values to a single safe line
if (!function_exists('wpauditor_log_sanitize_value')) {
    function wpauditor_log_sanitize_value($value, $max_len = 4000) {
        $s = (string) $value;

        $s = preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $s);
        $s = preg_replace('/\s+/u', ' ', $s);
        $s = trim($s);

        if ($max_len > 0 && function_exists('mb_strlen') && function_exists('mb_substr')) {
            if (mb_strlen($s) > $max_len) $s = mb_substr($s, 0, $max_len) . '…';
        } elseif ($max_len > 0 && strlen($s) > $max_len) {
            $s = substr($s, 0, $max_len) . '…';
        }

        return $s;
    }
}

// Neutralize reserved key tokens (category=, severity=, etc.)
if (!function_exists('wpauditor_log_neutralize_reserved_kv')) {
    function wpauditor_log_neutralize_reserved_kv($s) {
        $keys = [
            'category','severity','mitre_tactic','mitre_technique',
            'ip','cc','method','uri','ua','type','event','ts'
        ];
        foreach ($keys as $k) {
            $pattern = '/\b' . preg_quote($k, '/') . '\s*=\s*/i';
            $s = preg_replace($pattern, $k . ':', $s);
        }
        return $s;
    }
}

// Quote a UA string for ua="..."
if (!function_exists('wpauditor_log_quote_ua')) {
    function wpauditor_log_quote_ua($ua, $max_len = 2000) {
        $ua = wpauditor_log_sanitize_value($ua, $max_len);
        $ua = wpauditor_log_neutralize_reserved_kv($ua);
        $ua = str_replace('"', '\"', $ua);
        return $ua;
    }
}

// Cloudflare country code helper
if (!function_exists('wpauditor_get_country_code')) {
    function wpauditor_get_country_code() {
        if (!empty($_SERVER['HTTP_CF_IPCOUNTRY'])) {
            $cc = strtoupper(trim(wpauditor_server_text('HTTP_CF_IPCOUNTRY', '', 2)));
            if (preg_match('/^[A-Z0-9]{2}$/', $cc)) return $cc;
        }
        return '';
    }
}

// Category severity fallback mapping
if (!function_exists('wpauditor_map_category_severity')) {
    function wpauditor_map_category_severity($category) {
        $map = [
            'SECURITY'       => 'HIGH',
            'AUTH'           => 'MEDIUM',
            'USER'           => 'MEDIUM',
            'MEDIA'          => 'INFO',
            'PLUGIN'         => 'INFO',
            'THEME'          => 'INFO',
            'SETTINGS'       => 'MEDIUM',
            'POST'           => 'INFO',
            'UPLOAD'         => 'MEDIUM',
            'OBFUSCATION'    => 'MEDIUM',
            'FILE_FORENSICS' => 'INFO',
            'FILE_MONITORING'=> 'INFO',
            'Unusual HTTP'   => 'MEDIUM',
            'WEB_APP_ATTACK' => 'HIGH',
        ];
        return $map[$category] ?? 'info';
    }
}

// Write a normalized SIEM log line
if (!function_exists('wpauditor_log_event')) {
    function wpauditor_log_event($type, $details = '', $context = []) {
        if (!wpauditor_prepare_log_storage()) return;
        $log_dir  = rtrim(wpauditor_log_dir(), '/\\');
        $log_file = wpauditor_get_log_path();
        if ($log_dir === '' || $log_file === '') return;

        $timestamp = date_i18n('Y-m-d H:i:s');

        // IMPORTANT: allow caller to provide IP to avoid recursion
        $ip        = isset($context['ip']) ? (string)$context['ip'] : wpauditor_get_client_ip();

        $cc        = $context['cc'] ?? wpauditor_get_country_code();
        $method    = $context['method'] ?? strtoupper(sanitize_key(wpauditor_server_text('REQUEST_METHOD', 'UNKNOWN', 16)));
        $uri       = $context['uri']    ?? wpauditor_server_text('REQUEST_URI', '', 4000);
        $ua_raw    = $context['ua']     ?? wpauditor_server_text('HTTP_USER_AGENT', 'UNKNOWN', 2000);
        $category  = $context['category'] ?? '';

        $ip = wpauditor_log_sanitize_value($ip, 128);

        $cc = strtoupper(trim(wpauditor_log_sanitize_value($cc, 2)));
        if (!preg_match('/^[A-Z0-9]{2}$/', $cc)) $cc = '';

        $uri = preg_replace('/([?&](?:password|passwd|pwd|pass|token|access_token|api_key|apikey|secret|key|_wpnonce|nonce|wpa-login-bypass)=)[^&#]*/i', '$1[redacted]', (string) $uri);
        $method   = wpauditor_log_sanitize_value($method, 16);
        $uri      = wpauditor_log_neutralize_reserved_kv(wpauditor_log_sanitize_value($uri, 4000));
        $ua       = wpauditor_log_quote_ua($ua_raw, 2000);
        $category = wpauditor_log_sanitize_value($category, 128);

        if (is_array($details) || is_object($details)) {
            $details = wp_json_encode($details, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }
        $details = wpauditor_log_neutralize_reserved_kv(wpauditor_log_sanitize_value((string)$details, 4000));

        $severity_override = strtoupper((string) ($context['severity'] ?? ''));
        if (in_array($severity_override, ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], true)) {
            $severity = $severity_override;
        } elseif ($type === 'WEB_APP_ATTACK' && $category) {
            $severity = wpauditor_map_severity($category);
        } else {
            $severity = wpauditor_map_severity($type);
            if ($severity === 'info' && $category) $severity = wpauditor_map_category_severity($category);
        }

        $mitre           = wpauditor_get_mitre_mapping();
        $mitre_tactic    = $mitre[$category]['tactic']    ?? ($mitre[$type]['tactic']    ?? '');
        $mitre_technique = $mitre[$category]['technique'] ?? ($mitre[$type]['technique'] ?? '');

        $entry = "[$timestamp] [" . wpauditor_log_sanitize_value($type, 64) . "]"
            . " IP=$ip"
            . ($cc ? " cc=$cc" : "")
            . " method=$method"
            . " uri=$uri"
            . " ua=\"" . $ua . "\""
            . ($category ? " category=$category" : "")
            . " severity=" . wpauditor_log_sanitize_value($severity, 16)
            . ($mitre_tactic ? " mitre_tactic=\"" . wpauditor_log_sanitize_value($mitre_tactic, 64) . "\" mitre_technique=" . wpauditor_log_sanitize_value($mitre_technique, 32) : "")
            . ($details !== '' ? " $details" : "")
            . "\n";

        @file_put_contents($log_file, $entry, FILE_APPEND | LOCK_EX);

        $payload = [
            'type'      => $type,
            'severity'  => strtoupper((string)$severity),
            'category'  => $category ?: '',
            'message'   => $details ?: '',
            'uri'       => $uri,
            'IP'        => $ip,
            'cc'        => $cc,
            'ua'        => $ua_raw,
            'method'    => $method,
            'ts'        => $timestamp,
            'confidence'=> isset($context['confidence']) ? (int) $context['confidence'] : 0,
            'findings'  => isset($context['findings']) && is_array($context['findings']) ? $context['findings'] : [],
            'mitre'     => [
                'tactic'    => $mitre_tactic,
                'technique' => $mitre_technique,
            ],
        ];
        do_action('wpauditor_event_logged', $payload);
    }
}

// Build request haystacks (raw/decoded/body variants)
if (!function_exists('wpauditor_build_haystacks')) {
    function wpauditor_build_haystacks(string $raw_body): array {
        $req_uri = wpauditor_server_text('REQUEST_URI', '', 4000);
        $qs_raw  = wpauditor_server_text('QUERY_STRING', '', 4000);
        $path    = wp_parse_url($req_uri, PHP_URL_PATH);
        if ($path === null) $path = $req_uri;

        $combo_raw = $path . ($qs_raw !== '' ? ('?' . $qs_raw) : '');
        $d1_path  = urldecode($path);
        $d1_qs    = urldecode($qs_raw);
        $d1_combo = urldecode($combo_raw);
        $d2_path  = urldecode($d1_path);
        $d2_qs    = urldecode($d1_qs);
        $d2_combo = urldecode($d1_combo);
        $h1_combo = html_entity_decode($d2_combo, ENT_QUOTES | ENT_HTML5);

        $stacks = [
            $path, $qs_raw, $combo_raw,
            $d1_path, $d1_qs, $d1_combo,
            $d2_path, $d2_qs, $d2_combo,
            $h1_combo,
        ];

        $content_type = wpauditor_server_text('CONTENT_TYPE', wpauditor_server_text('HTTP_CONTENT_TYPE', '', 255), 255);

        if (stripos($content_type, 'application/x-www-form-urlencoded') !== false && !empty($_POST)) {
            $safe_post = map_deep(wp_unslash($_POST), 'sanitize_text_field');
            $post_qs   = http_build_query($safe_post, '', '&', PHP_QUERY_RFC3986);
            $post_d1   = urldecode($post_qs);
            $post_d2   = urldecode($post_d1);
            $post_html = html_entity_decode($post_d2, ENT_QUOTES | ENT_HTML5);
            array_push($stacks, $post_qs, $post_d1, $post_d2, $post_html);
        }

        $maybe_json = false;
        if ($raw_body !== '') {
            if (stripos($content_type, 'application/json') !== false) {
                $maybe_json = true;
            } else {
                $trim = ltrim($raw_body);
                if ($trim !== '' && ($trim[0] === '{' || $trim[0] === '[')) $maybe_json = true;
            }
        }

        if ($maybe_json) {
            $json = json_decode($raw_body, true);
            if (is_array($json) || is_string($json)) {
                $vals = [];
                $collect = function($v) use (&$vals, &$collect) {
                    if (is_array($v)) { foreach ($v as $vv) { $collect($vv); } }
                    elseif (is_object($v)) { foreach (get_object_vars($v) as $vv) { $collect($vv); } }
                    elseif (is_string($v) || is_numeric($v) || is_bool($v) || $v === null) {
                        $vals[] = (string)$v;
                    }
                };
                $collect($json);

                if ($vals) {
                    $joined = implode('&', array_filter($vals, fn($s)=>$s!=='' ));
                    $d1 = urldecode($joined);
                    $d2 = urldecode($d1);
                    $h1 = html_entity_decode($d2, ENT_QUOTES | ENT_HTML5);
                    array_push($stacks, $joined, $d1, $d2, $h1);
                }
            }
        }

        if ($raw_body !== '' && stripos($content_type, 'multipart/form-data') !== false) {
            if (!empty($_FILES)) {
                $safe_files = map_deep(wp_unslash($_FILES), 'sanitize_text_field');
                foreach ($safe_files as $f) {
                    if (!empty($f['name'])) {
                        $name = (string)$f['name'];
                        $ext  = pathinfo($name, PATHINFO_EXTENSION);
                        array_push($stacks, $name, $ext);
                    }
                }
            }

            if (preg_match('/boundary=(.+)$/i', $content_type, $m)) {
                $boundary = trim($m[1], "\" \t");
                $parts = explode('--' . $boundary, $raw_body);
                foreach ($parts as $part) {
                    $header_end = strpos($part, "\r\n\r\n");
                    $sep_len = 4;
                    if ($header_end === false) {
                        $header_end = strpos($part, "\n\n");
                        $sep_len = 2;
                    }
                    if ($header_end !== false) {
                        $headers = substr($part, 0, $header_end);
                        $body_snippet = substr($part, $header_end + $sep_len, 2048);

                        if (preg_match('/filename="([^"]+)"/i', $headers, $mm)) array_push($stacks, $mm[1]);
                        if (preg_match('/Content-Type:\s*([^\r\n]+)/i', $headers, $mm)) array_push($stacks, trim($mm[1]));

                        $b1 = urldecode($body_snippet);
                        $b2 = urldecode($b1);
                        $bh = html_entity_decode($b2, ENT_QUOTES | ENT_HTML5);
                        array_push($stacks, $body_snippet, $b1, $b2, $bh);
                    }
                }
            } else {
                $slice = substr($raw_body, 0, 4096);
                array_push($stacks, $slice);
            }
        }

        if ($raw_body !== '') {
            $p1 = urldecode($raw_body);
            $p2 = urldecode($p1);
            $ph = html_entity_decode($p2, ENT_QUOTES | ENT_HTML5);
            array_push($stacks, $raw_body, $p1, $p2, $ph);
        }

        return array_values(array_unique(array_filter($stacks, static fn($s) => $s !== '')));
    }
}

if (!function_exists('wpauditor_get_rest_nonce')) {
    function wpauditor_get_rest_nonce(): string {
        if (isset($_REQUEST['_wpnonce']) && is_scalar($_REQUEST['_wpnonce'])) {
            return sanitize_text_field(wp_unslash((string) $_REQUEST['_wpnonce']));
        }
        if (isset($_SERVER['HTTP_X_WP_NONCE']) && is_scalar($_SERVER['HTTP_X_WP_NONCE'])) {
            return sanitize_text_field(wp_unslash((string) $_SERVER['HTTP_X_WP_NONCE']));
        }
        return '';
    }
}

if (!function_exists('wpauditor_is_authenticated_rest_users_request')) {
    function wpauditor_is_authenticated_rest_users_request(): bool {
        $method = strtoupper(sanitize_key(wpauditor_server_text('REQUEST_METHOD', '', 16)));
        if (!is_user_logged_in()) return false;

        $rest_nonce = wpauditor_get_rest_nonce();
        if ($rest_nonce === '' || !wp_verify_nonce($rest_nonce, 'wp_rest')) return false;

        $rest_route = isset($_GET['rest_route']) && is_scalar($_GET['rest_route'])
            ? sanitize_text_field(wp_unslash((string) $_GET['rest_route']))
            : '';

        $rest_prefix = function_exists('rest_get_url_prefix') ? trim((string) rest_get_url_prefix(), '/') : 'wp-json';
        $core_users_route = wpauditor_detection_is_core_users_route(
            wpauditor_server_text('REQUEST_URI', '', 4000),
            $rest_route,
            $rest_prefix
        );
        return wpauditor_detection_should_skip_user_recon($method, true, $core_users_route);
    }
}

if (!function_exists('wpauditor_is_authenticated_rest_request')) {
    function wpauditor_is_authenticated_rest_request(): bool {
        if (!is_user_logged_in()) return false;

        $rest_nonce = wpauditor_get_rest_nonce();
        if ($rest_nonce === '' || !wp_verify_nonce($rest_nonce, 'wp_rest')) return false;

        $rest_route = isset($_GET['rest_route']) && is_scalar($_GET['rest_route'])
            ? sanitize_text_field(wp_unslash((string) $_GET['rest_route']))
            : '';
        $rest_prefix = function_exists('rest_get_url_prefix') ? (string) rest_get_url_prefix() : 'wp-json';

        return wpauditor_detection_is_rest_route(
            wpauditor_server_text('REQUEST_URI', '', 4000),
            $rest_route,
            $rest_prefix
        );
    }
}

// Front-end request inspection
add_action('init', function () {
    if (is_admin() && !(function_exists('wp_doing_ajax') && wp_doing_ajax())) return;

    $method   = strtoupper(sanitize_key(wpauditor_server_text('REQUEST_METHOD', 'UNKNOWN', 16)));
    $uri      = wpauditor_server_text('REQUEST_URI', '', 4000);
    $ua       = wpauditor_server_text('HTTP_USER_AGENT', 'UNKNOWN', 2000);

    $body_limit = wpauditor_detection_limit('max_body_bytes', 262144);
    $raw_body = file_get_contents('php://input', false, null, 0, $body_limit + 1);
    if (!is_string($raw_body)) $raw_body = '';

    $context = ['method' => $method, 'uri' => $uri, 'ua' => $ua];

    $rest_methods = ['OPTIONS', 'PUT', 'DELETE', 'PATCH'];
    $expected_rest_method = in_array($method, $rest_methods, true) && wpauditor_is_authenticated_rest_request();
    if (wpauditor_detection_should_log_unusual_method($method, $expected_rest_method)) {
        wpauditor_log_event('UNUSUAL_HTTP_METHOD', '', array_merge($context, ['category' => 'Unusual HTTP']));
    }

    $skip_authenticated_users = wpauditor_is_authenticated_rest_users_request();

    $detection_post = is_array($_POST ?? null) ? map_deep(wp_unslash($_POST), 'sanitize_text_field') : [];
    $detection_body = $raw_body;
    $request = [
        'method' => $method,
        'uri' => $uri,
        'query_string' => wpauditor_server_text('QUERY_STRING', '', 4000),
        'query' => is_array($_GET ?? null) ? map_deep(wp_unslash($_GET), 'sanitize_text_field') : [],
        'post' => $detection_post,
        'files' => is_array($_FILES ?? null) ? map_deep(wp_unslash($_FILES), 'sanitize_text_field') : [],
        'body' => $detection_body,
        'content_type' => wpauditor_server_text('CONTENT_TYPE', wpauditor_server_text('HTTP_CONTENT_TYPE', '', 255), 255),
        'authenticated' => is_user_logged_in(),
        'skip_wordpress_user_recon' => $skip_authenticated_users,
        'trusted_site_urls' => [home_url('/'), site_url('/'), admin_url('/')],
    ];
    $detection = wpauditor_detect_request($request);

    if ($detection['detected'] && !empty($detection['primary'])) {
        $primary = $detection['primary'];
        $rule_ids = array_values(array_unique(array_column($detection['findings'], 'rule_id')));
        $safe_parameter = preg_replace('/[^A-Za-z0-9_.\[\]-]/', '_', (string) $primary['parameter']);
        if (!is_string($safe_parameter) || $safe_parameter === '') $safe_parameter = '-';
        $details = 'rule_id=' . $primary['rule_id']
            . ' confidence=' . (int) $primary['confidence']
            . ' source=' . $primary['source']
            . ' parameter=' . $safe_parameter
            . ' transform=' . $primary['transform']
            . ' enforcement=observe'
            . ' findings=' . count($detection['findings'])
            . ' rules=' . implode(',', $rule_ids)
            . (!empty($detection['regex_errors']) ? ' inspection_regex_errors=' . count($detection['regex_errors']) : '')
            . ($detection['truncated'] ? ' inspection_truncated=1' : '');

        wpauditor_log_event('WEB_APP_ATTACK', $details, array_merge($context, [
            'category' => $primary['category'],
            'severity' => $detection['severity'],
            'confidence' => (int) $primary['confidence'],
            'enforcement' => 'observe',
            'findings' => $detection['findings'],
        ]));
    }

});
