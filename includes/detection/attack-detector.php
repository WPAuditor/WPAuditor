<?php
if (!defined('ABSPATH')) exit;

if (!function_exists('wpauditor_detection_ends_with')) {
    function wpauditor_detection_ends_with(string $value, string $suffix): bool {
        return $suffix === '' || substr($value, -strlen($suffix)) === $suffix;
    }
}

if (!function_exists('wpauditor_detection_enforcement')) {
    function wpauditor_detection_enforcement(array $rule): string {
        if (!array_key_exists('enforcement', $rule)) return 'score';
        $mode = strtolower((string) $rule['enforcement']);
        return in_array($mode, ['observe', 'score', 'block'], true) ? $mode : 'observe';
    }
}

if (!function_exists('wpauditor_detection_strongest_enforcement')) {
    function wpauditor_detection_strongest_enforcement(array $findings): string {
        $rank = ['observe' => 0, 'score' => 1, 'block' => 2];
        $strongest = 'observe';
        foreach ($findings as $finding) {
            $mode = wpauditor_detection_enforcement($finding);
            if ($rank[$mode] > $rank[$strongest]) $strongest = $mode;
        }
        return $strongest;
    }
}

if (!function_exists('wpauditor_detection_excerpt')) {
    function wpauditor_detection_excerpt(string $value, int $offset = 0): string {
        $start = max(0, $offset - 40);
        $excerpt = substr($value, $start, 180);
        $excerpt = preg_replace('/[\x00-\x1F\x7F]+/', ' ', $excerpt);
        $excerpt = preg_replace(
            '/\b(password|passwd|pwd|token|api[_-]?key|secret|authorization)\s*[:=]\s*[^&\s]{1,128}/i',
            '$1=[redacted]',
            (string) $excerpt
        );
        return trim(is_string($excerpt) ? $excerpt : '');
    }
}

if (!function_exists('wpauditor_detection_adjust_confidence')) {
    function wpauditor_detection_adjust_confidence(array $rule, array $field, array $request, string $matched): int {
        $confidence = (int) $rule['confidence'];
        $category = (string) $rule['category'];
        $parameter = strtolower((string) ($field['parameter'] ?? ''));
        $source = (string) ($field['source'] ?? '');
        $value = (string) ($field['value'] ?? '');
        $content_parameters = ['content', 'post_content', 'description', 'excerpt', 'message', 'comment', 'code', 'snippet', 'template'];
        $search_parameters = ['s', 'q', 'search', 'query'];
        $url_parameters = ['url', 'uri', 'src', 'href', 'redirect', 'redirect_to', 'callback', 'webhook', 'endpoint'];

        foreach ($content_parameters as $name) {
            if ($parameter === $name || wpauditor_detection_ends_with($parameter, '[' . $name . ']')) {
                if (in_array($category, ['SQL_INJECTION', 'XSS'], true)) $confidence -= 45;
                break;
            }
        }

        if (in_array($parameter, $search_parameters, true)) {
            if ($category === 'SQL_INJECTION') $confidence -= 35;
            if ($rule['id'] === 'WPA-XSS-006') $confidence -= 35;
        }

        if ($source === 'raw_body' && preg_match('/(?:json|x-www-form-urlencoded)/', (string) ($request['content_type'] ?? ''))) {
            if (in_array($category, ['SQL_INJECTION', 'XSS'], true)) $confidence -= 40;
            if (!empty($request['authenticated']) && in_array($category, ['SQL_INJECTION', 'XSS'], true)) $confidence -= 20;
        }

        if ($rule['id'] === 'WPA-SQLI-002') {
            $has_sql_context = preg_match('/(?:\bfrom\b|\bwhere\b|\bnull\b|--|#|\/\*|[\x27"`;]|\d\s*[=<>])/i', $value) === 1;
            if (!$has_sql_context) $confidence -= 30;
            if (preg_match('/\b(?:id|user|order|sort|filter|page)\b/i', $parameter)) $confidence += 8;
        }

        if ($category === 'LFI_RFI' && preg_match('~(?:etc/(?:passwd|shadow)|windows[\\/]win\.ini|wp-config\.php)~i', $value)) {
            $confidence += 25;
        }

        if ($rule['id'] === 'WPA-XSS-006' && in_array($parameter, $url_parameters, true)) $confidence += 20;
        if (!empty($request['authenticated']) && in_array($parameter, $content_parameters, true)) $confidence -= 20;
        if ($matched === '') $confidence -= 10;

        return max(0, min(100, $confidence));
    }
}

if (!function_exists('wpauditor_detection_normalize_host')) {
    function wpauditor_detection_normalize_host(string $host): string {
        $host = strtolower(trim($host, "[] \t\n\r\0\x0B."));
        if ($host === '' || strpos($host, ':') !== false) return $host;

        $parts = explode('.', $host);
        if (count($parts) > 4) return $host;
        $numbers = [];
        foreach ($parts as $part) {
            if ($part === '') return $host;
            if (preg_match('/^0x[0-9a-f]+$/i', $part)) {
                $number = hexdec(substr($part, 2));
            } elseif (strlen($part) > 1 && $part[0] === '0' && preg_match('/^[0-7]+$/', $part)) {
                $number = octdec($part);
            } elseif (ctype_digit($part)) {
                $number = (int) $part;
            } else {
                return $host;
            }
            $numbers[] = $number;
        }

        $count = count($numbers);
        if ($count === 1 && $numbers[0] <= 0xFFFFFFFF) {
            $packed = $numbers[0];
        } elseif ($count === 2 && $numbers[0] <= 0xFF && $numbers[1] <= 0xFFFFFF) {
            $packed = ($numbers[0] << 24) | $numbers[1];
        } elseif ($count === 3 && $numbers[0] <= 0xFF && $numbers[1] <= 0xFF && $numbers[2] <= 0xFFFF) {
            $packed = ($numbers[0] << 24) | ($numbers[1] << 16) | $numbers[2];
        } elseif ($count === 4 && max($numbers) <= 0xFF) {
            $packed = ($numbers[0] << 24) | ($numbers[1] << 16) | ($numbers[2] << 8) | $numbers[3];
        } else {
            return $host;
        }

        $normalized = long2ip((int) $packed);
        if (is_string($normalized)) return $normalized;
        return $host;
    }
}

if (!function_exists('wpauditor_detection_is_same_site_login_redirect')) {
    function wpauditor_detection_is_same_site_login_redirect(array $field, array $request, string $value): bool {
        if (strtolower((string) ($field['parameter'] ?? '')) !== 'redirect_to') return false;

        $request_path = wp_parse_url((string) ($request['uri'] ?? ''), PHP_URL_PATH);
        if (!is_string($request_path) || preg_match('#/wp-login\.php$#i', $request_path) !== 1) return false;

        $target = wp_parse_url(strpos($value, '//') === 0 ? 'http:' . $value : $value);
        if (!is_array($target) || !in_array(strtolower((string) ($target['scheme'] ?? '')), ['http', 'https'], true)) return false;

        $target_host = wpauditor_detection_normalize_host((string) ($target['host'] ?? ''));
        if ($target_host === '') return false;

        foreach ((array) ($request['trusted_site_urls'] ?? []) as $trusted_url) {
            if (!is_string($trusted_url) || $trusted_url === '') continue;
            $trusted_host = wp_parse_url($trusted_url, PHP_URL_HOST);
            if (!is_string($trusted_host) || $trusted_host === '') continue;
            if (hash_equals(wpauditor_detection_normalize_host($trusted_host), $target_host)) return true;
        }

        return false;
    }
}

if (!function_exists('wpauditor_detection_ssrf_finding')) {
    function wpauditor_detection_ssrf_finding(array $field, array $request = []): ?array {
        if (!in_array($field['source'] ?? '', ['query', 'form', 'json'], true)) return null;
        $parameter = strtolower((string) ($field['parameter'] ?? ''));
        if (!preg_match('/(?:url|uri|src|href|host|endpoint|callback|webhook|proxy|redirect|feed|image|destination|target)/', $parameter)) return null;

        $value = trim((string) ($field['raw_value'] ?? ''));
        $protocol_relative = strpos($value, '//') === 0;
        if (!$protocol_relative && !preg_match('~^(https?|file|gopher|dict|ftp)://~i', $value)) return null;
        $parse_value = $protocol_relative ? 'http:' . $value : $value;
        $parts = wp_parse_url($parse_value);
        if (!is_array($parts)) return null;
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = wpauditor_detection_normalize_host((string) ($parts['host'] ?? ''));

        if (wpauditor_detection_is_same_site_login_redirect($field, $request, $value)) return null;

        $reason = '';
        $confidence = 0;
        if (in_array($scheme, ['file', 'gopher', 'dict'], true)) {
            $reason = 'dangerous_scheme';
            $confidence = 92;
        } elseif ($host === 'localhost' || wpauditor_detection_ends_with($host, '.localhost')) {
            $reason = 'loopback_host';
            $confidence = 88;
        } elseif (in_array($host, ['metadata.google.internal', 'metadata', 'instance-data'], true)) {
            $reason = 'metadata_host';
            $confidence = 96;
        } elseif (filter_var($host, FILTER_VALIDATE_IP)) {
            $public = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
            if ($public === false) {
                $reason = in_array($host, ['169.254.169.254', '100.100.100.200'], true) ? 'cloud_metadata' : 'private_or_reserved_ip';
                $confidence = $reason === 'cloud_metadata' ? 98 : 88;
            }
        }
        if ($reason === '') return null;

        return [
            'rule_id' => 'WPA-SSRF-001',
            'category' => 'SSRF',
            'confidence' => $confidence,
            'enforcement' => in_array($reason, ['dangerous_scheme', 'metadata_host', 'cloud_metadata'], true) ? 'block' : 'score',
            'source' => $field['source'],
            'parameter' => $field['parameter'],
            'transform' => $field['transform'] ?? 'raw',
            'excerpt' => wpauditor_detection_excerpt($value),
            'reason' => $reason,
        ];
    }
}

if (!function_exists('wpauditor_detection_encoded_finding')) {
    function wpauditor_detection_encoded_finding(array $field): ?array {
        if (!in_array($field['source'] ?? '', ['query', 'form', 'json'], true)) return null;
        $raw = preg_replace('/\s+/', '', (string) ($field['raw_value'] ?? ''));
        if (!is_string($raw) || strlen($raw) < 120 || strlen($raw) > 16384 || preg_match('/^[A-Za-z0-9+\/=]+$/', $raw) !== 1) return null;

        $decoded = base64_decode(substr($raw, 0, 8192), true);
        $parameter = strtolower((string) ($field['parameter'] ?? ''));
        $suspicious_parameter = preg_match('/(?:payload|shell|cmd|exec|serialized|object|code)/', $parameter) === 1;
        $dangerous_content = is_string($decoded) && preg_match('/(?:<\?php|\beval\s*\(|\b(?:system|exec|shell_exec|passthru)\s*\(|\/bin\/(?:ba)?sh|powershell)/i', $decoded) === 1;
        if (!$suspicious_parameter && !$dangerous_content) return null;

        return [
            'rule_id' => 'WPA-OBF-BASE64-001',
            'category' => 'OBFUSCATION_ENCODING',
            'confidence' => $dangerous_content ? 90 : 58,
            'enforcement' => 'score',
            'source' => $field['source'],
            'parameter' => $field['parameter'],
            'transform' => $field['transform'] ?? 'raw',
            'excerpt' => substr($raw, 0, 80),
            'reason' => $dangerous_content ? 'decoded_executable_content' : 'suspicious_encoded_parameter',
        ];
    }
}

if (!function_exists('wpauditor_detection_serialized_finding')) {
    function wpauditor_detection_serialized_finding(array $field): ?array {
        if (!in_array($field['source'] ?? '', ['query', 'form', 'json', 'raw_body'], true)) return null;
        $raw = preg_replace('/\s+/', '', (string) ($field['raw_value'] ?? ''));
        if (!is_string($raw) || strlen($raw) < 16 || strlen($raw) > 16384 || preg_match('/^[A-Za-z0-9+\/=]+$/', $raw) !== 1) return null;

        $decoded = base64_decode($raw, true);
        if (!is_string($decoded) || preg_match('/(?:^|[;{}])(?:O|C):\d{1,7}:"[A-Za-z_\\\\][A-Za-z0-9_\\\\]{0,255}":\d{1,9}:\{/', $decoded) !== 1) return null;

        return [
            'rule_id' => 'WPA-PHP-OBJ-BASE64-001',
            'category' => 'PHP_OBJECT_INJECTION',
            'confidence' => 86,
            'enforcement' => 'score',
            'source' => $field['source'],
            'parameter' => $field['parameter'],
            'transform' => 'base64_decode',
            'excerpt' => substr($raw, 0, 80),
            'reason' => 'base64_serialized_php_object',
        ];
    }
}

if (!function_exists('wpauditor_detection_upload_findings')) {
    function wpauditor_detection_image_signature_matches(string $name, string $sample): bool {
        $extension = strtolower((string) pathinfo($name, PATHINFO_EXTENSION));
        if ($extension === 'jpg' || $extension === 'jpeg') return substr($sample, 0, 3) === "\xFF\xD8\xFF";
        if ($extension === 'png') return substr($sample, 0, 8) === "\x89PNG\r\n\x1A\n";
        if ($extension === 'gif') return in_array(substr($sample, 0, 6), ['GIF87a', 'GIF89a'], true);
        if ($extension === 'webp') return substr($sample, 0, 4) === 'RIFF' && substr($sample, 8, 4) === 'WEBP';
        if ($extension === 'bmp') return substr($sample, 0, 2) === 'BM';
        if ($extension === 'ico') return substr($sample, 0, 4) === "\x00\x00\x01\x00";
        return true;
    }

    function wpauditor_detection_upload_findings(array $uploads): array {
        $findings = [];
        foreach ($uploads as $upload) {
            $name = (string) ($upload['name'] ?? '');
            $mime = strtolower((string) ($upload['type'] ?? ''));
            $sample = (string) ($upload['sample'] ?? '');
            $parameter = (string) ($upload['parameter'] ?? '');

            if (preg_match('~(?:php|x-httpd-php|x-php)~i', $mime)) {
                $findings[] = [
                    'rule_id' => 'WPA-UPLOAD-MIME-001',
                    'category' => 'SUSPICIOUS_UPLOADS',
                    'confidence' => 88,
                    'enforcement' => 'score',
                    'source' => 'upload_mime',
                    'parameter' => $parameter,
                    'transform' => 'raw',
                    'excerpt' => wpauditor_detection_excerpt($name . ' mime=' . $mime),
                    'reason' => 'executable_mime',
                ];
            }

            $image_name = preg_match('/\.(?:jpe?g|png|gif|webp|svg|bmp|ico)$/i', $name) === 1;
            if ($image_name && $sample !== '' && preg_match('/<\?php|\b(?:eval|assert|shell_exec|passthru)\s*\(/i', $sample)) {
                $findings[] = [
                    'rule_id' => 'WPA-UPLOAD-CONTENT-001',
                    'category' => 'SUSPICIOUS_UPLOADS',
                    'confidence' => 98,
                    'enforcement' => 'block',
                    'source' => 'upload_content',
                    'parameter' => $parameter,
                    'transform' => 'raw',
                    'excerpt' => wpauditor_detection_excerpt($name),
                    'reason' => 'executable_content_in_image',
                ];
            }

            $svg_upload = preg_match('/\.svg$/i', $name) === 1 || strpos($mime, 'image/svg+xml') !== false;
            if (
                $svg_upload
                && $sample !== ''
                && preg_match('~<script\b|\son[a-z][a-z0-9_-]{1,48}\s*=|(?:href|xlink:href)\s*=\s*[\x27"]?\s*(?:javascript\s*:|data\s*:\s*text/html)|<!ENTITY\s+[^>]+\bSYSTEM\b|<[^>]+:include\b~i', $sample)
            ) {
                $findings[] = [
                    'rule_id' => 'WPA-UPLOAD-SVG-001',
                    'category' => 'SUSPICIOUS_UPLOADS',
                    'confidence' => 94,
                    'enforcement' => 'block',
                    'source' => 'upload_content',
                    'parameter' => $parameter,
                    'transform' => 'raw',
                    'excerpt' => wpauditor_detection_excerpt($name),
                    'reason' => 'active_content_in_svg',
                ];
            }

            $raster_name = preg_match('/\.(?:jpe?g|png|gif|webp|bmp|ico)$/i', $name) === 1;
            if ($raster_name && $sample !== '' && !wpauditor_detection_image_signature_matches($name, $sample)) {
                $findings[] = [
                    'rule_id' => 'WPA-UPLOAD-MAGIC-001',
                    'category' => 'SUSPICIOUS_UPLOADS',
                    'confidence' => 58,
                    'enforcement' => 'observe',
                    'source' => 'upload_content',
                    'parameter' => $parameter,
                    'transform' => 'raw',
                    'excerpt' => wpauditor_detection_excerpt($name),
                    'reason' => 'image_signature_mismatch',
                ];
            }
        }
        return $findings;
    }
}

if (!function_exists('wpauditor_detection_severity')) {
    function wpauditor_detection_severity(string $category, int $confidence): string {
        if ($confidence < 50) return 'LOW';
        if ($confidence < 70) return 'MEDIUM';
        if ($confidence >= 90 && in_array($category, ['REMOTE_CODE_EXECUTION', 'LFI_RFI', 'COMMAND_INJECTION', 'SSRF', 'SUSPICIOUS_UPLOADS', 'XXE'], true)) return 'CRITICAL';
        return $confidence >= 80 ? 'HIGH' : 'MEDIUM';
    }
}

if (!function_exists('wpauditor_detect_request')) {
    function wpauditor_detect_request(array $request): array {
        $normalized = wpauditor_normalize_request($request);
        $findings = [];
        $seen = [];
        $regex_errors = [];
        $max_findings = wpauditor_detection_limit('max_findings', 10);
        $minimum_confidence = wpauditor_detection_limit('minimum_confidence', 40);
        $rules = wpauditor_get_attack_rules();

        foreach ($normalized['fields'] as $field) {
            foreach ($rules as $rule) {
                if (
                    !empty($request['skip_wordpress_user_recon'])
                    && in_array($rule['id'], ['WPA-WP-RECON-001', 'WPA-WP-RECON-002'], true)
                ) continue;
                if (!empty($request['skip_wordpress_recon']) && $rule['category'] === 'WORDPRESS_RECON') continue;
                if (!empty($rule['sources']) && !in_array($field['source'], $rule['sources'], true)) continue;
                $result = @preg_match($rule['pattern'], (string) $field['value'], $match, PREG_OFFSET_CAPTURE);
                if ($result === false) {
                    $regex_errors[$rule['id']] = function_exists('preg_last_error_msg') ? preg_last_error_msg() : (string) preg_last_error();
                    continue;
                }
                if ($result !== 1) continue;

                $matched = (string) ($match[0][0] ?? '');
                $offset = (int) ($match[0][1] ?? 0);
                $confidence = wpauditor_detection_adjust_confidence($rule, $field, $request + $normalized, $matched);
                if ($confidence < $minimum_confidence) continue;

                $key = $rule['id'] . '|' . $field['source'] . '|' . $field['parameter'];
                if (isset($seen[$key])) continue;
                $seen[$key] = true;
                $findings[] = [
                    'rule_id' => $rule['id'],
                    'category' => $rule['category'],
                    'confidence' => $confidence,
                    'enforcement' => wpauditor_detection_enforcement($rule),
                    'source' => $field['source'],
                    'parameter' => $field['parameter'],
                    'transform' => $field['transform'],
                    'excerpt' => wpauditor_detection_excerpt((string) $field['value'], $offset),
                ];
            }

            foreach ([
                wpauditor_detection_ssrf_finding($field, $request),
                wpauditor_detection_encoded_finding($field),
                wpauditor_detection_serialized_finding($field),
            ] as $finding) {
                if (!$finding || $finding['confidence'] < $minimum_confidence) continue;
                $key = $finding['rule_id'] . '|' . $finding['source'] . '|' . $finding['parameter'];
                if (isset($seen[$key])) continue;
                $seen[$key] = true;
                $findings[] = $finding;
            }
        }

        foreach (wpauditor_detection_upload_findings($normalized['uploads']) as $finding) {
            if ($finding['confidence'] < $minimum_confidence) continue;
            $key = $finding['rule_id'] . '|' . $finding['source'] . '|' . $finding['parameter'];
            if (isset($seen[$key])) continue;
            $seen[$key] = true;
            $findings[] = $finding;
        }

        usort($findings, static function (array $a, array $b): int {
            return $b['confidence'] <=> $a['confidence'];
        });
        if (count($findings) > $max_findings) {
            $findings = array_slice($findings, 0, $max_findings);
            $normalized['truncated'] = true;
        }

        $primary = $findings[0] ?? null;
        $enforcement = $primary ? wpauditor_detection_strongest_enforcement($findings) : 'observe';
        return [
            'detected' => $primary !== null,
            'primary' => $primary,
            'findings' => $findings,
            'truncated' => (bool) $normalized['truncated'],
            'enforcement' => $enforcement,
            'regex_errors' => $regex_errors,
            'severity' => $primary ? wpauditor_detection_severity($primary['category'], (int) $primary['confidence']) : 'INFO',
        ];
    }
}
