<?php
if (!defined('ABSPATH')) exit;

// Bounded streaming reads inspect uploads without loading large files into memory.
// phpcs:disable WordPress.WP.AlternativeFunctions

if (!function_exists('wpauditor_detection_is_rest_route')) {
    function wpauditor_detection_is_rest_route(string $request_uri, string $rest_route = '', string $rest_prefix = 'wp-json'): bool {
        if ($rest_route !== '') {
            return substr($rest_route, 0, 1) === '/';
        }

        $request_path = wp_parse_url($request_uri, PHP_URL_PATH);
        $rest_prefix = trim($rest_prefix, '/');
        if (!is_string($request_path) || $request_path === '' || $rest_prefix === '') return false;

        return preg_match('#/' . preg_quote($rest_prefix, '#') . '(?:/|$)#i', $request_path) === 1;
    }
}

if (!function_exists('wpauditor_detection_is_core_users_route')) {
    function wpauditor_detection_is_core_users_route(string $request_uri, string $rest_route = '', string $rest_prefix = 'wp-json'): bool {
        if ($rest_route !== '') {
            $route_path = wp_parse_url($rest_route, PHP_URL_PATH);
        } else {
            $request_path = wp_parse_url($request_uri, PHP_URL_PATH);
            $rest_prefix = trim($rest_prefix, '/');
            if (!is_string($request_path) || $request_path === '' || $rest_prefix === '') return false;

            $marker = '/' . $rest_prefix;
            $marker_position = stripos($request_path, $marker);
            if ($marker_position === false) return false;
            $route_path = substr($request_path, $marker_position + strlen($marker));
        }

        return is_string($route_path)
            && preg_match('#^/?wp/v2/users(?:/(?:me|\d+))?/?$#i', $route_path) === 1;
    }
}

if (!function_exists('wpauditor_detection_should_skip_user_recon')) {
    function wpauditor_detection_should_skip_user_recon(string $method, bool $authenticated_rest, bool $core_users_route): bool {
        return in_array(strtoupper($method), ['GET', 'OPTIONS'], true)
            && $authenticated_rest
            && $core_users_route;
    }
}

if (!function_exists('wpauditor_detection_should_log_unusual_method')) {
    function wpauditor_detection_should_log_unusual_method(string $method, bool $authenticated_rest): bool {
        $method = strtoupper($method);
        $unusual = ['OPTIONS', 'PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT'];
        if (!in_array($method, $unusual, true)) return false;

        $rest_methods = ['OPTIONS', 'PUT', 'DELETE', 'PATCH'];
        return !$authenticated_rest || !in_array($method, $rest_methods, true);
    }
}

if (!function_exists('wpauditor_detection_limit')) {
    function wpauditor_detection_limit(string $name, int $default): int {
        $value = function_exists('apply_filters')
            ? apply_filters('wpauditor_detection_' . $name, $default)
            : $default;
        return max(1, (int) $value);
    }
}

if (!function_exists('wpauditor_detection_truncate')) {
    function wpauditor_detection_truncate(string $value, int $limit, bool &$truncated): string {
        if (strlen($value) <= $limit) return $value;
        $truncated = true;
        return substr($value, 0, $limit);
    }
}

if (!function_exists('wpauditor_detection_variants')) {
    function wpauditor_detection_variants(string $value, bool &$truncated): array {
        $field_limit = wpauditor_detection_limit('max_field_bytes', 16384);
        $decode_limit = wpauditor_detection_limit('max_decode_passes', 2);
        $value = wpauditor_detection_truncate($value, $field_limit, $truncated);

        $variants = [['value' => $value, 'transform' => 'raw']];
        $current = $value;

        for ($pass = 1; $pass <= $decode_limit; $pass++) {
            $decoded = rawurldecode(str_replace('+', ' ', $current));
            if ($decoded === $current) break;
            $decoded = wpauditor_detection_truncate($decoded, $field_limit, $truncated);
            $variants[] = ['value' => $decoded, 'transform' => 'url_decode_' . $pass];
            $current = $decoded;
        }

        $html = html_entity_decode($current, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        if ($html !== $current) {
            $variants[] = [
                'value' => wpauditor_detection_truncate($html, $field_limit, $truncated),
                'transform' => 'html_entity_decode',
            ];
        }

        foreach (array_column($variants, 'value') as $candidate) {
            $normalized = str_replace("\0", '', $candidate);
            $unicode_space = preg_replace('/[\x{00A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}]/u', ' ', $normalized);
            if (is_string($unicode_space)) $normalized = $unicode_space;
            if ($normalized !== $candidate) {
                $variants[] = ['value' => $normalized, 'transform' => 'unicode_normalized'];
            }

            // Two controlled SQL-comment views expose split keywords without unbounded decoding.
            $comment_stripped = preg_replace('~/\*[\s\S]{0,512}?\*/~', '', $normalized);
            if (is_string($comment_stripped) && $comment_stripped !== $normalized) {
                $variants[] = ['value' => $comment_stripped, 'transform' => 'sql_comments_removed'];
            }
            $comment_spaced = preg_replace('~/\*[\s\S]{0,512}?\*/~', ' ', $normalized);
            if (is_string($comment_spaced) && $comment_spaced !== $normalized) {
                $variants[] = ['value' => $comment_spaced, 'transform' => 'sql_comments_spaced'];
            }
        }

        $unique = [];
        foreach ($variants as $variant) {
            if ($variant['value'] === '') continue;
            $key = sha1($variant['value']);
            if (!isset($unique[$key])) $unique[$key] = $variant;
        }
        return array_values($unique);
    }
}

if (!function_exists('wpauditor_detection_collect_scalars')) {
    function wpauditor_detection_collect_scalars($value, string $prefix, array &$out, int &$remaining): void {
        if ($remaining <= 0) return;
        if (is_array($value) || is_object($value)) {
            foreach ((array) $value as $key => $item) {
                $child = $prefix === '' ? (string) $key : $prefix . '[' . (string) $key . ']';
                wpauditor_detection_collect_scalars($item, $child, $out, $remaining);
                if ($remaining <= 0) break;
            }
            return;
        }
        if (!is_scalar($value) && $value !== null) return;
        $out[] = ['parameter' => $prefix, 'value' => (string) $value];
        $remaining--;
    }
}

if (!function_exists('wpauditor_detection_collect_uploads')) {
    function wpauditor_detection_upload_sample(string $temp_name): string {
        if ($temp_name === '' || !is_uploaded_file($temp_name)) return '';

        $handle = @fopen($temp_name, 'rb');
        if (!is_resource($handle)) return '';

        $head = fread($handle, 4096);
        if (!is_string($head)) $head = '';

        $size = @filesize($temp_name);
        $tail = '';
        if (is_int($size) && $size > 4096 && @fseek($handle, max(4096, $size - 4096), SEEK_SET) === 0) {
            $tail_value = fread($handle, 4096);
            if (is_string($tail_value)) $tail = $tail_value;
        }
        fclose($handle);

        return $tail === '' ? $head : $head . "\n[WPAUDITOR_TAIL_SAMPLE]\n" . $tail;
    }

    function wpauditor_detection_collect_uploads(array $files): array {
        $out = [];
        $remaining = wpauditor_detection_limit('max_uploads', 32);

        foreach ($files as $parameter => $file) {
            if ($remaining <= 0 || !is_array($file) || !array_key_exists('name', $file)) continue;
            $names = [];
            wpauditor_detection_collect_scalars($file['name'], (string) $parameter, $names, $remaining);
            $types = [];
            $type_remaining = wpauditor_detection_limit('max_uploads', 32);
            wpauditor_detection_collect_scalars($file['type'] ?? '', (string) $parameter, $types, $type_remaining);
            $type_map = [];
            foreach ($types as $type) $type_map[$type['parameter']] = $type['value'];
            $temp_names = [];
            $temp_remaining = wpauditor_detection_limit('max_uploads', 32);
            wpauditor_detection_collect_scalars($file['tmp_name'] ?? '', (string) $parameter, $temp_names, $temp_remaining);
            $temp_map = [];
            foreach ($temp_names as $temp_name) $temp_map[$temp_name['parameter']] = $temp_name['value'];

            foreach ($names as $name) {
                if ($name['value'] === '') continue;
                $temp_name = $temp_map[$name['parameter']] ?? '';
                $sample = wpauditor_detection_upload_sample((string) $temp_name);
                $out[] = [
                    'parameter' => $name['parameter'],
                    'name' => $name['value'],
                    'type' => $type_map[$name['parameter']] ?? '',
                    'sample' => $sample,
                ];
            }
        }
        return $out;
    }
}

if (!function_exists('wpauditor_normalize_request')) {
    function wpauditor_normalize_request(array $request): array {
        $truncated = false;
        $max_fields = wpauditor_detection_limit('max_fields', 128);
        $remaining = $max_fields;
        $records = [];

        $uri = (string) ($request['uri'] ?? '');
        $path = wp_parse_url($uri, PHP_URL_PATH);
        if (!is_string($path)) $path = $uri;
        $raw_query = (string) ($request['query_string'] ?? '');
        if ($raw_query === '') {
            $parsed_query = wp_parse_url($uri, PHP_URL_QUERY);
            if (is_string($parsed_query)) $raw_query = $parsed_query;
        }

        if ($path !== '') $records[] = ['source' => 'path', 'parameter' => '_path', 'value' => $path, 'raw_value' => $path];
        $query = [];
        if ($raw_query !== '') parse_str($raw_query, $query);
        if (!empty($request['query']) && is_array($request['query'])) $query = array_replace_recursive($query, $request['query']);

        foreach (['query' => $query, 'form' => ($request['post'] ?? [])] as $source => $values) {
            if (!is_array($values)) continue;
            $scalars = [];
            wpauditor_detection_collect_scalars($values, '', $scalars, $remaining);
            foreach ($scalars as $scalar) {
                $assignment = $scalar['parameter'] !== ''
                    ? $scalar['parameter'] . '=' . $scalar['value']
                    : $scalar['value'];
                $records[] = [
                    'source' => $source,
                    'parameter' => $scalar['parameter'],
                    'value' => $assignment,
                    'raw_value' => $scalar['value'],
                ];
            }
        }

        $body_limit = wpauditor_detection_limit('max_body_bytes', 262144);
        $raw_body = wpauditor_detection_truncate((string) ($request['body'] ?? ''), $body_limit, $truncated);
        $content_type = strtolower((string) ($request['content_type'] ?? ''));

        $binary_body = preg_match('~(?:multipart/form-data|application/octet-stream|application/(?:zip|pdf)|image/|audio/|video/)~i', $content_type) === 1;
        if ($raw_body !== '' && !$binary_body) {
            $records[] = ['source' => 'raw_body', 'parameter' => '_body', 'value' => $raw_body, 'raw_value' => $raw_body];
        }

        $looks_json = strpos($content_type, 'json') !== false || preg_match('/^\s*[\[{]/', $raw_body) === 1;
        if ($raw_body !== '' && $looks_json) {
            $json = json_decode($raw_body, true);
            if (is_array($json)) {
                $scalars = [];
                wpauditor_detection_collect_scalars($json, '', $scalars, $remaining);
                foreach ($scalars as $scalar) {
                    $records[] = [
                        'source' => 'json',
                        'parameter' => $scalar['parameter'],
                        'value' => $scalar['parameter'] . '=' . $scalar['value'],
                        'raw_value' => $scalar['value'],
                    ];
                }
            }
        }

        $uploads = wpauditor_detection_collect_uploads(is_array($request['files'] ?? null) ? $request['files'] : []);
        foreach ($uploads as $upload) {
            $records[] = [
                'source' => 'upload_filename',
                'parameter' => $upload['parameter'],
                'value' => $upload['name'],
                'raw_value' => $upload['name'],
                'mime' => $upload['type'],
            ];
        }

        $fields = [];
        $max_variants = wpauditor_detection_limit('max_variants', 384);
        foreach ($records as $record) {
            foreach (wpauditor_detection_variants((string) $record['value'], $truncated) as $variant) {
                $field = $record;
                $field['value'] = $variant['value'];
                $field['transform'] = $variant['transform'];
                $fields[] = $field;
                if (count($fields) >= $max_variants) {
                    $truncated = true;
                    break 2;
                }
            }
        }

        return [
            'fields' => $fields,
            'uploads' => $uploads,
            'truncated' => $truncated,
            'content_type' => $content_type,
        ];
    }
}
