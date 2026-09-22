<?php
if (!defined('ABSPATH')) exit;

// Bounded streaming reads keep file forensics memory usage predictable.
// phpcs:disable WordPress.WP.AlternativeFunctions

class WPAuditor_Scanner {

    // Executable or active-content extensions that are unusual in uploads
    private static $suspicious_exts = [
        'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar',
        'html', 'htm', 'js', 'jsp', 'asp', 'aspx', 'cgi', 'pl', 'py', 'rb',
        'sh', 'bash', 'bat', 'cmd', 'ps1',
        'exe', 'dll', 'so', 'bin', 'msi', 'scr', 'com',
        'jar', 'class', 'vbs', 'wsf', 'hta', 'cpl', 'pif', 'gadget'
    ];

    // Recursive iterator excluding .quarantine
    private static function get_filtered_iterator($base) {
        return new RecursiveIteratorIterator(
            new RecursiveCallbackFilterIterator(
                new RecursiveDirectoryIterator($base, RecursiveDirectoryIterator::SKIP_DOTS),
                function ($file) {
                    $name = $file->getFilename();
                    if (in_array($name, ['.quarantine', '.wpauditor-free-quarantine', 'wpauditor-quarantine', 'wpauditor-free-logs', 'wpauditor'], true)) return false;

                    if ($file->isDir()) {
                        $path = wp_normalize_path($file->getPathname());
                        if (preg_match('#/\.git/(?:objects|refs|logs)$#i', $path)) return false;
                    }

                    return true;
                }
            ),
            RecursiveIteratorIterator::LEAVES_ONLY,
            RecursiveIteratorIterator::CATCH_GET_CHILD
        );
    }

    // Count the same readable file work units used by progress-aware scans.
    private static function count_scannable_files(string $base): int {
        if (!is_dir($base)) return 0;

        $total = 0;
        foreach (self::get_filtered_iterator($base) as $file) {
            if (!$file instanceof SplFileInfo || !$file->isFile() || $file->isLink()) continue;
            if (!$file->getRealPath()) continue;
            $total++;
        }

        return $total;
    }

    // Read bounded head and tail samples so appended payloads are still inspected
    private static function read_sample(string $path, int $max_bytes = 262144): string {
        $handle = @fopen($path, 'rb');
        if (!$handle) return '';

        $head = @fread($handle, $max_bytes);
        $head = is_string($head) ? $head : '';
        $tail = '';
        $size = @filesize($path);

        if (is_int($size) && $size > $max_bytes) {
            $tail_offset = max($max_bytes, $size - $max_bytes);
            if (@fseek($handle, $tail_offset, SEEK_SET) === 0) {
                $tail = @fread($handle, $max_bytes);
                $tail = is_string($tail) ? $tail : '';
            }
        }

        @fclose($handle);

        return $tail !== '' ? $head . "\n" . $tail : $head;
    }

    // Require structured short-echo syntax in valid binary images to avoid random byte matches
    private static function contains_php_marker(string $sample, bool $structured_short_echo = false): bool {
        if ($sample === '') return false;
        if (preg_match('/<\?php(?:\s|\/\*|$)/i', $sample)) return true;
        if (!$structured_short_echo) return (bool) preg_match('/<\?=/i', $sample);

        $offset = 0;
        while (($position = strpos($sample, '<?=', $offset)) !== false) {
            $candidate = substr($sample, $position + 3, 256);
            $terminators = array_filter([
                strpos($candidate, '?>'),
                strpos($candidate, ';'),
            ], static fn($value) => $value !== false);

            if ($terminators) {
                $code = trim(substr($candidate, 0, min($terminators)));
                if (
                    $code !== '' &&
                    preg_match('/^[\x09\x0A\x0D\x20-\x7E]+$/', $code) &&
                    preg_match('/(?:\$[A-Za-z_]|[A-Za-z_][A-Za-z0-9_]*\s*\(|[\'"0-9])/', $code)
                ) {
                    return true;
                }
            }

            $offset = $position + 3;
        }

        return false;
    }

    // Detect MIME safely when fileinfo is unavailable
    private static function detect_mime(string $path): string {
        if (function_exists('mime_content_type')) {
            $mime = @mime_content_type($path);
            if (is_string($mime) && $mime !== '') return $mime;
        }

        return 'unknown';
    }

    // Convert an absolute path under WordPress into a stable relative path
    private static function relative_path(string $path): string {
        $base = wpauditor_wordpress_root();
        $normalized = wp_normalize_path($path);

        if ($base !== '/' && str_starts_with($normalized, $base)) {
            return ltrim(substr($normalized, strlen($base)), '/');
        }

        return basename($normalized);
    }

    // Map the explainable forensic score to the shared severity scale
    private static function forensic_severity(int $score): string {
        if ($score >= 85) return 'Critical';
        if ($score >= 65) return 'High';
        if ($score >= 40) return 'Medium';
        if ($score >= 20) return 'Low';
        return 'Info';
    }

    // Build the normalized finding contract used by every file detector
    private static function build_finding(
        SplFileInfo $file,
        string $detector,
        string $location,
        array $rules,
        array $evidence,
        int $score
    ): array {
        $path = (string) $file->getRealPath();
        $relative = self::relative_path($path);
        $size = @filesize($path);
        $size = $size === false ? 0 : (int) $size;
        $score = max(0, min(100, $score));

        $high_confidence_rules = [
            'uploads.server_executable',
            'uploads.double_extension',
            'uploads.embedded_php',
            'sensitive.environment_file',
            'sensitive.private_key',
            'sensitive.database_dump',
            'sensitive.wp_config_backup',
            'sensitive.vcs_metadata',
        ];
        $confidence = array_intersect($rules, $high_confidence_rules)
            ? 'High'
            : ($score >= 40 ? 'Medium' : 'Low');

        $hash = '';
        if ($size > 0 && $size <= 64 * 1024 * 1024) {
            $hash = (string) (@hash_file('sha256', $path) ?: '');
        }

        return [
            'finding_id'   => substr(hash('sha256', $relative . '|' . $detector . '|' . implode('|', $rules)), 0, 24),
            'path'         => $path,
            'relative_path'=> $relative,
            'detector'     => $detector,
            'detectors'    => [$detector],
            'location'     => $location,
            'exposure'     => 'Potentially web-accessible',
            'rules'        => array_values(array_unique($rules)),
            'evidence'     => array_values(array_unique($evidence)),
            'reason'       => implode('; ', array_values(array_unique($evidence))),
            'score'        => $score,
            'severity'     => self::forensic_severity($score),
            'confidence'   => $confidence,
            'ext'          => strtolower($file->getExtension()),
            'mime'         => self::detect_mime($path),
            'size'         => $size,
            'sha256'       => $hash,
            'modified'     => wp_date('Y-m-d H:i:s', $file->getMTime()),
            'modified_ts'  => $file->getMTime(),
            'status'       => 'New',
        ];
    }

    // Scan uploads using extension, filename, MIME, image, and content evidence
    public static function scan_suspicious_files_uploads(?callable $progress_callback = null, ?int $progress_total = null) {
        $results = [];
        $uploads_dir = rtrim(wpauditor_uploads_base_dir(), '/\\');
        if (!is_dir($uploads_dir)) return $results;

        $iterator = self::get_filtered_iterator($uploads_dir);
        $progress_total = $progress_total ?? ($progress_callback ? self::count_scannable_files($uploads_dir) : 0);
        $progress_completed = 0;
        $server_exts = ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar', 'pht'];
        $browser_exts = ['html', 'htm', 'js', 'svg', 'hta'];
        $image_exts = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'ico', 'avif'];

        foreach ($iterator as $file) {
            if (!$file->isFile() || $file->isLink()) continue;

            $path = $file->getRealPath();
            if (!$path) continue;

            if ($progress_callback) {
                $progress_callback($progress_completed, $progress_total);
                $progress_completed++;
            }

            $filename = strtolower($file->getFilename());
            $ext = strtolower($file->getExtension());
            $mime = self::detect_mime($path);
            $rules = [];
            $evidence = [];
            $score = 0;

            $add = static function (string $rule, string $message, int $points) use (&$rules, &$evidence, &$score): void {
                if (in_array($rule, $rules, true)) return;
                $rules[] = $rule;
                $evidence[] = $message;
                $score += $points;
            };

            if (in_array($ext, $server_exts, true)) {
                $add('uploads.server_executable', 'Server-executable file type found in Media uploads', 85);
            } elseif (in_array($ext, $browser_exts, true)) {
                $add('uploads.active_content', 'Active browser content found in Media uploads', 20);
            } elseif (in_array($ext, self::$suspicious_exts, true)) {
                $add('uploads.executable_type', 'Executable or script file type found in Media uploads', 55);
            }

            if (preg_match('/\.(?:php\d?|pht|phtml|phar)(?:\.|%2e)[^.]+$/i', $filename)) {
                $add('uploads.double_extension', 'PHP-like double extension may disguise executable content', 60);
            }

            if (preg_match('/^(?:\.env(?:\..+)?|\.user\.ini|wp-config(?:\..+)?|id_rsa|authorized_keys)$/i', $filename)) {
                $add('uploads.sensitive_name', 'Sensitive configuration or credential filename found in uploads', 65);
            }

            if (str_starts_with($filename, '.') && !in_array($filename, ['.htaccess', '.well-known'], true)) {
                $add('uploads.hidden_file', 'Unexpected hidden file found in Media uploads', 25);
            }

            $valid_image = false;
            if (in_array($ext, $image_exts, true)) {
                $image_info = function_exists('getimagesize') ? @getimagesize($path) : false;
                $valid_image = $image_info !== false && str_starts_with($mime, 'image/');
                if ($image_info === false) {
                    $add('uploads.invalid_image', 'File uses an image extension but has no valid image header', 25);
                }

                if (
                    str_starts_with($mime, 'text/') ||
                    str_contains($mime, 'php') ||
                    str_contains($mime, 'html') ||
                    str_contains($mime, 'javascript')
                ) {
                    $add('uploads.mime_mismatch', 'Detected MIME type conflicts with the image extension', 35);
                }
            }

            $inspect_content = $rules || in_array($ext, $image_exts, true);
            if ($inspect_content) {
                $sample = self::read_sample($path);
                if (self::contains_php_marker($sample, $valid_image)) {
                    $add('uploads.embedded_php', 'PHP code marker detected inside the uploaded file', 60);
                }

                if ($sample !== '' && in_array($ext, array_merge($image_exts, ['svg']), true)) {
                    if (preg_match('/<script\b|\bonerror\s*=|javascript\s*:/i', $sample)) {
                        $add('uploads.embedded_script', 'Active script content detected inside media content', 40);
                    }
                }

                if (
                    $sample !== '' &&
                    preg_match('/\b(?:eval|assert)\s*\(/i', $sample) &&
                    preg_match('/\b(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(/i', $sample)
                ) {
                    $add('uploads.obfuscated_execution', 'Encoded or obfuscated execution chain detected', 50);
                }
            }

            if ($rules) {
                $finding = self::build_finding($file, 'uploads', 'Media uploads', $rules, $evidence, $score);
                $finding['mime'] = $mime;
                $results[] = $finding;
            }
        }

        if ($progress_callback) $progress_callback($progress_total, $progress_total);
        usort($results, fn($a, $b) => ($b['score'] <=> $a['score']) ?: strcmp($a['relative_path'], $b['relative_path']));
        return $results;
    }

    // Scan WordPress for sensitive files using filename, location, and bounded content evidence
    public static function scan_sensitive_files_root(?callable $progress_callback = null, ?int $progress_total = null) {
        $results = [];
        $base = rtrim(wpauditor_wordpress_root(), '/');
        if (!$base || !is_dir($base)) return $results;

        $iterator = self::get_filtered_iterator($base);
        $progress_total = $progress_total ?? ($progress_callback ? self::count_scannable_files($base) : 0);
        $progress_completed = 0;

        foreach ($iterator as $file) {
            if (!$file->isFile() || $file->isLink()) continue;

            $path = $file->getRealPath();
            if (!$path) continue;

            if ($progress_callback) {
                $progress_callback($progress_completed, $progress_total);
                $progress_completed++;
            }

            $relative = self::relative_path($path);
            $relative_lower = strtolower(wp_normalize_path($relative));
            $filename = strtolower($file->getFilename());
            $ext = strtolower($file->getExtension());
            $rules = [];
            $evidence = [];
            $score = 0;

            $add = static function (string $rule, string $message, int $points) use (&$rules, &$evidence, &$score): void {
                if (in_array($rule, $rules, true)) return;
                $rules[] = $rule;
                $evidence[] = $message;
                $score += $points;
            };

            $is_sample = preg_match('/(?:^|[._-])(?:example|sample|dist)(?:\.|$)/i', $filename) === 1;
            $is_root_level = strpos($relative_lower, '/') === false;
            $is_upload = str_starts_with($relative_lower, 'wp-content/uploads/');

            if (preg_match('/^\.env(?:\..+)?$/i', $filename) && !$is_sample) {
                $add('sensitive.environment_file', 'Environment configuration may expose credentials or secrets', 70);
            }

            if (
                preg_match('#(^|/)\.(?:git|svn|hg)/(?:config|head|index|packed-refs|entries|hgrc)$#i', $relative_lower) ||
                preg_match('#(^|/)\.git/config\.worktree$#i', $relative_lower)
            ) {
                $add('sensitive.vcs_metadata', 'Version-control metadata may disclose repository or deployment information', 70);
            }

            if (
                str_starts_with($filename, 'wp-config') &&
                !in_array($filename, ['wp-config.php', 'wp-config-sample.php'], true)
            ) {
                $add('sensitive.wp_config_backup', 'Unexpected WordPress configuration copy or backup', 75);
            }

            if (preg_match('/\.(?:sql|sql3|sqlite|db)(?:\.(?:gz|zip|bz2|xz))?$/i', $filename)) {
                $add('sensitive.database_dump', 'Database file or dump may expose site data and credentials', 70);
            }

            if (
                preg_match('/\.(?:pem|key|p12|pfx|ppk)$/i', $filename) ||
                preg_match('/^(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)$/i', $filename)
            ) {
                $add('sensitive.private_key', 'Private key or credential container found under the web root', 75);
            }

            if (in_array($filename, ['debug.log', 'error_log', 'php_error.log', '.bash_history', 'passwd', 'shadow'], true)) {
                $add('sensitive.diagnostic_or_system_file', 'Diagnostic or system file may disclose sensitive information', 45);
            }

            if (in_array($filename, ['.user.ini', 'php.ini'], true)) {
                $add('sensitive.runtime_configuration', 'Runtime configuration file is present under the web root', 35);
            }

            if (
                preg_match('/(?:backup|back-up|database|db|dump|site|wordpress|public_html|www)[^\/]*\.(?:zip|tar|tar\.gz|tgz|7z|rar|gz)$/i', $filename) ||
                ($is_root_level && preg_match('/\.(?:zip|tar|tar\.gz|tgz|7z|rar)$/i', $filename))
            ) {
                $add('sensitive.public_archive', 'Backup or source archive may be downloadable from the web root', 35);
            }

            if (
                preg_match('/\.(?:bak|backup|old|orig|save|swp)$/i', $filename) ||
                str_ends_with($filename, '~')
            ) {
                $add('sensitive.backup_copy', 'Backup or editor copy may expose the original file contents', 35);
            }

            $content_candidate = !$is_sample && $filename !== 'wp-config.php' && (
                $rules ||
                $is_root_level ||
                $is_upload ||
                in_array($ext, ['env', 'ini', 'config', 'yml', 'yaml', 'txt', 'log'], true) &&
                preg_match('/secret|credential|private|config|backup|dump|database|env/i', $filename)
            );

            if ($content_candidate) {
                $sample = self::read_sample($path);

                if ($sample !== '' && preg_match('/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i', $sample)) {
                    $add('sensitive.private_key_content', 'Private-key material marker detected without displaying its contents', 75);
                }

                if (
                    $sample !== '' &&
                    preg_match('/\b(?:DB_PASSWORD|AWS_SECRET_ACCESS_KEY|SECRET_KEY|API_KEY|CLIENT_SECRET)\b\s*(?:=|:|,)/i', $sample)
                ) {
                    $add('sensitive.credential_assignment', 'Credential assignment marker detected without displaying its value', 55);
                }

                if ($sample !== '' && preg_match('/define\s*\(\s*[\'\"]DB_PASSWORD[\'\"]/i', $sample)) {
                    $add('sensitive.wordpress_credentials', 'WordPress database credential marker detected in an unexpected file', 60);
                }
            }

            if ($rules && ($is_root_level || $is_upload)) {
                $add('sensitive.exposed_location', 'Finding is in a commonly web-accessible location', 15);
            }

            if ($rules) {
                $location = $is_upload ? 'Media uploads' : ($is_root_level ? 'WordPress root' : 'WordPress installation');
                $results[] = self::build_finding($file, 'sensitive', $location, $rules, $evidence, $score);
            }
        }

        if ($progress_callback) $progress_callback($progress_total, $progress_total);
        usort($results, fn($a, $b) => ($b['score'] <=> $a['score']) ?: strcmp($a['relative_path'], $b['relative_path']));
        return $results;
    }

    // Run one or both forensic detector packs and correlate duplicate paths
    public static function scan_file_forensics(string $scope = 'all', ?callable $progress_callback = null): array {
        $scope = in_array($scope, ['all', 'uploads', 'sensitive'], true) ? $scope : 'all';
        $findings = [];
        $uploads_dir = rtrim(wpauditor_uploads_base_dir(), '/\\');
        $uploads_total = $progress_callback && $uploads_dir !== '' && ($scope === 'all' || $scope === 'uploads')
            ? self::count_scannable_files($uploads_dir)
            : 0;
        $base = rtrim(wpauditor_wordpress_root(), '/');
        $sensitive_total = $progress_callback && ($scope === 'all' || $scope === 'sensitive') && $base
            ? self::count_scannable_files($base)
            : 0;
        $progress_total = $uploads_total + $sensitive_total;
        $progress_offset = 0;

        if ($scope === 'all' || $scope === 'uploads') {
            $uploads_progress = $progress_callback
                ? static function (int $completed) use ($progress_callback, $progress_total): void {
                    $progress_callback($completed, $progress_total);
                }
                : null;
            $findings = array_merge(
                $findings,
                self::scan_suspicious_files_uploads($uploads_progress, $uploads_total)
            );
            $progress_offset = $uploads_total;
        }
        if ($scope === 'all' || $scope === 'sensitive') {
            $sensitive_progress = $progress_callback
                ? static function (int $completed) use ($progress_callback, $progress_offset, $progress_total): void {
                    $progress_callback($progress_offset + $completed, $progress_total);
                }
                : null;
            $findings = array_merge(
                $findings,
                self::scan_sensitive_files_root($sensitive_progress, $sensitive_total)
            );
        }
        if ($progress_callback) $progress_callback($progress_total, $progress_total);

        $correlated = [];
        foreach ($findings as $finding) {
            $key = strtolower(wp_normalize_path((string) ($finding['relative_path'] ?? $finding['path'] ?? '')));
            if ($key === '') continue;

            if (!isset($correlated[$key])) {
                $correlated[$key] = $finding;
                continue;
            }

            $existing = $correlated[$key];
            $existing['detectors'] = array_values(array_unique(array_merge(
                (array) ($existing['detectors'] ?? [$existing['detector'] ?? '']),
                (array) ($finding['detectors'] ?? [$finding['detector'] ?? ''])
            )));
            $existing['detector'] = count($existing['detectors']) > 1 ? 'correlated' : $existing['detectors'][0];
            $existing['rules'] = array_values(array_unique(array_merge((array) $existing['rules'], (array) $finding['rules'])));
            $existing['evidence'] = array_values(array_unique(array_merge((array) $existing['evidence'], (array) $finding['evidence'])));
            $existing['reason'] = implode('; ', $existing['evidence']);
            $existing['score'] = min(100, max((int) $existing['score'], (int) $finding['score']) + 10);
            $existing['severity'] = self::forensic_severity((int) $existing['score']);
            if (($finding['confidence'] ?? '') === 'High') $existing['confidence'] = 'High';
            $existing['finding_id'] = substr(hash('sha256', $key . '|' . implode('|', $existing['rules'])), 0, 24);
            $correlated[$key] = $existing;
        }

        $results = array_values($correlated);
        usort($results, fn($a, $b) => ($b['score'] <=> $a['score']) ?: strcmp($a['relative_path'], $b['relative_path']));

        return $results;
    }

}
