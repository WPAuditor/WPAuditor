<?php
if (!defined('ABSPATH')) exit;

// Versioned request detection rules with stable IDs and confidence scores.
function wpauditor_get_attack_rules(): array {
    return [
        ['id' => 'WPA-SENS-001', 'category' => 'SENSITIVE_FILES', 'confidence' => 82, 'sources' => ['path', 'query'], 'pattern' => '~(?:^|[/?&=])wp-config\.php(?:[.\~_-]?(?:bak|old|orig|save|swp|txt))?(?=$|[/?&#])~i'],
        ['id' => 'WPA-SENS-002', 'category' => 'SENSITIVE_FILES', 'confidence' => 68, 'sources' => ['path', 'query'], 'pattern' => '~(?:^|[/?&=])\.env(?:\.[a-z0-9_.-]+)?(?=$|[/?&#])~i'],
        ['id' => 'WPA-SENS-003', 'category' => 'SENSITIVE_FILES', 'confidence' => 80, 'sources' => ['path', 'query'], 'pattern' => '~(?:^|[/?&=])\.git(?:/|\\\\)(?:HEAD|config|index|packed-refs|objects|refs)(?=$|[/?&#])~i'],
        ['id' => 'WPA-SENS-004', 'category' => 'SENSITIVE_FILES', 'confidence' => 65, 'sources' => ['path', 'query'], 'pattern' => '~(?:^|[/?&=])\.htaccess(?=$|[/?&#])~i'],
        ['id' => 'WPA-SENS-005', 'category' => 'SENSITIVE_FILES', 'confidence' => 88, 'sources' => ['path', 'query', 'form', 'json'], 'pattern' => '~(?:^|[=:\x27"])(?:/|\\\\)etc(?:/|\\\\)(?:passwd|shadow)(?=$|[?&#\x27"])~i'],

        ['id' => 'WPA-SQLI-000', 'category' => 'SQL_INJECTION', 'confidence' => 62, 'sources' => ['query', 'form'], 'pattern' => '~(?:^|[?&])?[a-z0-9_.\[\]-]{1,64}=-?\d{1,20}(?:\.\d{1,12})?[\x27"](?=$|[&#])~i'],
        ['id' => 'WPA-SQLI-001', 'category' => 'SQL_INJECTION', 'confidence' => 78, 'pattern' => '~\b(?:or|and)\s+(\d{1,18})\s*=\s*\1\b~i'],
        ['id' => 'WPA-SQLI-002', 'category' => 'SQL_INJECTION', 'confidence' => 66, 'pattern' => '~\bunion\b\s{1,32}\bselect\b~i'],
        ['id' => 'WPA-SQLI-003', 'category' => 'SQL_INJECTION', 'confidence' => 86, 'pattern' => '~[\x27"]\s*(?:or|and)\s*(?<q>[\x27"])(?<v>[^\x27"]{1,32})\k<q>\s*=\s*\k<q>\k<v>\k<q>~i'],
        ['id' => 'WPA-SQLI-004', 'category' => 'SQL_INJECTION', 'confidence' => 88, 'pattern' => '~(?:\x27|"|\d)\s*;\s*(?:drop|alter|truncate)\s+(?:table|database)\b~i'],
        ['id' => 'WPA-SQLI-005', 'category' => 'SQL_INJECTION', 'confidence' => 83, 'pattern' => '~(?:\b(?:and|or|select|;|case\b)[\s\S]{0,96})\b(?:sleep|benchmark|pg_sleep)\s*\(~i'],
        ['id' => 'WPA-SQLI-006', 'category' => 'SQL_INJECTION', 'confidence' => 90, 'pattern' => '~\bwaitfor\s+delay\s+[\x27"]\d{1,2}:\d{1,2}:\d{1,2}[\x27"]~i'],
        ['id' => 'WPA-SQLI-007', 'category' => 'SQL_INJECTION', 'confidence' => 88, 'pattern' => '~\b(?:extractvalue|updatexml)\s*\([^)]{0,256}(?:concat\s*\(|0x[0-9a-f]{4,})~i'],
        ['id' => 'WPA-SQLI-008', 'category' => 'SQL_INJECTION', 'confidence' => 84, 'pattern' => '~\b(?:from|join)\s+information_schema\.~i'],
        ['id' => 'WPA-SQLI-009', 'category' => 'SQL_INJECTION', 'confidence' => 90, 'pattern' => '~\bload_file\s*\(\s*(?:0x[0-9a-f]+|[\x27"])~i'],
        ['id' => 'WPA-SQLI-010', 'category' => 'SQL_INJECTION', 'confidence' => 92, 'pattern' => '~\binto\s+(?:out|dump)file\b~i'],
        ['id' => 'WPA-SQLI-011', 'category' => 'SQL_INJECTION', 'confidence' => 84, 'pattern' => '~\/\*!\d{4,6}\s+(?:union|select)\b~i'],
        ['id' => 'WPA-SQLI-012', 'category' => 'SQL_INJECTION', 'confidence' => 75, 'pattern' => '~\b(?:char|chr)\s*\(\s*\d{1,3}(?:\s*,\s*\d{1,3}){2,}\s*\)~i'],
        ['id' => 'WPA-SQLI-013', 'category' => 'SQL_INJECTION', 'confidence' => 72, 'pattern' => '~\b(?:or|and)\s+(?:-?\d{1,18}\s*(?:<>|!=|<=|>=|=|<|>)\s*-?\d{1,18}|true\b|false\b)~i'],
        ['id' => 'WPA-SQLI-014', 'category' => 'SQL_INJECTION', 'confidence' => 92, 'pattern' => '~\bdbms_pipe\s*\.\s*receive_message\s*\([^)]{0,256}\)~i'],
        ['id' => 'WPA-SQLI-015', 'category' => 'SQL_INJECTION', 'confidence' => 86, 'pattern' => '~\bselect\b[\s\S]{0,128}?(?:@@version\b|\bversion\s*\(|\bbanner\b[\s\S]{0,64}\bfrom\s+v\$version\b|\bversion\b[\s\S]{0,64}\bfrom\s+v\$instance\b)~i'],
        ['id' => 'WPA-SQLI-016', 'category' => 'SQL_INJECTION', 'confidence' => 84, 'pattern' => '~\bselect\b[\s\S]{0,256}?\bfrom\s+(?:all_tables|all_tab_columns|user_tables|user_tab_columns)\b~i'],
        ['id' => 'WPA-SQLI-017', 'category' => 'SQL_INJECTION', 'confidence' => 90, 'pattern' => '~\bcase\s+when\b[\s\S]{1,256}?\bthen\b[\s\S]{0,128}?(?:1\s*\/\s*0|to_char\s*\(\s*1\s*\/\s*0\s*\)|cast\s*\(\s*\(?\s*select\b)~i'],
        ['id' => 'WPA-SQLI-018', 'category' => 'SQL_INJECTION', 'confidence' => 88, 'pattern' => '~\b(?:cast|convert)\s*\(\s*\(?\s*select\b[\s\S]{0,256}?(?:\bas\s+(?:int|integer|numeric)\b|,\s*(?:int|integer|numeric)\b)~i'],
        ['id' => 'WPA-SQLI-019', 'category' => 'SQL_INJECTION', 'confidence' => 94, 'pattern' => '~\b(?:utl_inaddr\s*\.\s*get_host_address|xp_dirtree|xp_fileexist|xp_subdirs)\b~i'],
        ['id' => 'WPA-SQLI-020', 'category' => 'SQL_INJECTION', 'confidence' => 95, 'pattern' => '~\bcopy\b[\s\S]{1,512}?\bto\s+program\s+[\x27"]~i'],
        ['id' => 'WPA-SQLI-021', 'category' => 'SQL_INJECTION', 'confidence' => 88, 'pattern' => '~;\s*(?:declare\s+@[a-z_]|exec(?:ute)?\s+(?:master\s*\.\s*\.|xp_|sp_)|select\b[\s\S]{0,128}?\bfrom\b|insert\s+into\b|update\s+[a-z0-9_.\[\]`]+\s+set\b|delete\s+from\b|create\s+(?:table|function|procedure)\b)~i'],
        ['id' => 'WPA-SQLI-022', 'category' => 'SQL_INJECTION', 'confidence' => 72, 'sources' => ['query', 'form', 'json'], 'pattern' => '~[\x27"]\s*(?:--[\x20\x09]*(?:$|[&#])|#[\x20\x09]*(?:$|[&#]))~'],
        ['id' => 'WPA-SQLI-023', 'category' => 'SQL_INJECTION', 'confidence' => 86, 'pattern' => '~[\x27"]\s*(?:or|and)\s*(?<q>[\x27"])(?<v>[^\x27"]{1,32})\k<q>\s+like\s+\k<q>\k<v>\k<q>~i'],
        ['id' => 'WPA-SQLI-024', 'category' => 'SQL_INJECTION', 'confidence' => 89, 'pattern' => '~\bif\s*\([^)]{1,192},\s*(?:sleep|benchmark)\s*\(~i'],
        ['id' => 'WPA-SQLI-025', 'category' => 'SQL_INJECTION', 'confidence' => 94, 'pattern' => '~\bextractvalue\s*\(\s*xmltype\s*\([\s\S]{0,512}?(?:https?\s*:|utl_inaddr\s*\.)~i'],

        ['id' => 'WPA-XSS-001', 'category' => 'XSS', 'confidence' => 90, 'pattern' => '~<script\b[^>]{0,1024}>~i'],
        ['id' => 'WPA-XSS-002', 'category' => 'XSS', 'confidence' => 88, 'pattern' => '~<(?:svg|math)\b[\s\S]{0,2048}?(?:\s|/)on[a-z][a-z0-9_-]{1,48}\s*=~i'],
        ['id' => 'WPA-XSS-003', 'category' => 'XSS', 'confidence' => 86, 'pattern' => '~<[a-z][a-z0-9:-]{0,63}\b[^>]{0,1024}(?:\s|/)on[a-z][a-z0-9_-]{1,48}\s*=~i'],
        ['id' => 'WPA-XSS-004', 'category' => 'XSS', 'confidence' => 87, 'pattern' => '~<iframe\b[^>]{0,1024}\b(?:srcdoc|src)\s*=\s*[\x27"]?\s*(?:<|javascript\s*:|data\s*:)~i'],
        ['id' => 'WPA-XSS-005', 'category' => 'XSS', 'confidence' => 82, 'pattern' => '~\bsrcdoc\s*=\s*[\x27"]?[^>]{0,512}<~i'],
        ['id' => 'WPA-XSS-006', 'category' => 'XSS', 'confidence' => 60, 'pattern' => '~j[\x00-\x20]*a[\x00-\x20]*v[\x00-\x20]*a[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:[\x00-\x20]*(?:alert|confirm|prompt|eval|fetch|document\.|window\.|location\b|[a-z_$][\w$]*\s*\()~i'],
        ['id' => 'WPA-XSS-007', 'category' => 'XSS', 'confidence' => 78, 'pattern' => '~<(?:object|embed)\b[^>]{0,1024}\b(?:data|src)\s*=~i'],
        ['id' => 'WPA-XSS-008', 'category' => 'XSS', 'confidence' => 84, 'pattern' => '~<[a-z][a-z0-9:-]{0,63}\b[^>]{0,1024}\b(?:href|xlink:href|src|action|formaction|poster|background)\s*=\s*[\x27"]?\s*data\s*:\s*text\s*/\s*(?:html|javascript|ecmascript)\b~i'],
        ['id' => 'WPA-XSS-009', 'category' => 'XSS', 'confidence' => 89, 'pattern' => '~<(?:script|iframe|object|embed)\b[^>]{0,1024}\b(?:src|data)\s*=\s*[\x27"]?\s*data\s*:\s*(?:text\s*/\s*(?:html|javascript|ecmascript)|image\s*/\s*svg\+xml)\b~i'],
        ['id' => 'WPA-XSS-010', 'category' => 'XSS', 'confidence' => 86, 'pattern' => '~<meta\b(?=[^>]{0,1024}\bhttp-equiv\s*=\s*[\x27"]?\s*refresh\b)(?=[^>]{0,1024}\bcontent\s*=\s*[\x27"]?[^>]{0,512}(?:javascript\s*:|data\s*:\s*text\s*/\s*html\b))[^>]{0,1024}>~i'],

        ['id' => 'WPA-RCE-001', 'category' => 'REMOTE_CODE_EXECUTION', 'confidence' => 94, 'pattern' => '~\b(?:shell_exec|system|passthru|exec)\s*\(\s*(?:[\x27"]|(?:base64_decode|urldecode)\s*\()~i'],
        ['id' => 'WPA-RCE-002', 'category' => 'REMOTE_CODE_EXECUTION', 'confidence' => 96, 'pattern' => '~\b(?:include|require)(?:_once)?\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[~i'],
        ['id' => 'WPA-RCE-003', 'category' => 'REMOTE_CODE_EXECUTION', 'confidence' => 96, 'pattern' => '~\bassert\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[~i'],
        ['id' => 'WPA-RCE-004', 'category' => 'REMOTE_CODE_EXECUTION', 'confidence' => 96, 'pattern' => '~\b(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|urldecode)\s*\(~i'],
        ['id' => 'WPA-RCE-005', 'category' => 'REMOTE_CODE_EXECUTION', 'confidence' => 88, 'sources' => ['query', 'form', 'json'], 'pattern' => '~(?:^|[?&])?(?:cmd|exec|command|shell)=[^&]{0,256}(?:;|&&|\|\||\$\(|\x60|\b(?:id|whoami|uname|cat|curl|wget)\b)~i'],

        ['id' => 'WPA-LFI-001', 'category' => 'LFI_RFI', 'confidence' => 58, 'sources' => ['path', 'query', 'form', 'json'], 'pattern' => '~\.\.(?:/|\\\\)~'],
        ['id' => 'WPA-LFI-002', 'category' => 'LFI_RFI', 'confidence' => 92, 'pattern' => '~\bphp://(?:input|filter|fd|memory|temp)\b~i'],
        ['id' => 'WPA-LFI-003', 'category' => 'LFI_RFI', 'confidence' => 90, 'pattern' => '~\b(?:zip|phar)://[^\s]+~i'],
        ['id' => 'WPA-LFI-004', 'category' => 'LFI_RFI', 'confidence' => 94, 'pattern' => '~(?:^|[=:\x27"])(?:/|\\\\)(?:etc(?:/|\\\\)(?:passwd|shadow)|windows(?:/|\\\\)win\.ini)(?=$|[?&#\x27"])~i'],
        ['id' => 'WPA-LFI-005', 'category' => 'LFI_RFI', 'confidence' => 88, 'enforcement' => 'block', 'sources' => ['path', 'query', 'form', 'json'], 'pattern' => '~(?:\.\.(?:/|\\\\)){1,16}[^?&#\x00]{0,512}(?:wp-config\.php|(?:etc(?:/|\\\\)(?:passwd|shadow|hosts))|(?:windows(?:/|\\\\)(?:win\.ini|system32(?:/|\\\\)drivers(?:/|\\\\)etc(?:/|\\\\)hosts)))\x00?~i'],
        ['id' => 'WPA-LFI-006', 'category' => 'LFI_RFI', 'confidence' => 91, 'enforcement' => 'block', 'sources' => ['path', 'query', 'form', 'json'], 'pattern' => '~\b(?:expect|data)://[^\s?&#]{0,512}~i'],
        ['id' => 'WPA-LFI-007', 'category' => 'LFI_RFI', 'confidence' => 84, 'enforcement' => 'score', 'sources' => ['path', 'query', 'form', 'json'], 'pattern' => '~(?:^|[=:\x27"])(?:[a-z]:\\\\|\\\\\\\\)(?:windows\\\\(?:win\.ini|system\.ini)|inetpub\\\\wwwroot\\\\web\.config|users\\\\[^\\\\?&#\x27"]{1,64}\\\\\.ssh\\\\(?:id_rsa|authorized_keys))(?=$|[?&#\x27"])~i'],

        ['id' => 'WPA-CMDI-001', 'category' => 'COMMAND_INJECTION', 'confidence' => 90, 'pattern' => '~(?:;|&&|\|\||\$\(|%0[ad]|[\r\n])\s*(?:/[a-z0-9_./-]+/)?(?:id|whoami|uname|cat|head|tail|ls|curl|wget|nc|bash|sh|powershell|cmd)(?:\s|%20|\)|$)~i'],
        ['id' => 'WPA-CMDI-002', 'category' => 'COMMAND_INJECTION', 'confidence' => 90, 'pattern' => '~\x60\s*(?:id|whoami|uname|cat|curl|wget)\b[^\x60]{0,256}\x60~i'],
        ['id' => 'WPA-CMDI-003', 'category' => 'COMMAND_INJECTION', 'confidence' => 88, 'enforcement' => 'score', 'pattern' => '~(?:;|&&|\|\||\$\()[\x20\t]*(?:\$\{?IFS\}?|\$IFS\$[0-9])[^\r\n]{0,64}\b(?:id|whoami|uname|cat|curl|wget|nslookup|ping|bash|sh)\b~i'],
        ['id' => 'WPA-CMDI-004', 'category' => 'COMMAND_INJECTION', 'confidence' => 91, 'enforcement' => 'block', 'pattern' => '~(?:&|\||\r|\n)\s*(?:(?:cmd(?:\.exe)?\s*/c)|(?:powershell(?:\.exe)?(?:\s+-[a-z]+){1,4})|(?:certutil(?:\.exe)?\s+-urlcache)|(?:bitsadmin(?:\.exe)?\s+/transfer))\b~i'],
        ['id' => 'WPA-CMDI-005', 'category' => 'COMMAND_INJECTION', 'confidence' => 86, 'enforcement' => 'score', 'pattern' => '~(?:;|&&|\|\||\$\(|\x60|[\r\n])\s*(?:nslookup|dig|host|ping)\b[^\r\n;&|]{0,192}(?:[a-z0-9-]+\.)+[a-z]{2,63}\b~i'],

        ['id' => 'WPA-OBF-001', 'category' => 'OBFUSCATION_ENCODING', 'confidence' => 90, 'pattern' => '~\b(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(~i'],
        ['id' => 'WPA-OBF-002', 'category' => 'OBFUSCATION_ENCODING', 'confidence' => 88, 'pattern' => '~\bbase64_decode\s*\([^)]{1,512}\)\s*;?\s*(?:eval|assert)\b~i'],
        ['id' => 'WPA-OBF-003', 'category' => 'OBFUSCATION_ENCODING', 'confidence' => 92, 'pattern' => '~\b(?:gzinflate|gzuncompress)\s*\(\s*base64_decode\s*\(~i'],

        ['id' => 'WPA-RECON-001', 'category' => 'TOOL_FINGERPRINTS', 'confidence' => 52, 'sources' => ['path'], 'pattern' => '~(?:^|/)phpmyadmin(?:/|$|[?&#])~i'],
        ['id' => 'WPA-RECON-002', 'category' => 'TOOL_FINGERPRINTS', 'confidence' => 52, 'sources' => ['path'], 'pattern' => '~(?:^|/)adminer(?:\.php)?(?:/|$|[?&#])~i'],
        ['id' => 'WPA-RECON-003', 'category' => 'TOOL_FINGERPRINTS', 'confidence' => 48, 'sources' => ['path'], 'pattern' => '~/console/(?:login|app|config|server|terminal)?~i'],
        ['id' => 'WPA-WP-001', 'category' => 'WORDPRESS_EXPLOITS', 'confidence' => 88, 'sources' => ['query', 'form'], 'pattern' => '~(?:^|[?&])?action=revslider_ajax_action(?:&|$)~i'],
        ['id' => 'WPA-WP-RECON-001', 'category' => 'WORDPRESS_RECON', 'confidence' => 45, 'sources' => ['query'], 'pattern' => '~(?:^|[?&])?rest_route=/?wp/v2/users(?:/|&|$)~i'],
        ['id' => 'WPA-WP-RECON-002', 'category' => 'WORDPRESS_RECON', 'confidence' => 45, 'sources' => ['path'], 'pattern' => '~(?:^|/)wp-json/wp/v2/users(?:/|$|[?&#])~i'],

        ['id' => 'WPA-UPLOAD-001', 'category' => 'SUSPICIOUS_UPLOADS', 'confidence' => 94, 'sources' => ['upload_filename'], 'pattern' => '~(?:^|[.])(?:php\d?|pht|phtml|phar)(?:\x00)?$~i'],
        ['id' => 'WPA-UPLOAD-002', 'category' => 'SUSPICIOUS_UPLOADS', 'confidence' => 96, 'sources' => ['upload_filename'], 'pattern' => '~\.(?:php\d?|pht|phtml|phar)(?:\x00)?\.(?:jpe?g|png|gif|webp|svg|bmp|ico)$~i'],
        ['id' => 'WPA-UPLOAD-003', 'category' => 'SUSPICIOUS_UPLOADS', 'confidence' => 95, 'sources' => ['upload_filename'], 'pattern' => '~\.(?:php\d?|pht|phtml|phar)(?:;|%3b)[^/\\\\]*$~i'],
        ['id' => 'WPA-UPLOAD-004', 'category' => 'SUSPICIOUS_UPLOADS', 'confidence' => 92, 'enforcement' => 'block', 'sources' => ['upload_filename'], 'pattern' => '~(?:^|[/\\\\])(?:\.htaccess|\.user\.ini|web\.config)$~i'],

        ['id' => 'WPA-PHP-OBJ-001', 'category' => 'PHP_OBJECT_INJECTION', 'confidence' => 82, 'sources' => ['query', 'form', 'json', 'raw_body'], 'pattern' => '~(?:^|[=;{}])O:\d{1,7}:"[A-Za-z_\\\\][A-Za-z0-9_\\\\]{0,255}":\d{1,7}:\{~'],
        ['id' => 'WPA-PHP-OBJ-002', 'category' => 'PHP_OBJECT_INJECTION', 'confidence' => 84, 'enforcement' => 'score', 'sources' => ['query', 'form', 'json', 'raw_body'], 'pattern' => '~(?:^|[=;{}])C:\d{1,7}:"[A-Za-z_\\\\][A-Za-z0-9_\\\\]{0,255}":\d{1,9}:\{~'],
        ['id' => 'WPA-XXE-001', 'category' => 'XXE', 'confidence' => 88, 'sources' => ['raw_body', 'form'], 'pattern' => '~<!DOCTYPE\s+[^>]{0,512}\[?[^>]{0,1024}<!ENTITY\s+(?:%\s*)?[^>]{0,512}\bSYSTEM\s+[\x27"]\s*(?:[a-z][a-z0-9+.-]{1,15}\s*:|\\\\|//)~i'],
        ['id' => 'WPA-XXE-002', 'category' => 'XXE', 'confidence' => 88, 'sources' => ['raw_body', 'form'], 'pattern' => '~<!DOCTYPE\s+[a-z_][a-z0-9_.:-]{0,127}\s+(?:SYSTEM\s+[\x27"]\s*(?:[a-z][a-z0-9+.-]{1,15}\s*:|\\\\|//)|PUBLIC\s+[\x27"][^\x27"]{0,256}[\x27"]\s+[\x27"]\s*(?:[a-z][a-z0-9+.-]{1,15}\s*:|\\\\|//))~i'],
        ['id' => 'WPA-XXE-003', 'category' => 'XXE', 'confidence' => 89, 'sources' => ['raw_body', 'form'], 'pattern' => '~<!ENTITY\s+(?:%\s*)?[a-z_][a-z0-9_.:-]{0,127}\s+PUBLIC\s+[\x27"][^\x27"]{0,256}[\x27"]\s+[\x27"]\s*(?:[a-z][a-z0-9+.-]{1,15}\s*:|\\\\|//)~i'],
        ['id' => 'WPA-XXE-004', 'category' => 'XXE', 'confidence' => 87, 'sources' => ['raw_body', 'form'], 'pattern' => '~<[a-z_][a-z0-9_.-]{0,31}:include\b[^>]{0,1024}\bhref\s*=\s*[\x27"]\s*(?:[a-z][a-z0-9+.-]{1,15}\s*:|\\\\|//)[^>]{0,1024}>~i'],
        ['id' => 'WPA-XXE-005', 'category' => 'XXE', 'confidence' => 84, 'sources' => ['raw_body', 'form'], 'pattern' => '~\b(?:xsi:)?(?:schemaLocation|noNamespaceSchemaLocation)\s*=\s*[\x27"][^\x27"]{0,512}(?:(?:file|php|gopher|ftp)\s*:|https?\s*://\s*(?:localhost\b|127(?:\.\d{1,3}){3}\b|169\.254\.169\.254\b|10(?:\.\d{1,3}){3}\b|192\.168(?:\.\d{1,3}){2}\b|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}\b|\[?::1\]?))~i'],
    ];
}

// Keep the original grouped pattern contract for extensions and older callers.
function wpauditor_get_suspicious_patterns_grouped(): array {
    $grouped = [];
    foreach (wpauditor_get_attack_rules() as $rule) {
        $grouped[$rule['category']][] = $rule['pattern'];
    }
    return $grouped;
}
