<?php
class ZS_Config {
    const DEFAULT_GEMINI_MODEL = 'gemini-2.5-flash';
    const REDACTION_VERSION = 'redact_v2';
    const PROMPT_VERSION = 'prompt_v2';
    const MAX_SCAN_BYTES = 2097152;
    const JSON_SAFE = 315; // JSON_HEX_TAG|HEX_AMP|HEX_APOS|HEX_QUOT (15) + UNESCAPED_UNICODE (256) + INVALID_UTF8_SUBSTITUTE (1048576) applied at runtime

    public static $keyCooldowns = array();

    public static function jsonFlags() {
        $flags = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT;
        if (defined('JSON_UNESCAPED_UNICODE')) {
            $flags |= JSON_UNESCAPED_UNICODE;
        }
        if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
            $flags |= JSON_INVALID_UTF8_SUBSTITUTE;
        }
        return $flags;
    }

    public static function envelopeGuard() {
        return "<?php if (!defined('ZS_INTERNAL')) { http_response_code(403); header('Content-Type: text/plain; charset=UTF-8'); header('Cache-Control: no-store'); exit('Access Denied'); } ?>\n";
    }

    public static function sampleStub() {
        return "<?php http_response_code(403); header('Content-Type: text/plain; charset=UTF-8'); header('Cache-Control: no-store'); exit('Access Denied'); __HALT_COMPILER();\n";
    }

    public static function ensureUtf8($str) {
        if (!is_string($str) || $str === '') {
            return '';
        }
        if (function_exists('mb_check_encoding') && @mb_check_encoding($str, 'UTF-8')) {
            return $str;
        }
        if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
            $encoded = @json_encode($str, JSON_INVALID_UTF8_SUBSTITUTE);
            if ($encoded !== false) {
                $decoded = @json_decode($encoded);
                if (is_string($decoded)) {
                    return $decoded;
                }
            }
        }
        if (function_exists('mb_convert_encoding')) {
            return @mb_convert_encoding($str, 'UTF-8', 'UTF-8');
        }
        if (function_exists('iconv')) {
            $cleaned = @iconv('UTF-8', 'UTF-8//IGNORE', $str);
            if ($cleaned !== false) {
                return $cleaned;
            }
        }
        return $str;
    }

    public static function wrapJson($data) {
        $flags = JSON_UNESCAPED_SLASHES;
        if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
            $flags |= JSON_INVALID_UTF8_SUBSTITUTE;
        }
        $json = @json_encode($data, $flags);
        if ($json === false) {
            return false;
        }
        return self::envelopeGuard() . $json;
    }

    public static function unwrapJson($raw) {
        if (!is_string($raw) || $raw === '') {
            return null;
        }
        if (strpos($raw, '<?php') === 0) {
            $end = strpos($raw, "?>\n");
            if ($end === false) {
                $end = strpos($raw, '?>');
                if ($end === false) {
                    return null;
                }
                $raw = substr($raw, $end + 2);
                if (isset($raw[0]) && ($raw[0] === "\n" || $raw[0] === "\r")) {
                    $raw = ltrim($raw, "\r\n");
                }
            } else {
                $raw = substr($raw, $end + 3);
            }
        }
        $data = json_decode($raw, true);
        return is_array($data) ? $data : null;
    }

    public static function extractSamplePayload($raw) {
        if (!is_string($raw) || $raw === '') {
            return false;
        }
        $marker = '__HALT_COMPILER();';
        $pos = strpos($raw, $marker);
        if ($pos === false) {
            return false;
        }
        $start = $pos + strlen($marker);
        if (isset($raw[$start]) && $raw[$start] === "\r") {
            $start++;
        }
        if (isset($raw[$start]) && $raw[$start] === "\n") {
            $start++;
        }
        if (substr($raw, $start, 2) === '?>') {
            $start += 2;
            if (isset($raw[$start]) && ($raw[$start] === "\r" || $raw[$start] === "\n")) {
                $start++;
            }
            if (isset($raw[$start]) && $raw[$start] === "\n") {
                $start++;
            }
        }
        return substr($raw, $start);
    }

    public static function secureMkdir($dir) {
        if ($dir === '' || $dir === null) {
            return false;
        }
        if (is_dir($dir)) {
            @chmod($dir, 0700);
            return is_writable($dir);
        }
        if (!@mkdir($dir, 0700, true) && !is_dir($dir)) {
            return false;
        }
        @chmod($dir, 0700);
        return is_dir($dir) && is_writable($dir);
    }

    public static function atomicWrite($path, $contents, $mode = 0600) {
        $dir = dirname($path);
        if (!self::secureMkdir($dir)) {
            return false;
        }
        $tmp = $dir . '/.tmp_' . bin2hex(random_bytes(6)) . '.php';
        $n = @file_put_contents($tmp, $contents);
        if ($n === false || $n !== strlen($contents)) {
            @unlink($tmp);
            return false;
        }
        @chmod($tmp, $mode);
        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            return false;
        }
        @chmod($path, $mode);
        return true;
    }

    /**
     * Publish a new file without ever replacing an existing destination.
     *
     * Restore paths have already had their parents checked/created by
     * ZS_Quarantine.  Unlike atomicWrite(), this intentionally does not call
     * secureMkdir(): changing permissions on a site's existing directory while
     * restoring one file would be an unexpected and harmful side effect.
     */
    public static function atomicWriteNew($path, $contents, $mode = 0644) {
        $dir = dirname($path);
        if (!is_dir($dir) || @is_link($dir) || !is_writable($dir)) {
            return false;
        }
        $length = strlen($contents);

        // 1. Prefer link() from a temporary file for atomic destination creation
        // without replacing any existing destination.
        if (function_exists('link')) {
            $tmp = $dir . '/.zs_restore_' . bin2hex(random_bytes(12)) . '.tmp';
            $fp = @fopen($tmp, 'x');
            if ($fp) {
                $written = 0;
                $ok = true;
                while ($written < $length) {
                    $n = @fwrite($fp, substr($contents, $written));
                    if ($n === false || $n === 0) {
                        $ok = false;
                        break;
                    }
                    $written += $n;
                }
                if (!@fflush($fp)) {
                    $ok = false;
                }
                @fclose($fp);
                if ($ok && $written === $length) {
                    @chmod($tmp, $mode);
                    if (@link($tmp, $path)) {
                        @chmod($path, $mode);
                        @unlink($tmp);
                        return true;
                    }
                    // If link failed because destination was created concurrently, do not overwrite.
                    if (file_exists($path) || is_link($path)) {
                        @unlink($tmp);
                        return false;
                    }
                }
                @unlink($tmp);
            }
        }

        // 2. Fallback for environments where link() is disabled in disable_functions
        // or unsupported by the filesystem (e.g. Windows, FAT32, NFS, or shared hosting):
        // fopen('xb') uses POSIX O_CREAT | O_EXCL, which atomically creates the file
        // and fails if it already exists.
        if (file_exists($path) || is_link($path)) {
            return false;
        }
        $fp = @fopen($path, 'xb');
        if (!$fp) {
            return false;
        }
        $written = 0;
        $ok = true;
        while ($written < $length) {
            $n = @fwrite($fp, substr($contents, $written));
            if ($n === false || $n === 0) {
                $ok = false;
                break;
            }
            $written += $n;
        }
        if (!@fflush($fp)) {
            $ok = false;
        }
        @fclose($fp);
        if (!$ok || $written !== $length) {
            @unlink($path);
            return false;
        }
        @chmod($path, $mode);
        return true;
    }

    public static function getRoot() {
        if (defined('ZS_ROOT_DIR') && ZS_ROOT_DIR) {
            return rtrim(ZS_ROOT_DIR, '/\\');
        }
        return defined('ABSPATH') ? rtrim(ABSPATH, '/\\') : dirname(__FILE__);
    }

    public static function getDataDir($rootDir = null) {
        if ($rootDir === null) {
            $rootDir = self::getRoot();
        }
        $envData = getenv('MALWARE_CLEANER_DATA_DIR');
        if (is_string($envData) && $envData !== '') {
            return rtrim($envData, '/\\');
        }

        $realRoot = realpath($rootDir);
        $parent = $realRoot ? @realpath(dirname($realRoot)) : false;
        if ($parent && $realRoot && $parent !== $realRoot && is_writable($parent) && !self::isPathWithinRoot($parent, $realRoot)) {
            $suffix = substr(hash('sha256', $realRoot), 0, 12);
            return $parent . '/.zsdata_' . $suffix;
        }

        return rtrim($rootDir, '/\\') . '/malware_cleaner_data';
    }

    public static function denyAllHtaccess() {
        return "<IfModule mod_authz_core.c>\n  Require all denied\n</IfModule>\n"
            . "<IfModule !mod_authz_core.c>\n  Deny from all\n</IfModule>\n"
            . "Options -Indexes\n";
    }

    public static function initDataDir($dataDir) {
        if (!self::secureMkdir($dataDir)) {
            return false;
        }

        $htaccessFile = $dataDir . '/.htaccess';
        if (!file_exists($htaccessFile)) {
            self::atomicWrite($htaccessFile, self::denyAllHtaccess(), 0644);
        }

        $indexFile = $dataDir . '/index.php';
        if (!file_exists($indexFile)) {
            self::atomicWrite($indexFile, "<?php http_response_code(403); header('Cache-Control: no-store'); exit('Access Denied');\n", 0644);
        }

        return is_dir($dataDir) && is_writable($dataDir);
    }

    public static function getQuarantineDir($rootDir = null, $dataDir = null) {
        if ($rootDir === null) {
            $rootDir = self::getRoot();
        }
        if ($dataDir === null) {
            $dataDir = self::getDataDir($rootDir);
        }

        $quarantine = rtrim($dataDir, '/\\') . '/quarantine';
        self::initDataDir($dataDir);
        self::secureMkdir($quarantine);

        $htaccessFile = $quarantine . '/.htaccess';
        if (!file_exists($htaccessFile)) {
            self::atomicWrite($htaccessFile, self::denyAllHtaccess(), 0644);
        }
        $indexFile = $quarantine . '/index.php';
        if (!file_exists($indexFile)) {
            self::atomicWrite($indexFile, "<?php http_response_code(403); header('Cache-Control: no-store'); exit('Access Denied');\n", 0644);
        }

        return $quarantine;
    }

    public static function isPathWithinRoot($path, $rootDir) {
        $realPath = realpath($path);
        $realRoot = realpath($rootDir);
        if (!$realPath || !$realRoot) {
            return false;
        }
        $rootPrefix = rtrim(str_replace('\\', '/', $realRoot), '/') . '/';
        $pathNorm   = str_replace('\\', '/', $realPath);
        return ($pathNorm === rtrim($rootPrefix, '/') || strpos($pathNorm, $rootPrefix) === 0);
    }

    public static function canonicalizeWithinRoot($path, $rootDir) {
        $realRoot = realpath($rootDir);
        if ($realRoot === false) {
            return false;
        }
        $rootNorm = rtrim(str_replace('\\', '/', $realRoot), '/');
        $path = str_replace('\\', '/', (string)$path);
        if ($path === '') {
            return false;
        }

        $isAbs = ($path[0] === '/' || (bool)preg_match('#^[A-Za-z]:(/|$)#', $path));
        if (!$isAbs) {
            $path = $rootNorm . '/' . ltrim($path, '/');
        }

        $resolved = self::resolveDotSegments($path);
        $resolvedCmp = rtrim($resolved, '/');
        if ($resolvedCmp === $rootNorm) {
            return $resolvedCmp;
        }
        if (strpos($resolvedCmp . '/', $rootNorm . '/') === 0) {
            return $resolved;
        }

        $rawRootNorm = rtrim(str_replace('\\', '/', (string)$rootDir), '/');
        if ($rawRootNorm !== '' && ($resolvedCmp === $rawRootNorm || strpos($resolvedCmp . '/', $rawRootNorm . '/') === 0)) {
            $rel = substr($resolvedCmp, strlen($rawRootNorm));
            $mapped = self::resolveDotSegments($rootNorm . '/' . ltrim($rel, '/'));
            $mappedCmp = rtrim($mapped, '/');
            if ($mappedCmp === $rootNorm || strpos($mappedCmp . '/', $rootNorm . '/') === 0) {
                return $mapped;
            }
        }
        return false;
    }

    private static function resolveDotSegments($path) {
        $path = str_replace('\\', '/', $path);
        $prefix = '';
        if (preg_match('#^([A-Za-z]:)(/.*)$#', $path, $m)) {
            $prefix = $m[1];
            $path = $m[2];
        }
        $parts = array();
        foreach (explode('/', $path) as $seg) {
            if ($seg === '' || $seg === '.') {
                continue;
            }
            if ($seg === '..') {
                array_pop($parts);
                continue;
            }
            $parts[] = $seg;
        }
        $out = $prefix . '/' . implode('/', $parts);
        if ($out === '' || $out === $prefix . '/') {
            return $prefix === '' ? '/' : ($prefix . '/');
        }
        return $out;
    }

    public static function pathHasSymlink($path, $rootDir = null) {
        if (!is_string($path) || $path === '') {
            return true;
        }
        if (@is_link($path)) {
            return true;
        }
        if ($rootDir === null) {
            return false;
        }
        $realRoot = realpath($rootDir);
        if ($realRoot === false) {
            return true;
        }
        $rootN = rtrim(str_replace('\\', '/', $realRoot), '/');
        $realPath = file_exists($path) ? realpath($path) : false;
        if ($realPath) {
            $pathN = str_replace('\\', '/', $realPath);
            if ($pathN === $rootN) {
                return false;
            }
            if (strpos($pathN . '/', $rootN . '/') !== 0) {
                return true;
            }
            $rel = substr($pathN, strlen($rootN));
            $walk = $rootN;
            foreach (explode('/', $rel) as $part) {
                if ($part === '') {
                    continue;
                }
                $walk .= '/' . $part;
                if (@is_link($walk)) {
                    return true;
                }
            }
            return false;
        }
        $canon = self::canonicalizeWithinRoot($path, $rootDir);
        if ($canon === false) {
            return true;
        }
        $parent = dirname($canon);
        while ($parent !== $rootN && strlen($parent) > strlen($rootN)) {
            if (@is_link($parent)) {
                return true;
            }
            $next = dirname($parent);
            if ($next === $parent) {
                break;
            }
            $parent = $next;
        }
        return false;
    }

    public static function isRegularFile($path) {
        if (!is_string($path) || $path === '') {
            return false;
        }
        if (@is_link($path)) {
            return false;
        }
        $st = @lstat($path);
        if (!$st) {
            return false;
        }
        return is_file($path) && (($st['mode'] & 0170000) === 0100000);
    }

    public static function isProtectedPath($path, $rootDir, $dataDir = null) {
        $real = realpath($path);
        $check = $real ? $real : $path;
        $base = basename($check);

        if ($base === 'wp-config.php' || $base === 'zs-setup.secret' || $base === 'malware-cleaner.php') {
            return true;
        }

        $script = isset($_SERVER['SCRIPT_FILENAME']) ? realpath($_SERVER['SCRIPT_FILENAME']) : false;
        if ($script && $real && $real === $script) {
            return true;
        }
        $self = realpath(__FILE__);
        if ($self && $real && $real === $self) {
            return true;
        }

        if ($dataDir === null) {
            $dataDir = self::getDataDir($rootDir);
        }
        $realData = realpath($dataDir);
        $checkData = $realData ? $realData : $dataDir;
        $dataPrefix = rtrim(str_replace('\\', '/', $checkData), '/') . '/';
        $pathNorm = str_replace('\\', '/', $check);
        if ($pathNorm === rtrim($dataPrefix, '/') || strpos($pathNorm . '/', $dataPrefix) === 0) {
            return true;
        }
        if ($real && $realData) {
            $realPathNorm = str_replace('\\', '/', $real);
            if ($realPathNorm === rtrim($dataPrefix, '/') || strpos($realPathNorm . '/', $dataPrefix) === 0) {
                return true;
            }
        }
        $canon = self::canonicalizeWithinRoot($check, $rootDir);
        $dataCanon = self::canonicalizeWithinRoot($dataDir, $rootDir);
        if ($canon && $dataCanon && (strpos($canon . '/', rtrim($dataCanon, '/') . '/') === 0 || $canon === $dataCanon)) {
            return true;
        }

        return false;
    }

    public static function isDataInWebRoot($rootDir = null, $dataDir = null) {
        if ($rootDir === null) {
            $rootDir = self::getRoot();
        }
        if ($dataDir === null) {
            $dataDir = self::getDataDir($rootDir);
        }
        $realData = realpath($dataDir);
        if ($realData) {
            return self::isPathWithinRoot($realData, $rootDir);
        }
        $canon = self::canonicalizeWithinRoot($dataDir, $rootDir);
        return $canon !== false;
    }

    public static function getConfigFile($dataDir = null) {
        if ($dataDir === null) {
            $dataDir = self::getDataDir();
        }
        return $dataDir . '/config.php';
    }

    public static function getSetupSecretPath($rootDir = null) {
        if ($rootDir === null) {
            $rootDir = self::getRoot();
        }
        return rtrim($rootDir, '/\\') . '/zs-setup.secret';
    }

    public static function readSetupSecret($rootDir = null) {
        $env = getenv('ZS_SETUP_SECRET');
        if (is_string($env) && $env !== '') {
            return $env;
        }
        $file = self::getSetupSecretPath($rootDir);
        if (is_file($file) && !is_link($file)) {
            $raw = @file_get_contents($file);
            if (is_string($raw)) {
                return trim($raw);
            }
        }
        return '';
    }

    public static function defaultConfig() {
        return array(
            'key_hash'          => '',
            'gemini_api_keys'   => array(),
            'active_key_index'  => 0,
            'gemini_model'      => self::DEFAULT_GEMINI_MODEL,
            'ai_prompt_version' => self::PROMPT_VERSION,
            'csrf_secret'       => '',
            'report_endpoint'   => '',
            'github_repo'       => '',
            'rules_sync_url'    => '',
            'created_at'        => 0,
        );
    }

    public static function loadConfig($dataDir = null) {
        if ($dataDir === null) {
            $dataDir = self::getDataDir();
        }
        self::initDataDir($dataDir);

        $defaults = self::defaultConfig();
        $configFile = self::getConfigFile($dataDir);
        $config = $defaults;
        if (file_exists($configFile)) {
            if (!defined('ZS_INTERNAL')) {
                define('ZS_INTERNAL', true);
            }
            $loaded = @include $configFile;
            if (is_array($loaded)) {
                $config = array_merge($defaults, $loaded);
            }
        }

        $envKey = getenv('GEMINI_API_KEY');
        $envKeys = getenv('GEMINI_API_KEYS');
        if (!empty($envKeys)) {
            $parts = preg_split('/[\r\n,]+/', $envKeys);
            $clean = array();
            foreach ($parts as $p) {
                $p = trim($p);
                if ($p !== '') {
                    $clean[] = $p;
                }
            }
            if (!empty($clean)) {
                $config['gemini_api_keys'] = $clean;
                $config['_keys_from_env'] = true;
            }
        } elseif (!empty($envKey)) {
            $config['gemini_api_keys'] = array(trim($envKey));
            $config['_keys_from_env'] = true;
        }

        $envReport = getenv('REPORT_ENDPOINT');
        if (!empty($envReport)) {
            $config['report_endpoint'] = trim($envReport);
            $config['_report_from_env'] = true;
        }

        $config['data_dir'] = $dataDir;

        return $config;
    }

    public static function saveConfig($newConfig, $dataDir = null) {
        if ($dataDir === null) {
            $dataDir = self::getDataDir();
        }
        if (!self::initDataDir($dataDir)) {
            return false;
        }

        $configFile = self::getConfigFile($dataDir);
        $current = self::loadConfig($dataDir);
        unset($current['_keys_from_env'], $current['_report_from_env']);

        $fromEnvKeys = !empty($newConfig['_keys_from_env']) || getenv('GEMINI_API_KEYS') || getenv('GEMINI_API_KEY');
        $fromEnvReport = !empty($newConfig['_report_from_env']) || getenv('REPORT_ENDPOINT');
        unset($newConfig['_keys_from_env'], $newConfig['_report_from_env']);

        if ($fromEnvKeys && !array_key_exists('gemini_api_keys', $newConfig)) {
            unset($current['gemini_api_keys']);
        }
        if ($fromEnvReport && !array_key_exists('report_endpoint', $newConfig)) {
            unset($current['report_endpoint']);
        }

        $merged = array_merge($current, $newConfig);
        unset($merged['_keys_from_env'], $merged['_report_from_env'], $merged['data_dir']);

        if ($fromEnvKeys && !array_key_exists('gemini_api_keys', $newConfig)) {
            unset($merged['gemini_api_keys']);
        }
        if ($fromEnvReport && !array_key_exists('report_endpoint', $newConfig)) {
            unset($merged['report_endpoint']);
        }

        $content = "<?php\n"
            . "if (!defined('ZS_INTERNAL')) { http_response_code(403); header('Cache-Control: no-store'); exit('Access Denied'); }\n"
            . "return " . var_export($merged, true) . ";\n";
        return self::atomicWrite($configFile, $content, 0600);
    }

    public static function maskSecret($secret) {
        $secret = (string)$secret;
        $len = strlen($secret);
        if ($len === 0) {
            return '';
        }
        if ($len <= 8) {
            return str_repeat('•', $len);
        }
        return substr($secret, 0, 4) . str_repeat('•', max(4, $len - 8)) . substr($secret, -4);
    }

    public static function getGeminiKeys($config) {
        $keys = isset($config['gemini_api_keys']) && is_array($config['gemini_api_keys'])
            ? $config['gemini_api_keys']
            : array();
        return array_values(array_filter(array_map('trim', $keys)));
    }

    public static function getActiveGeminiKey(&$config, $dataDir = null) {
        $keys = self::getGeminiKeys($config);
        if (empty($keys)) {
            return null;
        }

        $total = count($keys);
        $idx = isset($config['active_key_index']) ? intval($config['active_key_index']) : 0;
        if ($idx >= $total || $idx < 0) {
            $idx = 0;
        }

        for ($i = 0; $i < $total; $i++) {
            $checkIdx = ($idx + $i) % $total;
            $candidateKey = $keys[$checkIdx];
            if (!self::isKeyCooling($candidateKey, $config, $dataDir)) {
                if ($checkIdx !== $idx) {
                    $config['active_key_index'] = $checkIdx;
                }
                return $candidateKey;
            }
        }

        return null;
    }

    public static function getCooldownFile($dataDir = null) {
        if ($dataDir === null) {
            $dataDir = self::getDataDir();
        }
        return rtrim($dataDir, '/\\') . '/cooldowns.php';
    }

    public static function loadCooldowns($dataDir = null) {
        $file = self::getCooldownFile($dataDir);
        if (!file_exists($file)) {
            return array();
        }
        $raw = @file_get_contents($file);
        $data = self::unwrapJson($raw);
        if (!is_array($data)) {
            return array();
        }
        $now = time();
        $valid = array();
        foreach ($data as $k => $until) {
            if (intval($until) > $now) {
                $valid[$k] = intval($until);
            }
        }
        return $valid;
    }

    public static function saveCooldowns($cooldowns, $dataDir = null) {
        $file = self::getCooldownFile($dataDir);
        return self::atomicWrite($file, self::wrapJson($cooldowns), 0600);
    }

    public static function markKeyCooldown($key, $duration = 60, &$config = null, $dataDir = null) {
        $until = time() + $duration;
        self::$keyCooldowns[$key] = $until;
        $fp = substr(hash('sha256', $key), 0, 16);
        if (is_array($config)) {
            if (!isset($config['key_cooldowns']) || !is_array($config['key_cooldowns'])) {
                $config['key_cooldowns'] = array();
            }
            $config['key_cooldowns'][$fp] = $until;
        }
        if ($dataDir === null) {
            $dataDir = (is_array($config) && !empty($config['data_dir'])) ? $config['data_dir'] : self::getDataDir();
        }
        if ($dataDir !== null) {
            $persisted = self::loadCooldowns($dataDir);
            $persisted[$fp] = $until;
            self::saveCooldowns($persisted, $dataDir);
        }
    }

    public static function isKeyCooling($key, $config = null, $dataDir = null) {
        if (isset(self::$keyCooldowns[$key])) {
            if (time() < self::$keyCooldowns[$key]) {
                return true;
            }
            unset(self::$keyCooldowns[$key]);
        }
        $fp = substr(hash('sha256', $key), 0, 16);
        if (is_array($config) && !empty($config['key_cooldowns']) && is_array($config['key_cooldowns'])) {
            if (isset($config['key_cooldowns'][$fp]) && time() < intval($config['key_cooldowns'][$fp])) {
                return true;
            }
        }
        if ($dataDir === null) {
            $dataDir = (is_array($config) && !empty($config['data_dir'])) ? $config['data_dir'] : self::getDataDir();
        }
        if ($dataDir !== null) {
            $persisted = self::loadCooldowns($dataDir);
            if (isset($persisted[$fp]) && time() < intval($persisted[$fp])) {
                return true;
            }
        }
        return false;
    }

    public static function clearKeyCooldown($key, &$config = null, $dataDir = null) {
        unset(self::$keyCooldowns[$key]);
        $fp = substr(hash('sha256', $key), 0, 16);
        if (is_array($config) && isset($config['key_cooldowns'][$fp])) {
            unset($config['key_cooldowns'][$fp]);
        }
        if ($dataDir === null) {
            $dataDir = (is_array($config) && !empty($config['data_dir'])) ? $config['data_dir'] : self::getDataDir();
        }
        if ($dataDir !== null) {
            $persisted = self::loadCooldowns($dataDir);
            if (isset($persisted[$fp])) {
                unset($persisted[$fp]);
                self::saveCooldowns($persisted, $dataDir);
            }
        }
    }

    public static function rotateGeminiKey(&$config, $dataDir = null) {
        $keys = self::getGeminiKeys($config);
        if (empty($keys)) {
            return null;
        }
        $total = count($keys);
        $idx = (isset($config['active_key_index']) ? intval($config['active_key_index']) : 0) + 1;
        $idx = $idx % $total;
        $config['active_key_index'] = $idx;
        return $keys[$idx];
    }

    public static function sendSecurityHeaders() {
        if (headers_sent()) {
            return;
        }
        header('Cache-Control: no-store, no-cache, must-revalidate');
        header('Pragma: no-cache');
        header('Referrer-Policy: no-referrer');
        header('X-Content-Type-Options: nosniff');
    }
}
