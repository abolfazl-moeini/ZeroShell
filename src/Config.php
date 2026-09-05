<?php
class ZS_Config {
    public static $keyCooldowns = array();

    public static function getRoot() {
        return defined('ABSPATH') ? rtrim(ABSPATH, '/\\') : dirname(__FILE__);
    }

    public static function getDataDir($rootDir = null) {
        if ($rootDir === null) {
            $rootDir = self::getRoot();
        }
        $envData = getenv('MALWARE_CLEANER_DATA_DIR');
        if (!empty($envData)) {
            return rtrim($envData, '/\\');
        }

        $wpContent = $rootDir . '/wp-content';
        if (is_dir($wpContent)) {
            return $wpContent . '/malware_cleaner_data';
        }
        return $rootDir . '/malware_cleaner_data';
    }

    public static function initDataDir($dataDir) {
        if (!is_dir($dataDir)) {
            @mkdir($dataDir, 0755, true);
        }

        $htaccessFile = $dataDir . '/.htaccess';
        if (!file_exists($htaccessFile)) {
            $htaccessContent = "<FilesMatch \"\\.(json|php)$\">\n"
                . "  <IfModule mod_authz_core.c>\n"
                . "    Require all denied\n"
                . "  </IfModule>\n"
                . "  <IfModule !mod_authz_core.c>\n"
                . "    Deny from all\n"
                . "  </IfModule>\n"
                . "</FilesMatch>\n";
            @file_put_contents($htaccessFile, $htaccessContent);
        }

        $indexFile = $dataDir . '/index.php';
        if (!file_exists($indexFile)) {
            @file_put_contents($indexFile, "<?php http_response_code(403); exit('Access Denied');\n");
        }
    }

    public static function getQuarantineDir($rootDir = null, $dataDir = null) {
        if ($rootDir === null) {
            $rootDir = self::getRoot();
        }
        if ($dataDir === null) {
            $dataDir = self::getDataDir($rootDir);
        }

        $wpContent = $rootDir . '/wp-content';
        if (is_dir($wpContent)) {
            $quarantine = $wpContent . '/malware_quarantine';
        } else {
            $quarantine = $dataDir . '/quarantine';
        }

        if (!is_dir($quarantine)) {
            @mkdir($quarantine, 0755, true);
        }

        $htaccessFile = $quarantine . '/.htaccess';
        if (!file_exists($htaccessFile)) {
            $htaccessContent = "<FilesMatch \".*\">\n"
                . "  <IfModule mod_authz_core.c>\n"
                . "    Require all denied\n"
                . "  </IfModule>\n"
                . "  <IfModule !mod_authz_core.c>\n"
                . "    Deny from all\n"
                . "  </IfModule>\n"
                . "</FilesMatch>\n";
            @file_put_contents($htaccessFile, $htaccessContent);
        }

        $indexFile = $quarantine . '/index.php';
        if (!file_exists($indexFile)) {
            @file_put_contents($indexFile, "<?php http_response_code(403); exit('Access Denied');\n");
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

    /**
     * Resolve a path that may not exist yet, rejecting .. escapes outside $rootDir.
     * Returns the normalized absolute path or false.
     */
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

    public static function isDataInWebRoot($rootDir = null, $dataDir = null) {
        if ($rootDir === null) {
            $rootDir = self::getRoot();
        }
        if ($dataDir === null) {
            $dataDir = self::getDataDir($rootDir);
        }
        return self::isPathWithinRoot($dataDir, $rootDir);
    }

    public static function getConfigFile($dataDir = null) {
        if ($dataDir === null) {
            $dataDir = self::getDataDir();
        }
        return $dataDir . '/config.php';
    }

    public static function loadConfig($dataDir = null) {
        if ($dataDir === null) {
            $dataDir = self::getDataDir();
        }
        self::initDataDir($dataDir);

        $defaults = array(
            'key_hash'          => '',
            'gemini_api_keys'   => array(),
            'active_key_index'  => 0,
            'gemini_model'      => 'gemini-2.0-flash',
            'ai_prompt_version' => 'prompt_v1',
            'csrf_secret'       => '',
            'report_endpoint'   => '',
            'github_repo'       => 'OWNER/REPO',
            'rules_sync_url'    => 'https://raw.githubusercontent.com/OWNER/REPO/main/rules/database.json',
            'created_at'        => 0,
        );

        $configFile = self::getConfigFile($dataDir);
        $config = $defaults;
        if (file_exists($configFile)) {
            $loaded = @include $configFile;
            if (is_array($loaded)) {
                $config = array_merge($defaults, $loaded);
            }
        }

        // Environment overrides
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
            }
        } elseif (!empty($envKey)) {
            $config['gemini_api_keys'] = array(trim($envKey));
        }

        $envReport = getenv('REPORT_ENDPOINT');
        if (!empty($envReport)) {
            $config['report_endpoint'] = trim($envReport);
        }

        return $config;
    }

    public static function saveConfig($newConfig, $dataDir = null) {
        if ($dataDir === null) {
            $dataDir = self::getDataDir();
        }
        self::initDataDir($dataDir);

        $configFile = self::getConfigFile($dataDir);
        $current = self::loadConfig($dataDir);
        $merged = array_merge($current, $newConfig);

        $content = "<?php\nreturn " . var_export($merged, true) . ";\n";
        $tmpFile = $configFile . '.tmp.' . bin2hex(random_bytes(6));
        $written = @file_put_contents($tmpFile, $content);
        if ($written !== false) {
            @rename($tmpFile, $configFile);
            return true;
        }
        return false;
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

        // Try to find a key that is not in cooldown
        for ($i = 0; $i < $total; $i++) {
            $checkIdx = ($idx + $i) % $total;
            $candidateKey = $keys[$checkIdx];
            if (!self::isKeyCooling($candidateKey)) {
                if ($checkIdx !== $idx) {
                    $config['active_key_index'] = $checkIdx;
                    self::saveConfig(array('active_key_index' => $checkIdx), $dataDir);
                }
                return $candidateKey;
            }
        }

        return null; // All keys are cooling
    }

    public static function markKeyCooldown($key, $duration = 60) {
        self::$keyCooldowns[$key] = time() + $duration;
    }

    public static function isKeyCooling($key) {
        if (isset(self::$keyCooldowns[$key])) {
            if (time() < self::$keyCooldowns[$key]) {
                return true;
            }
            unset(self::$keyCooldowns[$key]);
        }
        return false;
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
        self::saveConfig(array('active_key_index' => $idx), $dataDir);
        return $keys[$idx];
    }
}
