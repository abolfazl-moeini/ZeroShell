<?php
class ZS_Rules {
    public static $bundledCache = null;

    public static function bundled() {
        if (self::$bundledCache !== null) {
            return self::$bundledCache;
        }

        // Placeholder for build-time inlining:
        // {{BUNDLED_RULES_DATA}}

        $dbFile = dirname(dirname(__FILE__)) . '/rules/database.json';
        if (file_exists($dbFile)) {
            $raw = @file_get_contents($dbFile);
            $parsed = @json_decode($raw, true);
            if (is_array($parsed)) {
                self::$bundledCache = $parsed;
                return self::$bundledCache;
            }
        }

        self::$bundledCache = array(
            'schema_version' => 1,
            'hashes' => array(),
            'signatures' => array(),
            'structural' => array(),
            'paths' => array(),
        );
        return self::$bundledCache;
    }

    public static function validateRule($rule) {
        if (!is_array($rule) || empty($rule['id']) || !is_string($rule['id'])) {
            return false;
        }

        $type = isset($rule['type']) ? $rule['type'] : '';
        if (isset($rule['sha256'])) {
            // Hash rule
            if (!preg_match('/^[a-f0-9]{64}$/i', $rule['sha256'])) {
                return false;
            }
            return true;
        }

        $allowedTypes = array(
            'literal_contains', 'regex', 'normalized_hash', 'goto_hex',
            'goto_eval', 'ascii_range_decoder', 'goto_math_index', 'heavy_hex_octal',
            'languages_fake_php', 'uploads_php', 'rogue_core_path', 'double_extension'
        );

        if (!in_array($type, $allowedTypes, true)) {
            return false;
        }

        if (isset($rule['pattern'])) {
            if (strlen($rule['pattern']) > 2048) {
                return false;
            }
            if ($type === 'regex') {
                // Reject /e modifier
                $pattern = $rule['pattern'];
                if (preg_match('/\/[a-zA-Z]*e[a-zA-Z]*$/', $pattern)) {
                    return false;
                }
                if (@preg_match($pattern, '') === false) {
                    return false;
                }
            }
        }

        return true;
    }

    public static function validatePayload($rawJson) {
        if (!is_string($rawJson) || strlen($rawJson) > 512 * 1024) {
            return false;
        }

        $data = @json_decode($rawJson, true);
        if (!is_array($data) || !isset($data['schema_version'])) {
            return false;
        }

        $hasRules = (!empty($data['hashes']) || !empty($data['signatures']) || !empty($data['structural']) || !empty($data['paths']));
        if (!$hasRules) {
            return false;
        }

        $ids = array();
        $sections = array('hashes', 'signatures', 'structural', 'paths');
        foreach ($sections as $sec) {
            if (!empty($data[$sec]) && is_array($data[$sec])) {
                foreach ($data[$sec] as $rule) {
                    if (!self::validateRule($rule)) {
                        return false;
                    }
                    if (isset($ids[$rule['id']])) {
                        return false; // Duplicate ID
                    }
                    $ids[$rule['id']] = true;
                }
            }
        }

        return $data;
    }

    private static function mergeSection(&$baseList, $overrideList) {
        if (!is_array($overrideList)) {
            return;
        }
        $idIndex = array();
        foreach ($baseList as $idx => $item) {
            if (isset($item['id'])) {
                $idIndex[$item['id']] = $idx;
            }
        }

        foreach ($overrideList as $item) {
            if (!isset($item['id']) || !self::validateRule($item)) {
                continue;
            }
            $id = $item['id'];
            if (isset($idIndex[$id])) {
                $baseList[$idIndex[$id]] = $item;
            } else {
                $baseList[] = $item;
                $idIndex[$id] = count($baseList) - 1;
            }
        }
    }

    public static function mergeRuleSets($base, $override) {
        if (!is_array($override)) {
            return $base;
        }
        $sections = array('hashes', 'signatures', 'structural', 'paths');
        foreach ($sections as $sec) {
            if (!isset($base[$sec]) || !is_array($base[$sec])) {
                $base[$sec] = array();
            }
            if (isset($override[$sec]) && is_array($override[$sec])) {
                self::mergeSection($base[$sec], $override[$sec]);
            }
        }
        return $base;
    }

    public static function load($rootDir = null, $dataDir = null) {
        if ($rootDir === null) {
            $rootDir = ZS_Config::getRoot();
        }
        if ($dataDir === null) {
            $dataDir = ZS_Config::getDataDir($rootDir);
        }

        $rules = self::bundled();

        // 1. Check Synced override in data directory
        $syncedFile = $dataDir . '/rules_override.json';
        if (file_exists($syncedFile)) {
            $raw = @file_get_contents($syncedFile);
            $synced = self::validatePayload($raw);
            if ($synced !== false) {
                $rules = self::mergeRuleSets($rules, $synced);
            }
        }

        // 2. Check Local rules/database.json next to script (highest priority)
        $localDbFile = $rootDir . '/rules/database.json';
        if (file_exists($localDbFile)) {
            $raw = @file_get_contents($localDbFile);
            $local = self::validatePayload($raw);
            if ($local !== false) {
                $rules = self::mergeRuleSets($rules, $local);
            }
        }

        return $rules;
    }
}
