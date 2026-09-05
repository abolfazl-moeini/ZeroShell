<?php
@ini_set('memory_limit', '512M');
@ini_set('max_execution_time', 0);

if (!defined('ZS_INTERNAL')) {
    define('ZS_INTERNAL', true);
}

if (php_sapi_name() === 'cli') {
    $rootDir = ZS_Config::getRoot();
    $dataDir = ZS_Config::getDataDir($rootDir);
    $store   = new ZS_Store($dataDir);

    $isReset = false;
    $oneBatch = false;
    if (isset($argv) && is_array($argv)) {
        foreach ($argv as $arg) {
            if ($arg === '--reset' || $arg === '-r') {
                $isReset = true;
            }
            if ($arg === '--one-batch') {
                $oneBatch = true;
            }
        }
    }

    $session = $store->initSession($rootDir, $isReset);
    if ($session === false) {
        fwrite(STDERR, "Failed to open session: " . $store->lastError . "\n");
        exit(1);
    }

    if (!empty($session['is_completed'])) {
        echo "\n=== SCAN COMPLETE ===\n";
        echo "Scanned Files: " . intval($session['scanned_files']) . "\n";
        echo "Threats Found: " . count($session['infected_files']) . "\n";
        echo "Trusted Bypassed: " . intval($session['trusted_bypassed']) . "\n";
        exit(0);
    }

    ZS_Http::executeScanBatch($session, $rootDir, $dataDir, $store);
    exit(0);
}

ZS_Http::handleRequest();
