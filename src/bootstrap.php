<?php
@ini_set('memory_limit', '512M');
@ini_set('max_execution_time', 0);

if (php_sapi_name() === 'cli') {
    $rootDir = ZS_Config::getRoot();
    $dataDir = ZS_Config::getDataDir($rootDir);
    $store   = new ZS_Store($dataDir);

    $isReset = false;
    if (isset($argv) && is_array($argv)) {
        foreach ($argv as $arg) {
            if ($arg === '--reset' || $arg === '-r') {
                $isReset = true;
                break;
            }
        }
    }

    $session = $store->initSession($rootDir, $isReset);

    if (!empty($session['is_completed'])) {
        echo "\n=== SCAN COMPLETE ===\n";
        echo "Scanned Files: " . intval($session['scanned_files']) . "\n";
        echo "Scanned Dirs: " . intval($session['scanned_dirs']) . "\n";
        echo "Threats Found: " . count($session['infected_files']) . "\n";
        echo "Trusted Bypassed: " . intval($session['trusted_bypassed']) . "\n";
        exit(0);
    }

    ZS_Http::executeScanBatch($session, $rootDir, $dataDir, $store);
    exit(0);
} else {
    ZS_Http::handleRequest();
}
