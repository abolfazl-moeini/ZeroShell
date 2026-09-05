<?php
class ZS_Quarantine {
    public static function copyThenUnlink($targetPath, $rootDir, $quarantineDir) {
        if (empty($targetPath) || !file_exists($targetPath) || !is_file($targetPath)) {
            return array('success' => false, 'message' => 'File does not exist or is not a file.');
        }

        $realTarget = realpath($targetPath);
        $realSelf   = realpath(__FILE__);
        $realScript = isset($_SERVER['SCRIPT_FILENAME']) ? realpath($_SERVER['SCRIPT_FILENAME']) : null;

        if (!$realTarget || !ZS_Config::isPathWithinRoot($realTarget, $rootDir)) {
            return array('success' => false, 'message' => 'File target is outside root directory.');
        }

        if ($realTarget === $realSelf || ($realScript && $realTarget === $realScript) || basename($targetPath) === 'wp-config.php') {
            return array('success' => false, 'message' => 'Forbidden: Cannot delete scanner file or wp-config.php.');
        }

        if (!is_dir($quarantineDir)) {
            @mkdir($quarantineDir, 0755, true);
        }

        $backupName = md5($targetPath) . '_' . basename($targetPath);
        $backupPath = $quarantineDir . '/' . $backupName;

        if (!@copy($targetPath, $backupPath)) {
            return array('success' => false, 'message' => 'Failed to copy file to quarantine directory.');
        }

        // Write to manifest
        self::recordManifest($quarantineDir, $backupName, array(
            'backup_name'    => $backupName,
            'original_path'  => $targetPath,
            'quarantined_at' => time(),
            'size'           => filesize($backupPath),
            'raw_sha256'     => hash_file('sha256', $backupPath),
        ));

        if (!@unlink($targetPath)) {
            return array('success' => false, 'message' => 'File copied to quarantine, but failed to unlink original.');
        }

        return array('success' => true, 'backup_name' => $backupName);
    }

    public static function restore($backupName, $rootDir, $quarantineDir) {
        $backupPath = $quarantineDir . '/' . basename($backupName);
        if (!file_exists($backupPath) || !is_file($backupPath)) {
            return array('success' => false, 'message' => 'Quarantined backup file not found.');
        }

        $manifest = self::getManifest($quarantineDir);
        if (!isset($manifest[$backupName]) || empty($manifest[$backupName]['original_path'])) {
            return array('success' => false, 'message' => 'Original path for backup is unknown.');
        }

        $origPath = $manifest[$backupName]['original_path'];
        $resolved = ZS_Config::canonicalizeWithinRoot($origPath, $rootDir);
        if ($resolved === false) {
            return array('success' => false, 'message' => 'Original destination path is outside root directory.');
        }

        $realSelf   = realpath(__FILE__);
        $realScript = isset($_SERVER['SCRIPT_FILENAME']) ? realpath($_SERVER['SCRIPT_FILENAME']) : null;

        if (basename($resolved) === 'wp-config.php' || ($realSelf && $resolved === $realSelf) || ($realScript && $resolved === $realScript)) {
            return array('success' => false, 'message' => 'Cannot restore to protected filename.');
        }

        $destDir = dirname($resolved);
        if (!is_dir($destDir)) {
            @mkdir($destDir, 0755, true);
        }

        if (!@copy($backupPath, $resolved)) {
            return array('success' => false, 'message' => 'Failed to copy backup file back to original location.');
        }

        @unlink($backupPath);
        self::removeManifestEntry($quarantineDir, $backupName);

        return array('success' => true, 'path' => $resolved);
    }

    public static function getManifest($quarantineDir) {
        $file = $quarantineDir . '/manifest.json';
        if (!file_exists($file)) {
            return array();
        }
        $content = @file_get_contents($file);
        $data = @json_decode($content, true);
        return is_array($data) ? $data : array();
    }

    public static function recordManifest($quarantineDir, $backupName, $data) {
        $file = $quarantineDir . '/manifest.json';
        $manifest = self::getManifest($quarantineDir);
        $manifest[$backupName] = $data;
        @file_put_contents($file, json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }

    public static function removeManifestEntry($quarantineDir, $backupName) {
        $file = $quarantineDir . '/manifest.json';
        $manifest = self::getManifest($quarantineDir);
        if (isset($manifest[$backupName])) {
            unset($manifest[$backupName]);
            @file_put_contents($file, json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        }
    }

    public static function listQuarantined($quarantineDir) {
        return self::getManifest($quarantineDir);
    }
}
