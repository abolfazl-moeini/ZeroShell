<?php
class ZS_Quarantine {
    public static function copyThenUnlink($targetPath, $rootDir, $quarantineDir, $meta = array()) {
        if (!ZS_Config::isRegularFile($targetPath)) {
            return array('success' => false, 'message' => 'File does not exist or is not a regular file.');
        }
        if (ZS_Config::pathHasSymlink($targetPath, $rootDir)) {
            return array('success' => false, 'message' => 'Refusing to quarantine a path that contains a symlink.');
        }

        $realTarget = realpath($targetPath);
        if (!$realTarget || !ZS_Config::isPathWithinRoot($realTarget, $rootDir)) {
            return array('success' => false, 'message' => 'File target is outside root directory.');
        }
        if (ZS_Config::isProtectedPath($realTarget, $rootDir)) {
            return array('success' => false, 'message' => 'Forbidden: Cannot quarantine protected files.');
        }

        if (!ZS_Config::secureMkdir($quarantineDir)) {
            return array('success' => false, 'message' => 'Quarantine directory is not writable.');
        }

        $payload = @file_get_contents($realTarget);
        if ($payload === false) {
            return array('success' => false, 'message' => 'Could not read source file.');
        }
        $rawHash = hash('sha256', $payload);
        if (!empty($meta['expected_raw']) && !hash_equals((string)$meta['expected_raw'], $rawHash)) {
            return array('success' => false, 'message' => 'File content changed before quarantine could complete.', 'code' => 'CHANGED_SINCE_SCAN');
        }
        $id = bin2hex(random_bytes(16));
        $backupName = 'q_' . $id . '.php';
        $backupPath = $quarantineDir . '/' . $backupName;
        $packed = ZS_Config::sampleStub() . $payload;

        if (!ZS_Config::atomicWrite($backupPath, $packed, 0600)) {
            return array('success' => false, 'message' => 'Failed to write quarantine envelope.');
        }

        $verifyRaw = @file_get_contents($backupPath);
        $extracted = ZS_Config::extractSamplePayload($verifyRaw);
        if ($extracted === false || hash('sha256', $extracted) !== $rawHash) {
            @unlink($backupPath);
            return array('success' => false, 'message' => 'Quarantine envelope failed integrity check.');
        }

        $record = array(
            'backup_name'    => $backupName,
            'original_path'  => $realTarget,
            'quarantined_at' => time(),
            'size'           => strlen($payload),
            'raw_sha256'     => $rawHash,
            'finding_id'     => isset($meta['finding_id']) ? $meta['finding_id'] : '',
        );

        if (!self::recordManifest($quarantineDir, $backupName, $record)) {
            @unlink($backupPath);
            return array('success' => false, 'message' => 'Failed to record quarantine metadata; original file kept.');
        }

        if (!@unlink($realTarget)) {
            return array('success' => false, 'message' => 'File copied to quarantine, but failed to unlink original.', 'backup_name' => $backupName, 'raw_sha256' => $rawHash);
        }

        return array('success' => true, 'backup_name' => $backupName, 'raw_sha256' => $rawHash, 'id' => $id);
    }

    public static function restore($backupName, $rootDir, $quarantineDir, $destOverride = null) {
        $backupName = basename((string)$backupName);
        if ($backupName === '' || strpos($backupName, 'q_') !== 0) {
            return array('success' => false, 'message' => 'Invalid backup name.');
        }
        $backupPath = $quarantineDir . '/' . $backupName;
        if (!ZS_Config::isRegularFile($backupPath) || is_link($backupPath)) {
            return array('success' => false, 'message' => 'Quarantined backup file not found.');
        }
        if (ZS_Config::pathHasSymlink($backupPath, $quarantineDir)) {
            return array('success' => false, 'message' => 'Backup path contains a symlink.');
        }

        $manifest = self::getManifest($quarantineDir);
        if (!isset($manifest[$backupName]) || empty($manifest[$backupName]['original_path'])) {
            return array('success' => false, 'message' => 'Original path for backup is unknown.');
        }

        $packed = @file_get_contents($backupPath);
        $payload = ZS_Config::extractSamplePayload($packed);
        if ($payload === false) {
            return array('success' => false, 'message' => 'Backup envelope is unreadable.');
        }
        $actualHash = hash('sha256', $payload);
        $expectedHash = isset($manifest[$backupName]['raw_sha256']) ? $manifest[$backupName]['raw_sha256'] : '';
        if ($expectedHash === '' || !hash_equals($expectedHash, $actualHash)) {
            return array('success' => false, 'message' => 'Backup checksum does not match the manifest; restore aborted.');
        }

        $origPath = $destOverride !== null ? $destOverride : $manifest[$backupName]['original_path'];
        $resolved = ZS_Config::canonicalizeWithinRoot($origPath, $rootDir);
        if ($resolved === false) {
            return array('success' => false, 'message' => 'Original destination path is outside root directory.');
        }
        if (ZS_Config::pathHasSymlink($resolved, $rootDir) || ZS_Config::pathHasSymlink(dirname($resolved), $rootDir)) {
            return array('success' => false, 'message' => 'Refusing restore through a symlink.');
        }
        if (ZS_Config::isProtectedPath($resolved, $rootDir)) {
            return array('success' => false, 'message' => 'Cannot restore to a protected path.');
        }

        $parentCheck = self::ensureParentsInsideRoot($resolved, $rootDir);
        if ($parentCheck !== true) {
            return array('success' => false, 'message' => $parentCheck);
        }

        if (file_exists($resolved) || is_link($resolved)) {
            return array('success' => false, 'message' => 'Destination already exists. Restore refused to avoid overwrite.', 'code' => 'DEST_EXISTS', 'path' => $resolved);
        }

        if (!ZS_Config::atomicWriteNew($resolved, $payload, 0644)) {
            if (file_exists($resolved) || is_link($resolved)) {
                return array('success' => false, 'message' => 'Destination already exists. Restore refused to avoid overwrite.', 'code' => 'DEST_EXISTS', 'path' => $resolved);
            }
            return array('success' => false, 'message' => 'Failed to write restored file.');
        }
        if (hash_file('sha256', $resolved) !== $actualHash) {
            @unlink($resolved);
            return array('success' => false, 'message' => 'Restored file failed checksum verification.');
        }

        @unlink($backupPath);
        self::removeManifestEntry($quarantineDir, $backupName);

        return array('success' => true, 'path' => $resolved, 'raw_sha256' => $actualHash);
    }

    private static function ensureParentsInsideRoot($destPath, $rootDir) {
        $realRoot = realpath($rootDir);
        if (!$realRoot) {
            return 'Root directory is invalid.';
        }
        $rootNorm = rtrim(str_replace('\\', '/', $realRoot), '/');
        $canon = ZS_Config::canonicalizeWithinRoot($destPath, $rootDir);
        if ($canon === false) {
            return 'Destination path is outside root directory.';
        }
        $canonDir = dirname($canon);
        if ($canonDir === $rootNorm) {
            return true;
        }
        if (strpos($canonDir . '/', $rootNorm . '/') !== 0) {
            return 'Parent directory is outside root.';
        }

        $rel = substr($canonDir, strlen($rootNorm));
        $walk = $rootNorm;
        foreach (explode('/', $rel) as $part) {
            if ($part === '') {
                continue;
            }
            $walk .= '/' . $part;
            if (!is_dir($walk)) {
                if (@is_link($walk)) {
                    return 'Refusing to create parents through a symlink.';
                }
                if (!ZS_Config::secureMkdir($walk)) {
                    return 'Failed to create parent directory.';
                }
                $real = realpath($walk);
                if (!$real || strpos(str_replace('\\', '/', $real) . '/', $rootNorm . '/') !== 0) {
                    @rmdir($walk);
                    return 'Parent directory resolved outside root.';
                }
            } else {
                if (@is_link($walk)) {
                    return 'Refusing restore through a symlink parent.';
                }
                $real = realpath($walk);
                if (!$real || strpos(str_replace('\\', '/', $real) . '/', $rootNorm . '/') !== 0) {
                    return 'Parent directory is outside root.';
                }
            }
        }
        return true;
    }

    public static function getManifest($quarantineDir) {
        $file = $quarantineDir . '/manifest.php';
        $legacy = $quarantineDir . '/manifest.json';

        $data = array();
        if (file_exists($file)) {
            $raw = @file_get_contents($file);
            $parsed = ZS_Config::unwrapJson($raw);
            if (is_array($parsed)) {
                $data = $parsed;
            }
        }
        if (file_exists($legacy)) {
            if (!file_exists($file) || filemtime($legacy) >= filemtime($file)) {
                $legacyRaw = @file_get_contents($legacy);
                $legacyData = json_decode($legacyRaw, true);
                if (is_array($legacyData)) {
                    $data = array_merge($data, $legacyData);
                }
            }
        }
        return $data;
    }

    public static function recordManifest($quarantineDir, $backupName, $data) {
        $file = $quarantineDir . '/manifest.php';
        $lock = $quarantineDir . '/.lock_manifest';
        $fp = @fopen($lock, 'c+');
        if (!$fp) {
            return false;
        }
        if (!flock($fp, LOCK_EX)) {
            fclose($fp);
            return false;
        }
        $manifest = self::getManifest($quarantineDir);
        $manifest[$backupName] = $data;
        $ok = ZS_Config::atomicWrite($file, ZS_Config::wrapJson($manifest), 0600);
        flock($fp, LOCK_UN);
        fclose($fp);
        return $ok;
    }

    public static function removeManifestEntry($quarantineDir, $backupName) {
        $file = $quarantineDir . '/manifest.php';
        $lock = $quarantineDir . '/.lock_manifest';
        $fp = @fopen($lock, 'c+');
        if (!$fp) {
            return false;
        }
        if (!flock($fp, LOCK_EX)) {
            fclose($fp);
            return false;
        }
        $manifest = self::getManifest($quarantineDir);
        if (isset($manifest[$backupName])) {
            unset($manifest[$backupName]);
            ZS_Config::atomicWrite($file, ZS_Config::wrapJson($manifest), 0600);
        }
        flock($fp, LOCK_UN);
        fclose($fp);
        return true;
    }

    public static function listQuarantined($quarantineDir) {
        return self::getManifest($quarantineDir);
    }

    public static function readPayload($quarantineDir, $backupName) {
        $backupName = basename((string)$backupName);
        $path = $quarantineDir . '/' . $backupName;
        if (!ZS_Config::isRegularFile($path)) {
            return false;
        }
        $raw = @file_get_contents($path);
        return ZS_Config::extractSamplePayload($raw);
    }
}
