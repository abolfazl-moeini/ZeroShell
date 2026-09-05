<?php
class ZS_Share {
    public static function buildBundle($session, $rootDir, $rules = array()) {
        $findings = isset($session['infected_files']) && is_array($session['infected_files'])
            ? $session['infected_files']
            : array();

        $bundleItems = array();
        foreach ($findings as $item) {
            $path = isset($item['path']) ? $item['path'] : '';
            $relPath = self::anonymizePath($path, $rootDir);
            $rawHash = isset($item['raw_sha256']) ? $item['raw_sha256'] : '';
            $normHash = isset($item['norm_sha256']) ? $item['norm_sha256'] : '';
            $reason = isset($item['reason']) ? $item['reason'] : '';

            $evidence = '';
            if (file_exists($path) && is_readable($path)) {
                $content = @file_get_contents($path, false, null, 0, 16384);
                if ($content !== false) {
                    $evidence = self::extractEvidenceLines($content, 12, $rootDir);
                }
            }

            $bundleItems[] = array(
                'rel_path'    => $relPath,
                'raw_sha256'  => $rawHash,
                'norm_sha256' => $normHash,
                'reason'      => $reason,
                'evidence'    => $evidence,
            );
        }

        return array(
            'tool'        => 'ZeroShell Malware Cleaner',
            'version'     => '1.0.0',
            'created_at'  => time(),
            'total_items' => count($bundleItems),
            'items'       => $bundleItems,
        );
    }

    public static function anonymizePath($path, $rootDir) {
        $normPath = str_replace('\\', '/', $path);
        $normRoot = str_replace('\\', '/', rtrim($rootDir, '/\\'));

        if (!empty($normRoot) && strpos($normPath, $normRoot) === 0) {
            $sub = substr($normPath, strlen($normRoot));
            $sub = ltrim($sub, '/');
            return $sub;
        }

        // Fallback: look for wp-content or common WP folders
        $pos = strpos($normPath, 'wp-content');
        if ($pos !== false) {
            return substr($normPath, $pos);
        }
        $posInc = strpos($normPath, 'wp-includes');
        if ($posInc !== false) {
            return substr($normPath, $posInc);
        }
        $posAdm = strpos($normPath, 'wp-admin');
        if ($posAdm !== false) {
            return substr($normPath, $posAdm);
        }

        return basename($normPath);
    }

    public static function extractEvidenceLines($content, $maxLines = 12, $rootDir = '') {
        $redacted = ZS_Gemini::redact($content, $rootDir);

        // Check if redaction succeeded for secrets
        if (stripos($redacted, 'DB_PASSWORD') !== false && !preg_match("/\[REDACTED\]/", $redacted)) {
            return ''; // Omit evidence rather than leak
        }

        $lines = explode("\n", $redacted);
        $nonEmpty = array();
        foreach ($lines as $l) {
            $t = trim($l);
            if ($t !== '') {
                $nonEmpty[] = $t;
                if (count($nonEmpty) >= $maxLines) {
                    break;
                }
            }
        }

        return implode("\n", $nonEmpty);
    }

    public static function buildMarkdownReport($bundle, $githubRepo = 'OWNER/REPO') {
        $md = "### ZeroShell Malware Report\n\n";
        $md .= "- **Scanner:** ZeroShell v1.0.0\n";
        $md .= "- **Total Threats Detected:** " . intval($bundle['total_items']) . "\n\n";

        $md .= "| Relative Path | Detection Reason | Normalized SHA256 |\n";
        $md .= "|---|---|---|\n";

        foreach ($bundle['items'] as $item) {
            $safePath = htmlspecialchars($item['rel_path']);
            $safeReason = htmlspecialchars($item['reason']);
            $norm = $item['norm_sha256'];
            $md .= "| `{$safePath}` | {$safeReason} | `{$norm}` |\n";
        }

        $md .= "\n<details><summary>Short Redacted Evidence</summary>\n\n";
        foreach ($bundle['items'] as $item) {
            if (!empty($item['evidence'])) {
                $md .= "```php\n// File: " . $item['rel_path'] . "\n" . $item['evidence'] . "\n```\n\n";
            }
        }
        $md .= "</details>\n";

        return $md;
    }

    public static function getGithubShareData($bundle, $githubRepo = 'OWNER/REPO') {
        $repo = !empty($githubRepo) ? $githubRepo : 'OWNER/REPO';
        $title = "Malware Signature Submission: " . count($bundle['items']) . " threats detected";
        $body = self::buildMarkdownReport($bundle, $repo);

        $baseUrl = "https://github.com/{$repo}/issues/new";
        $fullUrl = $baseUrl . '?title=' . urlencode($title) . '&body=' . urlencode($body);

        if (strlen($fullUrl) < 1500) {
            return array(
                'url'            => $fullUrl,
                'body'           => $body,
                'need_clipboard' => false,
            );
        }

        return array(
            'url'            => $baseUrl . '?title=' . urlencode($title),
            'body'           => $body,
            'need_clipboard' => true,
        );
    }

    public static function submitToMaintainer($bundle, $reportEndpoint, $hasExplicitConsent, $includeSamples = false, $quarantineDir = '') {
        if (!$hasExplicitConsent) {
            return array('success' => false, 'message' => 'Submission refused: explicit consent not given.');
        }

        if (empty($reportEndpoint)) {
            return array('success' => false, 'message' => 'No maintainer report endpoint configured.');
        }

        // Validate HTTPS and single host
        $parts = parse_url($reportEndpoint);
        if (!isset($parts['scheme']) || strtolower($parts['scheme']) !== 'https') {
            return array('success' => false, 'message' => 'Endpoint must use HTTPS.');
        }
        if (empty($parts['host'])) {
            return array('success' => false, 'message' => 'Invalid endpoint URL.');
        }

        $payload = array(
            'bundle'   => $bundle,
            'samples'  => array(),
        );

        if ($includeSamples && !empty($quarantineDir) && is_dir($quarantineDir)) {
            $manifest = ZS_Quarantine::getManifest($quarantineDir);
            foreach ($manifest as $backupName => $meta) {
                $backupFile = $quarantineDir . '/' . $backupName;
                if (file_exists($backupFile) && filesize($backupFile) <= 1024 * 512) { // 512KB sample cap
                    $content = @file_get_contents($backupFile);
                    if ($content !== false) {
                        $payload['samples'][] = array(
                            'filename'    => $backupName,
                            'raw_sha256'  => isset($meta['raw_sha256']) ? $meta['raw_sha256'] : '',
                            'b64_content' => base64_encode($content),
                        );
                    }
                }
            }
        }

        $jsonPayload = json_encode($payload);
        $headers = array(
            'Content-Type: application/json',
            'User-Agent: ZeroShell-Cleaner/1.0',
        );

        $res = ZS_Gemini::executeHttpRequest($reportEndpoint, $headers, $jsonPayload);
        if (isset($res['status']) && $res['status'] >= 200 && $res['status'] < 300) {
            return array('success' => true, 'receipt' => $res['body']);
        }

        return array('success' => false, 'message' => 'Server response status ' . (isset($res['status']) ? $res['status'] : 0));
    }
}
