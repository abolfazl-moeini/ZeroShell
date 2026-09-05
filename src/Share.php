<?php
class ZS_Share {
    public static function buildBundle($session, $rootDir, $selectedIds = array(), $includeSamples = false, $quarantineDir = '') {
        $findings = isset($session['infected_files']) && is_array($session['infected_files'])
            ? $session['infected_files']
            : array();

        $selectedMap = array();
        foreach ((array)$selectedIds as $id) {
            $id = trim((string)$id);
            if ($id !== '') {
                $selectedMap[$id] = true;
            }
        }

        $bundleItems = array();
        $bytes = 0;
        $maxBytes = 262144;
        $maxItems = 25;

        foreach ($findings as $item) {
            $fid = isset($item['finding_id']) ? $item['finding_id'] : '';
            if (!empty($selectedMap) && ($fid === '' || !isset($selectedMap[$fid]))) {
                continue;
            }
            $status = isset($item['status']) ? $item['status'] : '';
            if ($status === 'TRUSTED_HIDDEN' || $status === 'TRUSTED' || $status === 'AI_SKIPPED') {
                continue;
            }
            if (count($bundleItems) >= $maxItems) {
                break;
            }

            $path = isset($item['path']) ? $item['path'] : '';
            $relPath = self::anonymizePath($path, $rootDir);
            $evidence = '';
            if (!empty($item['evidence']) && is_array($item['evidence'])) {
                $evidence = implode("\n", array_slice($item['evidence'], 0, 3));
            }
            $evidence = ZS_Gemini::redact($evidence, $rootDir);
            if (strlen($evidence) > 400) {
                $evidence = substr($evidence, 0, 400);
            }

            $entry = array(
                'finding_id'  => $fid,
                'rel_path'    => $relPath,
                'raw_sha256'  => isset($item['raw_sha256']) ? $item['raw_sha256'] : '',
                'norm_sha256' => isset($item['norm_sha256']) ? $item['norm_sha256'] : '',
                'reason'      => isset($item['reason']) ? $item['reason'] : '',
                'rule_ids'    => isset($item['rule_ids']) ? $item['rule_ids'] : array(),
                'status'      => $status,
                'evidence'    => $evidence,
            );

            if ($includeSamples && !empty($item['backup_name']) && $quarantineDir !== '') {
                $payload = ZS_Quarantine::readPayload($quarantineDir, $item['backup_name']);
                if (is_string($payload) && (strlen($payload) + $bytes) <= $maxBytes && strlen($payload) <= 512 * 1024) {
                    $entry['sample_b64'] = base64_encode($payload);
                    $entry['sample_sha256'] = hash('sha256', $payload);
                    $bytes += strlen($payload);
                }
            }

            $bundleItems[] = $entry;
        }

        return array(
            'tool'        => 'ZeroShell Malware Cleaner',
            'version'     => '1.0.0',
            'created_at'  => time(),
            'total_items' => count($bundleItems),
            'includes_samples' => $includeSamples,
            'items'       => $bundleItems,
        );
    }

    public static function anonymizePath($path, $rootDir) {
        $normPath = str_replace('\\', '/', $path);
        $normRoot = str_replace('\\', '/', rtrim($rootDir, '/\\'));
        if (!empty($normRoot) && strpos($normPath, $normRoot) === 0) {
            return ltrim(substr($normPath, strlen($normRoot)), '/');
        }
        foreach (array('wp-content', 'wp-includes', 'wp-admin') as $marker) {
            $pos = strpos($normPath, $marker);
            if ($pos !== false) {
                return substr($normPath, $pos);
            }
        }
        return basename($normPath);
    }

    public static function extractEvidenceLines($content, $maxLines = 12, $rootDir = '') {
        $redacted = ZS_Gemini::redact($content, $rootDir);
        if (stripos($redacted, 'DB_PASSWORD') !== false && strpos($redacted, '[REDACTED]') === false) {
            return '';
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

    public static function buildMarkdownReport($bundle, $githubRepo = '') {
        $md = "### ZeroShell Malware Report\n\n";
        $md .= "- **Scanner:** ZeroShell v1.0.0\n";
        $md .= "- **Selected findings:** " . intval($bundle['total_items']) . "\n\n";
        $md .= "| Relative Path | Rule IDs | Status | Raw SHA256 |\n|---|---|---|---|\n";
        foreach ($bundle['items'] as $item) {
            $ids = !empty($item['rule_ids']) ? implode(', ', $item['rule_ids']) : '-';
            $md .= '| `' . str_replace('|', '/', $item['rel_path']) . '` | ' . $ids . ' | ' . $item['status'] . ' | `' . $item['raw_sha256'] . "` |\n";
        }
        return $md;
    }

    public static function getGithubShareData($bundle, $githubRepo = '') {
        $repo = trim((string)$githubRepo);
        $title = 'Malware signature submission: ' . count($bundle['items']) . ' findings';
        $body = self::buildMarkdownReport($bundle, $repo);
        if ($repo === '' || strpos($repo, 'OWNER/REPO') !== false) {
            return array(
                'url'            => '',
                'body'           => $body,
                'need_clipboard' => true,
            );
        }
        $baseUrl = 'https://github.com/' . $repo . '/issues/new';
        $fullUrl = $baseUrl . '?title=' . rawurlencode($title) . '&body=' . rawurlencode($body);
        if (strlen($fullUrl) < 1500) {
            return array('url' => $fullUrl, 'body' => $body, 'need_clipboard' => false);
        }
        return array('url' => $baseUrl . '?title=' . rawurlencode($title), 'body' => $body, 'need_clipboard' => true);
    }

    public static function submitToMaintainer($bundle, $reportEndpoint, $hasExplicitConsent, $includeSamples = false, $quarantineDir = '') {
        if (!$hasExplicitConsent) {
            return array('success' => false, 'message' => 'Submission refused: explicit consent not given.');
        }
        if (empty($reportEndpoint)) {
            return array('success' => false, 'message' => 'No maintainer report endpoint configured. Download the JSON instead.');
        }
        $parts = parse_url($reportEndpoint);
        if (!isset($parts['scheme']) || strtolower($parts['scheme']) !== 'https' || empty($parts['host'])) {
            return array('success' => false, 'message' => 'Endpoint must be a valid HTTPS URL.');
        }
        $jsonPayload = json_encode($bundle);
        $headers = array('Content-Type: application/json', 'User-Agent: ZeroShell-Cleaner/1.0');
        $res = ZS_Gemini::executeHttpRequest($reportEndpoint, $headers, $jsonPayload, 'POST');
        if (isset($res['status']) && $res['status'] >= 200 && $res['status'] < 300) {
            return array('success' => true, 'receipt' => substr((string)$res['body'], 0, 500));
        }
        return array('success' => false, 'message' => 'Server response status ' . (isset($res['status']) ? $res['status'] : 0));
    }
}
