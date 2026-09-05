<?php
class ZS_Http {
    public static function handleRequest($rootDir = null, $dataDir = null) {
        if ($rootDir === null) {
            $rootDir = ZS_Config::getRoot();
        }
        if ($dataDir === null) {
            $dataDir = ZS_Config::getDataDir($rootDir);
        }

        $config = ZS_Config::loadConfig($dataDir);
        $store  = new ZS_Store($dataDir);

        // Language handling: check GET/POST/Cookie zs_lang
        $lang = 'en';
        if (!empty($_COOKIE['zs_lang'])) {
            $lang = $_COOKIE['zs_lang'];
        }
        if (!empty($_REQUEST['lang'])) {
            $lang = $_REQUEST['lang'];
            self::setCookieValue('zs_lang', $lang, time() + 86400 * 365, false);
        }
        ZS_I18n::setLang($lang);

        // 1. Setup Wizard: if no key_hash is stored
        if (empty($config['key_hash'])) {
            if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['do_action']) && $_POST['do_action'] === 'setup_wizard') {
                $chosenKey = !empty($_POST['custom_key']) ? trim($_POST['custom_key']) : trim($_POST['generated_key']);
                if (strlen($chosenKey) < 12) {
                    ZS_Ui::renderWizard($rootDir, $config, ZS_I18n::t('wizard_err_short'));
                    return;
                }

                $csrfSecret = bin2hex(random_bytes(32));
                $newConfig = array(
                    'key_hash'    => password_hash($chosenKey, PASSWORD_DEFAULT),
                    'csrf_secret' => $csrfSecret,
                    'created_at'  => time(),
                );
                ZS_Config::saveConfig($newConfig, $dataDir);
                self::setAuthCookie($csrfSecret, $newConfig['key_hash']);
                self::setCsrfCookie($csrfSecret);

                header('Location: ' . self::getCurrentScriptUrl());
                exit;
            }

            ZS_Ui::renderWizard($rootDir, $config);
            return;
        }

        // 2. Authentication Check
        $isAuthenticated = self::authenticate($config);
        if (!$isAuthenticated) {
            if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['do_action']) && $_POST['do_action'] === 'login') {
                $providedKey = isset($_POST['key']) ? trim($_POST['key']) : '';
                if (password_verify($providedKey, $config['key_hash'])) {
                    self::setAuthCookie($config['csrf_secret'], $config['key_hash']);
                    self::setCsrfCookie($config['csrf_secret']);
                    header('Location: ' . self::getCurrentScriptUrl());
                    exit;
                } else {
                    ZS_Ui::renderLogin(ZS_I18n::t('login_err'));
                    return;
                }
            }

            // Check if key was passed via GET
            if (isset($_GET['key']) && password_verify(trim($_GET['key']), $config['key_hash'])) {
                self::setAuthCookie($config['csrf_secret'], $config['key_hash']);
                self::setCsrfCookie($config['csrf_secret']);
                // Strip key from URL while preserving other parameters (e.g. reset=1, lang=fa)
                $queryParams = $_GET;
                unset($queryParams['key']);
                $redirectUrl = self::getCurrentScriptUrl();
                if (!empty($queryParams)) {
                    $redirectUrl .= '?' . http_build_query($queryParams);
                }
                header('Location: ' . $redirectUrl);
                exit;
            }

            ZS_Ui::renderLogin();
            return;
        }

        // Ensure CSRF cookie is present
        if (empty($_COOKIE['zs_csrf']) && !empty($config['csrf_secret'])) {
            self::setCsrfCookie($config['csrf_secret']);
        }

        $action = isset($_REQUEST['do_action']) ? trim($_REQUEST['do_action']) : '';
        $quarantineDir = ZS_Config::getQuarantineDir($rootDir, $dataDir);

        // 3. Routing AJAX and Form Actions
        if ($action !== '') {
            self::routeAction($action, $rootDir, $dataDir, $config, $store, $quarantineDir);
            return;
        }

        // 4. Batch Scanning or Completed Report View
        $actionReset = isset($_GET['reset']) && $_GET['reset'] == '1';
        $session = $store->initSession($rootDir, $actionReset);

        if (!empty($session['is_completed'])) {
            ZS_Ui::renderReport($session, $rootDir, $dataDir, $config, $store);
            return;
        }

        // Run one scan batch (5 seconds or 500 files)
        self::executeScanBatch($session, $rootDir, $dataDir, $store);
    }

    private static function isHttps() {
        return (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off')
            || (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443);
    }

    private static function getCurrentScriptUrl() {
        $scheme = self::isHttps() ? 'https://' : 'http://';
        $host   = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'localhost';
        $uri    = strtok(isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '', '?');
        return $scheme . $host . $uri;
    }

    private static function cookiePath() {
        $script = isset($_SERVER['SCRIPT_NAME']) ? str_replace('\\', '/', $_SERVER['SCRIPT_NAME']) : '/';
        $dir = dirname($script);
        if ($dir === '/' || $dir === '\\' || $dir === '.' || $dir === '') {
            return '/';
        }
        return $dir;
    }

    private static function setCookieValue($name, $value, $expiry, $httpOnly) {
        $path = self::cookiePath();
        if (PHP_VERSION_ID >= 70300) {
            setcookie($name, $value, array(
                'expires'  => $expiry,
                'path'     => $path,
                'secure'   => self::isHttps(),
                'httponly' => $httpOnly,
                'samesite' => 'Lax',
            ));
        } else {
            setcookie($name, $value, $expiry, $path, '', self::isHttps(), $httpOnly);
        }
        $_COOKIE[$name] = $value;
    }

    private static function setAuthCookie($csrfSecret, $keyHash) {
        $expiry = time() + 43200;
        $hash = hash_hmac('sha256', 'zs_auth:' . $expiry . ':' . $keyHash, $csrfSecret);
        $token = $hash . ':' . $expiry;
        self::setCookieValue('zs_session', $token, $expiry, true);
    }

    public static function setCsrfCookie($csrfSecret) {
        $expiry = time() + 43200;
        $hash = hash_hmac('sha256', 'zs_csrf:' . $expiry, $csrfSecret);
        $token = $hash . ':' . $expiry;
        self::setCookieValue('zs_csrf', $token, $expiry, false);
        return $token;
    }

    public static function getCsrfToken($csrfSecret) {
        if (!empty($_COOKIE['zs_csrf']) && !empty($csrfSecret)) {
            $parts = explode(':', $_COOKIE['zs_csrf']);
            if (count($parts) === 2 && time() <= intval($parts[1])) {
                $expected = hash_hmac('sha256', 'zs_csrf:' . $parts[1], $csrfSecret);
                if (hash_equals($expected, $parts[0])) {
                    return $_COOKIE['zs_csrf'];
                }
            }
        }
        return self::setCsrfCookie($csrfSecret);
    }

    private static function verifyCsrf($config) {
        $secret = isset($config['csrf_secret']) ? $config['csrf_secret'] : '';
        if (empty($secret)) {
            return false;
        }

        $token = '';
        if (isset($_SERVER['HTTP_X_CSRF_TOKEN'])) {
            $token = trim($_SERVER['HTTP_X_CSRF_TOKEN']);
        } elseif (isset($_POST['csrf_token'])) {
            $token = trim($_POST['csrf_token']);
        }

        if (empty($token)) {
            return false;
        }

        $parts = explode(':', $token);
        if (count($parts) !== 2) {
            return false;
        }

        $hash   = $parts[0];
        $expiry = intval($parts[1]);

        if (time() > $expiry) {
            return false;
        }

        $expected = hash_hmac('sha256', 'zs_csrf:' . $expiry, $secret);
        return hash_equals($expected, $hash);
    }

    private static function authenticate($config) {
        $secret  = isset($config['csrf_secret']) ? $config['csrf_secret'] : '';
        $keyHash = isset($config['key_hash']) ? $config['key_hash'] : '';
        if (isset($_COOKIE['zs_session']) && $secret !== '' && $keyHash !== '') {
            $parts = explode(':', $_COOKIE['zs_session']);
            if (count($parts) === 2 && time() <= intval($parts[1])) {
                $expected = hash_hmac('sha256', 'zs_auth:' . $parts[1] . ':' . $keyHash, $secret);
                if (hash_equals($expected, $parts[0])) {
                    return true;
                }
            }
        }

        if (isset($_REQUEST['key'])) {
            $key = trim($_REQUEST['key']);
            if (password_verify($key, $config['key_hash'])) {
                return true;
            }
        }

        return false;
    }

    private static function routeAction($action, $rootDir, $dataDir, $config, $store, $quarantineDir) {
        // Mutating actions require POST and CSRF
        $mutatingActions = array(
            'delete_single', 'restore_file', 'mark_clean', 'revoke_trusted',
            'revoke_candidate', 'clear_ai_cache', 'ask_ai', 'auto_review_step',
            'sync_rules', 'save_settings', 'share_bundle', 'self_destruct'
        );

        if (in_array($action, $mutatingActions, true)) {
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                http_response_code(405);
                header('Content-Type: application/json; charset=utf-8');
                echo json_encode(array('success' => false, 'message' => 'Method Not Allowed. POST required.'));
                exit;
            }

            if (!self::verifyCsrf($config)) {
                http_response_code(403);
                header('Content-Type: application/json; charset=utf-8');
                echo json_encode(array('success' => false, 'message' => 'CSRF validation failed.'));
                exit;
            }
        }

        header('Content-Type: application/json; charset=utf-8');

        switch ($action) {
            case 'view_file':
                self::actionViewFile($rootDir);
                break;

            case 'delete_single':
                self::actionDeleteSingle($rootDir, $quarantineDir, $store);
                break;

            case 'restore_file':
                self::actionRestoreFile($rootDir, $quarantineDir);
                break;

            case 'mark_clean':
                self::actionMarkClean($store);
                break;

            case 'revoke_trusted':
                self::actionRevokeTrusted($store);
                break;

            case 'revoke_candidate':
                self::actionRevokeCandidate($store);
                break;

            case 'clear_ai_cache':
                $store->clearAiCache();
                echo json_encode(array('success' => true, 'message' => ZS_I18n::t('toast_cache_cleared')));
                exit;

            case 'sync_rules':
                self::actionSyncRules($config, $dataDir);
                break;

            case 'save_settings':
                self::actionSaveSettings($config, $dataDir);
                break;

            case 'ask_ai':
                self::actionAskAi($rootDir, $config, $store);
                break;

            case 'auto_review_step':
                self::actionAutoReviewStep($rootDir, $config, $store, $quarantineDir);
                break;

            case 'share_bundle':
                self::actionShareBundle($rootDir, $config, $store, $quarantineDir);
                break;

            case 'self_destruct':
                self::actionSelfDestruct($rootDir, $dataDir, $store, $quarantineDir);
                break;

            default:
                http_response_code(400);
                echo json_encode(array('success' => false, 'message' => 'Unknown action.'));
                exit;
        }
    }

    private static function actionViewFile($rootDir) {
        $targetB64 = isset($_REQUEST['file_target']) ? $_REQUEST['file_target'] : '';
        $targetPath = base64_decode($targetB64);

        if (empty($targetPath) || !file_exists($targetPath) || !is_file($targetPath)) {
            echo json_encode(array('success' => false, 'message' => 'File not found.'));
            exit;
        }

        $realTarget = realpath($targetPath);
        if (!$realTarget || !ZS_Config::isPathWithinRoot($realTarget, $rootDir)) {
            echo json_encode(array('success' => false, 'message' => 'Access denied: Path outside root jail.'));
            exit;
        }

        $size = filesize($targetPath);
        $maxPreview = 1024 * 1024; // 1MB preview cap
        $content = @file_get_contents($targetPath, false, null, 0, $maxPreview);

        if ($content === false) {
            echo json_encode(array('success' => false, 'message' => 'Could not read file contents.'));
            exit;
        }

        echo json_encode(array(
            'success'      => true,
            'filename'     => basename($targetPath),
            'path'         => $targetPath,
            'size'         => $size,
            'size_fmt'     => number_format($size) . ' B',
            'content'      => $content,
            'is_truncated' => ($size > $maxPreview),
        ), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        exit;
    }

    private static function actionDeleteSingle($rootDir, $quarantineDir, $store) {
        $targetB64 = isset($_POST['file_target']) ? $_POST['file_target'] : '';
        $targetPath = base64_decode($targetB64);

        $normHash = '';
        if (file_exists($targetPath)) {
            $rawContent = @file_get_contents($targetPath);
            if ($rawContent !== false) {
                $normHash = ZS_Hash::normalized($rawContent);
            }
        }

        $res = ZS_Quarantine::copyThenUnlink($targetPath, $rootDir, $quarantineDir);
        if ($res['success']) {
            // Conflict transition: If candidate, revoke candidate status
            $candidateRevoked = false;
            if (!empty($normHash)) {
                $candidateRevoked = $store->revokeCandidate($normHash);
            }

            // Update status in session
            $session = $store->loadSession();
            if ($session && !empty($session['infected_files'])) {
                foreach ($session['infected_files'] as $idx => $inf) {
                    if ($inf['path'] === $targetPath) {
                        $store->updateInfectedItem($idx, array('status' => 'QUARANTINED'));
                    }
                }
            }

            $msg = $candidateRevoked
                ? ZS_I18n::t('toast_revoked_by_malicious')
                : ZS_I18n::t('toast_quarantined');

            echo json_encode(array(
                'success'           => true,
                'message'           => $msg,
                'candidate_revoked' => $candidateRevoked,
            ));
        } else {
            echo json_encode(array('success' => false, 'message' => $res['message']));
        }
        exit;
    }

    private static function actionRestoreFile($rootDir, $quarantineDir) {
        $backupName = isset($_POST['backup_name']) ? trim($_POST['backup_name']) : '';
        $res = ZS_Quarantine::restore($backupName, $rootDir, $quarantineDir);
        if ($res['success']) {
            echo json_encode(array('success' => true, 'message' => ZS_I18n::t('toast_restored'), 'path' => $res['path']));
        } else {
            echo json_encode(array('success' => false, 'message' => $res['message']));
        }
        exit;
    }

    private static function actionMarkClean($store) {
        $normHash = isset($_POST['norm_hash']) ? trim($_POST['norm_hash']) : '';
        $path     = isset($_POST['path']) ? trim($_POST['path']) : '';

        if (empty($normHash) || empty($path)) {
            echo json_encode(array('success' => false, 'message' => 'Missing hash or path.'));
            exit;
        }

        $session = $store->loadSession();
        $sessionId = isset($session['scan_session_id']) ? $session['scan_session_id'] : 'session_default';

        $res = $store->markClean($normHash, $path, $sessionId);

        $msg = '';
        if ($res['status'] === 'promoted_to_trusted') {
            $msg = ZS_I18n::t('toast_strike2');
        } elseif ($res['status'] === 'candidate_added') {
            $msg = ZS_I18n::t('toast_strike1');
        } elseif ($res['status'] === 'already_trusted') {
            $msg = ZS_I18n::t('toast_already_trusted');
        } else {
            $msg = ZS_I18n::t('strike1_warning', array('sample_path' => $path));
        }

        echo json_encode(array(
            'success' => true,
            'status'  => $res['status'],
            'message' => $msg,
        ));
        exit;
    }

    private static function actionRevokeTrusted($store) {
        $normHash = isset($_POST['norm_hash']) ? trim($_POST['norm_hash']) : '';
        if ($store->revokeTrusted($normHash)) {
            echo json_encode(array('success' => true, 'message' => ZS_I18n::t('toast_trusted_revoked')));
        } else {
            echo json_encode(array('success' => false, 'message' => 'Hash not found in trusted list.'));
        }
        exit;
    }

    private static function actionRevokeCandidate($store) {
        $normHash = isset($_POST['norm_hash']) ? trim($_POST['norm_hash']) : '';
        if ($store->revokeCandidate($normHash)) {
            echo json_encode(array('success' => true, 'message' => 'Candidate status revoked.'));
        } else {
            echo json_encode(array('success' => false, 'message' => 'Hash not found in candidates list.'));
        }
        exit;
    }

    private static function actionSyncRules($config, $dataDir) {
        $syncUrl = !empty($config['rules_sync_url']) ? $config['rules_sync_url'] : 'https://raw.githubusercontent.com/OWNER/REPO/main/rules/database.json';
        $res = ZS_Gemini::executeHttpRequest($syncUrl, array('User-Agent: ZeroShell-Cleaner/1.0'), '');

        if (!isset($res['status']) || $res['status'] < 200 || $res['status'] >= 300 || empty($res['body'])) {
            echo json_encode(array('success' => false, 'message' => 'Could not fetch rules from URL: ' . $syncUrl));
            exit;
        }

        $validated = ZS_Rules::validatePayload($res['body']);
        if ($validated === false) {
            echo json_encode(array('success' => false, 'message' => 'Fetched rules payload is invalid or exceeds 512KB.'));
            exit;
        }

        $dest = $dataDir . '/rules_override.json';
        @file_put_contents($dest, $res['body']);

        $activeRules = ZS_Rules::load(ZS_Config::getRoot(), $dataDir);
        $sigs = count(isset($activeRules['signatures']) ? $activeRules['signatures'] : array());
        $hashes = count(isset($activeRules['hashes']) ? $activeRules['hashes'] : array());

        $msg = ZS_I18n::t('toast_rules_updated', array('sigs' => $sigs, 'hashes' => $hashes));
        echo json_encode(array(
            'success'    => true,
            'message'    => $msg,
            'signatures' => $sigs,
            'hashes'     => $hashes,
        ));
        exit;
    }

    private static function actionSaveSettings($config, $dataDir) {
        $updates = array();

        if (!empty($_POST['new_access_key'])) {
            $newKey = trim($_POST['new_access_key']);
            if (strlen($newKey) < 12) {
                echo json_encode(array('success' => false, 'message' => ZS_I18n::t('wizard_err_short')));
                exit;
            }
            $updates['key_hash'] = password_hash($newKey, PASSWORD_DEFAULT);
        }

        if (isset($_POST['gemini_api_keys'])) {
            $rawKeys = preg_split('/[\r\n,]+/', $_POST['gemini_api_keys']);
            $keys = array();
            foreach ($rawKeys as $k) {
                $t = trim($k);
                if ($t !== '') {
                    $keys[] = $t;
                }
            }
            $updates['gemini_api_keys'] = $keys;
        }

        if (!empty($_POST['gemini_model'])) {
            $updates['gemini_model'] = trim($_POST['gemini_model']);
        }

        if (isset($_POST['rules_sync_url'])) {
            $updates['rules_sync_url'] = trim($_POST['rules_sync_url']);
        }

        if (isset($_POST['github_repo'])) {
            $updates['github_repo'] = trim($_POST['github_repo']);
        }

        if (isset($_POST['report_endpoint'])) {
            $updates['report_endpoint'] = trim($_POST['report_endpoint']);
        }

        ZS_Config::saveConfig($updates, $dataDir);
        echo json_encode(array('success' => true, 'message' => 'Settings saved successfully.'));
        exit;
    }

    private static function actionAskAi($rootDir, $config, $store) {
        $targetB64 = isset($_POST['file_target']) ? $_POST['file_target'] : '';
        $targetPath = base64_decode($targetB64);

        if (empty($targetPath) || !file_exists($targetPath)) {
            echo json_encode(array('success' => false, 'message' => 'File not found.'));
            exit;
        }

        $realTarget = realpath($targetPath);
        if (!$realTarget || !ZS_Config::isPathWithinRoot($realTarget, $rootDir)) {
            echo json_encode(array('success' => false, 'message' => 'Target outside root jail.'));
            exit;
        }

        $content = @file_get_contents($targetPath);
        if ($content === false) {
            echo json_encode(array('success' => false, 'message' => 'Could not read file.'));
            exit;
        }

        $normHash = ZS_Hash::normalized($content);
        $reasons = isset($_POST['reasons']) ? (array)$_POST['reasons'] : array('Manual review requested');

        $verdict = ZS_Gemini::ask($normHash, $targetPath, $content, $reasons, $config, $store);

        // Conflict transition: If high-confidence malicious, revoke candidate status
        $candidateRevoked = false;
        if ($verdict['verdict'] === 'malicious' && $verdict['confidence'] >= 0.85) {
            $candidateRevoked = $store->revokeCandidate($normHash);
        }

        echo json_encode(array(
            'success'           => true,
            'verdict'           => $verdict,
            'candidate_revoked' => $candidateRevoked,
            'candidate_message' => $candidateRevoked ? ZS_I18n::t('toast_revoked_by_malicious') : '',
        ));
        exit;
    }

    private static function actionAutoReviewStep($rootDir, $config, $store, $quarantineDir) {
        if (!empty($_POST['force_error'])) {
            $claimed = $store->claimNextInfectedForAutoReview();
            if ($claimed !== null) {
                $store->updateInfectedItem($claimed['index'], array('status' => 'AI_ERROR'));
                echo json_encode(array(
                    'finished'        => false,
                    'path'            => $claimed['item']['path'],
                    'action_taken'    => 'error',
                    'remaining_count' => self::getRemainingFoundCount($store),
                ));
                exit;
            }
        }

        $claimed = $store->claimNextInfectedForAutoReview();
        if ($claimed === null) {
            // Count remaining
            echo json_encode(array(
                'finished' => true,
                'message'  => ZS_I18n::t('auto_ai_done'),
            ));
            exit;
        }

        $itemIndex = $claimed['index'];
        $item = $claimed['item'];
        $path = $item['path'];

        if (!file_exists($path)) {
            $store->updateInfectedItem($itemIndex, array('status' => 'AI_SKIPPED'));
            echo json_encode(array(
                'finished'        => false,
                'path'            => $path,
                'action_taken'    => 'skipped_missing',
                'cache_hit'       => false,
                'remaining_count' => self::getRemainingFoundCount($store),
            ));
            exit;
        }

        $content = @file_get_contents($path);
        $normHash = isset($item['norm_sha256']) ? $item['norm_sha256'] : ZS_Hash::normalized($content);
        $reasons  = isset($item['reason']) ? explode(' | ', $item['reason']) : array();

        $verdict = ZS_Gemini::ask($normHash, $path, $content, $reasons, $config, $store);

        $isMalicious = ($verdict['verdict'] === 'malicious');
        $isHighConf  = ($verdict['confidence'] >= 0.85);
        $isQuarantine = ($verdict['recommended_action'] === 'quarantine');

        $actionTaken = 'skipped';
        $newStatus   = 'AI_SKIPPED';
        $candidateRevoked = false;

        if (isset($verdict['error']) && $verdict['error'] === 'all_cooling') {
            // Revert status to FOUND so retry works
            $store->updateInfectedItem($itemIndex, array('status' => 'FOUND'));
            echo json_encode(array(
                'finished'        => false,
                'error'           => 'all_cooling',
                'retry_after'     => isset($verdict['retry_after']) ? $verdict['retry_after'] : 20,
                'remaining_count' => self::getRemainingFoundCount($store),
            ));
            exit;
        }

        if (isset($verdict['error'])) {
            $actionTaken = 'error';
            $newStatus   = 'AI_ERROR';
        } elseif ($isMalicious && $isHighConf && $isQuarantine) {
            // Revoke candidate status if existed
            $candidateRevoked = $store->revokeCandidate($normHash);

            $qRes = ZS_Quarantine::copyThenUnlink($path, $rootDir, $quarantineDir);
            if ($qRes['success']) {
                $actionTaken = 'quarantined';
                $newStatus   = 'AI_QUARANTINED';
            } else {
                $actionTaken = 'failed_quarantine';
                $newStatus   = 'FAILED_DELETE';
            }
        } elseif ($isMalicious && $isHighConf) {
            $candidateRevoked = $store->revokeCandidate($normHash);
        }

        $store->updateInfectedItem($itemIndex, array(
            'status'     => $newStatus,
            'ai_verdict' => $verdict,
        ));

        $activeIdx = isset($config['active_key_index']) ? $config['active_key_index'] : 0;
        $totalKeys = count(ZS_Config::getGeminiKeys($config));

        echo json_encode(array(
            'finished'          => false,
            'path'              => $path,
            'verdict'           => $verdict['verdict'],
            'confidence'        => $verdict['confidence'],
            'cache_hit'         => !empty($verdict['cache_hit']),
            'action_taken'      => $actionTaken,
            'candidate_revoked' => $candidateRevoked,
            'active_key_index'  => $activeIdx + 1,
            'total_keys'        => $totalKeys,
            'remaining_count'   => self::getRemainingFoundCount($store),
        ));
        exit;
    }

    private static function getRemainingFoundCount($store) {
        $session = $store->loadSession();
        if (!$session || empty($session['infected_files'])) {
            return 0;
        }
        $count = 0;
        foreach ($session['infected_files'] as $f) {
            if (isset($f['status']) && $f['status'] === 'FOUND') {
                $count++;
            }
        }
        return $count;
    }

    private static function actionShareBundle($rootDir, $config, $store, $quarantineDir) {
        $session = $store->loadSession();
        $bundle  = ZS_Share::buildBundle($session, $rootDir);

        $submitMaintainer = !empty($_POST['submit_maintainer']);
        if ($submitMaintainer) {
            $hasConsent = !empty($_POST['consent']);
            $includeSamples = !empty($_POST['include_samples']);
            $endpoint = !empty($config['report_endpoint']) ? $config['report_endpoint'] : '';

            $res = ZS_Share::submitToMaintainer($bundle, $endpoint, $hasConsent, $includeSamples, $quarantineDir);
            echo json_encode($res);
            exit;
        }

        $githubRepo = !empty($config['github_repo']) ? $config['github_repo'] : 'OWNER/REPO';
        $shareData = ZS_Share::getGithubShareData($bundle, $githubRepo);

        echo json_encode(array(
            'success'        => true,
            'bundle'         => $bundle,
            'github_url'     => $shareData['url'],
            'markdown_body'  => $shareData['body'],
            'need_clipboard' => $shareData['need_clipboard'],
        ));
        exit;
    }

    private static function actionSelfDestruct($rootDir, $dataDir, $store, $quarantineDir) {
        $deleteKnowledge = !empty($_POST['delete_knowledge']);
        $deleteQuarantine = !empty($_POST['delete_quarantine']);

        $store->resetSession();

        if ($deleteKnowledge) {
            $knowledge = $store->getKnowledgeFile();
            if (file_exists($knowledge)) {
                @unlink($knowledge);
            }
            $configFile = ZS_Config::getConfigFile($dataDir);
            if (file_exists($configFile)) {
                @unlink($configFile);
            }
            $override = $dataDir . '/rules_override.json';
            if (file_exists($override)) {
                @unlink($override);
            }
        }

        if ($deleteQuarantine && is_dir($quarantineDir)) {
            $manifest = ZS_Quarantine::getManifest($quarantineDir);
            foreach ($manifest as $backupName => $meta) {
                $backupPath = $quarantineDir . '/' . basename($backupName);
                if (is_file($backupPath)) {
                    @unlink($backupPath);
                }
            }
            @unlink($quarantineDir . '/manifest.json');
        }

        $script = isset($_SERVER['SCRIPT_FILENAME']) ? realpath($_SERVER['SCRIPT_FILENAME']) : realpath(__FILE__);
        $deletedSelf = false;
        if ($script && is_file($script) && ZS_Config::isPathWithinRoot($script, $rootDir)) {
            $deletedSelf = @unlink($script);
        }

        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(array(
            'success'      => true,
            'deleted_self' => $deletedSelf,
            'message'      => ZS_I18n::t('toast_self_destructed'),
        ));
        exit;
    }

    public static function executeScanBatch(&$session, $rootDir, $dataDir, $store) {
        $batchStartTime = microtime(true);
        $maxBatchSeconds = 5.0;
        $maxFilesPerBatch = 500;
        $filesInThisBatch = 0;

        $rules = ZS_Rules::load($rootDir, $dataDir);
        $quarantineDir = ZS_Config::getQuarantineDir($rootDir, $dataDir);
        $realSelf   = realpath(__FILE__);
        $realScript = isset($_SERVER['SCRIPT_FILENAME']) ? realpath($_SERVER['SCRIPT_FILENAME']) : null;

        while (!empty($session['dir_queue'])) {
            if ((microtime(true) - $batchStartTime) >= $maxBatchSeconds || $filesInThisBatch >= $maxFilesPerBatch) {
                break;
            }

            $currentDir = array_shift($session['dir_queue']);
            $session['current_dir'] = $currentDir;
            $session['scanned_dirs']++;

            $items = @scandir($currentDir);
            if ($items === false) {
                continue;
            }

            foreach ($items as $item) {
                if ($item === '.' || $item === '..' || $item === '.git' || $item === 'malware_quarantine' || $item === 'malware_cleaner_data') {
                    continue;
                }

                $path = rtrim($currentDir, '/\\') . DIRECTORY_SEPARATOR . $item;

                if (is_dir($path)) {
                    // Skip quarantine or data directory paths
                    $realPath = realpath($path);
                    if ($realPath && ($realPath === realpath($quarantineDir) || $realPath === realpath($dataDir))) {
                        continue;
                    }
                    $session['dir_queue'][] = $path;
                } elseif (is_file($path)) {
                    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
                    $filename = strtolower($item);

                    $isSuspiciousExt = ($ext === 'php' || strpos($filename, '.php') !== false || $ext === 'suspected' || $ext === 'bak');
                    if (!$isSuspiciousExt) {
                        continue;
                    }

                    $realP = realpath($path);
                    if ($realP && ($realP === $realSelf || ($realScript && $realP === $realScript))) {
                        continue;
                    }

                    $session['scanned_files']++;
                    $filesInThisBatch++;

                    $content = @file_get_contents($path);
                    if ($content === false || $content === '') {
                        continue;
                    }

                    $rawHash  = ZS_Hash::raw($content);
                    $normHash = ZS_Hash::normalized($content);

                    // If normHash is already trusted in knowledge, bypass!
                    if ($store->isTrusted($normHash)) {
                        $session['trusted_bypassed']++;
                        continue;
                    }

                    $engineResult = ZS_Engine::scanFile($path, $item, $content, $normHash, $rules, $rootDir);
                    if ($engineResult['detected']) {
                        $session['infected_files'][] = array(
                            'path'        => $path,
                            'reason'      => implode(' | ', $engineResult['reasons']),
                            'size'        => filesize($path),
                            'status'      => 'FOUND',
                            'raw_sha256'  => $rawHash,
                            'norm_sha256' => $normHash,
                        );
                    }
                }
            }
        }

        if (empty($session['dir_queue'])) {
            $session['is_completed'] = true;
        }

        $store->saveSession($session);

        if (php_sapi_name() === 'cli') {
            echo "Progress: " . intval($session['scanned_files']) . " files scanned. Queue: " . count($session['dir_queue']) . " dirs. Infected: " . count($session['infected_files']) . "\n";
            if (!$session['is_completed']) {
                $script = !empty($_SERVER['SCRIPT_FILENAME']) ? $_SERVER['SCRIPT_FILENAME'] : __FILE__;
                passthru('php ' . escapeshellarg($script));
            } else {
                echo "\n=== SCAN COMPLETE ===\n";
                echo "Scanned Files: " . intval($session['scanned_files']) . "\n";
                echo "Scanned Dirs: " . intval($session['scanned_dirs']) . "\n";
                echo "Threats Found: " . count($session['infected_files']) . "\n";
                echo "Trusted Bypassed: " . intval($session['trusted_bypassed']) . "\n";
            }
        } else {
            ZS_Ui::renderScanProgress($session, $rootDir);
        }
    }
}
