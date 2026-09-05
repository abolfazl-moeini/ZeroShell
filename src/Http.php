<?php
class ZS_Http {
    public static function handleRequest($rootDir = null, $dataDir = null) {
        ZS_Config::sendSecurityHeaders();
        if ($rootDir === null) {
            $rootDir = ZS_Config::getRoot();
        }
        if ($dataDir === null) {
            $dataDir = ZS_Config::getDataDir($rootDir);
        }

        $config = ZS_Config::loadConfig($dataDir);
        $store  = new ZS_Store($dataDir);

        $lang = 'en';
        if (!empty($_COOKIE['zs_lang'])) {
            $lang = $_COOKIE['zs_lang'];
        }
        if (!empty($_REQUEST['lang'])) {
            $lang = $_REQUEST['lang'];
            self::setCookieValue('zs_lang', $lang === 'fa' ? 'fa' : 'en', time() + 86400 * 365, false);
        }
        ZS_I18n::setLang($lang);

        $method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';
        $action = '';
        if (isset($_POST['do_action'])) {
            $action = trim((string)$_POST['do_action']);
        } elseif (isset($_GET['do_action'])) {
            $action = trim((string)$_GET['do_action']);
        }

        if ($method === 'POST' && $action === 'setup_wizard') {
            if (!empty($config['key_hash'])) {
                http_response_code(403);
                header('Content-Type: text/plain; charset=UTF-8');
                echo 'Setup has already been completed.';
                return;
            }
            self::handleSetup($rootDir, $dataDir, $config);
            return;
        }

        if (empty($config['key_hash'])) {
            ZS_Ui::renderWizard($rootDir, $config);
            return;
        }

        if ($method === 'POST' && $action === 'login') {
            self::handleLogin($config, $store, $dataDir);
            return;
        }

        if ($method === 'POST' && $action === 'logout') {
            self::clearAuthCookies();
            header('Location: ' . self::getCurrentScriptUrl());
            exit;
        }

        if ($method === 'GET' && isset($_GET['key'])) {
            if (self::isLoginLocked($store)) {
                ZS_Ui::renderLogin(ZS_I18n::t('login_locked'));
                return;
            }
            if (password_verify(trim((string)$_GET['key']), $config['key_hash'])) {
                self::clearLoginFailures($store);
                self::setAuthCookie($config['csrf_secret'], $config['key_hash']);
                self::setCsrfCookie($config['csrf_secret'], self::currentSessionToken());
                $queryParams = $_GET;
                unset($queryParams['key']);
                $redirectUrl = self::getCurrentScriptUrl();
                if (!empty($queryParams)) {
                    $redirectUrl .= '?' . http_build_query($queryParams);
                }
                header('Location: ' . $redirectUrl);
                exit;
            } else {
                self::noteLoginFailure($store);
                ZS_Ui::renderLogin(ZS_I18n::t('login_err'));
                return;
            }
        }

        if (!self::isCookieAuthenticated($config)) {
            if (self::wantsJson()) {
                http_response_code(401);
                header('Content-Type: application/json; charset=utf-8');
                echo json_encode(array('success' => false, 'message' => 'Authentication required.', 'code' => 'AUTH'), ZS_Config::jsonFlags());
                exit;
            }
            ZS_Ui::renderLogin();
            return;
        }

        if (empty($_COOKIE['zs_csrf']) && !empty($config['csrf_secret'])) {
            self::setCsrfCookie($config['csrf_secret'], self::currentSessionToken());
        }

        $quarantineDir = ZS_Config::getQuarantineDir($rootDir, $dataDir);

        if ($method === 'GET' && isset($_GET['reset']) && $_GET['reset'] == '1') {
            http_response_code(405);
            echo 'Reset requires POST.';
            return;
        }

        if ($method === 'POST' && $action === 'reset_scan') {
            if (!self::verifyCsrf($config)) {
                self::jsonFail(403, 'CSRF validation failed.');
            }
            $session = $store->loadSession();
            if (is_array($session) && isset($session['auto_review']['status']) && $session['auto_review']['status'] === 'running') {
                self::jsonFail(409, 'Cannot reset while auto-review is running.');
            }
            $store->resetSession();
            header('Location: ' . self::getCurrentScriptUrl());
            exit;
        }

        if ($action !== '') {
            self::routeAction($action, $rootDir, $dataDir, $config, $store, $quarantineDir);
            return;
        }

        $session = $store->initSession($rootDir, false);
        if ($session === false) {
            echo 'Failed to load scan session: ' . htmlspecialchars($store->lastError);
            return;
        }

        if (!empty($session['is_completed'])) {
            ZS_Ui::renderReport($session, $rootDir, $dataDir, $config, $store);
            return;
        }

        $store->withNamedLock('scan_batch', function () use (&$session, $rootDir, $dataDir, $store) {
            $fresh = $store->loadSessionUnlocked();
            if (is_array($fresh)) {
                $session = $fresh;
            }
            if (!empty($session['is_completed'])) {
                return;
            }
            self::executeScanBatch($session, $rootDir, $dataDir, $store);
        });

        if (!empty($session['is_completed']) && php_sapi_name() !== 'cli') {
            ZS_Ui::renderReport($session, $rootDir, $dataDir, $config, $store);
            return;
        }
    }

    private static function wantsJson() {
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH'])) {
            return true;
        }
        $accept = isset($_SERVER['HTTP_ACCEPT']) ? $_SERVER['HTTP_ACCEPT'] : '';
        return (strpos($accept, 'application/json') !== false);
    }

    private static function jsonFail($code, $message, $extra = array()) {
        http_response_code($code);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(array_merge(array('success' => false, 'message' => $message), $extra), ZS_Config::jsonFlags());
        exit;
    }

    private static function jsonOk($payload) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(array_merge(array('success' => true), $payload), ZS_Config::jsonFlags());
        exit;
    }

    private static function handleSetup($rootDir, $dataDir, $config) {
        $secret = ZS_Config::readSetupSecret($rootDir);
        $provided = isset($_POST['setup_secret']) ? trim((string)$_POST['setup_secret']) : '';
        if ($secret === '' || !hash_equals($secret, $provided)) {
            ZS_Ui::renderWizard($rootDir, $config, ZS_I18n::t('wizard_err_setup_secret'));
            return;
        }
        $chosenKey = !empty($_POST['custom_key']) ? trim($_POST['custom_key']) : trim(isset($_POST['generated_key']) ? $_POST['generated_key'] : '');
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
        if (!ZS_Config::saveConfig($newConfig, $dataDir)) {
            ZS_Ui::renderWizard($rootDir, $config, ZS_I18n::t('wizard_err_write'));
            return;
        }
        self::setAuthCookie($csrfSecret, $newConfig['key_hash']);
        self::setCsrfCookie($csrfSecret, self::currentSessionToken());
        $secretFile = ZS_Config::getSetupSecretPath($rootDir);
        if (is_file($secretFile)) {
            @unlink($secretFile);
        }
        header('Location: ' . self::getCurrentScriptUrl());
        exit;
    }

    private static function handleLogin($config, $store, $dataDir) {
        if (self::isLoginLocked($store)) {
            ZS_Ui::renderLogin(ZS_I18n::t('login_locked'));
            return;
        }
        $providedKey = isset($_POST['key']) ? trim((string)$_POST['key']) : '';
        if ($providedKey !== '' && password_verify($providedKey, $config['key_hash'])) {
            self::clearLoginFailures($store);
            self::setAuthCookie($config['csrf_secret'], $config['key_hash']);
            self::setCsrfCookie($config['csrf_secret'], self::currentSessionToken());
            header('Location: ' . self::getCurrentScriptUrl());
            exit;
        }
        self::noteLoginFailure($store);
        ZS_Ui::renderLogin(ZS_I18n::t('login_err'));
    }

    private static function clientIp() {
        return isset($_SERVER['REMOTE_ADDR']) ? (string)$_SERVER['REMOTE_ADDR'] : '0.0.0.0';
    }

    private static function isLoginLocked($store) {
        $k = $store->loadKnowledge();
        if (!is_array($k) || empty($k['login_attempts'])) {
            return false;
        }
        $ip = self::clientIp();
        if (!isset($k['login_attempts'][$ip])) {
            return false;
        }
        $row = $k['login_attempts'][$ip];
        return isset($row['locked_until']) && time() < intval($row['locked_until']);
    }

    private static function noteLoginFailure($store) {
        $ip = self::clientIp();
        $store->mutateKnowledge(function ($k) use ($ip) {
            if (!isset($k['login_attempts']) || !is_array($k['login_attempts'])) {
                $k['login_attempts'] = array();
            }
            $row = isset($k['login_attempts'][$ip]) ? $k['login_attempts'][$ip] : array('count' => 0);
            $row['count'] = isset($row['count']) ? intval($row['count']) + 1 : 1;
            $row['last'] = time();
            if ($row['count'] >= 8) {
                $row['locked_until'] = time() + 900;
            }
            $k['login_attempts'][$ip] = $row;
            return array('_knowledge' => $k);
        });
    }

    private static function clearLoginFailures($store) {
        $ip = self::clientIp();
        $store->mutateKnowledge(function ($k) use ($ip) {
            if (isset($k['login_attempts'][$ip])) {
                unset($k['login_attempts'][$ip]);
            }
            return array('_knowledge' => $k);
        });
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
        $dir = rtrim(str_replace('\\', '/', dirname($script)), '/');
        if ($dir === '' || $dir === '.' || $dir === '/') {
            return '/';
        }
        return $dir;
    }

    private static function setCookieValue($name, $value, $expiry, $httpOnly) {
        $path = self::cookiePath();
        if (!headers_sent()) {
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
        }
        $_COOKIE[$name] = $value;
    }

    private static function currentSessionToken() {
        return isset($_COOKIE['zs_session']) ? $_COOKIE['zs_session'] : '';
    }

    private static function setAuthCookie($csrfSecret, $keyHash) {
        $expiry = time() + 43200;
        $hash = hash_hmac('sha256', 'zs_auth:' . $expiry . ':' . $keyHash, $csrfSecret);
        $token = $hash . ':' . $expiry;
        self::setCookieValue('zs_session', $token, $expiry, true);
    }

    public static function setCsrfCookie($csrfSecret, $sessionToken = '') {
        $expiry = time() + 43200;
        $hash = hash_hmac('sha256', 'zs_csrf:' . $expiry . ':' . $sessionToken, $csrfSecret);
        $token = $hash . ':' . $expiry;
        self::setCookieValue('zs_csrf', $token, $expiry, false);
        return $token;
    }

    public static function getCsrfToken($csrfSecret) {
        $sessionToken = self::currentSessionToken();
        if (!empty($_COOKIE['zs_csrf']) && !empty($csrfSecret)) {
            $parts = explode(':', $_COOKIE['zs_csrf']);
            if (count($parts) === 2 && time() <= intval($parts[1])) {
                $expected = hash_hmac('sha256', 'zs_csrf:' . $parts[1] . ':' . $sessionToken, $csrfSecret);
                if (hash_equals($expected, $parts[0])) {
                    return $_COOKIE['zs_csrf'];
                }
            }
        }
        return self::setCsrfCookie($csrfSecret, $sessionToken);
    }

    private static function verifyCsrf($config) {
        $secret = isset($config['csrf_secret']) ? $config['csrf_secret'] : '';
        if ($secret === '') {
            return false;
        }
        $token = '';
        if (isset($_SERVER['HTTP_X_CSRF_TOKEN'])) {
            $token = trim($_SERVER['HTTP_X_CSRF_TOKEN']);
        } elseif (isset($_POST['csrf_token'])) {
            $token = trim($_POST['csrf_token']);
        }
        if ($token === '') {
            return false;
        }
        $parts = explode(':', $token);
        if (count($parts) !== 2) {
            return false;
        }
        $expiry = intval($parts[1]);
        if (time() > $expiry) {
            return false;
        }
        $expected = hash_hmac('sha256', 'zs_csrf:' . $expiry . ':' . self::currentSessionToken(), $secret);
        return hash_equals($expected, $parts[0]);
    }

    private static function isCookieAuthenticated($config) {
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
        return false;
    }

    private static function clearAuthCookies() {
        self::setCookieValue('zs_session', '', time() - 3600, true);
        self::setCookieValue('zs_csrf', '', time() - 3600, false);
        unset($_COOKIE['zs_session'], $_COOKIE['zs_csrf']);
    }

    private static function routeAction($action, $rootDir, $dataDir, $config, $store, $quarantineDir) {
        $mutating = array(
            'delete_single', 'restore_file', 'mark_clean', 'revoke_trusted',
            'revoke_candidate', 'clear_ai_cache', 'ask_ai', 'auto_review_step',
            'auto_review_control', 'save_settings', 'share_bundle', 'test_gemini',
            'reset_scan', 'sync_rules',
        );
        if (in_array($action, $mutating, true)) {
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                self::jsonFail(405, 'Method Not Allowed. POST required.');
            }
            if (!self::verifyCsrf($config)) {
                self::jsonFail(403, 'CSRF validation failed.');
            }
        }

        switch ($action) {
            case 'view_file':
                self::actionViewFile($rootDir, $store);
                break;
            case 'delete_single':
                self::actionDeleteSingle($rootDir, $quarantineDir, $store);
                break;
            case 'restore_file':
                self::actionRestoreFile($rootDir, $quarantineDir, $store);
                break;
            case 'mark_clean':
                self::actionMarkClean($rootDir, $store);
                break;
            case 'revoke_trusted':
                $norm = isset($_POST['raw_hash']) ? trim($_POST['raw_hash']) : (isset($_POST['norm_hash']) ? trim($_POST['norm_hash']) : '');
                $ok = $store->revokeTrusted($norm);
                self::jsonOk(array('message' => $ok ? ZS_I18n::t('toast_trusted_revoked') : 'Hash not found.'));
                break;
            case 'clear_ai_cache':
                $store->clearAiCache();
                self::jsonOk(array('message' => ZS_I18n::t('toast_cache_cleared')));
                break;
            case 'save_settings':
                self::actionSaveSettings($config, $dataDir);
                break;
            case 'sync_rules':
                $url = !empty($config['rules_sync_url']) ? $config['rules_sync_url'] : '';
                if (isset($_POST['rules_sync_url']) && trim($_POST['rules_sync_url']) !== '') {
                    $url = trim($_POST['rules_sync_url']);
                }
                if (empty($url)) {
                    self::jsonFail(400, 'Remote rules sync is disabled. Configure rules_sync_url first.');
                }
                $res = ZS_Rules::syncFromUrl($url, $dataDir);
                if (!empty($res['success'])) {
                    self::jsonOk($res);
                }
                self::jsonFail(400, $res['message']);
                break;
            case 'ask_ai':
                self::actionAskAi($rootDir, $config, $store, $dataDir);
                break;
            case 'auto_review_step':
                self::actionAutoReviewStep($rootDir, $config, $store, $quarantineDir, $dataDir);
                break;
            case 'auto_review_control':
                self::actionAutoReviewControl($store);
                break;
            case 'share_bundle':
                self::actionShareBundle($rootDir, $config, $store, $quarantineDir);
                break;
            case 'test_gemini':
                self::jsonOk(ZS_Gemini::ping($config));
                break;
            default:
                self::jsonFail(400, 'Unknown action.');
        }
    }

    private static function resolveFinding($store, $rootDir, $mustExist = true) {
        $fid = isset($_POST['finding_id']) ? trim((string)$_POST['finding_id']) : (isset($_GET['finding_id']) ? trim((string)$_GET['finding_id']) : '');
        $sid = isset($_POST['scan_session_id']) ? trim((string)$_POST['scan_session_id']) : (isset($_GET['scan_session_id']) ? trim((string)$_GET['scan_session_id']) : '');
        $expected = isset($_POST['expected_raw']) ? trim((string)$_POST['expected_raw']) : (isset($_GET['expected_raw']) ? trim((string)$_GET['expected_raw']) : '');
        $session = $store->loadSession();
        if (!is_array($session) || $sid === '' || $session['scan_session_id'] !== $sid) {
            return array('ok' => false, 'message' => 'Session mismatch.');
        }
        $found = $store->findInfected($session, $fid);
        if ($found === null) {
            return array('ok' => false, 'message' => 'Finding not found.');
        }
        $item = $found['item'];
        $path = $item['path'];
        if (ZS_Config::isProtectedPath($path, $rootDir, $store->getDataDir())) {
            return array('ok' => false, 'message' => 'Protected path.');
        }
        if ($mustExist) {
            if (!ZS_Config::isRegularFile($path) || ZS_Config::pathHasSymlink($path, $rootDir) || !ZS_Config::isPathWithinRoot($path, $rootDir)) {
                return array('ok' => false, 'message' => 'File is not a readable regular file inside the site root.', 'code' => 'MISSING');
            }
            $currentRaw = ZS_Hash::rawFile($path);
            $sessionRaw = isset($item['raw_sha256']) ? (string)$item['raw_sha256'] : '';
            if ($currentRaw === false || $sessionRaw === '' || !hash_equals($sessionRaw, $currentRaw)) {
                $store->updateInfectedItem($found['index'], array('status' => 'CHANGED_SINCE_SCAN'));
                return array('ok' => false, 'message' => 'File changed since scan.', 'code' => 'CHANGED_SINCE_SCAN', 'index' => $found['index']);
            }
            if ($expected !== '' && !hash_equals($sessionRaw, $expected)) {
                return array('ok' => false, 'message' => 'Expected hash mismatch.', 'code' => 'CHANGED_SINCE_SCAN', 'index' => $found['index']);
            }
            return array('ok' => true, 'session' => $session, 'index' => $found['index'], 'item' => $item, 'path' => $path, 'raw' => $currentRaw);
        }
        return array('ok' => true, 'session' => $session, 'index' => $found['index'], 'item' => $item, 'path' => $path, 'raw' => isset($item['raw_sha256']) ? $item['raw_sha256'] : '');
    }

    private static function actionViewFile($rootDir, $store) {
        $resolved = self::resolveFinding($store, $rootDir, true);
        if (empty($resolved['ok'])) {
            self::jsonFail(400, $resolved['message'], array('code' => isset($resolved['code']) ? $resolved['code'] : ''));
        }
        $path = $resolved['path'];
        $size = filesize($path);
        $maxPreview = 1024 * 1024;
        $content = @file_get_contents($path, false, null, 0, $maxPreview);
        if ($content === false) {
            self::jsonFail(500, 'Could not read file contents.');
        }
        self::jsonOk(array(
            'filename'     => basename($path),
            'path'         => $path,
            'size'         => $size,
            'size_fmt'     => number_format($size) . ' B',
            'content'      => $content,
            'is_truncated' => ($size > $maxPreview),
            'raw_sha256'   => $resolved['raw'],
            'finding_id'   => $resolved['item']['finding_id'],
        ));
    }

    private static function actionDeleteSingle($rootDir, $quarantineDir, $store) {
        $resolved = self::resolveFinding($store, $rootDir, true);
        if (empty($resolved['ok'])) {
            self::jsonFail(400, $resolved['message'], array('code' => isset($resolved['code']) ? $resolved['code'] : ''));
        }
        $res = ZS_Quarantine::copyThenUnlink($resolved['path'], $rootDir, $quarantineDir, array(
            'finding_id'   => $resolved['item']['finding_id'],
            'expected_raw' => $resolved['raw'],
        ));
        if ($res['success']) {
            $store->revokeCandidate($resolved['raw']);
            $store->updateInfectedItem($resolved['index'], array('status' => 'QUARANTINED', 'backup_name' => $res['backup_name']));
            self::jsonOk(array('message' => ZS_I18n::t('toast_quarantined'), 'backup_name' => $res['backup_name']));
        }
        self::jsonFail(500, $res['message']);
    }

    private static function actionRestoreFile($rootDir, $quarantineDir, $store) {
        $backupName = isset($_POST['backup_name']) ? trim($_POST['backup_name']) : '';
        $destOverride = !empty($_POST['dest_override']) ? trim($_POST['dest_override']) : null;
        $res = ZS_Quarantine::restore($backupName, $rootDir, $quarantineDir, $destOverride);
        if ($res['success']) {
            $session = $store->loadSession();
            if (is_array($session) && !empty($session['infected_files'])) {
                foreach ($session['infected_files'] as $idx => $inf) {
                    if (isset($inf['backup_name']) && $inf['backup_name'] === $backupName) {
                        $store->updateInfectedItem($idx, array('status' => 'RESTORED', 'path' => $res['path']));
                    }
                }
            }
            self::jsonOk(array('message' => ZS_I18n::t('toast_restored'), 'path' => $res['path']));
        }
        self::jsonFail(400, $res['message'], array('code' => isset($res['code']) ? $res['code'] : ''));
    }

    private static function actionMarkClean($rootDir, $store) {
        $resolved = self::resolveFinding($store, $rootDir, true);
        if (empty($resolved['ok'])) {
            self::jsonFail(400, $resolved['message'], array('code' => isset($resolved['code']) ? $resolved['code'] : ''));
        }
        $sid = $resolved['session']['scan_session_id'];
        $res = $store->markClean($resolved['raw'], $resolved['path'], $sid);
        self::jsonOk(array(
            'status'  => $res['status'],
            'message' => ($res['status'] === 'promoted_to_trusted')
                ? ZS_I18n::t('toast_strike2')
                : (($res['status'] === 'candidate_added') ? ZS_I18n::t('toast_strike1') : ZS_I18n::t('toast_already_trusted')),
            'raw_sha256' => $resolved['raw'],
        ));
    }

    private static function actionSaveSettings($config, $dataDir) {
        $updates = array();
        if (!empty($_POST['new_access_key'])) {
            $newKey = trim($_POST['new_access_key']);
            if (strlen($newKey) < 12) {
                self::jsonFail(400, ZS_I18n::t('wizard_err_short'));
            }
            $updates['key_hash'] = password_hash($newKey, PASSWORD_DEFAULT);
        }
        if (isset($_POST['gemini_api_keys']) && trim((string)$_POST['gemini_api_keys']) !== '') {
            $rawKeys = preg_split('/[\r\n,]+/', $_POST['gemini_api_keys']);
            $keys = array();
            foreach ($rawKeys as $k) {
                $t = trim($k);
                if ($t !== '') {
                    $keys[] = $t;
                }
            }
            if (!empty($keys)) {
                $updates['gemini_api_keys'] = $keys;
            }
        }
        if (!empty($_POST['clear_gemini_keys'])) {
            $updates['gemini_api_keys'] = array();
        }
        if (!empty($_POST['gemini_model'])) {
            $updates['gemini_model'] = trim($_POST['gemini_model']);
        }
        if (isset($_POST['github_repo'])) {
            $updates['github_repo'] = trim($_POST['github_repo']);
        }
        if (isset($_POST['report_endpoint'])) {
            $updates['report_endpoint'] = trim($_POST['report_endpoint']);
        }
        if (isset($_POST['rules_sync_url'])) {
            $updates['rules_sync_url'] = trim($_POST['rules_sync_url']);
        }
        if (!ZS_Config::saveConfig($updates, $dataDir)) {
            self::jsonFail(500, 'Could not save settings.');
        }
        self::jsonOk(array('message' => ZS_I18n::t('settings_saved')));
    }

    private static function rulesDigest($rootDir, $dataDir) {
        $rules = ZS_Rules::load($rootDir, $dataDir);
        return substr(hash('sha256', json_encode($rules)), 0, 16);
    }

    private static function actionAskAi($rootDir, $config, $store, $dataDir) {
        $resolved = self::resolveFinding($store, $rootDir, true);
        if (empty($resolved['ok'])) {
            self::jsonFail(400, $resolved['message'], array('code' => isset($resolved['code']) ? $resolved['code'] : ''));
        }
        $content = @file_get_contents($resolved['path']);
        $after = ZS_Hash::raw($content);
        if ($after !== $resolved['raw']) {
            $store->updateInfectedItem($resolved['index'], array('status' => 'CHANGED_SINCE_SCAN'));
            self::jsonFail(409, 'File changed since scan.', array('code' => 'CHANGED_SINCE_SCAN'));
        }
        $config['root_dir'] = $rootDir;
        $reasons = isset($resolved['item']['reason']) ? explode(' | ', $resolved['item']['reason']) : array();
        $hint = !empty($resolved['item']['evidence'][0]) ? $resolved['item']['evidence'][0] : '';
        $digest = self::rulesDigest($rootDir, $dataDir);
        $verdict = ZS_Gemini::ask($resolved['raw'], $resolved['path'], $content, $reasons, $config, $store, $digest, $hint);
        $store->updateInfectedItem($resolved['index'], array('ai_verdict' => $verdict));
        if ($verdict['verdict'] === 'malicious' && $verdict['confidence'] >= 0.85) {
            $store->revokeCandidate($resolved['raw']);
        }
        self::jsonOk(array('verdict' => $verdict, 'advisory' => true));
    }

    private static function actionAutoReviewControl($store) {
        $op = isset($_POST['op']) ? $_POST['op'] : '';
        $session = $store->loadSession();
        if (!is_array($session)) {
            self::jsonFail(500, 'No session.');
        }
        $job = isset($session['auto_review']) ? $session['auto_review'] : ZS_Store::defaultAutoReview();
        if ($op === 'start') {
            $job['status'] = 'running';
            $job['job_id'] = bin2hex(random_bytes(8));
            $job['updated_at'] = time();
        } elseif ($op === 'pause') {
            $job['status'] = 'paused';
        } elseif ($op === 'cancel') {
            $job['status'] = 'idle';
            $job['job_id'] = '';
        }
        $job['stats'] = $store->autoReviewStats($session);
        $store->mutateSession(function ($s) use ($job, $op) {
            $s['auto_review'] = $job;
            if ($op === 'cancel' || $op === 'start') {
                $s['generation'] = isset($s['generation']) ? intval($s['generation']) + 1 : 2;
            }
            return $s;
        });
        self::jsonOk(array('job' => $job));
    }

    private static function actionAutoReviewStep($rootDir, $config, $store, $quarantineDir, $dataDir) {
        $session = $store->loadSession();
        if (!is_array($session)) {
            self::jsonFail(500, 'No session.');
        }
        $job = isset($session['auto_review']) ? $session['auto_review'] : ZS_Store::defaultAutoReview();
        if ($job['status'] === 'paused' || $job['status'] === 'idle') {
            self::jsonOk(array('finished' => false, 'paused' => true, 'stats' => $store->autoReviewStats($session), 'job' => $job));
        }

        $claimed = $store->claimNextInfectedForAutoReview($job['job_id']);
        if ($claimed === false) {
            self::jsonFail(500, $store->lastError);
        }
        if ($claimed === null) {
            $stats = $store->autoReviewStats($session);
            $job['status'] = ($stats['processing'] > 0) ? 'running' : 'completed';
            $job['stats'] = $stats;
            $store->mutateSession(function ($s) use ($job) {
                $s['auto_review'] = $job;
                return $s;
            });
            self::jsonOk(array(
                'finished' => ($stats['processing'] === 0 && $stats['pending'] === 0),
                'stats'    => $stats,
                'job'      => $job,
            ));
        }

        $item = $claimed['item'];
        $path = $item['path'];
        $idx = $claimed['index'];
        $token = $claimed['token'];
        $generation = $claimed['generation'];

        if (!ZS_Config::isRegularFile($path) || ZS_Config::pathHasSymlink($path, $rootDir) || !ZS_Config::isPathWithinRoot($path, $rootDir)) {
            $store->updateInfectedItem($idx, array('status' => 'AI_SKIPPED'), $token, $generation);
            self::jsonOk(array('finished' => false, 'action_taken' => 'skipped_missing', 'path' => $path, 'stats' => $store->autoReviewStats($store->loadSession())));
        }

        $content = @file_get_contents($path);
        $currentRaw = ZS_Hash::raw($content);
        $expected = isset($item['raw_sha256']) ? $item['raw_sha256'] : '';
        if ($currentRaw !== $expected) {
            $store->updateInfectedItem($idx, array('status' => 'CHANGED_SINCE_SCAN'), $token, $generation);
            self::jsonOk(array('finished' => false, 'action_taken' => 'changed', 'code' => 'CHANGED_SINCE_SCAN', 'path' => $path));
        }

        $config['root_dir'] = $rootDir;
        $reasons = isset($item['reason']) ? explode(' | ', $item['reason']) : array();
        $hint = !empty($item['evidence'][0]) ? $item['evidence'][0] : '';
        $digest = self::rulesDigest($rootDir, $dataDir);
        $verdict = ZS_Gemini::ask($currentRaw, $path, $content, $reasons, $config, $store, $digest, $hint);

        if (isset($verdict['error']) && $verdict['error'] === 'all_cooling') {
            $store->updateInfectedItem($idx, array('status' => 'FOUND', 'claim_token' => ''), $token, $generation);
            self::jsonOk(array(
                'finished'    => false,
                'error'       => 'all_cooling',
                'retry_after' => isset($verdict['retry_after']) ? $verdict['retry_after'] : 20,
            ));
        }

        $coverage = isset($verdict['coverage']) ? $verdict['coverage'] : 'full';
        $after = ZS_Hash::rawFile($path);
        if ($after !== $currentRaw) {
            $store->updateInfectedItem($idx, array('status' => 'CHANGED_SINCE_SCAN', 'ai_verdict' => $verdict), $token, $generation);
            self::jsonOk(array('finished' => false, 'action_taken' => 'changed', 'code' => 'CHANGED_SINCE_SCAN'));
        }

        $actionTaken = 'skipped';
        $newStatus = 'AI_SKIPPED';
        if (!empty($verdict['error'])) {
            $actionTaken = 'error';
            $newStatus = 'AI_ERROR';
        } elseif (ZS_Gemini::shouldAutoQuarantine($verdict, $coverage)) {
            $store->revokeCandidate($currentRaw);
            $qRes = ZS_Quarantine::copyThenUnlink($path, $rootDir, $quarantineDir, array(
                'finding_id'   => isset($item['finding_id']) ? $item['finding_id'] : '',
                'expected_raw' => $currentRaw,
            ));
            if ($qRes['success']) {
                $actionTaken = 'quarantined';
                $newStatus = 'AI_QUARANTINED';
            } else {
                $actionTaken = 'failed_quarantine';
                $newStatus = 'FAILED_DELETE';
            }
        }

        $store->updateInfectedItem($idx, array(
            'status'       => $newStatus,
            'ai_verdict'   => $verdict,
            'ai_cache_hit' => !empty($verdict['cache_hit']),
            'backup_name'  => isset($qRes['backup_name']) ? $qRes['backup_name'] : '',
        ), $token, $generation);

        $fresh = $store->loadSession();
        self::jsonOk(array(
            'finished'     => false,
            'path'         => $path,
            'verdict'      => $verdict['verdict'],
            'confidence'   => $verdict['confidence'],
            'cache_hit'    => !empty($verdict['cache_hit']),
            'action_taken' => $actionTaken,
            'coverage'     => $coverage,
            'advisory'     => true,
            'stats'        => $store->autoReviewStats($fresh),
        ));
    }

    private static function actionShareBundle($rootDir, $config, $store, $quarantineDir) {
        $session = $store->loadSession();
        $selected = array();
        if (!empty($_POST['finding_ids']) && is_array($_POST['finding_ids'])) {
            $selected = $_POST['finding_ids'];
        } elseif (!empty($_POST['finding_ids']) && is_string($_POST['finding_ids'])) {
            $selected = array_filter(explode(',', $_POST['finding_ids']));
        }
        $previewOnly = empty($_POST['confirm_send']);
        $includeSamples = !empty($_POST['include_samples']);
        $bundle = ZS_Share::buildBundle($session, $rootDir, $selected, $includeSamples, $quarantineDir);

        $submitMaintainer = !empty($_POST['submit_maintainer']);
        if ($submitMaintainer && !$previewOnly) {
            $hasConsent = !empty($_POST['consent']);
            $endpoint = !empty($config['report_endpoint']) ? $config['report_endpoint'] : '';
            $res = ZS_Share::submitToMaintainer($bundle, $endpoint, $hasConsent, $includeSamples, $quarantineDir);
            self::jsonOk($res);
        }

        $githubRepo = !empty($config['github_repo']) ? $config['github_repo'] : '';
        $shareData = ZS_Share::getGithubShareData($bundle, $githubRepo);
        self::jsonOk(array(
            'bundle'         => $bundle,
            'preview'        => $bundle,
            'github_url'     => $shareData['url'],
            'markdown_body'  => $shareData['body'],
            'need_clipboard' => $shareData['need_clipboard'],
        ));
    }

    public static function isScanExtension($filename) {
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        $ok = array('php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'phar', 'suspected', 'bak');
        if (in_array($ext, $ok, true)) {
            return true;
        }
        return (strpos(strtolower($filename), '.php') !== false);
    }

    public static function executeScanBatch(&$session, $rootDir, $dataDir, $store) {
        $batchStartTime = microtime(true);
        $maxBatchSeconds = 5.0;
        $maxFilesPerBatch = 500;
        $filesInThisBatch = 0;

        $rules = ZS_Rules::load($rootDir, $dataDir);
        $quarantineDir = ZS_Config::getQuarantineDir($rootDir, $dataDir);
        $knowledge = $store->loadKnowledge();
        $trusted = (is_array($knowledge) && isset($knowledge['trusted'])) ? $knowledge['trusted'] : array();

        if (!isset($session['dir_cursor']) || !is_array($session['dir_cursor'])) {
            $session['dir_cursor'] = array('dir' => '', 'offset' => 0, 'names' => array());
        }
        if (!isset($session['visited_dirs']) || !is_array($session['visited_dirs'])) {
            $session['visited_dirs'] = array();
        }

        while ((microtime(true) - $batchStartTime) < $maxBatchSeconds && $filesInThisBatch < $maxFilesPerBatch) {
            $cursor = $session['dir_cursor'];
            $names = isset($cursor['names']) && is_array($cursor['names']) ? $cursor['names'] : array();
            $offset = isset($cursor['offset']) ? intval($cursor['offset']) : 0;
            $currentDir = isset($cursor['dir']) ? $cursor['dir'] : '';

            if ($currentDir === '' || $offset >= count($names)) {
                if (empty($session['dir_queue'])) {
                    $session['is_completed'] = true;
                    break;
                }
                $nextDir = array_shift($session['dir_queue']);
                if (@is_link($nextDir) || ZS_Config::pathHasSymlink($nextDir, $rootDir)) {
                    $session['skipped_symlink'] = isset($session['skipped_symlink']) ? $session['skipped_symlink'] + 1 : 1;
                    continue;
                }
                $realDir = realpath($nextDir);
                if (!$realDir || !is_dir($realDir) || !ZS_Config::isPathWithinRoot($realDir, $rootDir)) {
                    continue;
                }
                if ($realDir === realpath($dataDir) || $realDir === realpath($quarantineDir)) {
                    continue;
                }
                if (isset($session['visited_dirs'][$realDir])) {
                    continue;
                }
                $session['visited_dirs'][$realDir] = 1;
                $session['current_dir'] = $realDir;
                $session['scanned_dirs']++;
                $items = @scandir($realDir);
                if ($items === false) {
                    $session['skipped_unreadable'] = isset($session['skipped_unreadable']) ? $session['skipped_unreadable'] + 1 : 1;
                    continue;
                }
                $session['dir_cursor'] = array('dir' => $realDir, 'offset' => 0, 'names' => array_values($items));
                continue;
            }

            $item = $names[$offset];
            $session['dir_cursor']['offset'] = $offset + 1;
            if ($item === '.' || $item === '..' || $item === '.git' || $item === 'malware_quarantine' || $item === 'malware_cleaner_data') {
                continue;
            }

            $path = rtrim($currentDir, '/\\') . DIRECTORY_SEPARATOR . $item;
            if (@is_link($path)) {
                $session['skipped_symlink'] = isset($session['skipped_symlink']) ? $session['skipped_symlink'] + 1 : 1;
                continue;
            }
            if (is_dir($path)) {
                $realPath = realpath($path);
                if ($realPath && !isset($session['visited_dirs'][$realPath]) && ZS_Config::isPathWithinRoot($realPath, $rootDir)) {
                    $session['dir_queue'][] = $path;
                }
                continue;
            }
            if (!is_file($path)) {
                continue;
            }
            if (!self::isScanExtension($item)) {
                continue;
            }
            if (ZS_Config::isProtectedPath($path, $rootDir, $dataDir)) {
                continue;
            }

            $session['scanned_files']++;
            $filesInThisBatch++;

            $rawHash = ZS_Hash::rawFile($path);
            if ($rawHash === false) {
                $session['skipped_unreadable'] = isset($session['skipped_unreadable']) ? $session['skipped_unreadable'] + 1 : 1;
                continue;
            }
            if (isset($trusted[$rawHash])) {
                $session['trusted_bypassed']++;
                continue;
            }

            $size = @filesize($path);
            $truncated = ($size !== false && $size > ZS_Config::MAX_SCAN_BYTES);
            if ($truncated) {
                $session['coverage_partial'] = isset($session['coverage_partial']) ? $session['coverage_partial'] + 1 : 1;
                $content = @file_get_contents($path, false, null, 0, ZS_Config::MAX_SCAN_BYTES);
            } else {
                $content = @file_get_contents($path);
            }
            if ($content === false) {
                $session['skipped_unreadable'] = isset($session['skipped_unreadable']) ? $session['skipped_unreadable'] + 1 : 1;
                continue;
            }
            $normHash = ZS_Hash::normalized($content);
            $engineResult = ZS_Engine::scanFile($path, $item, $content, $normHash, $rules, $rootDir, $truncated);
            if ($engineResult['detected']) {
                $session['infected_files'][] = array(
                    'finding_id'     => bin2hex(random_bytes(8)),
                    'path'           => $path,
                    'reason'         => implode(' | ', $engineResult['reasons']),
                    'rule_ids'       => $engineResult['rule_ids'],
                    'evidence'       => $engineResult['evidence'],
                    'severity'       => $engineResult['severity'],
                    'size'           => $size,
                    'status'         => 'FOUND',
                    'raw_sha256'     => $rawHash,
                    'norm_sha256'    => $normHash,
                    'coverage'       => $truncated ? 'partial' : 'full',
                    'scan_session_id'=> $session['scan_session_id'],
                );
            }
        }

        if (empty($session['dir_queue']) && (empty($session['dir_cursor']['names']) || $session['dir_cursor']['offset'] >= count($session['dir_cursor']['names']))) {
            $session['is_completed'] = true;
        }

        $store->saveSession($session);

        if (defined('ZS_TEST_MODE') && ZS_TEST_MODE) {
            return;
        }

        $cli = (php_sapi_name() === 'cli');
        if ($cli) {
            echo "Progress: " . intval($session['scanned_files']) . " files. Queue: " . count($session['dir_queue']) . " dirs. Infected: " . count($session['infected_files']) . "\n";
            global $argv;
            $oneBatch = false;
            if (isset($argv) && is_array($argv)) {
                $oneBatch = in_array('--one-batch', $argv, true);
            }
            if (!$session['is_completed']) {
                if ($oneBatch) {
                    exit(10);
                }
                $script = !empty($_SERVER['SCRIPT_FILENAME']) ? $_SERVER['SCRIPT_FILENAME'] : __FILE__;
                $bin = (defined('PHP_BINARY') && PHP_BINARY) ? PHP_BINARY : 'php';
                $code = 10;
                while ($code === 10) {
                    passthru(escapeshellarg($bin) . ' ' . escapeshellarg($script) . ' --one-batch', $code);
                }
            } else {
                echo "\n=== SCAN COMPLETE ===\n";
                echo "Scanned Files: " . intval($session['scanned_files']) . "\n";
                echo "Threats Found: " . count($session['infected_files']) . "\n";
                echo "Trusted Bypassed: " . intval($session['trusted_bypassed']) . "\n";
                if (!empty($session['skipped_unreadable']) || !empty($session['skipped_symlink']) || !empty($session['coverage_partial'])) {
                    echo "Unreadable: " . intval(isset($session['skipped_unreadable']) ? $session['skipped_unreadable'] : 0)
                        . " Symlinks skipped: " . intval(isset($session['skipped_symlink']) ? $session['skipped_symlink'] : 0)
                        . " Partial reads: " . intval(isset($session['coverage_partial']) ? $session['coverage_partial'] : 0) . "\n";
                }
            }
        } else {
            ZS_Ui::renderScanProgress($session, $rootDir);
        }
    }
}
