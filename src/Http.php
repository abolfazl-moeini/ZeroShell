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
            // Logout changes the browser's authenticated state too.  Do not let
            // a third-party form silently sign a reviewer out mid-review.
            if (!self::isCookieAuthenticated($config) || !self::verifyCsrf($config)) {
                http_response_code(403);
                header('Content-Type: text/plain; charset=UTF-8');
                echo 'CSRF validation failed.';
                return;
            }
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

        if (!empty($_GET['nojs']) && empty($session['is_completed'])) {
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
            $fresh = $store->loadSession();
            if (is_array($fresh)) {
                $session = $fresh;
            }
        }

        ZS_Ui::renderReport($session, $rootDir, $dataDir, $config, $store);
        return;
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
            'reset_scan', 'sync_rules', 'set_review_cursor', 'scan_batch',
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
                self::actionViewFile($rootDir, $store, $quarantineDir);
                break;
            case 'set_review_cursor':
                $idx = isset($_POST['index']) ? intval($_POST['index']) : 0;
                $fid = isset($_POST['finding_id']) ? trim((string)$_POST['finding_id']) : '';
                $sid = isset($_POST['scan_session_id']) ? trim((string)$_POST['scan_session_id']) : '';
                $session = $store->loadSession();
                if (!is_array($session) || $sid === '' || $session['scan_session_id'] !== $sid) {
                    self::jsonFail(400, 'Session mismatch.');
                }
                $store->setReviewCursor($idx, $fid);
                self::jsonOk(array('success' => true, 'review_cursor' => $idx));
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
                $testConfig = ZS_Config::loadConfig($dataDir);
                if (!empty($_POST['gemini_api_keys'])) {
                    $candidateKeys = ZS_Config::getGeminiKeys(array('gemini_api_keys' => $_POST['gemini_api_keys']));
                    if (!empty($candidateKeys)) {
                        $testConfig['gemini_api_keys'] = $candidateKeys;
                    }
                }
                self::jsonOk(ZS_Gemini::ping($testConfig));
                break;
            case 'scan_batch':
                self::actionScanBatch($rootDir, $dataDir, $config, $store);
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
                $store->updateInfectedItem($found['index'], array('status' => 'CHANGED_SINCE_SCAN', 'reviewed' => true));
                return array('ok' => false, 'message' => 'File is not a readable regular file inside the site root.', 'code' => 'MISSING', 'index' => $found['index']);
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

    private static function actionViewFile($rootDir, $store, $quarantineDir) {
        $resolved = self::resolveFinding($store, $rootDir, false);
        if (empty($resolved['ok'])) {
            self::jsonFail(400, $resolved['message'], array('code' => isset($resolved['code']) ? $resolved['code'] : ''));
        }
        $item = $resolved['item'];
        $path = $resolved['path'];
        $maxPreview = 1024 * 1024;
        $content = false;
        $size = 0;
        $isQuarantined = (!empty($item['backup_name']) || (isset($item['status']) && ($item['status'] === 'QUARANTINED' || $item['status'] === 'AI_QUARANTINED')));

        if ($isQuarantined && !empty($item['backup_name'])) {
            $payload = ZS_Quarantine::readPayload($quarantineDir, $item['backup_name']);
            if ($payload !== false) {
                $size = strlen($payload);
                $content = substr($payload, 0, $maxPreview);
            }
        }

        if ($content === false) {
            if (!ZS_Config::isRegularFile($path) || ZS_Config::pathHasSymlink($path, $rootDir) || !ZS_Config::isPathWithinRoot($path, $rootDir)) {
                self::jsonFail(400, 'File is not a readable regular file inside the site root.', array('code' => 'MISSING'));
            }
            $currentRaw = ZS_Hash::rawFile($path);
            $sessionRaw = isset($item['raw_sha256']) ? (string)$item['raw_sha256'] : '';
            if ($currentRaw === false || $sessionRaw === '' || !hash_equals($sessionRaw, $currentRaw)) {
                $store->updateInfectedItem($resolved['index'], array('status' => 'CHANGED_SINCE_SCAN'));
                self::jsonFail(400, 'File changed since scan.', array('code' => 'CHANGED_SINCE_SCAN'));
            }
            $expected = isset($_POST['expected_raw']) ? trim((string)$_POST['expected_raw']) : (isset($_GET['expected_raw']) ? trim((string)$_GET['expected_raw']) : '');
            if ($expected !== '' && !hash_equals($sessionRaw, $expected)) {
                self::jsonFail(400, 'Expected hash mismatch.', array('code' => 'CHANGED_SINCE_SCAN'));
            }
            $size = filesize($path);
            $content = @file_get_contents($path, false, null, 0, $maxPreview);
            if ($content === false) {
                self::jsonFail(500, 'Could not read file contents.');
            }
        }

        self::jsonOk(array(
            'filename'       => basename($path),
            'path'           => $path,
            'size'           => $size,
            'size_fmt'       => number_format($size) . ' B',
            'content'        => $content,
            'is_truncated'   => ($size > $maxPreview),
            'raw_sha256'     => $resolved['raw'],
            'finding_id'     => $resolved['item']['finding_id'],
            'is_quarantined' => $isQuarantined,
        ));
    }

    private static function actionDeleteSingle($rootDir, $quarantineDir, $store) {
        $sid = isset($_POST['scan_session_id']) ? trim((string)$_POST['scan_session_id']) : '';
        $fid = isset($_POST['finding_id']) ? trim((string)$_POST['finding_id']) : '';
        $session = $store->loadSession();
        if (is_array($session) && $sid !== '' && isset($session['scan_session_id']) && $session['scan_session_id'] === $sid && $fid !== '') {
            $found = $store->findInfected($session, $fid);
            if ($found !== null && isset($found['item']['status']) &&
                ($found['item']['status'] === 'QUARANTINED' || $found['item']['status'] === 'AI_QUARANTINED')) {
                $cur = $store->getReviewCursor($session);
                $newCursor = $store->findNextUnreviewedIndex($session, $cur);
                self::jsonOk(array(
                    'message'             => ZS_I18n::t('toast_quarantined'),
                    'backup_name'         => isset($found['item']['backup_name']) ? $found['item']['backup_name'] : '',
                    'review_cursor'       => $newCursor,
                    'already_quarantined' => true,
                ));
            }
        }
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
            $newCursor = 0;
            $store->mutateSession(function ($session) use ($resolved, $res, &$newCursor, $store) {
                if (!is_array($session)) {
                    return false;
                }
                $idx = $resolved['index'];
                if (isset($session['infected_files'][$idx])) {
                    $session['infected_files'][$idx]['status'] = 'QUARANTINED';
                    $session['infected_files'][$idx]['backup_name'] = $res['backup_name'];
                    $session['infected_files'][$idx]['reviewed'] = true;
                }
                $cur = $store->getReviewCursor($session);
                $newCursor = $store->findNextUnreviewedIndex($session, $cur);
                $session['review_cursor'] = $newCursor;
                return $session;
            });
            self::jsonOk(array(
                'message'       => ZS_I18n::t('toast_quarantined'),
                'backup_name'   => $res['backup_name'],
                'review_cursor' => $newCursor,
            ));
        }
        $sessCheck = $store->loadSession();
        if (is_array($sessCheck) && $fid !== '') {
            $foundCheck = $store->findInfected($sessCheck, $fid);
            if ($foundCheck !== null && isset($foundCheck['item']['status']) &&
                ($foundCheck['item']['status'] === 'QUARANTINED' || $foundCheck['item']['status'] === 'AI_QUARANTINED')) {
                $cur = $store->getReviewCursor($sessCheck);
                $newCursor = $store->findNextUnreviewedIndex($sessCheck, $cur);
                self::jsonOk(array(
                    'message'             => ZS_I18n::t('toast_quarantined'),
                    'backup_name'         => isset($foundCheck['item']['backup_name']) ? $foundCheck['item']['backup_name'] : '',
                    'review_cursor'       => $newCursor,
                    'already_quarantined' => true,
                ));
            }
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
        $newCursor = 0;
        $store->mutateSession(function ($session) use ($resolved, &$newCursor, $store) {
            if (!is_array($session)) {
                return false;
            }
            $idx = $resolved['index'];
            if (isset($session['infected_files'][$idx])) {
                $session['infected_files'][$idx]['reviewed'] = true;
            }
            $cur = $store->getReviewCursor($session);
            $newCursor = $store->findNextUnreviewedIndex($session, $cur);
            $session['review_cursor'] = $newCursor;
            return $session;
        });
        self::jsonOk(array(
            'status'        => $res['status'],
            'message'       => ($res['status'] === 'promoted_to_trusted')
                ? ZS_I18n::t('toast_strike2')
                : (($res['status'] === 'candidate_added') ? ZS_I18n::t('toast_strike1') : ZS_I18n::t('toast_already_trusted')),
            'raw_sha256'    => $resolved['raw'],
            'review_cursor' => $newCursor,
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
        $submittedKeys = array();
        if (isset($_POST['gemini_api_keys']) && trim((string)$_POST['gemini_api_keys']) !== '') {
            $rawKeys = preg_split('/[\r\n,]+/', $_POST['gemini_api_keys']);
            foreach ($rawKeys as $k) {
                $t = trim((string)$k);
                $t = trim($t, " \t\n\r\0\x0B\"'");
                if (preg_match('/^(?:gemini_api_keys?|api_key)\s*[:=]\s*(.+)$/i', $t, $pm)) {
                    $t = trim($pm[1], " \t\n\r\0\x0B\"'");
                }
                if ($t !== '' && strpos($t, '•') === false && strpos($t, '*') === false && !in_array($t, $submittedKeys, true)) {
                    $submittedKeys[] = $t;
                }
            }
            if (!empty($submittedKeys)) {
                if (!empty($_POST['append_gemini_keys'])) {
                    // Do not copy environment-supplied keys into persistent configuration
                    $currentConfig = ZS_Config::loadConfig($dataDir);
                    $existingKeys = empty($currentConfig['_keys_from_env']) ? ZS_Config::getGeminiKeys($currentConfig) : array();
                    $keys = $existingKeys;
                    foreach ($submittedKeys as $sk) {
                        if (!in_array($sk, $keys, true)) {
                            $keys[] = $sk;
                        }
                    }
                } else {
                    $keys = $submittedKeys;
                }
                if (!empty($keys)) {
                    $updates['gemini_api_keys'] = $keys;
                    foreach ($submittedKeys as $sk) {
                        ZS_Config::clearKeyCooldown($sk, $config, $dataDir);
                    }
                }
            }
        }
        if (!empty($_POST['clear_gemini_keys']) && empty($submittedKeys)) {
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
        $savedConfig = ZS_Config::loadConfig($dataDir);
        if (!empty($updates['key_hash']) && !empty($savedConfig['csrf_secret'])) {
            self::setAuthCookie($savedConfig['csrf_secret'], $updates['key_hash']);
            self::setCsrfCookie($savedConfig['csrf_secret'], self::currentSessionToken());
        }
        $savedKeys = ZS_Config::getGeminiKeys($savedConfig);
        self::jsonOk(array(
            'message'    => ZS_I18n::t('settings_saved'),
            'has_ai'     => !empty($savedKeys),
            'keys_count' => count($savedKeys),
        ));
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
        $config = ZS_Config::loadConfig($dataDir);
        $config['root_dir'] = $rootDir;
        $reasons = isset($resolved['item']['reason']) ? explode(' | ', $resolved['item']['reason']) : array();
        $hint = !empty($resolved['item']['evidence'][0]) ? $resolved['item']['evidence'][0] : '';
        $digest = self::rulesDigest($rootDir, $dataDir);
        $verdict = ZS_Gemini::ask($resolved['raw'], $resolved['path'], $content, $reasons, $config, $store, $digest, $hint);
        if (empty($verdict['error'])) {
            $store->updateInfectedItem($resolved['index'], array('ai_verdict' => $verdict));
            if ($verdict['verdict'] === 'malicious' && $verdict['confidence'] >= 0.85) {
                $store->revokeCandidate($resolved['raw']);
            }
        }
        self::jsonOk(array(
            'verdict'            => $verdict,
            'advisory'           => true,
            'rate_limit_rotated' => !empty($verdict['rate_limit_rotated']),
        ));
    }

    private static function actionAutoReviewControl($store) {
        $op = isset($_POST['op']) ? $_POST['op'] : '';
        if (!in_array($op, array('start', 'pause', 'cancel'), true)) {
            self::jsonFail(400, 'Invalid auto-review operation.');
        }
        $updated = $store->mutateSession(function ($s) use ($op, $store) {
            if (!is_array($s)) {
                return false;
            }
            $job = isset($s['auto_review']) ? $s['auto_review'] : ZS_Store::defaultAutoReview();
            if ($op === 'start') {
                $job['status'] = 'running';
                $job['job_id'] = bin2hex(random_bytes(8));
                $job['updated_at'] = time();
            } elseif ($op === 'pause') {
                $job['status'] = 'paused';
                $job['updated_at'] = time();
            } else {
                $job['status'] = 'idle';
                $job['job_id'] = '';
                $job['updated_at'] = time();
            }

            // Starting a new job or cancelling the current one must invalidate
            // in-flight claims immediately.  Otherwise an old browser request
            // could remain in AI_PROCESSING for 90 seconds and, worse, act after
            // the user has cancelled it.
            if ($op === 'start' || $op === 'cancel') {
                $s['generation'] = isset($s['generation']) ? intval($s['generation']) + 1 : 2;
                if (!empty($s['infected_files']) && is_array($s['infected_files'])) {
                    foreach ($s['infected_files'] as &$item) {
                        if (isset($item['status']) && $item['status'] === 'AI_PROCESSING') {
                            $item['status'] = 'FOUND';
                            $item['claim_token'] = '';
                            $item['claim_job'] = '';
                            $item['claim_generation'] = 0;
                            $item['ai_claimed_at'] = 0;
                        }
                    }
                    unset($item);
                }
            }
            $job['stats'] = $store->autoReviewStats($s);
            $s['auto_review'] = $job;
            return array('_session' => $s, 'job' => $job);
        });
        if ($updated === false || !isset($updated['job'])) {
            self::jsonFail(500, 'No session.');
        }
        self::jsonOk(array('job' => $updated['job']));
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

        $config = ZS_Config::loadConfig($dataDir);
        $config['root_dir'] = $rootDir;
        $reasons = isset($item['reason']) ? explode(' | ', $item['reason']) : array();
        $hint = !empty($item['evidence'][0]) ? $item['evidence'][0] : '';
        $digest = self::rulesDigest($rootDir, $dataDir);
        $verdict = ZS_Gemini::ask($currentRaw, $path, $content, $reasons, $config, $store, $digest, $hint);

        if (isset($verdict['error']) && ($verdict['error'] === 'all_cooling' || $verdict['error'] === 'no_api_key')) {
            $finished = $store->finishAutoReviewClaim($idx, $token, $generation, $job['job_id'], function () {
                return array(
                    'updates' => array(
                        'status' => 'FOUND',
                        'claim_token' => '',
                        'claim_job' => '',
                        'claim_generation' => 0,
                        'ai_claimed_at' => 0,
                    ),
                );
            });
            if ($finished === false) {
                self::jsonOk(array('finished' => false, 'action_taken' => 'cancelled', 'stats' => $store->autoReviewStats($store->loadSession())));
            }
            self::jsonOk(array(
                'finished'    => false,
                'error'       => $verdict['error'],
                'message'     => isset($verdict['summary']) ? $verdict['summary'] : '',
                'retry_after' => isset($verdict['retry_after']) ? $verdict['retry_after'] : 20,
            ));
        }

        $coverage = isset($verdict['coverage']) ? $verdict['coverage'] : 'full';
        $after = ZS_Hash::rawFile($path);
        if ($after !== $currentRaw) {
            $store->updateInfectedItem($idx, array('status' => 'CHANGED_SINCE_SCAN', 'ai_verdict' => $verdict), $token, $generation);
            self::jsonOk(array('finished' => false, 'action_taken' => 'changed', 'code' => 'CHANGED_SINCE_SCAN'));
        }

        $shouldQuarantine = ZS_Gemini::shouldAutoQuarantine($verdict, $coverage);
        $finished = $store->finishAutoReviewClaim($idx, $token, $generation, $job['job_id'], function () use ($verdict, $shouldQuarantine, $path, $rootDir, $quarantineDir, $item, $currentRaw) {
            $actionTaken = 'skipped';
            $newStatus = 'AI_SKIPPED';
            $qRes = array();
            if (!empty($verdict['error'])) {
                $actionTaken = 'error';
                $newStatus = 'AI_ERROR';
            } elseif ($shouldQuarantine) {
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

            return array(
                'updates' => array(
                    'status'       => $newStatus,
                    'ai_verdict'   => $verdict,
                    'ai_cache_hit' => !empty($verdict['cache_hit']),
                    'backup_name'  => isset($qRes['backup_name']) ? $qRes['backup_name'] : '',
                ),
                'result' => array(
                    'action_taken' => $actionTaken,
                    'new_status'   => $newStatus,
                ),
            );
        });
        if ($finished === false) {
            self::jsonOk(array('finished' => false, 'action_taken' => 'cancelled', 'stats' => $store->autoReviewStats($store->loadSession())));
        }
        if ($shouldQuarantine) {
            $store->revokeCandidate($currentRaw);
        }

        $actionTaken = isset($finished['action_taken']) ? $finished['action_taken'] : 'skipped';

        $fresh = $store->loadSession();
        self::jsonOk(array(
            'finished'           => false,
            'path'               => $path,
            'verdict'            => $verdict['verdict'],
            'confidence'         => $verdict['confidence'],
            'cache_hit'          => !empty($verdict['cache_hit']),
            'action_taken'       => $actionTaken,
            'rate_limit_rotated' => !empty($verdict['rate_limit_rotated']),
            'coverage'           => $coverage,
            'advisory'           => true,
            'stats'              => $store->autoReviewStats($fresh),
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

    private static function actionScanBatch($rootDir, $dataDir, $config, $store) {
        $session = $store->loadSession();
        if (!is_array($session)) {
            self::jsonFail(400, 'Session not found.');
        }

        if (!empty($session['is_completed'])) {
            self::jsonOk(array(
                'is_completed'     => true,
                'scanned_files'    => isset($session['scanned_files']) ? intval($session['scanned_files']) : 0,
                'scanned_dirs'     => isset($session['scanned_dirs']) ? intval($session['scanned_dirs']) : 0,
                'infected_count'   => isset($session['infected_files']) && is_array($session['infected_files']) ? count($session['infected_files']) : 0,
                'trusted_bypassed' => isset($session['trusted_bypassed']) ? intval($session['trusted_bypassed']) : 0,
                'current_dir'      => isset($session['current_dir']) ? $session['current_dir'] : '',
                'new_findings'     => array(),
            ));
        }

        $beforeFindingCount = isset($session['infected_files']) && is_array($session['infected_files'])
            ? count($session['infected_files']) : 0;

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

        $fresh = $store->loadSession();
        if (is_array($fresh)) {
            $session = $fresh;
        }

        $allInfected = isset($session['infected_files']) && is_array($session['infected_files'])
            ? $session['infected_files'] : array();

        $newFindings = array();
        $knowledge = $store->loadKnowledge();
        $candidates = (is_array($knowledge) && isset($knowledge['candidates'])) ? $knowledge['candidates'] : array();

        for ($i = $beforeFindingCount; $i < count($allInfected); $i++) {
            $f = $allInfected[$i];
            $status = isset($f['status']) ? $f['status'] : 'FOUND';
            if ($status === 'TRUSTED_HIDDEN' || $status === 'TRUSTED') {
                continue;
            }
            $raw = isset($f['raw_sha256']) ? $f['raw_sha256'] : '';
            $newFindings[] = array(
                'idx'            => $i,
                'finding_id'     => isset($f['finding_id']) ? $f['finding_id'] : '',
                'scan_session_id'=> isset($session['scan_session_id']) ? $session['scan_session_id'] : '',
                'path'           => $f['path'],
                'filename'       => basename($f['path']),
                'reason'         => $f['reason'],
                'rule_ids'       => isset($f['rule_ids']) ? $f['rule_ids'] : array(),
                'size'           => $f['size'],
                'size_fmt'       => number_format($f['size']) . ' B',
                'status'         => $status,
                'raw_sha256'     => $raw,
                'norm_sha256'    => isset($f['norm_sha256']) ? $f['norm_sha256'] : '',
                'row_id'         => 'row_' . md5($f['path'] . $i),
                'is_candidate'   => isset($candidates[$raw]),
                'first_path'     => (isset($candidates[$raw]['first_path']) ? $candidates[$raw]['first_path'] : ''),
                'ai_verdict'     => isset($f['ai_verdict']) ? $f['ai_verdict'] : null,
                'coverage'       => isset($f['coverage']) ? $f['coverage'] : 'full',
                'backup_name'    => isset($f['backup_name']) ? $f['backup_name'] : '',
                'severity'       => isset($f['severity']) ? $f['severity'] : 'suspect',
                'reviewed'       => !empty($f['reviewed']),
            );
        }

        self::jsonOk(array(
            'is_completed'     => !empty($session['is_completed']),
            'scanned_files'    => isset($session['scanned_files']) ? intval($session['scanned_files']) : 0,
            'scanned_dirs'     => isset($session['scanned_dirs']) ? intval($session['scanned_dirs']) : 0,
            'infected_count'   => count($allInfected),
            'trusted_bypassed' => isset($session['trusted_bypassed']) ? intval($session['trusted_bypassed']) : 0,
            'current_dir'      => isset($session['current_dir']) ? $session['current_dir'] : '',
            'new_findings'     => $newFindings,
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
        $dirsInThisBatch = 0;
        $bypassedInThisBatch = 0;
        $symlinksInThisBatch = 0;
        $unreadableInThisBatch = 0;
        $partialInThisBatch = 0;
        $newFindingsThisBatch = array();

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
                    $symlinksInThisBatch++;
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
                $dirsInThisBatch++;
                $items = @scandir($realDir);
                if ($items === false) {
                    $session['skipped_unreadable'] = isset($session['skipped_unreadable']) ? $session['skipped_unreadable'] + 1 : 1;
                    $unreadableInThisBatch++;
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
                $symlinksInThisBatch++;
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
                $unreadableInThisBatch++;
                continue;
            }
            if (isset($trusted[$rawHash])) {
                $session['trusted_bypassed']++;
                $bypassedInThisBatch++;
                continue;
            }

            $size = @filesize($path);
            $truncated = ($size !== false && $size > ZS_Config::MAX_SCAN_BYTES);
            if ($truncated) {
                $session['coverage_partial'] = isset($session['coverage_partial']) ? $session['coverage_partial'] + 1 : 1;
                $partialInThisBatch++;
                $content = @file_get_contents($path, false, null, 0, ZS_Config::MAX_SCAN_BYTES);
            } else {
                $content = @file_get_contents($path);
            }
            if ($content === false) {
                $session['skipped_unreadable'] = isset($session['skipped_unreadable']) ? $session['skipped_unreadable'] + 1 : 1;
                $unreadableInThisBatch++;
                continue;
            }
            $normHash = ZS_Hash::normalized($content);
            $engineResult = ZS_Engine::scanFile($path, $item, $content, $normHash, $rules, $rootDir, $truncated);
            if ($engineResult['detected']) {
                $findingItem = array(
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
                $session['infected_files'][] = $findingItem;
                $newFindingsThisBatch[] = $findingItem;
            }
        }

        if (empty($session['dir_queue']) && (empty($session['dir_cursor']['names']) || $session['dir_cursor']['offset'] >= count($session['dir_cursor']['names']))) {
            $session['is_completed'] = true;
        }

        $batchSid = isset($session['scan_session_id']) ? $session['scan_session_id'] : '';
        $cursor = $session['dir_cursor'];
        $queue = $session['dir_queue'];
        $visited = $session['visited_dirs'];
        $currentDir = isset($session['current_dir']) ? $session['current_dir'] : '';
        $isCompleted = !empty($session['is_completed']);
        $newFindings = $newFindingsThisBatch;

        $store->mutateSession(function ($fresh) use (
            $batchSid, $newFindings, $filesInThisBatch, $dirsInThisBatch,
            $bypassedInThisBatch, $symlinksInThisBatch, $unreadableInThisBatch, $partialInThisBatch,
            $cursor, $queue, $visited, $currentDir, $isCompleted
        ) {
            if (!is_array($fresh)) {
                return false;
            }
            if ($batchSid !== '' && isset($fresh['scan_session_id']) && $fresh['scan_session_id'] !== $batchSid) {
                return $fresh;
            }
            $fresh['scanned_files'] = (isset($fresh['scanned_files']) ? intval($fresh['scanned_files']) : 0) + $filesInThisBatch;
            $fresh['scanned_dirs'] = (isset($fresh['scanned_dirs']) ? intval($fresh['scanned_dirs']) : 0) + $dirsInThisBatch;
            if ($bypassedInThisBatch > 0) {
                $fresh['trusted_bypassed'] = (isset($fresh['trusted_bypassed']) ? intval($fresh['trusted_bypassed']) : 0) + $bypassedInThisBatch;
            }
            if ($symlinksInThisBatch > 0) {
                $fresh['skipped_symlink'] = (isset($fresh['skipped_symlink']) ? intval($fresh['skipped_symlink']) : 0) + $symlinksInThisBatch;
            }
            if ($unreadableInThisBatch > 0) {
                $fresh['skipped_unreadable'] = (isset($fresh['skipped_unreadable']) ? intval($fresh['skipped_unreadable']) : 0) + $unreadableInThisBatch;
            }
            if ($partialInThisBatch > 0) {
                $fresh['coverage_partial'] = (isset($fresh['coverage_partial']) ? intval($fresh['coverage_partial']) : 0) + $partialInThisBatch;
            }

            $fresh['dir_cursor'] = $cursor;
            $fresh['dir_queue'] = $queue;
            $fresh['visited_dirs'] = $visited;
            $fresh['current_dir'] = $currentDir;
            if ($isCompleted) {
                $fresh['is_completed'] = true;
            }

            if (!isset($fresh['infected_files']) || !is_array($fresh['infected_files'])) {
                $fresh['infected_files'] = array();
            }
            foreach ($newFindings as $nf) {
                $fresh['infected_files'][] = $nf;
            }

            return $fresh;
        });

        $fresh = $store->loadSession();
        if (is_array($fresh)) {
            $session = $fresh;
        }

        if (defined('ZS_TEST_MODE') && ZS_TEST_MODE) {
            return;
        }

        $cli = (php_sapi_name() === 'cli' && empty($_POST['do_action']) && empty($_GET['do_action']));
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
            if (!self::wantsJson() && empty($_POST['do_action']) && empty($_GET['do_action'])) {
                ZS_Ui::renderScanProgress($session, $rootDir);
            }
        }
    }
}
