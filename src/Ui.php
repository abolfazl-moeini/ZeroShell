<?php
class ZS_Ui {
    public static function getCss() {
        // Placeholder for build-time inlining:
        // {{INLINED_CSS}}
        $cssFile = dirname(__FILE__) . '/assets/app.css';
        if (file_exists($cssFile)) {
            return @file_get_contents($cssFile);
        }
        return '';
    }

    public static function getJs() {
        // Placeholder for build-time inlining:
        // {{INLINED_JS}}
        $jsFile = dirname(__FILE__) . '/assets/app.js';
        if (file_exists($jsFile)) {
            return @file_get_contents($jsFile);
        }
        return '';
    }

    private static function renderHtmlHeader($title = '', $extraHead = '') {
        if ($title === '') {
            $title = ZS_I18n::t('app_title');
        }
        $isRtl = ZS_I18n::isRtl();
        $lang  = ZS_I18n::getLang();
        $dir   = $isRtl ? 'rtl' : 'ltr';
        $css   = self::getCss();
        ?>
<!DOCTYPE html>
<html lang="<?php echo htmlspecialchars($lang, ENT_QUOTES, 'UTF-8'); ?>" dir="<?php echo $dir; ?>">
<head>
    <meta charset="UTF-8">
    <title><?php echo htmlspecialchars($title, ENT_QUOTES, 'UTF-8'); ?></title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="referrer" content="no-referrer">
<?php echo $extraHead; ?>
    <style>
<?php echo $css; ?>
    </style>
</head>
<body>
        <?php
    }

    private static function renderHtmlFooter() {
        $js = self::getJs();
        ?>
    <div id="toastNotify" class="toast-notify"></div>
    <script>
<?php echo $js; ?>
    </script>
</body>
</html>
        <?php
    }

    public static function renderWizard($rootDir, $config, $errorMsg = '') {
        self::renderHtmlHeader(ZS_I18n::t('wizard_title'));
        $genKey = bin2hex(random_bytes(16));
        $lang = ZS_I18n::getLang();
        $secretPath = 'zs-setup.secret';
        ?>
    <div class="card" style="max-width: 600px; margin-top: 40px;">
        <div class="header-row">
            <h2><?php echo htmlspecialchars(ZS_I18n::t('wizard_title'), ENT_QUOTES, 'UTF-8'); ?></h2>
            <button type="button" class="btn btn-outline" data-switch-lang="<?php echo $lang === 'fa' ? 'en' : 'fa'; ?>">
                <?php echo $lang === 'fa' ? 'English' : 'فارسی'; ?>
            </button>
        </div>
        <p style="color: #cbd5e1; font-size: 13px; line-height: 1.6;">
            <?php echo htmlspecialchars(ZS_I18n::t('wizard_desc'), ENT_QUOTES, 'UTF-8'); ?>
        </p>
        <?php
        $secretFile = ZS_Config::getSetupSecretPath($rootDir);
        $secretExists = (is_file($secretFile) && !is_link($secretFile));
        ?>
        <?php if ($secretExists) : ?>
            <p style="color: #6ee7b7; font-size: 13px; line-height: 1.5; background: #064e3b; padding: 12px; border-radius: 8px; margin: 15px 0;">
                <?php echo htmlspecialchars(ZS_I18n::t('wizard_secret_found', array('file' => $secretPath)), ENT_QUOTES, 'UTF-8'); ?>
            </p>
        <?php else : ?>
            <p style="color: #fde68a; font-size: 13px; line-height: 1.5; background: #451a03; padding: 12px; border-radius: 8px; margin: 15px 0;">
                <?php echo htmlspecialchars(ZS_I18n::t('wizard_secret_missing', array('file' => $secretPath)), ENT_QUOTES, 'UTF-8'); ?>
            </p>
        <?php endif; ?>
        <?php if (!empty($errorMsg)) : ?>
            <div style="background: #7f1d1d; color: #fee2e2; padding: 10px; border-radius: 6px; font-size: 13px; margin-bottom: 15px;">
                <?php echo htmlspecialchars($errorMsg, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>
        <form method="POST" action="">
            <input type="hidden" name="do_action" value="setup_wizard">
            <input type="hidden" name="generated_key" value="<?php echo htmlspecialchars($genKey, ENT_QUOTES, 'UTF-8'); ?>">
            <div class="form-group">
                <label><?php echo htmlspecialchars(ZS_I18n::t('wizard_setup_secret'), ENT_QUOTES, 'UTF-8'); ?></label>
                <input type="password" name="setup_secret" class="form-input" required>
            </div>
            <div class="form-group">
                <label><?php echo htmlspecialchars(ZS_I18n::t('wizard_generated'), ENT_QUOTES, 'UTF-8'); ?></label>
                <input type="text" readonly class="form-input" value="<?php echo htmlspecialchars($genKey, ENT_QUOTES, 'UTF-8'); ?>" style="font-family: monospace;" onclick="this.select();">
            </div>
            <div class="form-group">
                <label><?php echo htmlspecialchars(ZS_I18n::t('wizard_custom'), ENT_QUOTES, 'UTF-8'); ?></label>
                <input type="text" name="custom_key" class="form-input" minlength="12">
            </div>
            <button type="submit" class="btn btn-blue" style="width: 100%; padding: 12px;">
                <?php echo htmlspecialchars(ZS_I18n::t('wizard_submit'), ENT_QUOTES, 'UTF-8'); ?>
            </button>
        </form>
    </div>
        <?php
        self::renderHtmlFooter();
    }

    public static function renderLogin($errorMsg = '') {
        self::renderHtmlHeader(ZS_I18n::t('login_title'));
        $lang = ZS_I18n::getLang();
        ?>
    <div class="card" style="max-width: 480px; margin-top: 60px;">
        <div class="header-row">
            <h2><?php echo htmlspecialchars(ZS_I18n::t('login_title'), ENT_QUOTES, 'UTF-8'); ?></h2>
            <button type="button" class="btn btn-outline" data-switch-lang="<?php echo $lang === 'fa' ? 'en' : 'fa'; ?>">
                <?php echo $lang === 'fa' ? 'English' : 'فارسی'; ?>
            </button>
        </div>
        <p style="color: #94a3b8; font-size: 13px; margin: 10px 0 18px 0; line-height: 1.5;">
            <?php echo htmlspecialchars(ZS_I18n::t('login_prompt'), ENT_QUOTES, 'UTF-8'); ?>
        </p>
        <?php if (!empty($errorMsg)) : ?>
            <div style="background: #7f1d1d; color: #fee2e2; padding: 10px; border-radius: 6px; font-size: 13px; margin-bottom: 15px;">
                <?php echo htmlspecialchars($errorMsg, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>
        <form method="POST" action="">
            <input type="hidden" name="do_action" value="login">
            <div class="form-group">
                <label><?php echo htmlspecialchars(ZS_I18n::t('settings_access_key'), ENT_QUOTES, 'UTF-8'); ?></label>
                <input type="password" name="key" class="form-input" placeholder="<?php echo htmlspecialchars(ZS_I18n::t('settings_access_key'), ENT_QUOTES, 'UTF-8'); ?>" required autofocus>
            </div>
            <button type="submit" class="btn btn-blue" style="width: 100%; padding: 10px;">
                <?php echo htmlspecialchars(ZS_I18n::t('login_submit'), ENT_QUOTES, 'UTF-8'); ?>
            </button>
        </form>
    </div>
        <?php
        self::renderHtmlFooter();
    }

    public static function renderScanProgress($session, $rootDir) {
        $refreshUrl = strtok($_SERVER['REQUEST_URI'], '?');
        if (empty($_COOKIE['zs_session']) && isset($_REQUEST['key'])) {
            $refreshUrl .= '?key=' . rawurlencode($_REQUEST['key']);
        }
        $extraHead = '    <meta http-equiv="refresh" content="1;url=' . htmlspecialchars($refreshUrl, ENT_QUOTES, 'UTF-8') . '">' . "\n";
        self::renderHtmlHeader('', $extraHead);
        ?>
    <div class="card">
        <h2><?php echo htmlspecialchars(ZS_I18n::t('app_title'), ENT_QUOTES, 'UTF-8'); ?></h2>
        <div class="status running"><?php echo htmlspecialchars(ZS_I18n::t('status_running'), ENT_QUOTES, 'UTF-8'); ?></div>
        <div class="stats">
            <div class="stat-box"><div class="stat-num"><?php echo number_format(isset($session['scanned_files']) ? $session['scanned_files'] : 0); ?></div><div><?php echo htmlspecialchars(ZS_I18n::t('stat_scanned_files'), ENT_QUOTES, 'UTF-8'); ?></div></div>
            <div class="stat-box"><div class="stat-num"><?php echo number_format(isset($session['scanned_dirs']) ? $session['scanned_dirs'] : 0); ?></div><div><?php echo htmlspecialchars(ZS_I18n::t('stat_scanned_dirs'), ENT_QUOTES, 'UTF-8'); ?></div></div>
            <div class="stat-box"><div class="stat-num danger"><?php echo count(isset($session['infected_files']) ? $session['infected_files'] : array()); ?></div><div><?php echo htmlspecialchars(ZS_I18n::t('stat_infected_files'), ENT_QUOTES, 'UTF-8'); ?></div></div>
            <div class="stat-box"><div class="stat-num success"><?php echo number_format(isset($session['trusted_bypassed']) ? $session['trusted_bypassed'] : 0); ?></div><div><?php echo htmlspecialchars(ZS_I18n::t('stat_trusted_bypassed'), ENT_QUOTES, 'UTF-8'); ?></div></div>
        </div>
        <p class="dir-path"><?php echo htmlspecialchars(isset($session['current_dir']) ? $session['current_dir'] : $rootDir, ENT_QUOTES, 'UTF-8'); ?></p>
        <p style="color:#94a3b8;font-size:12px;"><?php echo htmlspecialchars(ZS_I18n::t('scan_not_clean_claim'), ENT_QUOTES, 'UTF-8'); ?></p>
    </div>
        <?php
        self::renderHtmlFooter();
    }

    public static function renderReport($session, $rootDir, $dataDir, $config, $store) {
        self::renderHtmlHeader();
        $lang = ZS_I18n::getLang();
        $infected = isset($session['infected_files']) && is_array($session['infected_files']) ? $session['infected_files'] : array();
        $knowledge = $store->loadKnowledge();
        $candidates = (is_array($knowledge) && isset($knowledge['candidates'])) ? $knowledge['candidates'] : array();
        $autoJob = isset($session['auto_review']) ? $session['auto_review'] : ZS_Store::defaultAutoReview();
        $stats = $store->autoReviewStats($session);

        $infectedJs = array();
        foreach ($infected as $idx => $f) {
            $status = isset($f['status']) ? $f['status'] : 'FOUND';
            if ($status === 'TRUSTED_HIDDEN' || $status === 'TRUSTED') {
                continue;
            }
            $raw = isset($f['raw_sha256']) ? $f['raw_sha256'] : '';
            $infectedJs[] = array(
                'idx'            => $idx,
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
                'row_id'         => 'row_' . md5($f['path'] . $idx),
                'is_candidate'   => isset($candidates[$raw]),
                'first_path'     => (isset($candidates[$raw]['first_path']) ? $candidates[$raw]['first_path'] : ''),
                'ai_verdict'     => isset($f['ai_verdict']) ? $f['ai_verdict'] : null,
                'coverage'       => isset($f['coverage']) ? $f['coverage'] : 'full',
                'backup_name'    => isset($f['backup_name']) ? $f['backup_name'] : '',
                'severity'       => isset($f['severity']) ? $f['severity'] : 'suspect',
                'reviewed'       => !empty($f['reviewed']),
            );
        }

        $csrfToken = ZS_Http::getCsrfToken(isset($config['csrf_secret']) ? $config['csrf_secret'] : '');
        $hasGeminiKeys = !empty(ZS_Config::getGeminiKeys($config));
        $maskedKeys = array();
        foreach (ZS_Config::getGeminiKeys($config) as $k) {
            $maskedKeys[] = ZS_Config::maskSecret($k);
        }
        $reviewCursor = $store->findFirstUnreviewedIndex($session);
        $boot = array(
            'items' => $infectedJs,
            'csrf' => $csrfToken,
            'i18n' => ZS_I18n::getAll(),
            'session_id' => isset($session['scan_session_id']) ? $session['scan_session_id'] : '',
            'has_ai' => $hasGeminiKeys,
            'job' => $autoJob,
            'stats' => $stats,
            'review_cursor' => $reviewCursor,
        );
        ?>
    <script>
        <?php
        $jsonBoot = json_encode($boot, ZS_Config::jsonFlags());
        if ($jsonBoot === false) {
            $jsonBoot = '{}';
        }
        ?>
        window.ZS_BOOT = <?php echo $jsonBoot; ?>;
        window.REVIEW_ITEMS = window.ZS_BOOT.items || [];
        window.ZS_I18N = window.ZS_BOOT.i18n || {};
        window.ZS_CSRF = window.ZS_BOOT.csrf || '';
        window.ZS_SESSION_ID = window.ZS_BOOT.session_id || '';
    </script>
    <div class="card">
        <div class="header-row">
            <h2><?php echo htmlspecialchars(ZS_I18n::t('app_title'), ENT_QUOTES, 'UTF-8'); ?></h2>
            <div style="display:flex;gap:8px;flex-wrap:wrap;">
                <button type="button" class="btn btn-outline" id="btnSettings"><?php echo htmlspecialchars(ZS_I18n::t('btn_settings'), ENT_QUOTES, 'UTF-8'); ?></button>
                <button type="button" class="btn btn-outline" data-switch-lang="<?php echo $lang === 'fa' ? 'en' : 'fa'; ?>"><?php echo $lang === 'fa' ? 'English' : 'فارسی'; ?></button>
                <form method="POST" action="" style="display:inline;">
                    <input type="hidden" name="do_action" value="logout">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">
                    <button type="submit" class="btn btn-gray"><?php echo htmlspecialchars(ZS_I18n::t('btn_logout'), ENT_QUOTES, 'UTF-8'); ?></button>
                </form>
            </div>
        </div>
        <div class="status completed"><?php echo htmlspecialchars(ZS_I18n::t('status_completed'), ENT_QUOTES, 'UTF-8'); ?></div>
        <p style="color:#94a3b8;font-size:12px;"><?php echo htmlspecialchars(ZS_I18n::t('scan_not_clean_claim'), ENT_QUOTES, 'UTF-8'); ?></p>
        <div class="stats">
            <div class="stat-box"><div class="stat-num"><?php echo number_format(isset($session['scanned_files']) ? $session['scanned_files'] : 0); ?></div><div><?php echo htmlspecialchars(ZS_I18n::t('stat_scanned_files'), ENT_QUOTES, 'UTF-8'); ?></div></div>
            <div class="stat-box"><div class="stat-num danger"><?php echo count($infectedJs); ?></div><div><?php echo htmlspecialchars(ZS_I18n::t('stat_infected_files'), ENT_QUOTES, 'UTF-8'); ?></div></div>
            <div class="stat-box"><div class="stat-num success"><?php echo number_format(isset($session['trusted_bypassed']) ? $session['trusted_bypassed'] : 0); ?></div><div><?php echo htmlspecialchars(ZS_I18n::t('stat_trusted_bypassed'), ENT_QUOTES, 'UTF-8'); ?></div></div>
            <div class="stat-box"><div class="stat-num"><?php echo intval($stats['quarantined']); ?></div><div><?php echo htmlspecialchars(ZS_I18n::t('stat_quarantined'), ENT_QUOTES, 'UTF-8'); ?></div></div>
        </div>
        <div style="margin: 20px 0; display: flex; gap: 10px; flex-wrap: wrap;">
            <form method="POST" action="" onsubmit="return confirm(window.ZS_I18N.confirm_rescan || '');">
                <input type="hidden" name="do_action" value="reset_scan">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">
                <button type="submit" class="btn btn-gray"><?php echo htmlspecialchars(ZS_I18n::t('btn_rescan'), ENT_QUOTES, 'UTF-8'); ?></button>
            </form>
            <?php if (!empty($infectedJs)) : ?>
                <button type="button" class="btn btn-purple" id="btnStartReview"><?php echo htmlspecialchars(ZS_I18n::t('btn_review'), ENT_QUOTES, 'UTF-8'); ?></button>
                <button type="button" class="btn btn-blue" id="btnStartAuto"><?php echo htmlspecialchars(ZS_I18n::t('btn_auto_ai'), ENT_QUOTES, 'UTF-8'); ?></button>
            <?php endif; ?>
        </div>
        <p style="font-size:12px;color:#94a3b8;"><?php echo htmlspecialchars(ZS_I18n::t('ai_advisory'), ENT_QUOTES, 'UTF-8'); ?></p>

        <h3><?php echo htmlspecialchars(ZS_I18n::t('stat_infected_files'), ENT_QUOTES, 'UTF-8'); ?> (<?php echo count($infectedJs); ?>)</h3>
        <?php if (empty($infectedJs)) : ?>
            <p style="color:#4ade80;"><?php echo htmlspecialchars(ZS_I18n::t('no_threats_found'), ENT_QUOTES, 'UTF-8'); ?></p>
        <?php else : ?>
            <table>
                <thead><tr>
                    <th style="width:30px;"><input type="checkbox" id="selectAllFindings" title="Select / Deselect All"></th><th>#</th><th><?php echo htmlspecialchars(ZS_I18n::t('table_path'), ENT_QUOTES, 'UTF-8'); ?></th>
                    <th><?php echo htmlspecialchars(ZS_I18n::t('table_reason'), ENT_QUOTES, 'UTF-8'); ?></th>
                    <th><?php echo htmlspecialchars(ZS_I18n::t('table_actions'), ENT_QUOTES, 'UTF-8'); ?></th>
                </tr></thead>
                <tbody id="infectedTableBody">
                <?php foreach ($infectedJs as $row) : ?>
                    <tr id="<?php echo htmlspecialchars($row['row_id'], ENT_QUOTES, 'UTF-8'); ?>">
                        <td><input type="checkbox" class="share-select" data-finding-id="<?php echo htmlspecialchars($row['finding_id'], ENT_QUOTES, 'UTF-8'); ?>"></td>
                        <td><?php echo intval($row['idx']) + 1; ?></td>
                        <td class="dir-path"></td>
                        <td class="reason-cell"></td>
                        <td class="action-cell">
                            <button type="button" class="btn-view-single" data-finding-id="<?php echo htmlspecialchars($row['finding_id'], ENT_QUOTES, 'UTF-8'); ?>" data-review-idx="<?php echo intval($row['idx']); ?>"><?php echo htmlspecialchars(ZS_I18n::t('btn_inspect'), ENT_QUOTES, 'UTF-8'); ?></button>
                            <button type="button" class="btn-del-single" data-finding-id="<?php echo htmlspecialchars($row['finding_id'], ENT_QUOTES, 'UTF-8'); ?>" data-raw="<?php echo htmlspecialchars($row['raw_sha256'], ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars(ZS_I18n::t('btn_delete'), ENT_QUOTES, 'UTF-8'); ?></button>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>

        <?php if (!empty($autoJob['stats']) && $autoJob['status'] !== 'idle') : ?>
            <div class="share-card" id="autoReviewReport">
                <h3><?php echo htmlspecialchars(ZS_I18n::t('auto_ai_title'), ENT_QUOTES, 'UTF-8'); ?> — <?php echo htmlspecialchars($autoJob['status'], ENT_QUOTES, 'UTF-8'); ?></h3>
                <p><?php echo htmlspecialchars(ZS_I18n::t('auto_ai_stats', $stats), ENT_QUOTES, 'UTF-8'); ?></p>
            </div>
        <?php endif; ?>

        <div class="share-card">
            <h3><?php echo htmlspecialchars(ZS_I18n::t('share_title'), ENT_QUOTES, 'UTF-8'); ?></h3>
            <p style="color:#cbd5e1;font-size:13px;"><?php echo htmlspecialchars(ZS_I18n::t('share_desc'), ENT_QUOTES, 'UTF-8'); ?></p>
            <p style="font-size:12px;color:#94a3b8;"><?php echo htmlspecialchars(ZS_I18n::t('share_select_help'), ENT_QUOTES, 'UTF-8'); ?></p>
            <label style="font-size:12px;color:#cbd5e1;"><input type="checkbox" id="chkIncludeSamples"> <?php echo htmlspecialchars(ZS_I18n::t('share_include_samples'), ENT_QUOTES, 'UTF-8'); ?></label>
            <div class="share-actions" style="margin-top:10px;">
                <button type="button" class="btn btn-blue" id="btnShareGithub"><?php echo htmlspecialchars(ZS_I18n::t('share_btn_github'), ENT_QUOTES, 'UTF-8'); ?></button>
                <button type="button" class="btn btn-gray" id="btnShareCopy"><?php echo htmlspecialchars(ZS_I18n::t('share_btn_copy'), ENT_QUOTES, 'UTF-8'); ?></button>
                <button type="button" class="btn btn-outline" id="btnShareJson"><?php echo htmlspecialchars(ZS_I18n::t('share_btn_json'), ENT_QUOTES, 'UTF-8'); ?></button>
            </div>
            <pre id="sharePreview" class="code-viewer" style="max-height:180px;margin-top:12px;display:none;"></pre>
        </div>
    </div>

    <div id="fileViewerModal" class="modal-overlay">
        <div class="modal-content" role="dialog" aria-modal="true">
            <div class="review-progress-bar"><div class="review-progress-fill" id="reviewProgressFill"></div></div>
            <div class="modal-header">
                <div class="modal-header-left">
                    <span class="badge-counter" id="modalCounter">1 / 1</span>
                    <span class="badge-status pending" id="modalFileStatus"></span>
                    <span class="badge-counter" id="modalAiBadge" style="display:none;background:#6366f1;"></span>
                    <strong id="modalFileName" style="color:#38bdf8;font-family:monospace;"></strong>
                </div>
                <div class="modal-nav-group">
                    <button type="button" class="btn btn-gray" id="btnPrevTop">←</button>
                    <button type="button" class="btn btn-blue" id="btnNextTop">→</button>
                    <button type="button" class="modal-close" id="btnCloseModal">&times;</button>
                </div>
            </div>
            <div id="strikeBanner" class="strike-banner"></div>
            <div class="modal-info-bar">
                <div><?php echo htmlspecialchars(ZS_I18n::t('modal_path'), ENT_QUOTES, 'UTF-8'); ?> <span class="tag tag-clickable" id="modalFilePath" role="button" tabindex="0" title="<?php echo htmlspecialchars(ZS_I18n::t('copy_path_hint'), ENT_QUOTES, 'UTF-8'); ?>" aria-label="<?php echo htmlspecialchars(ZS_I18n::t('copy_path_hint'), ENT_QUOTES, 'UTF-8'); ?>"></span></div>
                <div><?php echo htmlspecialchars(ZS_I18n::t('modal_reason'), ENT_QUOTES, 'UTF-8'); ?> <span id="modalFileReason" style="color:#facc15;"></span></div>
                <div><?php echo htmlspecialchars(ZS_I18n::t('modal_raw_hash'), ENT_QUOTES, 'UTF-8'); ?> <span class="tag" id="modalRawHash"></span></div>
            </div>
            <div class="modal-body">
                <button type="button" class="btn-copy-floating" id="btnCopyFloating"><?php echo htmlspecialchars(ZS_I18n::t('modal_copy_code'), ENT_QUOTES, 'UTF-8'); ?></button>
                <pre class="code-viewer"><code id="modalFileContent"></code></pre>
            </div>
            <div class="modal-footer">
                <div class="kbd-guide">
                    <span><kbd>C</kbd></span><span><kbd>D</kbd></span><span><kbd>N</kbd></span><span><kbd>B</kbd></span><span><kbd>A</kbd></span><span><kbd>Esc</kbd></span>
                </div>
                <div class="modal-footer-actions">
                    <button type="button" class="btn btn-outline" id="modalAskAiBtn"><?php echo htmlspecialchars(ZS_I18n::t('btn_ask_ai'), ENT_QUOTES, 'UTF-8'); ?></button>
                    <button type="button" class="btn btn-gray" id="btnMarkClean"><?php echo htmlspecialchars(ZS_I18n::t('btn_mark_clean'), ENT_QUOTES, 'UTF-8'); ?></button>
                    <button type="button" class="btn btn-blue" id="btnNextBottom"><?php echo htmlspecialchars(ZS_I18n::t('btn_next_keep'), ENT_QUOTES, 'UTF-8'); ?></button>
                    <button type="button" class="btn btn-red" id="modalDeleteBtn"><?php echo htmlspecialchars(ZS_I18n::t('btn_del_next'), ENT_QUOTES, 'UTF-8'); ?></button>
                </div>
            </div>
        </div>
    </div>

    <div id="autoReviewModal" class="modal-overlay">
        <div class="modal-content modal-md" role="dialog">
            <div class="modal-header">
                <strong style="color:#38bdf8;"><?php echo htmlspecialchars(ZS_I18n::t('auto_ai_title'), ENT_QUOTES, 'UTF-8'); ?></strong>
                <button type="button" class="modal-close" id="btnCloseAuto">&times;</button>
            </div>
            <div class="modal-body-standard">
                <p><?php echo htmlspecialchars(ZS_I18n::t('auto_ai_desc'), ENT_QUOTES, 'UTF-8'); ?></p>
                <p style="font-size:12px;color:#fde68a;"><?php echo htmlspecialchars(ZS_I18n::t('ai_sends_code'), ENT_QUOTES, 'UTF-8'); ?></p>
                <div class="review-progress-bar" style="height:8px;border-radius:4px;"><div class="review-progress-fill" id="autoReviewFill"></div></div>
                <div id="autoReviewProgressText"></div>
                <div id="autoReviewStats" style="color:#94a3b8;font-size:13px;margin:10px 0;"></div>
                <button type="button" class="btn btn-gray" id="btnAutoPause"><?php echo htmlspecialchars(ZS_I18n::t('auto_ai_pause'), ENT_QUOTES, 'UTF-8'); ?></button>
                <button type="button" class="btn btn-blue" id="btnAutoResume" style="display:none;"><?php echo htmlspecialchars(ZS_I18n::t('auto_ai_resume'), ENT_QUOTES, 'UTF-8'); ?></button>
                <button type="button" class="btn btn-red" id="btnAutoCancel"><?php echo htmlspecialchars(ZS_I18n::t('auto_ai_cancel'), ENT_QUOTES, 'UTF-8'); ?></button>
            </div>
        </div>
    </div>

    <div id="settingsModal" class="modal-overlay">
        <div class="modal-content modal-md" role="dialog">
            <div class="modal-header">
                <strong style="color:#38bdf8;"><?php echo htmlspecialchars(ZS_I18n::t('settings_title'), ENT_QUOTES, 'UTF-8'); ?></strong>
                <button type="button" class="modal-close" id="btnCloseSettings">&times;</button>
            </div>
            <div class="modal-body-standard">
                <form id="formSettings">
                    <div class="form-group">
                        <label><?php echo htmlspecialchars(ZS_I18n::t('settings_new_key'), ENT_QUOTES, 'UTF-8'); ?></label>
                        <input type="password" id="set_new_access_key" class="form-input">
                    </div>
                    <div class="form-group">
                        <label><?php echo htmlspecialchars(ZS_I18n::t('settings_gemini_keys'), ENT_QUOTES, 'UTF-8'); ?></label>
                        <p style="font-size:12px;color:#94a3b8;"><?php echo htmlspecialchars(implode(' ', $maskedKeys) ?: ZS_I18n::t('settings_no_keys'), ENT_QUOTES, 'UTF-8'); ?></p>
                        <textarea id="set_gemini_api_keys" class="form-textarea" placeholder="<?php echo htmlspecialchars(ZS_I18n::t('settings_keys_placeholder'), ENT_QUOTES, 'UTF-8'); ?>"></textarea>
                        <label style="font-size:12px;"><input type="checkbox" id="chkClearKeys"> <?php echo htmlspecialchars(ZS_I18n::t('settings_clear_keys'), ENT_QUOTES, 'UTF-8'); ?></label>
                    </div>
                    <div class="form-group">
                        <label><?php echo htmlspecialchars(ZS_I18n::t('settings_gemini_model'), ENT_QUOTES, 'UTF-8'); ?></label>
                        <input type="text" id="set_gemini_model" class="form-input" value="<?php echo htmlspecialchars(isset($config['gemini_model']) ? $config['gemini_model'] : ZS_Config::DEFAULT_GEMINI_MODEL, ENT_QUOTES, 'UTF-8'); ?>">
                    </div>
                    <div class="form-group">
                        <label><?php echo htmlspecialchars(ZS_I18n::t('settings_github_repo'), ENT_QUOTES, 'UTF-8'); ?></label>
                        <input type="text" id="set_github_repo" class="form-input" value="<?php echo htmlspecialchars(isset($config['github_repo']) ? $config['github_repo'] : '', ENT_QUOTES, 'UTF-8'); ?>">
                    </div>
                    <div class="form-group">
                        <label><?php echo htmlspecialchars(ZS_I18n::t('settings_sync_url'), ENT_QUOTES, 'UTF-8'); ?></label>
                        <input type="text" id="set_rules_sync_url" class="form-input" value="<?php echo htmlspecialchars(isset($config['rules_sync_url']) ? $config['rules_sync_url'] : '', ENT_QUOTES, 'UTF-8'); ?>" placeholder="https://...">
                    </div>
                    <button type="submit" class="btn btn-blue"><?php echo htmlspecialchars(ZS_I18n::t('settings_save'), ENT_QUOTES, 'UTF-8'); ?></button>
                    <button type="button" class="btn btn-outline" id="btnTestGemini"><?php echo htmlspecialchars(ZS_I18n::t('settings_test_gemini'), ENT_QUOTES, 'UTF-8'); ?></button>
                    <button type="button" class="btn btn-outline" id="btnClearCache"><?php echo htmlspecialchars(ZS_I18n::t('settings_clear_cache'), ENT_QUOTES, 'UTF-8'); ?></button>
                    <button type="button" class="btn btn-outline" id="btnSyncRules"><?php echo htmlspecialchars(ZS_I18n::t('btn_sync_rules'), ENT_QUOTES, 'UTF-8'); ?></button>
                </form>
                <hr style="border:0;border-top:1px solid #334155;margin:20px 0;">
                <h4><?php echo htmlspecialchars(ZS_I18n::t('settings_trusted_title'), ENT_QUOTES, 'UTF-8'); ?></h4>
                <?php
                $trusted = (is_array($knowledge) && isset($knowledge['trusted'])) ? $knowledge['trusted'] : array();
                if (empty($trusted)) : ?>
                    <p style="color:#94a3b8;font-size:12px;"><?php echo htmlspecialchars(ZS_I18n::t('settings_no_trusted'), ENT_QUOTES, 'UTF-8'); ?></p>
                <?php else : foreach ($trusted as $h => $tMeta) : ?>
                    <div>
                        <code><?php echo htmlspecialchars(substr($h, 0, 16), ENT_QUOTES, 'UTF-8'); ?>…</code>
                        <button type="button" class="btn-del-single" data-revoke-hash="<?php echo htmlspecialchars($h, ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars(ZS_I18n::t('settings_btn_revoke'), ENT_QUOTES, 'UTF-8'); ?></button>
                    </div>
                <?php endforeach; endif; ?>
                <h4><?php echo htmlspecialchars(ZS_I18n::t('settings_quarantine_title'), ENT_QUOTES, 'UTF-8'); ?></h4>
                <?php
                $quarantineDir = ZS_Config::getQuarantineDir($rootDir, $dataDir);
                $quarantined = ZS_Quarantine::listQuarantined($quarantineDir);
                if (empty($quarantined)) : ?>
                    <p style="color:#94a3b8;font-size:12px;"><?php echo htmlspecialchars(ZS_I18n::t('settings_no_quarantine'), ENT_QUOTES, 'UTF-8'); ?></p>
                <?php else : foreach ($quarantined as $bName => $qMeta) : ?>
                    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;gap:8px;">
                        <div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;">
                            <code><?php echo htmlspecialchars($bName, ENT_QUOTES, 'UTF-8'); ?></code>
                            <?php if (!empty($qMeta['original_path'])) : ?>
                                <span style="color:#94a3b8;margin-left:6px;"><?php echo htmlspecialchars(ZS_Share::anonymizePath($qMeta['original_path'], $rootDir), ENT_QUOTES, 'UTF-8'); ?></span>
                            <?php endif; ?>
                        </div>
                        <button type="button" class="btn btn-green" data-restore="<?php echo htmlspecialchars($bName, ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars(ZS_I18n::t('settings_btn_restore'), ENT_QUOTES, 'UTF-8'); ?></button>
                    </div>
                <?php endforeach; endif; ?>
            </div>
        </div>
    </div>

    <div id="geminiKeyModal" class="modal-overlay">
        <div class="modal-content modal-sm" role="dialog" aria-labelledby="geminiKeyModalTitle">
            <div class="modal-header">
                <strong id="geminiKeyModalTitle" style="color:#38bdf8;"><?php echo htmlspecialchars(ZS_I18n::t('gemini_key_modal_title'), ENT_QUOTES, 'UTF-8'); ?></strong>
                <button type="button" class="modal-close" id="btnCloseGeminiKeyModal">&times;</button>
            </div>
            <div class="modal-body-standard">
                <p id="geminiKeyModalDesc"><?php echo htmlspecialchars(ZS_I18n::t('gemini_key_modal_desc'), ENT_QUOTES, 'UTF-8'); ?></p>
                <div id="geminiKeyRateLimitNotice" style="display:none;background:#450a0a;border:1px solid #b91c1c;color:#fecaca;padding:10px 12px;border-radius:6px;margin-bottom:14px;font-size:13px;line-height:1.5;">
                    <?php echo htmlspecialchars(ZS_I18n::t('gemini_key_ratelimit_notice'), ENT_QUOTES, 'UTF-8'); ?>
                </div>
                <form id="formGeminiKeyModal">
                    <div class="form-group">
                        <label for="modal_gemini_api_keys"><?php echo htmlspecialchars(ZS_I18n::t('gemini_key_input_label'), ENT_QUOTES, 'UTF-8'); ?></label>
                        <textarea id="modal_gemini_api_keys" class="form-textarea" rows="3" placeholder="<?php echo htmlspecialchars(ZS_I18n::t('settings_keys_placeholder'), ENT_QUOTES, 'UTF-8'); ?>"></textarea>
                        <p style="font-size:12px;color:#94a3b8;margin-top:4px;"><?php echo htmlspecialchars(ZS_I18n::t('gemini_key_hint'), ENT_QUOTES, 'UTF-8'); ?></p>
                    </div>
                    <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:16px;">
                        <button type="button" class="btn btn-gray" id="btnCancelGeminiKeyModal"><?php echo htmlspecialchars(ZS_I18n::t('gemini_key_btn_cancel'), ENT_QUOTES, 'UTF-8'); ?></button>
                        <button type="submit" class="btn btn-blue" id="btnSaveGeminiKeyModal"><?php echo htmlspecialchars(ZS_I18n::t('gemini_key_btn_save'), ENT_QUOTES, 'UTF-8'); ?></button>
                    </div>
                </form>
            </div>
        </div>
    </div>
        <?php
        self::renderHtmlFooter();
    }
}
