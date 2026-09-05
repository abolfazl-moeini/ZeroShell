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
<html lang="<?php echo htmlspecialchars($lang); ?>" dir="<?php echo $dir; ?>">
<head>
    <meta charset="UTF-8">
    <title><?php echo htmlspecialchars($title); ?></title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
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
        ?>
    <div class="card" style="max-width: 600px; margin-top: 40px;">
        <div class="header-row">
            <h2>🛡️ <?php echo htmlspecialchars(ZS_I18n::t('wizard_title')); ?></h2>
            <div>
                <button type="button" class="btn btn-outline" onclick="switchLang('<?php echo $lang === 'fa' ? 'en' : 'fa'; ?>')">
                    🌐 <?php echo $lang === 'fa' ? 'English' : 'فارسی'; ?>
                </button>
            </div>
        </div>
        <p style="color: #cbd5e1; font-size: 13px; line-height: 1.6;">
            <?php echo htmlspecialchars(ZS_I18n::t('wizard_desc')); ?>
        </p>

        <?php if (!empty($errorMsg)) : ?>
            <div style="background: #7f1d1d; color: #fee2e2; padding: 10px; border-radius: 6px; font-size: 13px; margin-bottom: 15px;">
                ⚠️ <?php echo htmlspecialchars($errorMsg); ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="">
            <input type="hidden" name="do_action" value="setup_wizard">
            <input type="hidden" name="generated_key" value="<?php echo htmlspecialchars($genKey); ?>">

            <div class="form-group">
                <label><?php echo htmlspecialchars(ZS_I18n::t('wizard_generated')); ?></label>
                <input type="text" readonly class="form-input" value="<?php echo htmlspecialchars($genKey); ?>" style="font-family: monospace; font-weight: bold; color: #38bdf8; background: #1e293b;" onclick="this.select();">
            </div>

            <div class="form-group">
                <label><?php echo htmlspecialchars(ZS_I18n::t('wizard_custom')); ?></label>
                <input type="text" name="custom_key" class="form-input" placeholder="<?php echo htmlspecialchars($genKey); ?>" minlength="12">
            </div>

            <button type="submit" class="btn btn-blue" style="width: 100%; margin-top: 10px; padding: 12px;">
                🚀 <?php echo htmlspecialchars(ZS_I18n::t('wizard_submit')); ?>
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
            <h2>🔒 <?php echo htmlspecialchars(ZS_I18n::t('login_title')); ?></h2>
            <div>
                <button type="button" class="btn btn-outline" onclick="switchLang('<?php echo $lang === 'fa' ? 'en' : 'fa'; ?>')">
                    🌐 <?php echo $lang === 'fa' ? 'English' : 'فارسی'; ?>
                </button>
            </div>
        </div>

        <?php if (!empty($errorMsg)) : ?>
            <div style="background: #7f1d1d; color: #fee2e2; padding: 10px; border-radius: 6px; font-size: 13px; margin-bottom: 15px;">
                ⚠️ <?php echo htmlspecialchars($errorMsg); ?>
            </div>
        <?php endif; ?>

        <p style="color: #cbd5e1; font-size: 13px;">
            <?php echo htmlspecialchars(ZS_I18n::t('login_prompt')); ?>
        </p>

        <form method="POST" action="">
            <input type="hidden" name="do_action" value="login">
            <div class="form-group">
                <input type="password" name="key" class="form-input" required autofocus placeholder="••••••••••••">
            </div>
            <button type="submit" class="btn btn-blue" style="width: 100%; padding: 10px;">
                🔓 <?php echo htmlspecialchars(ZS_I18n::t('login_submit')); ?>
            </button>
        </form>
    </div>
        <?php
        self::renderHtmlFooter();
    }

    public static function renderScanProgress($session, $rootDir) {
        $refreshUrl = strtok($_SERVER['REQUEST_URI'], '?');
        // If cookie missing, fallback query param
        if (empty($_COOKIE['zs_session']) && isset($_REQUEST['key'])) {
            $refreshUrl .= '?key=' . urlencode($_REQUEST['key']);
        }

        $extraHead = '    <meta http-equiv="refresh" content="1;url=' . htmlspecialchars($refreshUrl, ENT_QUOTES, 'UTF-8') . '">' . "\n";
        self::renderHtmlHeader('', $extraHead);
        ?>
    <div class="card">
        <div class="header-row">
            <h2>🛡️ <?php echo htmlspecialchars(ZS_I18n::t('app_title')); ?></h2>
            <div>
                <button type="button" class="btn btn-outline" onclick="switchLang('<?php echo ZS_I18n::getLang() === 'fa' ? 'en' : 'fa'; ?>')">
                    🌐 <?php echo ZS_I18n::getLang() === 'fa' ? 'English' : 'فارسی'; ?>
                </button>
            </div>
        </div>

        <div class="status running">
            ⏳ <?php echo htmlspecialchars(ZS_I18n::t('status_running')); ?>
        </div>

        <div class="stats">
            <div class="stat-box">
                <div class="stat-num"><?php echo number_format(isset($session['scanned_files']) ? $session['scanned_files'] : 0); ?></div>
                <div><?php echo htmlspecialchars(ZS_I18n::t('stat_scanned_files')); ?></div>
            </div>
            <div class="stat-box">
                <div class="stat-num"><?php echo number_format(isset($session['scanned_dirs']) ? $session['scanned_dirs'] : 0); ?></div>
                <div><?php echo htmlspecialchars(ZS_I18n::t('stat_scanned_dirs')); ?></div>
            </div>
            <div class="stat-box">
                <div class="stat-num danger"><?php echo count(isset($session['infected_files']) ? $session['infected_files'] : array()); ?></div>
                <div><?php echo htmlspecialchars(ZS_I18n::t('stat_infected_files')); ?></div>
            </div>
            <div class="stat-box">
                <div class="stat-num success"><?php echo number_format(isset($session['trusted_bypassed']) ? $session['trusted_bypassed'] : 0); ?></div>
                <div><?php echo htmlspecialchars(ZS_I18n::t('stat_trusted_bypassed')); ?></div>
            </div>
        </div>

        <p style="font-size: 13px;">
            <strong><?php echo htmlspecialchars(ZS_I18n::t('current_dir')); ?></strong>
            <span class="dir-path"><?php echo htmlspecialchars(isset($session['current_dir']) ? $session['current_dir'] : $rootDir); ?></span>
        </p>
    </div>
        <?php
        self::renderHtmlFooter();
    }

    public static function renderReport($session, $rootDir, $dataDir, $config, $store) {
        self::renderHtmlHeader();
        $lang = ZS_I18n::getLang();
        $infected = isset($session['infected_files']) && is_array($session['infected_files']) ? $session['infected_files'] : array();
        $knowledge = $store->loadKnowledge();
        $candidates = isset($knowledge['candidates']) ? $knowledge['candidates'] : array();

        $infectedJs = array();
        foreach ($infected as $idx => $f) {
            $path = $f['path'];
            $norm = isset($f['norm_sha256']) ? $f['norm_sha256'] : '';
            $isCandidate = isset($candidates[$norm]);
            $candFirstPath = $isCandidate && isset($candidates[$norm]['first_path']) ? $candidates[$norm]['first_path'] : '';

            $infectedJs[] = array(
                'idx'          => $idx,
                'path'         => $path,
                'filename'     => basename($path),
                'b64'          => base64_encode($path),
                'reason'       => $f['reason'],
                'size'         => $f['size'],
                'size_fmt'     => number_format($f['size']) . ' B',
                'status'       => $f['status'],
                'raw_sha256'   => isset($f['raw_sha256']) ? $f['raw_sha256'] : '',
                'norm_sha256'  => $norm,
                'row_id'       => 'row_' . md5($path),
                'is_candidate' => $isCandidate,
                'first_path'   => $candFirstPath,
                'ai_verdict'   => isset($f['ai_verdict']) ? $f['ai_verdict'] : null,
            );
        }

        $csrfToken = ZS_Http::getCsrfToken(isset($config['csrf_secret']) ? $config['csrf_secret'] : '');
        $hasGeminiKeys = !empty(ZS_Config::getGeminiKeys($config));
        ?>
    <script>
        window.REVIEW_ITEMS = <?php echo json_encode($infectedJs, JSON_UNESCAPED_SLASHES); ?>;
        window.ZS_I18N = <?php echo json_encode(ZS_I18n::getAll(), JSON_UNESCAPED_SLASHES); ?>;
        window.ZS_CSRF = <?php echo json_encode($csrfToken); ?>;
    </script>

    <div class="card">
        <div class="header-row">
            <h2>🛡️ <?php echo htmlspecialchars(ZS_I18n::t('app_title')); ?></h2>
            <div style="display: flex; gap: 8px;">
                <button type="button" class="btn btn-outline" onclick="openSettingsModal()">
                    ⚙️ <?php echo htmlspecialchars(ZS_I18n::t('btn_settings')); ?>
                </button>
                <button type="button" class="btn btn-outline" onclick="switchLang('<?php echo $lang === 'fa' ? 'en' : 'fa'; ?>')">
                    🌐 <?php echo $lang === 'fa' ? 'English' : 'فارسی'; ?>
                </button>
            </div>
        </div>

        <div class="status completed">
            ✅ <?php echo htmlspecialchars(ZS_I18n::t('status_completed')); ?>
        </div>

        <div class="stats">
            <div class="stat-box">
                <div class="stat-num"><?php echo number_format(isset($session['scanned_files']) ? $session['scanned_files'] : 0); ?></div>
                <div><?php echo htmlspecialchars(ZS_I18n::t('stat_scanned_files')); ?></div>
            </div>
            <div class="stat-box">
                <div class="stat-num"><?php echo number_format(isset($session['scanned_dirs']) ? $session['scanned_dirs'] : 0); ?></div>
                <div><?php echo htmlspecialchars(ZS_I18n::t('stat_scanned_dirs')); ?></div>
            </div>
            <div class="stat-box">
                <div class="stat-num danger"><?php echo count($infected); ?></div>
                <div><?php echo htmlspecialchars(ZS_I18n::t('stat_infected_files')); ?></div>
            </div>
            <div class="stat-box">
                <div class="stat-num success"><?php echo number_format(isset($session['trusted_bypassed']) ? $session['trusted_bypassed'] : 0); ?></div>
                <div><?php echo htmlspecialchars(ZS_I18n::t('stat_trusted_bypassed')); ?></div>
            </div>
        </div>

        <!-- Toolbar -->
        <div style="margin: 20px 0; display: flex; gap: 10px; flex-wrap: wrap; align-items: center;">
            <a href="?reset=1" class="btn btn-gray" onclick="return confirm('<?php echo htmlspecialchars(ZS_I18n::t('confirm_rescan')); ?>')">
                🔄 <?php echo htmlspecialchars(ZS_I18n::t('btn_rescan')); ?>
            </a>

            <?php if (!empty($infected)) : ?>
                <button type="button" class="btn btn-purple" onclick="startReviewMode()">
                    ⚡ <?php echo htmlspecialchars(ZS_I18n::t('btn_review')); ?> (<?php echo count($infected); ?>)
                </button>
                <button type="button" class="btn btn-blue" onclick="startAutoAiReview()" <?php echo $hasGeminiKeys ? '' : 'disabled title="Configure Gemini API key in Settings first"'; ?>>
                    🤖 <?php echo htmlspecialchars(ZS_I18n::t('btn_auto_ai')); ?>
                </button>
            <?php endif; ?>
        </div>

        <!-- Threats Table -->
        <h3>📋 <?php echo htmlspecialchars(ZS_I18n::t('stat_infected_files')); ?> (<?php echo count($infected); ?>):</h3>
        <?php if (empty($infected)) : ?>
            <p style="color: #4ade80;"><?php echo htmlspecialchars(ZS_I18n::t('no_threats_found')); ?></p>
        <?php else : ?>
            <table>
                <thead>
                    <tr>
                        <th><?php echo htmlspecialchars(ZS_I18n::t('table_num')); ?></th>
                        <th><?php echo htmlspecialchars(ZS_I18n::t('table_path')); ?></th>
                        <th><?php echo htmlspecialchars(ZS_I18n::t('table_reason')); ?></th>
                        <th><?php echo htmlspecialchars(ZS_I18n::t('table_size')); ?></th>
                        <th><?php echo htmlspecialchars(ZS_I18n::t('table_actions')); ?></th>
                    </tr>
                </thead>
                <tbody id="infectedTableBody">
                    <?php foreach ($infected as $idx => $f) : ?>
                        <?php
                        $status = isset($f['status']) ? $f['status'] : 'FOUND';
                        $isDel = (strpos($status, 'QUARANTINED') !== false || strpos($status, 'DELETED') !== false);
                        $isTrusted = ($status === 'TRUSTED' || $status === 'TRUSTED_HIDDEN');
                        $isAiQuarantine = ($status === 'AI_QUARANTINED');
                        $isAiSkip = ($status === 'AI_SKIPPED');
                        $isAiError = ($status === 'AI_ERROR');
                        $norm = isset($f['norm_sha256']) ? $f['norm_sha256'] : '';
                        $isCandidate = isset($candidates[$norm]);
                        $rowId = 'row_' . md5($f['path']);
                        ?>
                        <tr id="<?php echo $rowId; ?>">
                            <td><?php echo $idx + 1; ?></td>
                            <td class="dir-path"><?php echo htmlspecialchars($f['path']); ?></td>
                            <td style="color: #facc15;"><?php echo htmlspecialchars($f['reason']); ?></td>
                            <td><?php echo number_format($f['size']); ?> B</td>
                            <td class="action-cell">
                                <div class="btn-action-group">
                                    <button type="button" class="btn-view-single" onclick="startReviewMode(<?php echo $idx; ?>)">
                                        👁️ <?php echo htmlspecialchars(ZS_I18n::t('btn_inspect')); ?>
                                    </button>
                                    <?php if ($isAiQuarantine) : ?>
                                        <span class="badge-del"><?php echo htmlspecialchars(ZS_I18n::t('badge_ai_quarantined')); ?> ✅</span>
                                    <?php elseif ($isDel) : ?>
                                        <span class="badge-del"><?php echo htmlspecialchars(ZS_I18n::t('badge_deleted')); ?> ✅</span>
                                    <?php elseif ($isTrusted) : ?>
                                        <span class="badge-trusted"><?php echo htmlspecialchars(ZS_I18n::t('badge_trusted')); ?> 🛡️</span>
                                    <?php elseif ($isAiSkip) : ?>
                                        <span class="badge-ai-skip"><?php echo htmlspecialchars(ZS_I18n::t('badge_ai_skipped')); ?></span>
                                        <button type="button" class="btn-del-single" onclick="deleteFileDirect('<?php echo base64_encode($f['path']); ?>', '<?php echo $rowId; ?>', <?php echo $idx; ?>)">
                                            🗑️ <?php echo htmlspecialchars(ZS_I18n::t('btn_delete')); ?>
                                        </button>
                                    <?php elseif ($isAiError) : ?>
                                        <span class="badge-found"><?php echo htmlspecialchars(ZS_I18n::t('badge_ai_error')); ?></span>
                                        <button type="button" class="btn-del-single" onclick="deleteFileDirect('<?php echo base64_encode($f['path']); ?>', '<?php echo $rowId; ?>', <?php echo $idx; ?>)">
                                            🗑️ <?php echo htmlspecialchars(ZS_I18n::t('btn_delete')); ?>
                                        </button>
                                    <?php elseif ($isCandidate) : ?>
                                        <span class="badge-strike1"><?php echo htmlspecialchars(ZS_I18n::t('badge_strike1')); ?></span>
                                        <button type="button" class="btn-del-single" onclick="deleteFileDirect('<?php echo base64_encode($f['path']); ?>', '<?php echo $rowId; ?>', <?php echo $idx; ?>)">
                                            🗑️ <?php echo htmlspecialchars(ZS_I18n::t('btn_delete')); ?>
                                        </button>
                                    <?php else : ?>
                                        <button type="button" class="btn-del-single" onclick="deleteFileDirect('<?php echo base64_encode($f['path']); ?>', '<?php echo $rowId; ?>', <?php echo $idx; ?>)">
                                            🗑️ <?php echo htmlspecialchars(ZS_I18n::t('btn_delete')); ?>
                                        </button>
                                    <?php endif; ?>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>

        <!-- Share CTA Card -->
        <div class="share-card">
            <h3>🤝 <?php echo htmlspecialchars(ZS_I18n::t('share_title')); ?></h3>
            <p style="color: #cbd5e1; font-size: 13px; line-height: 1.6; margin: 0 0 15px 0;">
                <?php echo htmlspecialchars(ZS_I18n::t('share_desc')); ?>
            </p>

            <?php if (!empty($config['report_endpoint'])) : ?>
                <div style="margin-bottom: 12px; font-size: 12px; color: #94a3b8;">
                    <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                        <input type="checkbox" id="chkIncludeSamples">
                        <?php echo htmlspecialchars(ZS_I18n::t('share_include_samples')); ?>
                    </label>
                </div>
            <?php endif; ?>

            <div class="share-actions">
                <?php if (!empty($config['report_endpoint'])) : ?>
                    <button type="button" class="btn btn-green" onclick="submitMaintainer()">
                        🚀 <?php echo htmlspecialchars(ZS_I18n::t('share_btn_maintainer')); ?>
                    </button>
                <?php endif; ?>

                <button type="button" class="btn btn-blue" onclick="shareViaGithub()">
                    🐙 <?php echo htmlspecialchars(ZS_I18n::t('share_btn_github')); ?>
                </button>
                <button type="button" class="btn btn-gray" onclick="copyShareMarkdown()">
                    📋 <?php echo htmlspecialchars(ZS_I18n::t('share_btn_copy')); ?>
                </button>
                <button type="button" class="btn btn-outline" onclick="downloadShareJson()">
                    💾 <?php echo htmlspecialchars(ZS_I18n::t('share_btn_json')); ?>
                </button>
            </div>
        </div>
    </div>

    <!-- Review Modal -->
    <div id="fileViewerModal" class="modal-overlay" onclick="onBackdropClick(event, 'fileViewerModal')">
        <div class="modal-content">
            <div class="review-progress-bar">
                <div class="review-progress-fill" id="reviewProgressFill"></div>
            </div>
            <div class="modal-header">
                <div class="modal-header-left">
                    <span class="badge-counter" id="modalCounter">1 / 1</span>
                    <span class="badge-status pending" id="modalFileStatus"><?php echo htmlspecialchars(ZS_I18n::t('modal_pending')); ?></span>
                    <span class="badge-counter" id="modalAiBadge" style="display: none; background: #6366f1;">AI</span>
                    <strong id="modalFileName" style="color: #38bdf8; font-size: 15px; direction: ltr; font-family: monospace;">-</strong>
                </div>
                <div class="modal-nav-group">
                    <button type="button" class="btn btn-gray" id="btnPrevTop" onclick="prevReviewFile()">⬅️</button>
                    <button type="button" class="btn btn-blue" id="btnNextTop" onclick="nextReviewFile()">➡️</button>
                    <button type="button" class="modal-close" onclick="closeViewModal()">&times;</button>
                </div>
            </div>
            <div id="strikeBanner" class="strike-banner"></div>
            <div class="modal-info-bar">
                <div><?php echo htmlspecialchars(ZS_I18n::t('modal_path')); ?> <span class="tag" id="modalFilePath">-</span></div>
                <div><?php echo htmlspecialchars(ZS_I18n::t('modal_size')); ?> <span class="tag" id="modalFileSize">-</span></div>
                <div><?php echo htmlspecialchars(ZS_I18n::t('modal_reason')); ?> <span style="color: #facc15;" id="modalFileReason">-</span></div>
                <div><?php echo htmlspecialchars(ZS_I18n::t('modal_raw_hash')); ?> <span class="tag" id="modalRawHash">-</span></div>
                <div><?php echo htmlspecialchars(ZS_I18n::t('modal_norm_hash')); ?> <span class="tag" id="modalNormHash">-</span></div>
            </div>
            <div class="modal-body">
                <button type="button" class="btn-copy-floating" id="btnCopyFloating" onclick="copyModalContent(this)">
                    📋 <span class="copy-text"><?php echo htmlspecialchars(ZS_I18n::t('modal_copy_code')); ?></span>
                </button>
                <pre class="code-viewer"><code id="modalFileContent"><?php echo htmlspecialchars(ZS_I18n::t('modal_loading')); ?></code></pre>
            </div>
            <div class="modal-footer">
                <div class="kbd-guide">
                    <span><?php echo htmlspecialchars(ZS_I18n::t('kbd_guide')); ?></span>
                    <span><kbd>C</kbd> <?php echo htmlspecialchars(ZS_I18n::t('kbd_copy')); ?></span>
                    <span><kbd>D</kbd> <?php echo htmlspecialchars(ZS_I18n::t('kbd_delete')); ?></span>
                    <span><kbd>N</kbd> / <kbd>Space</kbd> <?php echo htmlspecialchars(ZS_I18n::t('kbd_next')); ?></span>
                    <span><kbd>P</kbd> <?php echo htmlspecialchars(ZS_I18n::t('kbd_prev')); ?></span>
                    <span><kbd>B</kbd> <?php echo htmlspecialchars(ZS_I18n::t('kbd_clean')); ?></span>
                    <span><kbd>A</kbd> <?php echo htmlspecialchars(ZS_I18n::t('kbd_ai')); ?></span>
                    <span><kbd>Esc</kbd> <?php echo htmlspecialchars(ZS_I18n::t('kbd_esc')); ?></span>
                </div>
                <div class="modal-footer-actions">
                    <button type="button" class="btn btn-outline" id="modalAskAiBtn" onclick="askAiCurrent()" <?php echo $hasGeminiKeys ? '' : 'disabled title="Set Gemini API key in Settings"'; ?>>
                        🤖 <?php echo htmlspecialchars(ZS_I18n::t('btn_ask_ai')); ?> [A]
                    </button>
                    <button type="button" class="btn btn-gray" onclick="markCleanCurrent()">
                        🛡️ <?php echo htmlspecialchars(ZS_I18n::t('btn_mark_clean')); ?> [B]
                    </button>
                    <button type="button" class="btn btn-gray" id="btnPrevBottom" onclick="prevReviewFile()">
                        ⬅️ <?php echo htmlspecialchars(ZS_I18n::t('btn_prev')); ?>
                    </button>
                    <button type="button" class="btn btn-blue" id="btnNextBottom" onclick="nextReviewFile()">
                        ➡️ <?php echo htmlspecialchars(ZS_I18n::t('btn_next_keep')); ?>
                    </button>
                    <button type="button" class="btn btn-red" id="modalDeleteBtn" onclick="deleteAndNext()">
                        🗑️ <?php echo htmlspecialchars(ZS_I18n::t('btn_del_next')); ?>
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Auto AI Review Modal -->
    <div id="autoReviewModal" class="modal-overlay" onclick="onBackdropClick(event, 'autoReviewModal')">
        <div class="modal-content modal-md">
            <div class="modal-header">
                <strong style="color: #38bdf8; font-size: 16px;">🤖 <?php echo htmlspecialchars(ZS_I18n::t('auto_ai_title')); ?></strong>
                <button type="button" class="modal-close" onclick="closeAutoReviewModal()">&times;</button>
            </div>
            <div class="modal-body-standard">
                <p style="color: #cbd5e1; font-size: 13px; line-height: 1.6; margin-top: 0;">
                    <?php echo htmlspecialchars(ZS_I18n::t('auto_ai_desc')); ?>
                </p>

                <div class="review-progress-bar" style="border-radius: 4px; height: 8px; margin: 20px 0;">
                    <div class="review-progress-fill" id="autoReviewFill" style="background: #38bdf8; border-radius: 4px;"></div>
                </div>

                <div id="autoReviewProgressText" style="font-weight: bold; font-size: 14px; color: #f8fafc; margin-bottom: 10px;">
                    Starting AI review...
                </div>

                <div id="autoReviewStats" style="font-size: 13px; color: #94a3b8; margin-bottom: 20px;">
                    Cache hits: 0 | Quarantined: 0 | Skipped: 0 | Errors: 0
                </div>

                <div style="display: flex; gap: 10px;">
                    <button type="button" class="btn btn-gray" id="btnAutoPause" onclick="pauseAutoReview()">
                        ⏸️ <?php echo htmlspecialchars(ZS_I18n::t('auto_ai_pause')); ?>
                    </button>
                    <button type="button" class="btn btn-blue" id="btnAutoResume" style="display: none;" onclick="resumeAutoReview()">
                        ▶️ <?php echo htmlspecialchars(ZS_I18n::t('auto_ai_resume')); ?>
                    </button>
                    <button type="button" class="btn btn-red" onclick="closeAutoReviewModal()">
                        ⏹️ <?php echo htmlspecialchars(ZS_I18n::t('auto_ai_cancel')); ?>
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Settings Modal -->
    <div id="settingsModal" class="modal-overlay" onclick="onBackdropClick(event, 'settingsModal')">
        <div class="modal-content modal-md">
            <div class="modal-header">
                <strong style="color: #38bdf8; font-size: 16px;">⚙️ <?php echo htmlspecialchars(ZS_I18n::t('settings_title')); ?></strong>
                <button type="button" class="modal-close" onclick="closeSettingsModal()">&times;</button>
            </div>
            <div class="modal-body-standard">
                <?php if (ZS_Config::isDataInWebRoot($rootDir, $dataDir)) : ?>
                    <div style="background: rgba(245, 158, 11, 0.15); border: 1px solid #f59e0b; color: #fde68a; padding: 10px 14px; border-radius: 6px; font-size: 12px; margin-bottom: 15px; line-height: 1.5;">
                        ⚠️ <strong>Security Advisory:</strong> Data directory is within the web root (<code><?php echo htmlspecialchars($dataDir); ?></code>). It is guarded by <code>.htaccess</code> and <code>index.php</code>, but setting <code>MALWARE_CLEANER_DATA_DIR</code> outside the web root is strongly recommended for API keys and state files.
                    </div>
                <?php endif; ?>
                <form id="formSettings" onsubmit="event.preventDefault(); saveSettingsNow();">
                    <div class="form-group">
                        <label><?php echo htmlspecialchars(ZS_I18n::t('settings_new_key')); ?></label>
                        <input type="password" id="set_new_access_key" class="form-input" placeholder="Min 12 characters">
                    </div>

                    <div class="form-group">
                        <label><?php echo htmlspecialchars(ZS_I18n::t('settings_gemini_keys')); ?></label>
                        <textarea id="set_gemini_api_keys" class="form-textarea" placeholder="AIzaSy..."><?php
                            $keys = ZS_Config::getGeminiKeys($config);
                            echo htmlspecialchars(implode("\n", $keys));
                        ?></textarea>
                    </div>

                    <div class="form-group">
                        <label><?php echo htmlspecialchars(ZS_I18n::t('settings_gemini_model')); ?></label>
                        <input type="text" id="set_gemini_model" class="form-input" value="<?php echo htmlspecialchars(isset($config['gemini_model']) ? $config['gemini_model'] : 'gemini-2.0-flash'); ?>">
                    </div>

                    <div class="form-group">
                        <label><?php echo htmlspecialchars(ZS_I18n::t('settings_sync_url')); ?></label>
                        <input type="text" id="set_rules_sync_url" class="form-input" value="<?php echo htmlspecialchars(isset($config['rules_sync_url']) ? $config['rules_sync_url'] : ''); ?>">
                    </div>

                    <div class="form-group">
                        <label><?php echo htmlspecialchars(ZS_I18n::t('settings_github_repo')); ?></label>
                        <input type="text" id="set_github_repo" class="form-input" value="<?php echo htmlspecialchars(isset($config['github_repo']) ? $config['github_repo'] : 'OWNER/REPO'); ?>">
                    </div>

                    <div class="form-group">
                        <label><?php echo htmlspecialchars(ZS_I18n::t('settings_report_endpoint')); ?></label>
                        <input type="text" id="set_report_endpoint" class="form-input" placeholder="https://..." value="<?php echo htmlspecialchars(isset($config['report_endpoint']) ? $config['report_endpoint'] : ''); ?>">
                    </div>

                    <div style="display: flex; gap: 10px; margin-bottom: 25px;">
                        <button type="submit" class="btn btn-blue">💾 <?php echo htmlspecialchars(ZS_I18n::t('settings_save')); ?></button>
                        <button type="button" class="btn btn-outline" id="btnSyncRulesModal" onclick="syncRulesNow()">🔄 <?php echo htmlspecialchars(ZS_I18n::t('btn_sync_rules')); ?></button>
                        <button type="button" class="btn btn-outline" onclick="clearAiCacheNow()">🧹 <?php echo htmlspecialchars(ZS_I18n::t('settings_clear_cache')); ?></button>
                    </div>
                </form>

                <hr style="border: 0; border-top: 1px solid #334155; margin: 25px 0;">

                <!-- Trusted Hashes Whitelist -->
                <h4>🛡️ <?php echo htmlspecialchars(ZS_I18n::t('settings_trusted_title')); ?></h4>
                <?php
                $trusted = isset($knowledge['trusted']) && is_array($knowledge['trusted']) ? $knowledge['trusted'] : array();
                if (empty($trusted)) : ?>
                    <p style="color: #94a3b8; font-size: 12px;"><?php echo htmlspecialchars(ZS_I18n::t('settings_no_trusted')); ?></p>
                <?php else : ?>
                    <table>
                        <thead>
                            <tr>
                                <th>Hash</th>
                                <th>Path</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($trusted as $h => $tMeta) : ?>
                                <tr id="trusted_row_<?php echo htmlspecialchars($h); ?>">
                                    <td class="dir-path"><?php echo htmlspecialchars(substr($h, 0, 16)); ?>...</td>
                                    <td class="dir-path"><?php echo htmlspecialchars(isset($tMeta['first_path']) ? $tMeta['first_path'] : '-'); ?></td>
                                    <td>
                                        <button type="button" class="btn-del-single" onclick="revokeTrustedHash('<?php echo htmlspecialchars($h); ?>')">
                                            <?php echo htmlspecialchars(ZS_I18n::t('settings_btn_revoke')); ?>
                                        </button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>

                <hr style="border: 0; border-top: 1px solid #334155; margin: 25px 0;">

                <!-- Quarantined Files -->
                <h4>📦 <?php echo htmlspecialchars(ZS_I18n::t('settings_quarantine_title')); ?></h4>
                <?php
                $quarantineDir = ZS_Config::getQuarantineDir($rootDir, $dataDir);
                $quarantined = ZS_Quarantine::listQuarantined($quarantineDir);
                if (empty($quarantined)) : ?>
                    <p style="color: #94a3b8; font-size: 12px;"><?php echo htmlspecialchars(ZS_I18n::t('settings_no_quarantine')); ?></p>
                <?php else : ?>
                    <table>
                        <thead>
                            <tr>
                                <th>File</th>
                                <th>Original Path</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($quarantined as $bName => $qMeta) : ?>
                                <tr id="quarantine_row_<?php echo htmlspecialchars($bName); ?>">
                                    <td><?php echo htmlspecialchars(isset($qMeta['backup_name']) ? $qMeta['backup_name'] : $bName); ?></td>
                                    <td class="dir-path"><?php echo htmlspecialchars(isset($qMeta['original_path']) ? $qMeta['original_path'] : '-'); ?></td>
                                    <td>
                                        <button type="button" class="btn btn-green" style="padding: 4px 8px; font-size: 11px;" onclick="restoreQuarantinedFile('<?php echo htmlspecialchars($bName); ?>')">
                                            <?php echo htmlspecialchars(ZS_I18n::t('settings_btn_restore')); ?>
                                        </button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>

                <hr style="border: 0; border-top: 1px solid #334155; margin: 25px 0;">

                <h4>💣 <?php echo htmlspecialchars(ZS_I18n::t('settings_self_destruct')); ?></h4>
                <p style="color: #94a3b8; font-size: 12px; line-height: 1.5;">
                    <?php echo htmlspecialchars(ZS_I18n::t('settings_self_destruct_help')); ?>
                </p>
                <label style="display: flex; align-items: center; gap: 8px; font-size: 12px; color: #cbd5e1; margin: 8px 0;">
                    <input type="checkbox" id="chkDestructKnowledge">
                    <?php echo htmlspecialchars(ZS_I18n::t('settings_self_destruct_knowledge')); ?>
                </label>
                <label style="display: flex; align-items: center; gap: 8px; font-size: 12px; color: #cbd5e1; margin: 8px 0 12px 0;">
                    <input type="checkbox" id="chkDestructQuarantine">
                    <?php echo htmlspecialchars(ZS_I18n::t('settings_self_destruct_quarantine')); ?>
                </label>
                <button type="button" class="btn btn-red" onclick="selfDestructNow()">
                    <?php echo htmlspecialchars(ZS_I18n::t('settings_self_destruct_btn')); ?>
                </button>
            </div>
        </div>
    </div>
        <?php
        self::renderHtmlFooter();
    }
}
