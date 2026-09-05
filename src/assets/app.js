let currentReviewIndex = 0;
let isModalActive = false;
let autoReviewActive = false;
let autoReviewPaused = false;
let autoReviewStats = { hits: 0, quarantined: 0, skipped: 0, errors: 0 };

function t(key, vars = {}) {
    let str = (window.ZS_I18N && window.ZS_I18N[key]) ? window.ZS_I18N[key] : key;
    for (let k in vars) {
        str = str.replace(new RegExp('\\{' + k + '\\}', 'g'), vars[k]);
    }
    return str;
}

function showToast(msg) {
    const toast = document.getElementById('toastNotify');
    if (!toast) return;
    toast.innerText = msg;
    toast.style.display = 'block';
    setTimeout(() => {
        toast.style.display = 'none';
    }, 3000);
}

function getCsrfToken() {
    return window.ZS_CSRF || '';
}

// Language switch
function switchLang(lang) {
    document.cookie = "zs_lang=" + lang + ";path=/;max-age=" + (86400 * 365);
    window.location.reload();
}

// -------------------------------------------------------------
// Review Modal Functions
// -------------------------------------------------------------
function startReviewMode(startIndex = -1) {
    if (!window.REVIEW_ITEMS || window.REVIEW_ITEMS.length === 0) {
        alert(t('no_threats_found'));
        return;
    }

    if (startIndex >= 0 && startIndex < window.REVIEW_ITEMS.length) {
        currentReviewIndex = startIndex;
    } else {
        const firstPending = window.REVIEW_ITEMS.findIndex(item => !item.status.includes('QUARANTINED') && !item.status.includes('DELETED'));
        currentReviewIndex = (firstPending !== -1) ? firstPending : 0;
    }

    const modal = document.getElementById('fileViewerModal');
    if (modal) {
        modal.classList.add('active');
        isModalActive = true;
        loadCurrentFile();
    }
}

async function loadCurrentFile() {
    if (currentReviewIndex < 0 || currentReviewIndex >= window.REVIEW_ITEMS.length) return;
    const file = window.REVIEW_ITEMS[currentReviewIndex];

    const progressPct = Math.round(((currentReviewIndex + 1) / window.REVIEW_ITEMS.length) * 100);
    const progressFill = document.getElementById('reviewProgressFill');
    if (progressFill) progressFill.style.width = progressPct + '%';

    document.getElementById('modalCounter').innerText = `${currentReviewIndex + 1} / ${window.REVIEW_ITEMS.length}`;
    document.getElementById('modalFileName').innerText = file.filename;
    document.getElementById('modalFilePath').innerText = file.path;
    document.getElementById('modalFileSize').innerText = file.size_fmt;
    document.getElementById('modalFileReason').innerText = file.reason;
    document.getElementById('modalRawHash').innerText = file.raw_sha256 || '-';
    document.getElementById('modalNormHash').innerText = file.norm_sha256 || '-';

    const statusEl = document.getElementById('modalFileStatus');
    const delBtn = document.getElementById('modalDeleteBtn');
    const isDeleted = file.status && (file.status.includes('QUARANTINED') || file.status.includes('DELETED'));

    if (isDeleted) {
        statusEl.className = 'badge-status deleted';
        statusEl.innerText = t('badge_deleted') + ' ✅';
        if (delBtn) delBtn.disabled = true;
    } else if (file.status === 'TRUSTED') {
        statusEl.className = 'badge-status trusted';
        statusEl.innerText = t('badge_trusted') + ' 🛡️';
        if (delBtn) delBtn.disabled = false;
    } else {
        statusEl.className = 'badge-status pending';
        statusEl.innerText = t('modal_pending') + ' ⚠️';
        if (delBtn) delBtn.disabled = false;
    }

    // Strike 1 banner
    const strikeBanner = document.getElementById('strikeBanner');
    if (strikeBanner) {
        if (file.is_candidate) {
            strikeBanner.innerText = t('strike1_warning', { sample_path: file.first_path || file.path });
            strikeBanner.style.display = 'block';
        } else {
            strikeBanner.style.display = 'none';
        }
    }

    // AI Badge
    const aiBadge = document.getElementById('modalAiBadge');
    if (aiBadge) {
        if (file.ai_verdict) {
            aiBadge.style.display = 'inline-block';
            aiBadge.innerText = 'AI: ' + file.ai_verdict.verdict + ' (' + Math.round(file.ai_verdict.confidence * 100) + '%)';
        } else {
            aiBadge.style.display = 'none';
        }
    }

    const isFirst = (currentReviewIndex === 0);
    const isLast  = (currentReviewIndex === window.REVIEW_ITEMS.length - 1);
    const prevTop = document.getElementById('btnPrevTop');
    const prevBottom = document.getElementById('btnPrevBottom');
    if (prevTop) prevTop.disabled = isFirst;
    if (prevBottom) prevBottom.disabled = isFirst;

    const nextTop = document.getElementById('btnNextTop');
    const nextBottom = document.getElementById('btnNextBottom');
    if (nextTop) nextTop.innerText = isLast ? '🏁' : t('btn_next_keep');
    if (nextBottom) nextBottom.innerText = isLast ? '🏁 [Esc]' : t('btn_next_keep');

    // Highlight row in table
    document.querySelectorAll('tr.active-review-row').forEach(tr => tr.classList.remove('active-review-row'));
    const activeRow = document.getElementById(file.row_id);
    if (activeRow) {
        activeRow.classList.add('active-review-row');
        activeRow.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    // Fetch file content
    const codeEl = document.getElementById('modalFileContent');
    codeEl.textContent = t('modal_loading');

    try {
        const res = await fetch('?do_action=view_file&file_target=' + encodeURIComponent(file.b64));
        const data = await res.json();
        if (data.success) {
            codeEl.textContent = data.content;
            if (data.is_truncated) {
                codeEl.textContent += '\n\n' + t('modal_trunc_notice');
            }
        } else {
            codeEl.textContent = 'Error: ' + (data.message || 'Cannot read file.');
        }
    } catch (e) {
        codeEl.textContent = 'Network error fetching file content.';
    }
}

function nextReviewFile() {
    if (currentReviewIndex < window.REVIEW_ITEMS.length - 1) {
        currentReviewIndex++;
        loadCurrentFile();
    } else {
        showToast(t('auto_ai_done'));
        closeViewModal();
    }
}

function prevReviewFile() {
    if (currentReviewIndex > 0) {
        currentReviewIndex--;
        loadCurrentFile();
    }
}

function closeViewModal() {
    const modal = document.getElementById('fileViewerModal');
    if (modal) modal.classList.remove('active');
    isModalActive = false;
    document.querySelectorAll('tr.active-review-row').forEach(tr => tr.classList.remove('active-review-row'));
}

function onBackdropClick(event, modalId) {
    if (event.target.id === modalId) {
        const modal = document.getElementById(modalId);
        if (modal) modal.classList.remove('active');
        if (modalId === 'fileViewerModal') isModalActive = false;
    }
}

async function deleteAndNext() {
    if (currentReviewIndex < 0 || currentReviewIndex >= window.REVIEW_ITEMS.length) return;
    const file = window.REVIEW_ITEMS[currentReviewIndex];

    const delBtn = document.getElementById('modalDeleteBtn');
    if (delBtn) delBtn.disabled = true;

    try {
        const formData = new FormData();
        formData.append('do_action', 'delete_single');
        formData.append('file_target', file.b64);
        formData.append('csrf_token', getCsrfToken());

        const res = await fetch(window.location.pathname, {
            method: 'POST',
            headers: { 'X-CSRF-Token': getCsrfToken() },
            body: formData,
        });
        const data = await res.json();

        if (data.success) {
            file.status = 'QUARANTINED';
            file.is_candidate = false;

            const row = document.getElementById(file.row_id);
            if (row) {
                const actCell = row.querySelector('.action-cell');
                if (actCell) {
                    actCell.innerHTML = `<button type="button" class="btn-view-single" onclick="startReviewMode(${file.idx})">${t('btn_inspect')}</button> <span class="badge-del">${t('badge_deleted')} ✅</span>`;
                }
            }

            const strikeBanner = document.getElementById('strikeBanner');
            if (strikeBanner) strikeBanner.style.display = 'none';

            if (data.candidate_revoked) {
                showToast(t('toast_revoked_by_malicious'));
            } else {
                showToast(t('toast_quarantined'));
            }
            if (currentReviewIndex < window.REVIEW_ITEMS.length - 1) {
                currentReviewIndex++;
                loadCurrentFile();
            } else {
                loadCurrentFile();
            }
        } else {
            alert(data.message || 'Delete failed.');
            if (delBtn) delBtn.disabled = false;
        }
    } catch (err) {
        alert('Server communication error during delete.');
        if (delBtn) delBtn.disabled = false;
    }
}

async function deleteFileDirect(b64, rowId, idx) {
    if (!confirm(t('confirm_delete'))) return;

    const formData = new FormData();
    formData.append('do_action', 'delete_single');
    formData.append('file_target', b64);
    formData.append('csrf_token', getCsrfToken());

    const res = await fetch(window.location.pathname, {
        method: 'POST',
        headers: { 'X-CSRF-Token': getCsrfToken() },
        body: formData,
    });
    const data = await res.json();

    if (data.success) {
        if (window.REVIEW_ITEMS && window.REVIEW_ITEMS[idx]) {
            window.REVIEW_ITEMS[idx].status = 'QUARANTINED';
            window.REVIEW_ITEMS[idx].is_candidate = false;
        }
        const row = document.getElementById(rowId);
        if (row) {
            const actCell = row.querySelector('.action-cell');
            if (actCell) {
                actCell.innerHTML = `<button type="button" class="btn-view-single" onclick="startReviewMode(${idx})">${t('btn_inspect')}</button> <span class="badge-del">${t('badge_deleted')} ✅</span>`;
            }
        }
        if (data.candidate_revoked) {
            showToast(t('toast_revoked_by_malicious'));
        } else {
            showToast(t('toast_quarantined'));
        }
    } else {
        alert(data.message || 'Delete failed.');
    }
}

async function markCleanCurrent() {
    if (currentReviewIndex < 0 || currentReviewIndex >= window.REVIEW_ITEMS.length) return;
    const file = window.REVIEW_ITEMS[currentReviewIndex];

    try {
        const formData = new FormData();
        formData.append('do_action', 'mark_clean');
        formData.append('norm_hash', file.norm_sha256);
        formData.append('path', file.path);
        formData.append('csrf_token', getCsrfToken());

        const res = await fetch(window.location.pathname, {
            method: 'POST',
            headers: { 'X-CSRF-Token': getCsrfToken() },
            body: formData,
        });
        const data = await res.json();

        if (data.success) {
            showToast(data.message);
            if (data.status === 'promoted_to_trusted') {
                file.status = 'TRUSTED';
                file.is_candidate = false;
                // Update other items with same hash
                window.REVIEW_ITEMS.forEach(it => {
                    if (it.norm_sha256 === file.norm_sha256) {
                        it.status = 'TRUSTED';
                        const row = document.getElementById(it.row_id);
                        if (row) {
                            const actCell = row.querySelector('.action-cell');
                            if (actCell) {
                                actCell.innerHTML = `<button type="button" class="btn-view-single" onclick="startReviewMode(${it.idx})">${t('btn_inspect')}</button> <span class="badge-trusted">${t('badge_trusted')}</span>`;
                            }
                        }
                    }
                });
            } else if (data.status === 'candidate_added' || data.status === 'candidate_already_recorded') {
                window.REVIEW_ITEMS.forEach(function (it) {
                    if (it.norm_sha256 === file.norm_sha256) {
                        it.is_candidate = true;
                        it.first_path = file.path;
                    }
                });
            }
            nextReviewFile();
        } else {
            alert(data.message || 'Failed to mark file.');
        }
    } catch (e) {
        alert('Server error.');
    }
}

async function askAiCurrent() {
    if (currentReviewIndex < 0 || currentReviewIndex >= window.REVIEW_ITEMS.length) return;
    const file = window.REVIEW_ITEMS[currentReviewIndex];

    const aiBtn = document.getElementById('modalAskAiBtn');
    if (aiBtn) {
        aiBtn.disabled = true;
        aiBtn.innerText = 'Analyzing...';
    }

    try {
        const formData = new FormData();
        formData.append('do_action', 'ask_ai');
        formData.append('file_target', file.b64);
        formData.append('csrf_token', getCsrfToken());

        const res = await fetch(window.location.pathname, {
            method: 'POST',
            headers: { 'X-CSRF-Token': getCsrfToken() },
            body: formData,
        });
        const data = await res.json();

        if (data.success && data.verdict) {
            file.ai_verdict = data.verdict;
            const aiBadge = document.getElementById('modalAiBadge');
            if (aiBadge) {
                aiBadge.style.display = 'inline-block';
                aiBadge.innerText = 'AI: ' + data.verdict.verdict + ' (' + Math.round(data.verdict.confidence * 100) + '%)';
            }
            if (data.candidate_revoked) {
                file.is_candidate = false;
                const strikeBanner = document.getElementById('strikeBanner');
                if (strikeBanner) strikeBanner.style.display = 'none';
                showToast(t('toast_revoked_by_malicious'));
            } else {
                showToast('AI Verdict: ' + data.verdict.verdict + ' - ' + data.verdict.summary);
            }
        } else {
            alert(data.message || 'AI request failed.');
        }
    } catch (e) {
        alert('Failed to connect to AI service.');
    } finally {
        if (aiBtn) {
            aiBtn.disabled = false;
            aiBtn.innerText = t('btn_ask_ai');
        }
    }
}

function copyModalContent(triggerBtn = null) {
    const codeEl = document.getElementById('modalFileContent');
    const text = codeEl ? (codeEl.textContent || codeEl.innerText || '') : '';

    if (!text || text.includes(t('modal_loading'))) {
        showToast('⚠️ No content to copy.');
        return;
    }

    function onCopySuccess() {
        showToast(t('modal_copied'));
        const floatingBtn = document.getElementById('btnCopyFloating');
        const bottomBtn = document.getElementById('btnCopyBottom');
        [floatingBtn, bottomBtn].forEach(btn => {
            if (btn) {
                const origText = btn.innerHTML;
                btn.innerHTML = '<span>✅</span> <span>' + t('modal_copied') + '</span>';
                btn.classList.add('copied');
                setTimeout(() => {
                    btn.innerHTML = origText;
                    btn.classList.remove('copied');
                }, 2000);
            }
        });
    }

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(onCopySuccess).catch(() => {
            fallbackCopy(text, onCopySuccess);
        });
    } else {
        fallbackCopy(text, onCopySuccess);
    }
}

function fallbackCopy(text, cb) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.top = '-9999px';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    try {
        document.execCommand('copy');
        cb();
    } catch (e) {
        prompt('Copy manually:', text);
    }
    document.body.removeChild(ta);
}

// -------------------------------------------------------------
// Auto AI Review Loop
// -------------------------------------------------------------
function openAutoReviewModal() {
    const modal = document.getElementById('autoReviewModal');
    if (modal) {
        modal.classList.add('active');
        autoReviewStats = { hits: 0, quarantined: 0, skipped: 0, errors: 0 };
        updateAutoReviewUi(0, 1, '-');
    }
}

function closeAutoReviewModal() {
    const modal = document.getElementById('autoReviewModal');
    if (modal) modal.classList.remove('active');
    autoReviewActive = false;
    autoReviewPaused = false;
}

function pauseAutoReview() {
    autoReviewPaused = true;
    document.getElementById('btnAutoPause').style.display = 'none';
    document.getElementById('btnAutoResume').style.display = 'inline-flex';
}

function resumeAutoReview() {
    autoReviewPaused = false;
    document.getElementById('btnAutoPause').style.display = 'inline-flex';
    document.getElementById('btnAutoResume').style.display = 'none';
    runAutoReviewNextStep();
}

function startAutoAiReview() {
    openAutoReviewModal();
    autoReviewActive = true;
    autoReviewPaused = false;
    runAutoReviewNextStep();
}

let coolingRetryPending = false;

async function runAutoReviewNextStep() {
    if (!autoReviewActive || autoReviewPaused) return;

    try {
        const formData = new FormData();
        formData.append('do_action', 'auto_review_step');
        formData.append('csrf_token', getCsrfToken());

        const res = await fetch(window.location.pathname, {
            method: 'POST',
            headers: { 'X-CSRF-Token': getCsrfToken() },
            body: formData,
        });
        const data = await res.json();

        if (data.finished) {
            autoReviewActive = false;
            coolingRetryPending = false;
            document.getElementById('autoReviewProgressText').innerText = t('auto_ai_done');
            showToast(t('auto_ai_done'));
            setTimeout(() => {
                window.location.reload();
            }, 1500);
            return;
        }

        if (data.error === 'all_cooling') {
            if (!coolingRetryPending) {
                // Wait countdown, retry same file once
                coolingRetryPending = true;
                const waitSec = data.retry_after || 20;
                document.getElementById('autoReviewProgressText').innerText = `Rate limit reached. Backing off for ${waitSec}s... (will retry once)`;
                await new Promise(r => setTimeout(r, waitSec * 1000));
                runAutoReviewNextStep();
                return;
            } else {
                // Retry failed! Mark AI_ERROR and continue
                coolingRetryPending = false;
                const forceFormData = new FormData();
                forceFormData.append('do_action', 'auto_review_step');
                forceFormData.append('force_error', '1');
                forceFormData.append('csrf_token', getCsrfToken());

                const forceRes = await fetch(window.location.pathname, {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': getCsrfToken() },
                    body: forceFormData,
                });
                const forceData = await forceRes.json();
                autoReviewStats.errors++;
                updateAutoReviewUi(forceData.remaining_count, window.REVIEW_ITEMS.length, forceData.path);
                setTimeout(() => {
                    if (autoReviewActive && !autoReviewPaused) {
                        runAutoReviewNextStep();
                    }
                }, 1500);
                return;
            }
        }

        coolingRetryPending = false;

        if (data.cache_hit) autoReviewStats.hits++;
        if (data.action_taken === 'quarantined') autoReviewStats.quarantined++;
        if (data.action_taken === 'skipped') autoReviewStats.skipped++;
        if (data.action_taken === 'error' || data.action_taken === 'failed_quarantine') autoReviewStats.errors++;
        if (data.candidate_revoked) showToast(t('toast_revoked_by_malicious'));

        updateAutoReviewUi(data.remaining_count, window.REVIEW_ITEMS.length, data.path);

        // Interval calculation
        const totalKeys = Math.max(1, parseInt(data.total_keys, 10) || 1);
        const delay = data.cache_hit ? 200 : Math.max(4500, Math.floor(4500 / totalKeys));

        setTimeout(() => {
            if (autoReviewActive && !autoReviewPaused) {
                runAutoReviewNextStep();
            }
        }, delay);

    } catch (e) {
        autoReviewStats.errors++;
        setTimeout(() => {
            if (autoReviewActive && !autoReviewPaused) {
                runAutoReviewNextStep();
            }
        }, 3000);
    }
}

function updateAutoReviewUi(remaining, total, currentPath) {
    const done = total - remaining;
    const pct = total > 0 ? Math.round((done / total) * 100) : 0;

    const fill = document.getElementById('autoReviewFill');
    if (fill) fill.style.width = pct + '%';

    const text = document.getElementById('autoReviewProgressText');
    if (text) text.innerText = t('auto_ai_progress', { current: done, total: total }) + ' (' + (currentPath ? currentPath.split(/[\\/]/).pop() : '') + ')';

    const stats = document.getElementById('autoReviewStats');
    if (stats) stats.innerText = t('auto_ai_stats', {
        hits: autoReviewStats.hits,
        quarantined: autoReviewStats.quarantined,
        skipped: autoReviewStats.skipped,
        errors: autoReviewStats.errors,
    });
}

// -------------------------------------------------------------
// Settings & Rules Sync
// -------------------------------------------------------------
function openSettingsModal() {
    const modal = document.getElementById('settingsModal');
    if (modal) modal.classList.add('active');
}

function closeSettingsModal() {
    const modal = document.getElementById('settingsModal');
    if (modal) modal.classList.remove('active');
}

async function saveSettingsNow() {
    const formData = new FormData();
    formData.append('do_action', 'save_settings');
    formData.append('new_access_key', document.getElementById('set_new_access_key').value);
    formData.append('gemini_api_keys', document.getElementById('set_gemini_api_keys').value);
    formData.append('gemini_model', document.getElementById('set_gemini_model').value);
    formData.append('rules_sync_url', document.getElementById('set_rules_sync_url').value);
    formData.append('github_repo', document.getElementById('set_github_repo').value);
    formData.append('report_endpoint', document.getElementById('set_report_endpoint').value);
    formData.append('csrf_token', getCsrfToken());

    const res = await fetch(window.location.pathname, {
        method: 'POST',
        headers: { 'X-CSRF-Token': getCsrfToken() },
        body: formData,
    });
    const data = await res.json();
    showToast(data.message);
    if (data.success) {
        setTimeout(() => window.location.reload(), 1000);
    }
}

async function syncRulesNow() {
    const btn = document.getElementById('btnSyncRulesModal');
    if (btn) btn.disabled = true;

    try {
        const formData = new FormData();
        formData.append('do_action', 'sync_rules');
        formData.append('csrf_token', getCsrfToken());

        const res = await fetch(window.location.pathname, {
            method: 'POST',
            headers: { 'X-CSRF-Token': getCsrfToken() },
            body: formData,
        });
        const data = await res.json();
        showToast(data.message);
    } catch (e) {
        alert('Rule sync failed.');
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function revokeTrustedHash(hash) {
    if (!confirm('Revoke trusted status for this checksum?')) return;

    const formData = new FormData();
    formData.append('do_action', 'revoke_trusted');
    formData.append('norm_hash', hash);
    formData.append('csrf_token', getCsrfToken());

    const res = await fetch(window.location.pathname, {
        method: 'POST',
        headers: { 'X-CSRF-Token': getCsrfToken() },
        body: formData,
    });
    const data = await res.json();
    showToast(data.message);
    const row = document.getElementById('trusted_row_' + hash);
    if (row) row.remove();
}

async function restoreQuarantinedFile(backupName) {
    if (!confirm('Restore this file to its original location?')) return;

    const formData = new FormData();
    formData.append('do_action', 'restore_file');
    formData.append('backup_name', backupName);
    formData.append('csrf_token', getCsrfToken());

    const res = await fetch(window.location.pathname, {
        method: 'POST',
        headers: { 'X-CSRF-Token': getCsrfToken() },
        body: formData,
    });
    const data = await res.json();
    showToast(data.message);
    const row = document.getElementById('quarantine_row_' + backupName);
    if (row) row.remove();
}

async function clearAiCacheNow() {
    const formData = new FormData();
    formData.append('do_action', 'clear_ai_cache');
    formData.append('csrf_token', getCsrfToken());

    const res = await fetch(window.location.pathname, {
        method: 'POST',
        headers: { 'X-CSRF-Token': getCsrfToken() },
        body: formData,
    });
    const data = await res.json();
    showToast(data.message);
}

// -------------------------------------------------------------
// Share CTA
// -------------------------------------------------------------
async function shareViaGithub() {
    const formData = new FormData();
    formData.append('do_action', 'share_bundle');
    formData.append('csrf_token', getCsrfToken());

    const res = await fetch(window.location.pathname, {
        method: 'POST',
        headers: { 'X-CSRF-Token': getCsrfToken() },
        body: formData,
    });
    const data = await res.json();

    if (!data.github_url || data.github_url.indexOf('OWNER/REPO') !== -1) {
        fallbackCopy(data.markdown_body || '', () => {
            showToast(t('share_toast_copied'));
        });
        return;
    }
    if (data.need_clipboard) {
        fallbackCopy(data.markdown_body, () => {
            showToast(t('share_toast_copied'));
            window.open(data.github_url, '_blank');
        });
    } else {
        window.open(data.github_url, '_blank');
    }
}

async function copyShareMarkdown() {
    const formData = new FormData();
    formData.append('do_action', 'share_bundle');
    formData.append('csrf_token', getCsrfToken());

    const res = await fetch(window.location.pathname, {
        method: 'POST',
        headers: { 'X-CSRF-Token': getCsrfToken() },
        body: formData,
    });
    const data = await res.json();
    fallbackCopy(data.markdown_body, () => {
        showToast(t('modal_copied'));
    });
}

async function downloadShareJson() {
    const formData = new FormData();
    formData.append('do_action', 'share_bundle');
    formData.append('csrf_token', getCsrfToken());

    const res = await fetch(window.location.pathname, {
        method: 'POST',
        headers: { 'X-CSRF-Token': getCsrfToken() },
        body: formData,
    });
    const data = await res.json();

    const blob = new Blob([JSON.stringify(data.bundle, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'zeroshell_malware_report_' + Math.floor(Date.now() / 1000) + '.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

async function selfDestructNow() {
    if (!confirm(t('confirm_self_destruct'))) return;
    if (!confirm(t('confirm_self_destruct'))) return;

    const formData = new FormData();
    formData.append('do_action', 'self_destruct');
    formData.append('csrf_token', getCsrfToken());
    if (document.getElementById('chkDestructKnowledge') && document.getElementById('chkDestructKnowledge').checked) {
        formData.append('delete_knowledge', '1');
    }
    if (document.getElementById('chkDestructQuarantine') && document.getElementById('chkDestructQuarantine').checked) {
        formData.append('delete_quarantine', '1');
    }

    try {
        const res = await fetch(window.location.pathname, {
            method: 'POST',
            headers: { 'X-CSRF-Token': getCsrfToken() },
            body: formData,
        });
        const data = await res.json();
        document.body.innerHTML = '<div class="card" style="max-width:480px;margin:60px auto;"><h2>' + (data.message || t('toast_self_destructed')) + '</h2></div>';
    } catch (e) {
        alert('Self-destruct failed.');
    }
}

async function submitMaintainer() {
    const includeSamples = document.getElementById('chkIncludeSamples') ? document.getElementById('chkIncludeSamples').checked : false;

    const formData = new FormData();
    formData.append('do_action', 'share_bundle');
    formData.append('submit_maintainer', '1');
    formData.append('consent', '1');
    formData.append('include_samples', includeSamples ? '1' : '0');
    formData.append('csrf_token', getCsrfToken());

    try {
        const res = await fetch(window.location.pathname, {
            method: 'POST',
            headers: { 'X-CSRF-Token': getCsrfToken() },
            body: formData,
        });
        const data = await res.json();
        if (data.success) {
            showToast(t('share_maintainer_success'));
        } else {
            alert(data.message || 'Maintainer submission failed.');
        }
    } catch (e) {
        alert('Failed to connect to maintainer endpoint.');
    }
}

// -------------------------------------------------------------
// Keyboard Shortcuts
// -------------------------------------------------------------
document.addEventListener('keydown', function(e) {
    // Ignore keystrokes when typing inside inputs/textareas
    const tag = (e.target.tagName || '').toLowerCase();
    if (tag === 'input' || tag === 'textarea' || tag === 'select') {
        return;
    }

    const key = e.key.toLowerCase();
    if (key === 'escape') {
        if (isModalActive) closeViewModal();
        closeSettingsModal();
        closeAutoReviewModal();
        return;
    }

    if (!isModalActive) return;

    if (e.code === 'Space') {
        e.preventDefault();
        nextReviewFile();
        return;
    }

    if (key === 'c' && !e.ctrlKey && !e.metaKey) {
        copyModalContent(document.getElementById('btnCopyFloating'));
    } else if (key === 'd' || e.key === 'Delete') {
        deleteAndNext();
    } else if (key === 'n' || e.key === 'ArrowRight') {
        nextReviewFile();
    } else if (key === 'p' || e.key === 'ArrowLeft') {
        prevReviewFile();
    } else if (key === 'b') {
        markCleanCurrent();
    } else if (key === 'a') {
        askAiCurrent();
    }
});
