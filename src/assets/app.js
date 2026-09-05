let currentReviewIndex = 0;
let isModalActive = false;
let autoReviewActive = false;
let autoReviewPaused = false;
let previewAbort = null;
let decisionsLocked = false;
let lastFocused = null;

function t(key, vars) {
    vars = vars || {};
    let str = (window.ZS_I18N && window.ZS_I18N[key]) ? window.ZS_I18N[key] : key;
    for (let k in vars) {
        str = str.replace(new RegExp('\\{' + k + '\\}', 'g'), vars[k]);
    }
    return str;
}

function showToast(msg) {
    const toast = document.getElementById('toastNotify');
    if (!toast) return;
    toast.textContent = msg;
    toast.style.display = 'block';
    setTimeout(function () { toast.style.display = 'none'; }, 3000);
}

function getCsrfToken() {
    return (window.ZS_BOOT && window.ZS_BOOT.csrf) || window.ZS_CSRF || '';
}

function postForm(fields) {
    const formData = new FormData();
    for (const k in fields) {
        if (Object.prototype.hasOwnProperty.call(fields, k) && fields[k] !== undefined && fields[k] !== null) {
            formData.append(k, fields[k]);
        }
    }
    formData.append('csrf_token', getCsrfToken());
    return fetch(window.location.pathname, {
        method: 'POST',
        headers: { 'X-CSRF-Token': getCsrfToken(), 'Accept': 'application/json' },
        body: formData,
        credentials: 'same-origin',
    }).then(function (res) {
        return res.json().catch(function () {
            return { success: false, message: 'Authentication required.', code: 'AUTH' };
        });
    });
}

function findingFields(file) {
    return {
        finding_id: file.finding_id,
        scan_session_id: file.scan_session_id || window.ZS_SESSION_ID,
        expected_raw: file.raw_sha256,
    };
}

function switchLang(lang) {
    const p = window.location.pathname.replace(/\/[^/]*$/, '') || '/';
    document.cookie = 'zs_lang=' + lang + ';path=' + p + ';max-age=' + (86400 * 365) + ';SameSite=Lax';
    window.location.reload();
}

function fillTableText() {
    if (!window.REVIEW_ITEMS) return;
    window.REVIEW_ITEMS.forEach(function (file) {
        const row = document.getElementById(file.row_id);
        if (!row) return;
        const pathCell = row.querySelector('.dir-path');
        const reasonCell = row.querySelector('.reason-cell');
        if (pathCell) pathCell.textContent = file.path;
        if (reasonCell) {
            let txt = file.reason;
            if (file.ai_verdict && file.ai_verdict.verdict) {
                txt += ' [AI: ' + file.ai_verdict.verdict + ' ' + Math.round((file.ai_verdict.confidence || 0) * 100) + '%]';
            }
            reasonCell.textContent = txt;
        }
    });
}

function setDecisionLocked(locked) {
    decisionsLocked = locked;
    ['modalDeleteBtn', 'btnMarkClean', 'modalAskAiBtn', 'btnNextBottom', 'btnPrevTop', 'btnNextTop'].forEach(function (id) {
        const el = document.getElementById(id);
        if (el) el.disabled = locked;
    });
}

function reviewableItems() {
    return (window.REVIEW_ITEMS || []).filter(function (it) {
        return it.status !== 'TRUSTED_HIDDEN' && it.status !== 'TRUSTED';
    });
}

function startReviewMode(startIndex) {
    const items = window.REVIEW_ITEMS || [];
    if (!items.length) {
        alert(t('no_threats_found'));
        return;
    }
    if (typeof startIndex === 'number' && startIndex >= 0) {
        const pos = items.findIndex(function (it) { return it.idx === startIndex; });
        currentReviewIndex = pos >= 0 ? pos : 0;
    } else {
        const firstPending = items.findIndex(function (item) {
            return item.status === 'FOUND' || item.status === 'AI_SKIPPED' || item.status === 'AI_ERROR';
        });
        currentReviewIndex = firstPending !== -1 ? firstPending : 0;
    }
    lastFocused = document.activeElement;
    const modal = document.getElementById('fileViewerModal');
    if (modal) {
        modal.classList.add('active');
        isModalActive = true;
        loadCurrentFile();
        document.getElementById('btnCloseModal').focus();
    }
}

function loadCurrentFile() {
    const items = window.REVIEW_ITEMS || [];
    if (currentReviewIndex < 0 || currentReviewIndex >= items.length) return;
    const file = items[currentReviewIndex];
    const progressFill = document.getElementById('reviewProgressFill');
    if (progressFill) progressFill.style.width = Math.round(((currentReviewIndex + 1) / items.length) * 100) + '%';
    document.getElementById('modalCounter').textContent = (currentReviewIndex + 1) + ' / ' + items.length;
    document.getElementById('modalFileName').textContent = file.filename;
    document.getElementById('modalFilePath').textContent = file.path;
    document.getElementById('modalFileReason').textContent = file.reason;
    document.getElementById('modalRawHash').textContent = file.raw_sha256 || '-';

    const statusEl = document.getElementById('modalFileStatus');
    statusEl.textContent = file.status;
    const strikeBanner = document.getElementById('strikeBanner');
    if (file.is_candidate) {
        strikeBanner.textContent = t('strike1_warning', { sample_path: file.first_path || file.path });
        strikeBanner.style.display = 'block';
    } else {
        strikeBanner.style.display = 'none';
    }
    const aiBadge = document.getElementById('modalAiBadge');
    if (file.ai_verdict) {
        aiBadge.style.display = 'inline-block';
        aiBadge.textContent = 'AI: ' + file.ai_verdict.verdict + ' (' + Math.round(file.ai_verdict.confidence * 100) + '%) — ' + t('ai_advisory_short');
    } else {
        aiBadge.style.display = 'none';
    }

    document.getElementById('btnPrevTop').disabled = currentReviewIndex === 0;
    const codeEl = document.getElementById('modalFileContent');
    codeEl.textContent = t('modal_loading');
    setDecisionLocked(true);

    if (previewAbort) previewAbort.abort();
    previewAbort = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const q = '?do_action=view_file&finding_id=' + encodeURIComponent(file.finding_id)
        + '&scan_session_id=' + encodeURIComponent(file.scan_session_id || window.ZS_SESSION_ID)
        + '&expected_raw=' + encodeURIComponent(file.raw_sha256);
    const loadId = file.finding_id;
    fetch(q, { credentials: 'same-origin', signal: previewAbort ? previewAbort.signal : undefined, headers: { 'Accept': 'application/json' } })
        .then(function (res) { return res.json(); })
        .then(function (data) {
            if ((window.REVIEW_ITEMS[currentReviewIndex] || {}).finding_id !== loadId) return;
            if (data.success) {
                codeEl.textContent = data.content + (data.is_truncated ? '\n\n' + t('modal_trunc_notice') : '');
            } else {
                codeEl.textContent = data.message || t('modal_err_read');
            }
            setDecisionLocked(false);
        })
        .catch(function (e) {
            if (e && e.name === 'AbortError') return;
            if ((window.REVIEW_ITEMS[currentReviewIndex] || {}).finding_id !== loadId) return;
            codeEl.textContent = t('modal_err_network');
            setDecisionLocked(false);
        });
}

function nextReviewFile() {
    if (decisionsLocked) return;
    if (currentReviewIndex < window.REVIEW_ITEMS.length - 1) {
        currentReviewIndex++;
        loadCurrentFile();
    } else {
        closeViewModal();
    }
}

function prevReviewFile() {
    if (decisionsLocked) return;
    if (currentReviewIndex > 0) {
        currentReviewIndex--;
        loadCurrentFile();
    }
}

function closeViewModal() {
    const modal = document.getElementById('fileViewerModal');
    if (modal) modal.classList.remove('active');
    isModalActive = false;
    if (previewAbort) previewAbort.abort();
    if (lastFocused && lastFocused.focus) lastFocused.focus();
}

function currentFile() {
    return window.REVIEW_ITEMS[currentReviewIndex];
}

function deleteAndNext() {
    if (decisionsLocked) return;
    const file = currentFile();
    if (!file) return;
    setDecisionLocked(true);
    const fields = findingFields(file);
    fields.do_action = 'delete_single';
    postForm(fields).then(function (data) {
        if (data.success) {
            file.status = 'QUARANTINED';
            showToast(data.message || t('toast_quarantined'));
            nextReviewFile();
        } else {
            alert(data.message || t('err_delete_failed'));
            setDecisionLocked(false);
        }
    }).catch(function () { setDecisionLocked(false); });
}

function markCleanCurrent() {
    if (decisionsLocked) return;
    const file = currentFile();
    if (!file) return;
    const fields = findingFields(file);
    fields.do_action = 'mark_clean';
    postForm(fields).then(function (data) {
        if (!data.success) {
            alert(data.message || 'Failed');
            return;
        }
        showToast(data.message);
        if (data.status === 'promoted_to_trusted') {
            const trustedHash = file.raw_sha256;
            window.REVIEW_ITEMS.forEach(function (it) {
                if (it.raw_sha256 === trustedHash) {
                    const row = document.getElementById(it.row_id);
                    if (row) row.remove();
                }
            });
            window.REVIEW_ITEMS = window.REVIEW_ITEMS.filter(function (it) {
                return it.raw_sha256 !== trustedHash;
            });
            if (window.REVIEW_ITEMS.length === 0 || currentReviewIndex >= window.REVIEW_ITEMS.length) {
                closeViewModal();
                return;
            }
            loadCurrentFile();
            return;
        }
        if (data.status === 'candidate_added' || data.status === 'candidate_already_recorded') {
            window.REVIEW_ITEMS.forEach(function (it) {
                if (it.raw_sha256 === file.raw_sha256) {
                    it.is_candidate = true;
                    it.first_path = file.path;
                }
            });
        }
        nextReviewFile();
    });
}

function askAiCurrent() {
    const file = currentFile();
    if (!file) return;
    const btn = document.getElementById('modalAskAiBtn');
    if (btn) btn.disabled = true;
    const fields = findingFields(file);
    fields.do_action = 'ask_ai';
    postForm(fields).then(function (data) {
        if (btn) btn.disabled = false;
        if (data.success && data.verdict) {
            file.ai_verdict = data.verdict;
            const aiBadge = document.getElementById('modalAiBadge');
            aiBadge.style.display = 'inline-block';
            aiBadge.textContent = 'AI: ' + data.verdict.verdict + ' — ' + t('ai_advisory_short');
            showToast((data.verdict.summary || data.verdict.verdict) + ' (' + t('ai_advisory_short') + ')');
        } else {
            alert(data.message || t('err_ai_failed'));
        }
    }).catch(function () { if (btn) btn.disabled = false; });
}

function copyModalContent() {
    const codeEl = document.getElementById('modalFileContent');
    const text = codeEl ? codeEl.textContent : '';
    if (!text) return;
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(function () { showToast(t('modal_copied')); });
    } else {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        showToast(t('modal_copied'));
    }
}

let autoTimer = null;
function clearAutoTimer() {
    if (autoTimer) {
        clearTimeout(autoTimer);
        autoTimer = null;
    }
}

function startAutoAiReview() {
    if (autoReviewActive) return;
    if (!window.ZS_BOOT || !window.ZS_BOOT.has_ai) {
        alert(t('ai_need_key'));
        return;
    }
    if (!confirm(t('ai_sends_code'))) return;
    autoReviewActive = true;
    autoReviewPaused = false;
    document.getElementById('autoReviewModal').classList.add('active');
    postForm({ do_action: 'auto_review_control', op: 'start' }).then(function () {
        runAutoReviewNextStep();
    });
}

function pauseAutoReview() {
    autoReviewPaused = true;
    clearAutoTimer();
    postForm({ do_action: 'auto_review_control', op: 'pause' });
    document.getElementById('btnAutoPause').style.display = 'none';
    document.getElementById('btnAutoResume').style.display = 'inline-flex';
}

function resumeAutoReview() {
    autoReviewPaused = false;
    autoReviewActive = true;
    document.getElementById('btnAutoPause').style.display = 'inline-flex';
    document.getElementById('btnAutoResume').style.display = 'none';
    postForm({ do_action: 'auto_review_control', op: 'start' }).then(function () {
        runAutoReviewNextStep();
    });
}

function cancelAutoReview() {
    autoReviewActive = false;
    autoReviewPaused = true;
    clearAutoTimer();
    postForm({ do_action: 'auto_review_control', op: 'cancel' }).then(function () {
        document.getElementById('autoReviewModal').classList.remove('active');
        window.location.reload();
    });
}

let autoConsecutiveErrors = 0;

function runAutoReviewNextStep() {
    if (!autoReviewActive || autoReviewPaused) return;
    postForm({ do_action: 'auto_review_step' }).then(function (data) {
        if (data.code === 'AUTH') {
            autoReviewActive = false;
            clearAutoTimer();
            alert(t('auto_ai_auth_expired'));
            window.location.reload();
            return;
        }
        if (!data.success) {
            autoConsecutiveErrors++;
            if (autoConsecutiveErrors >= 5) {
                autoReviewActive = false;
                clearAutoTimer();
                const errTxt = t('auto_ai_stopped_errors');
                document.getElementById('autoReviewProgressText').textContent = errTxt;
                showToast(errTxt);
                return;
            }
            autoTimer = setTimeout(function () {
                if (autoReviewActive && !autoReviewPaused) runAutoReviewNextStep();
            }, 5000);
            return;
        }
        autoConsecutiveErrors = 0;
        if (data.paused) return;
        if (data.finished) {
            autoReviewActive = false;
            document.getElementById('autoReviewProgressText').textContent = t('auto_ai_done');
            setTimeout(function () { window.location.reload(); }, 1200);
            return;
        }
        if (data.error === 'all_cooling') {
            const wait = (data.retry_after || 20) * 1000;
            document.getElementById('autoReviewProgressText').textContent = t('auto_ai_rate_limit');
            autoTimer = setTimeout(runAutoReviewNextStep, wait);
            return;
        }
        if (data.stats) {
            document.getElementById('autoReviewStats').textContent = t('auto_ai_stats', data.stats);
        }
        const delay = data.cache_hit ? 200 : 4500;
        autoTimer = setTimeout(function () {
            if (autoReviewActive && !autoReviewPaused) runAutoReviewNextStep();
        }, delay);
    }).catch(function () {
        autoConsecutiveErrors++;
        if (autoConsecutiveErrors >= 5) {
            autoReviewActive = false;
            clearAutoTimer();
            const errTxt = t('auto_ai_stopped_errors');
            document.getElementById('autoReviewProgressText').textContent = errTxt;
            showToast(errTxt);
            return;
        }
        autoTimer = setTimeout(function () {
            if (autoReviewActive && !autoReviewPaused) runAutoReviewNextStep();
        }, 5000);
    });
}

function selectedFindingIds() {
    const ids = [];
    document.querySelectorAll('.share-select:checked').forEach(function (el) {
        ids.push(el.getAttribute('data-finding-id'));
    });
    return ids;
}

function shareAction(extra) {
    extra = extra || {};
    extra.do_action = 'share_bundle';
    const ids = selectedFindingIds();
    extra.finding_ids = ids.join(',');
    extra.include_samples = document.getElementById('chkIncludeSamples') && document.getElementById('chkIncludeSamples').checked ? '1' : '0';
    return postForm(extra);
}

function bindUi() {
    fillTableText();
    document.querySelectorAll('[data-switch-lang]').forEach(function (btn) {
        btn.addEventListener('click', function () { switchLang(btn.getAttribute('data-switch-lang')); });
    });
    const startReview = document.getElementById('btnStartReview');
    if (startReview) startReview.addEventListener('click', function () { startReviewMode(); });
    const startAuto = document.getElementById('btnStartAuto');
    if (startAuto) startAuto.addEventListener('click', startAutoAiReview);
    document.querySelectorAll('[data-review-idx]').forEach(function (btn) {
        btn.addEventListener('click', function () { startReviewMode(parseInt(btn.getAttribute('data-review-idx'), 10)); });
    });
    document.querySelectorAll('.btn-del-single[data-finding-id]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            if (!confirm(t('confirm_delete'))) return;
            const fid = btn.getAttribute('data-finding-id');
            const raw = btn.getAttribute('data-raw');
            postForm({ do_action: 'delete_single', finding_id: fid, scan_session_id: window.ZS_SESSION_ID, expected_raw: raw }).then(function (data) {
                showToast(data.message || '');
                if (data.success) window.location.reload();
            });
        });
    });
    const closeModal = document.getElementById('btnCloseModal');
    if (closeModal) closeModal.addEventListener('click', closeViewModal);
    const overlay = document.getElementById('fileViewerModal');
    if (overlay) overlay.addEventListener('click', function (e) { if (e.target.id === 'fileViewerModal') closeViewModal(); });
    const btnNext = document.getElementById('btnNextTop');
    const btnNextB = document.getElementById('btnNextBottom');
    const btnPrev = document.getElementById('btnPrevTop');
    if (btnNext) btnNext.addEventListener('click', nextReviewFile);
    if (btnNextB) btnNextB.addEventListener('click', nextReviewFile);
    if (btnPrev) btnPrev.addEventListener('click', prevReviewFile);
    const delBtn = document.getElementById('modalDeleteBtn');
    if (delBtn) delBtn.addEventListener('click', deleteAndNext);
    const markBtn = document.getElementById('btnMarkClean');
    if (markBtn) markBtn.addEventListener('click', markCleanCurrent);
    const askBtn = document.getElementById('modalAskAiBtn');
    if (askBtn) askBtn.addEventListener('click', askAiCurrent);
    const copyBtn = document.getElementById('btnCopyFloating');
    if (copyBtn) copyBtn.addEventListener('click', copyModalContent);

    const btnSettings = document.getElementById('btnSettings');
    if (btnSettings) btnSettings.addEventListener('click', function () { document.getElementById('settingsModal').classList.add('active'); });
    ['btnCloseSettings', 'btnCloseAuto'].forEach(function (id) {
        const el = document.getElementById(id);
        if (el) el.addEventListener('click', function () {
            document.getElementById(id === 'btnCloseSettings' ? 'settingsModal' : 'autoReviewModal').classList.remove('active');
            if (id === 'btnCloseAuto') cancelAutoReview();
        });
    });
    const pause = document.getElementById('btnAutoPause');
    const resume = document.getElementById('btnAutoResume');
    const cancel = document.getElementById('btnAutoCancel');
    if (pause) pause.addEventListener('click', pauseAutoReview);
    if (resume) resume.addEventListener('click', resumeAutoReview);
    if (cancel) cancel.addEventListener('click', cancelAutoReview);

    const form = document.getElementById('formSettings');
    if (form) form.addEventListener('submit', function (e) {
        e.preventDefault();
        postForm({
            do_action: 'save_settings',
            new_access_key: document.getElementById('set_new_access_key').value,
            gemini_api_keys: document.getElementById('set_gemini_api_keys').value,
            gemini_model: document.getElementById('set_gemini_model').value,
            github_repo: document.getElementById('set_github_repo').value,
            rules_sync_url: document.getElementById('set_rules_sync_url') ? document.getElementById('set_rules_sync_url').value : '',
            clear_gemini_keys: document.getElementById('chkClearKeys').checked ? '1' : '',
        }).then(function (data) {
            showToast(data.message || '');
            if (data.success) setTimeout(function () { window.location.reload(); }, 600);
        });
    });
    const testG = document.getElementById('btnTestGemini');
    if (testG) testG.addEventListener('click', function () {
        postForm({ do_action: 'test_gemini' }).then(function (data) { showToast(data.message || JSON.stringify(data)); });
    });
    const clearCache = document.getElementById('btnClearCache');
    if (clearCache) clearCache.addEventListener('click', function () {
        postForm({ do_action: 'clear_ai_cache' }).then(function (data) { showToast(data.message || ''); });
    });
    const syncRules = document.getElementById('btnSyncRules');
    if (syncRules) syncRules.addEventListener('click', function () {
        const urlInput = document.getElementById('set_rules_sync_url');
        const url = urlInput ? urlInput.value : '';
        postForm({ do_action: 'sync_rules', rules_sync_url: url }).then(function (data) {
            showToast(data.message || (data.success ? t('toast_rules_updated_simple') : t('toast_rules_sync_failed')));
        });
    });
    const selectAll = document.getElementById('selectAllFindings');
    if (selectAll) {
        selectAll.addEventListener('change', function () {
            document.querySelectorAll('.share-select').forEach(function (chk) {
                chk.checked = selectAll.checked;
            });
        });
    }
    document.querySelectorAll('[data-revoke-hash]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            postForm({ do_action: 'revoke_trusted', raw_hash: btn.getAttribute('data-revoke-hash') }).then(function (data) {
                showToast(data.message || '');
                if (data.success) btn.parentNode.remove();
            });
        });
    });
    document.querySelectorAll('[data-restore]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            const backupName = btn.getAttribute('data-restore');
            postForm({ do_action: 'restore_file', backup_name: backupName }).then(function (data) {
                if (!data.success) {
                    if (data.code === 'DEST_EXISTS') {
                        const override = prompt((data.message || '') + '\n' + t('prompt_dest_override'));
                        if (override && override.trim()) {
                            postForm({ do_action: 'restore_file', backup_name: backupName, dest_override: override.trim() }).then(function (res2) {
                                if (!res2.success) {
                                    alert(res2.message || t('err_restore_failed'));
                                } else {
                                    showToast(res2.message || t('toast_restored'));
                                    window.location.reload();
                                }
                            });
                            return;
                        }
                    }
                    alert(data.message || t('err_restore_failed'));
                } else {
                    showToast(data.message || t('toast_restored'));
                    window.location.reload();
                }
            });
        });
    });

    function showShare(data) {
        const pre = document.getElementById('sharePreview');
        pre.style.display = 'block';
        if (data.receipt) {
            pre.textContent = 'Server Receipt:\n' + data.receipt + '\n\nPayload:\n' + JSON.stringify(data.preview || data.bundle, null, 2);
        } else {
            pre.textContent = data.markdown_body || JSON.stringify(data.preview || data.bundle, null, 2);
        }
        if (data.github_url) window.open(data.github_url, '_blank');
    }
    const gBtn = document.getElementById('btnShareGithub');
    if (gBtn) gBtn.addEventListener('click', function () { shareAction({}).then(showShare); });
    const cBtn = document.getElementById('btnShareCopy');
    if (cBtn) cBtn.addEventListener('click', function () {
        shareAction({}).then(function (data) {
            showShare(data);
            showToast(t('share_toast_copied'));
        });
    });
    const jBtn = document.getElementById('btnShareJson');
    if (jBtn) jBtn.addEventListener('click', function () {
        shareAction({}).then(function (data) {
            const blob = new Blob([JSON.stringify(data.bundle, null, 2)], { type: 'application/json' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'zeroshell-report.json';
            a.click();
        });
    });
}

document.addEventListener('DOMContentLoaded', bindUi);

function trapFocus(modalEl, e) {
    if (e.key !== 'Tab') return;
    const focusables = modalEl.querySelectorAll('button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])');
    if (!focusables.length) return;
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    if (e.shiftKey) {
        if (document.activeElement === first) {
            e.preventDefault();
            last.focus();
        }
    } else {
        if (document.activeElement === last) {
            e.preventDefault();
            first.focus();
        }
    }
}

document.addEventListener('keydown', function (e) {
    const activeModal = document.querySelector('.modal-overlay.active');
    if (activeModal && e.key === 'Tab') {
        trapFocus(activeModal, e);
        return;
    }
    const tag = (e.target.tagName || '').toLowerCase();
    if (tag === 'input' || tag === 'textarea' || tag === 'select') return;
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    const key = e.key.toLowerCase();
    if (key === 'escape') {
        closeViewModal();
        const sm = document.getElementById('settingsModal');
        const am = document.getElementById('autoReviewModal');
        if (sm) sm.classList.remove('active');
        if (am) am.classList.remove('active');
        return;
    }
    if (!isModalActive || decisionsLocked) return;
    if (e.code === 'Space') {
        e.preventDefault();
        nextReviewFile();
        return;
    }
    if (key === 'c') copyModalContent();
    else if (key === 'd' || e.key === 'Delete') deleteAndNext();
    else if (key === 'n' || e.key === 'ArrowRight') nextReviewFile();
    else if (key === 'p' || e.key === 'ArrowLeft') prevReviewFile();
    else if (key === 'b') markCleanCurrent();
    else if (key === 'a') askAiCurrent();
});
