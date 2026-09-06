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

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

const PHP_KEYWORDS = {
    'abstract': 1, 'and': 1, 'array': 1, 'as': 1, 'break': 1, 'callable': 1, 'case': 1, 'catch': 1,
    'class': 1, 'clone': 1, 'const': 1, 'continue': 1, 'declare': 1, 'default': 1,
    'die': 1, 'do': 1, 'echo': 1, 'else': 1, 'elseif': 1, 'empty': 1, 'enddeclare': 1,
    'endfor': 1, 'endforeach': 1, 'endif': 1, 'endswitch': 1, 'endwhile': 1, 'enum': 1, 'exit': 1,
    'extends': 1, 'final': 1, 'finally': 1, 'fn': 1, 'for': 1, 'foreach': 1, 'from': 1,
    'function': 1, 'global': 1, 'goto': 1, 'if': 1, 'implements': 1, 'include': 1,
    'include_once': 1, 'instanceof': 1, 'insteadof': 1, 'interface': 1, 'isset': 1,
    'list': 1, 'match': 1, 'namespace': 1, 'new': 1, 'or': 1, 'print': 1, 'private': 1,
    'protected': 1, 'public': 1, 'readonly': 1, 'require': 1, 'require_once': 1,
    'return': 1, 'static': 1, 'switch': 1, 'throw': 1, 'trait': 1, 'try': 1,
    'unset': 1, 'use': 1, 'var': 1, 'while': 1, 'xor': 1, 'yield': 1,
    'int': 1, 'float': 1, 'bool': 1, 'string': 1, 'void': 1, 'iterable': 1, 'object': 1, 'mixed': 1, 'never': 1
};

const PHP_DANGEROUS = {
    'eval': 1, 'assert': 1, 'base64_decode': 1, 'base64_encode': 1,
    'gzinflate': 1, 'gzuncompress': 1, 'gzdecode': 1, 'str_rot13': 1,
    'create_function': 1, 'preg_replace': 1, 'preg_replace_callback': 1,
    'shell_exec': 1, 'exec': 1, 'system': 1, 'passthru': 1, 'proc_open': 1,
    'popen': 1, 'curl_exec': 1, 'file_get_contents': 1, 'file_put_contents': 1,
    'readfile': 1, 'fopen': 1, 'fwrite': 1, 'unlink': 1, 'chmod': 1,
    'move_uploaded_file': 1, 'unserialize': 1,
    'hex2bin': 1, 'bin2hex': 1, 'rawurldecode': 1, 'urldecode': 1, 'chr': 1, 'ord': 1
};

const PHP_CONSTANTS = {
    'true': 1, 'false': 1, 'null': 1, 'self': 1, 'parent': 1,
    '__file__': 1, '__dir__': 1, '__line__': 1, '__function__': 1,
    '__class__': 1, '__method__': 1, '__namespace__': 1, '__trait__': 1
};

const phpTokenRegex = /(\/\*[\s\S]*?(?:\*\/|$)|(?:\/\/|#)(?:(?!\?>)[^\r\n])*)|(\x27[^\x27\\]*(?:\\.[^\x27\\]*)*(?:\x27|$)|"[^"\\]*(?:\\.[^"\\]*)*(?:"|$)|`[^`\\]*(?:\\.[^`\\]*)*(?:`|$))|(<\?(?:php|=)?|\?>)|(\$+[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)|(\b0x[0-9a-fA-F]+\b|\b0b[01]+\b|\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b)|([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)/g;

function highlightPhp(code) {
    if (!code) return '';
    phpTokenRegex.lastIndex = 0;
    let out = '';
    let lastIndex = 0;
    let match;

    while ((match = phpTokenRegex.exec(code)) !== null) {
        if (match.index > lastIndex) {
            out += escapeHtml(code.slice(lastIndex, match.index));
        }
        lastIndex = phpTokenRegex.lastIndex;

        const full = match[0];
        const comment = match[1];
        const str = match[2];
        const tag = match[3];
        const variable = match[4];
        const num = match[5];
        const word = match[6];
        const escaped = escapeHtml(full);

        if (comment) {
            out += '<span class="zs-hl-comment">' + escaped + '</span>';
        } else if (str) {
            out += '<span class="zs-hl-str">' + escaped + '</span>';
        } else if (tag) {
            out += '<span class="zs-hl-tag">' + escaped + '</span>';
        } else if (variable) {
            out += '<span class="zs-hl-var">' + escaped + '</span>';
        } else if (num) {
            out += '<span class="zs-hl-num">' + escaped + '</span>';
        } else if (word) {
            const lower = word.toLowerCase();
            if (PHP_DANGEROUS[lower]) {
                out += '<span class="zs-hl-danger">' + escaped + '</span>';
            } else if (PHP_KEYWORDS[lower]) {
                out += '<span class="zs-hl-kw">' + escaped + '</span>';
            } else if (PHP_CONSTANTS[lower]) {
                out += '<span class="zs-hl-const">' + escaped + '</span>';
            } else {
                out += escaped;
            }
        } else {
            out += escaped;
        }
    }

    if (lastIndex < code.length) {
        out += escapeHtml(code.slice(lastIndex));
    }
    return out;
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

function getReviewStorageKey() {
    return 'zs_review_' + (window.ZS_SESSION_ID || 'default');
}

function loadSavedReviewState() {
    try {
        const raw = localStorage.getItem(getReviewStorageKey());
        if (raw) return JSON.parse(raw);
    } catch (e) {}
    return null;
}

function saveReviewState(overrides) {
    try {
        const key = getReviewStorageKey();
        let state = loadSavedReviewState() || {
            index: currentReviewIndex,
            modal_open: isModalActive,
            reviewed_ids: {}
        };
        state.index = currentReviewIndex;
        state.modal_open = isModalActive;
        const cur = currentFile();
        if (cur) state.finding_id = cur.finding_id;
        if (overrides) {
            for (let k in overrides) {
                state[k] = overrides[k];
            }
        }
        localStorage.setItem(key, JSON.stringify(state));
    } catch (e) {}
}

function markItemReviewedInStorage(findingId) {
    if (!findingId) return;
    try {
        const key = getReviewStorageKey();
        let state = loadSavedReviewState() || {
            index: currentReviewIndex,
            modal_open: isModalActive,
            reviewed_ids: {}
        };
        if (!state.reviewed_ids || typeof state.reviewed_ids !== 'object') {
            state.reviewed_ids = {};
        }
        state.reviewed_ids[findingId] = true;
        localStorage.setItem(key, JSON.stringify(state));
    } catch (e) {}
}

function isFindingReviewed(item, savedReviewedIds) {
    if (!item) return false;
    if (item.reviewed) return true;
    if (item.finding_id && savedReviewedIds && savedReviewedIds[item.finding_id]) return true;
    const status = item.status || 'FOUND';
    if (status === 'QUARANTINED' || status === 'AI_QUARANTINED' || status === 'RESTORED' ||
        status === 'CHANGED_SINCE_SCAN' || status === 'FAILED_DELETE' ||
        status === 'TRUSTED_HIDDEN' || status === 'TRUSTED') {
        return true;
    }
    return false;
}

function calculateInitialReviewIndex() {
    const items = window.REVIEW_ITEMS || [];
    if (!items.length) return 0;

    const saved = loadSavedReviewState();
    const savedIds = (saved && saved.reviewed_ids) ? saved.reviewed_ids : {};

    const firstUnreviewed = items.findIndex(function (item) {
        return !isFindingReviewed(item, savedIds);
    });

    if (firstUnreviewed === -1) {
        return items.length - 1;
    }

    if (saved && typeof saved.index === 'number' && saved.index >= 0 && saved.index < items.length) {
        if (!isFindingReviewed(items[saved.index], savedIds)) {
            return saved.index;
        }
    }

    if (window.ZS_BOOT && typeof window.ZS_BOOT.review_cursor === 'number') {
        const bootIdx = window.ZS_BOOT.review_cursor;
        if (bootIdx >= 0 && bootIdx < items.length && !isFindingReviewed(items[bootIdx], savedIds)) {
            return bootIdx;
        }
    }

    return firstUnreviewed;
}

function updateActiveTableRow() {
    document.querySelectorAll('#infectedTableBody tr.active-review-row').forEach(function (tr) {
        tr.classList.remove('active-review-row');
    });
    const items = window.REVIEW_ITEMS || [];
    if (currentReviewIndex >= 0 && currentReviewIndex < items.length) {
        const file = items[currentReviewIndex];
        if (file && file.row_id) {
            const row = document.getElementById(file.row_id);
            if (row) {
                row.classList.add('active-review-row');
            }
        }
    }
}

function setDecisionLocked(locked) {
    decisionsLocked = locked;
    const file = currentFile();
    const isQuarantined = file && (file.status === 'QUARANTINED' || file.status === 'AI_QUARANTINED');
    ['modalDeleteBtn', 'btnMarkClean', 'modalAskAiBtn', 'btnNextBottom', 'btnPrevTop', 'btnNextTop'].forEach(function (id) {
        const el = document.getElementById(id);
        if (!el) return;
        if (locked) {
            el.disabled = true;
        } else {
            if (id === 'btnPrevTop') {
                el.disabled = currentReviewIndex === 0;
            } else if (id === 'modalDeleteBtn' || id === 'btnMarkClean' || id === 'modalAskAiBtn') {
                el.disabled = !!isQuarantined;
            } else {
                el.disabled = false;
            }
        }
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
    setDecisionLocked(false);
    if (typeof startIndex === 'string') {
        const pos = items.findIndex(function (it) { return it.finding_id === startIndex; });
        currentReviewIndex = pos >= 0 ? pos : calculateInitialReviewIndex();
    } else if (typeof startIndex === 'number' && startIndex >= 0) {
        let pos = items.findIndex(function (it) { return it.idx === startIndex; });
        if (pos < 0 && startIndex < items.length) {
            pos = startIndex;
        }
        currentReviewIndex = pos >= 0 ? pos : calculateInitialReviewIndex();
    } else {
        currentReviewIndex = calculateInitialReviewIndex();
    }
    lastFocused = document.activeElement;
    const modal = document.getElementById('fileViewerModal');
    if (modal) {
        modal.classList.add('active');
        isModalActive = true;
        saveReviewState({ modal_open: true, index: currentReviewIndex });
        loadCurrentFile();
        updateActiveTableRow();
        const closeBtn = document.getElementById('btnCloseModal');
        if (closeBtn && closeBtn.focus) closeBtn.focus();
    }
}

function loadCurrentFile() {
    const items = window.REVIEW_ITEMS || [];
    if (currentReviewIndex < 0 || currentReviewIndex >= items.length) return;
    const file = items[currentReviewIndex];
    saveReviewState({ index: currentReviewIndex });
    updateActiveTableRow();

    const progressFill = document.getElementById('reviewProgressFill');
    if (progressFill) progressFill.style.width = Math.round(((currentReviewIndex + 1) / items.length) * 100) + '%';
    const counterEl = document.getElementById('modalCounter');
    if (counterEl) counterEl.textContent = (currentReviewIndex + 1) + ' / ' + items.length;
    const nameEl = document.getElementById('modalFileName');
    if (nameEl) nameEl.textContent = file.filename || '';
    const pathEl = document.getElementById('modalFilePath');
    if (pathEl) {
        pathEl.textContent = file.path || '';
        pathEl.setAttribute('data-full-path', file.path || '');
        pathEl.title = t('copy_path_hint');
        pathEl.setAttribute('aria-label', (file.path ? file.path + ' - ' : '') + t('copy_path_hint'));
        pathEl.classList.remove('copied');
    }
    const btnCopyFloating = document.getElementById('btnCopyFloating');
    if (btnCopyFloating) btnCopyFloating.classList.remove('copied');
    const reasonEl = document.getElementById('modalFileReason');
    if (reasonEl) reasonEl.textContent = file.reason || '';
    const hashEl = document.getElementById('modalRawHash');
    if (hashEl) hashEl.textContent = file.raw_sha256 || '-';

    const statusEl = document.getElementById('modalFileStatus');
    if (statusEl) {
        statusEl.textContent = file.status || '';
        const st = file.status || 'FOUND';
        if (st === 'QUARANTINED' || st === 'AI_QUARANTINED') {
            statusEl.className = 'badge-status deleted';
        } else if (st === 'TRUSTED' || st === 'TRUSTED_HIDDEN') {
            statusEl.className = 'badge-status trusted';
        } else {
            statusEl.className = 'badge-status pending';
        }
    }
    const strikeBanner = document.getElementById('strikeBanner');
    if (strikeBanner) {
        if (file.is_candidate) {
            strikeBanner.textContent = t('strike1_warning', { sample_path: file.first_path || file.path });
            strikeBanner.style.display = 'block';
        } else {
            strikeBanner.style.display = 'none';
        }
    }
    const aiBadge = document.getElementById('modalAiBadge');
    if (aiBadge) {
        if (file.ai_verdict && file.ai_verdict.verdict) {
            aiBadge.style.display = 'inline-block';
            aiBadge.textContent = 'AI: ' + file.ai_verdict.verdict + ' (' + Math.round((file.ai_verdict.confidence || 0) * 100) + '%) — ' + t('ai_advisory_short');
        } else {
            aiBadge.style.display = 'none';
        }
    }

    const btnPrevTop = document.getElementById('btnPrevTop');
    if (btnPrevTop) btnPrevTop.disabled = currentReviewIndex === 0;
    const codeEl = document.getElementById('modalFileContent');
    if (codeEl) codeEl.textContent = t('modal_loading');
    const modalBody = document.querySelector('#fileViewerModal .modal-body');
    if (modalBody) modalBody.scrollTop = 0;
    setDecisionLocked(true);

    if (previewAbort) previewAbort.abort();
    previewAbort = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const q = '?do_action=view_file&finding_id=' + encodeURIComponent(file.finding_id)
        + '&scan_session_id=' + encodeURIComponent(file.scan_session_id || window.ZS_SESSION_ID)
        + '&expected_raw=' + encodeURIComponent(file.raw_sha256 || '');
    const loadId = file.finding_id;
    fetch(q, { credentials: 'same-origin', signal: previewAbort ? previewAbort.signal : undefined, headers: { 'Accept': 'application/json' } })
        .then(function (res) { return res.json(); })
        .then(function (data) {
            if ((window.REVIEW_ITEMS[currentReviewIndex] || {}).finding_id !== loadId) return;
            if (data.success) {
                if (codeEl) {
                    const rawContent = data.content + (data.is_truncated ? '\n\n' + t('modal_trunc_notice') : '');
                    codeEl.innerHTML = highlightPhp(rawContent);
                }
                if (data.is_quarantined) {
                    file.status = file.status === 'AI_QUARANTINED' ? 'AI_QUARANTINED' : 'QUARANTINED';
                    if (statusEl) {
                        statusEl.textContent = file.status;
                        statusEl.className = 'badge-status deleted';
                    }
                }
            } else {
                if (codeEl) codeEl.textContent = data.message || t('modal_err_read');
            }
            setDecisionLocked(false);
        })
        .catch(function (e) {
            if (e && e.name === 'AbortError') return;
            if ((window.REVIEW_ITEMS[currentReviewIndex] || {}).finding_id !== loadId) return;
            if (codeEl) codeEl.textContent = t('modal_err_network');
            setDecisionLocked(false);
        });
}

function nextReviewFile() {
    if (decisionsLocked) return;
    const items = window.REVIEW_ITEMS || [];
    if (!items.length) {
        closeViewModal();
        return;
    }
    if (currentReviewIndex < items.length - 1) {
        currentReviewIndex++;
        loadCurrentFile();
    } else {
        showToast(t('all_items_reviewed'));
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
    saveReviewState({ modal_open: false, index: currentReviewIndex });
    updateActiveTableRow();
    if (previewAbort) previewAbort.abort();
    setDecisionLocked(false);
    if (lastFocused && lastFocused.focus) lastFocused.focus();
}

function skipAndNext() {
    if (decisionsLocked) return;
    const file = currentFile();
    if (!file) return;
    file.reviewed = true;
    markItemReviewedInStorage(file.finding_id);
    postForm({
        do_action: 'set_review_cursor',
        finding_id: file.finding_id,
        scan_session_id: file.scan_session_id || window.ZS_SESSION_ID,
        expected_raw: file.raw_sha256,
        index: currentReviewIndex + 1,
        skipped: '1'
    }).catch(function () {});
    nextReviewFile();
}

function currentFile() {
    return window.REVIEW_ITEMS[currentReviewIndex];
}

function deleteAndNext() {
    if (decisionsLocked) return;
    const file = currentFile();
    if (!file) return;
    if (file.status === 'QUARANTINED' || file.status === 'AI_QUARANTINED') return;
    setDecisionLocked(true);
    const fields = findingFields(file);
    fields.do_action = 'delete_single';
    postForm(fields).then(function (data) {
        if (data && data.success) {
            file.status = 'QUARANTINED';
            file.reviewed = true;
            markItemReviewedInStorage(file.finding_id);
            const statusEl = document.getElementById('modalFileStatus');
            if (statusEl) {
                statusEl.textContent = file.status;
                statusEl.className = 'badge-status deleted';
            }
            if (file.row_id) {
                const row = document.getElementById(file.row_id);
                if (row) {
                    const delBtn = row.querySelector('.btn-del-single');
                    if (delBtn) delBtn.disabled = true;
                }
            }
            showToast(data.message || t('toast_quarantined'));
            setDecisionLocked(false);
            nextReviewFile();
        } else {
            setDecisionLocked(false);
            alert((data && data.message) || t('err_delete_failed'));
        }
    }).catch(function (err) {
        setDecisionLocked(false);
        alert((err && err.message) || t('err_delete_failed'));
    });
}

function markCleanCurrent() {
    if (decisionsLocked) return;
    const file = currentFile();
    if (!file) return;
    if (file.status === 'QUARANTINED' || file.status === 'AI_QUARANTINED') return;
    setDecisionLocked(true);
    const fields = findingFields(file);
    fields.do_action = 'mark_clean';
    postForm(fields).then(function (data) {
        if (!data || !data.success) {
            setDecisionLocked(false);
            alert((data && data.message) || 'Failed');
            return;
        }
        showToast(data.message);
        file.reviewed = true;
        markItemReviewedInStorage(file.finding_id);
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
            if (window.REVIEW_ITEMS.length === 0) {
                setDecisionLocked(false);
                closeViewModal();
                return;
            }
            if (currentReviewIndex >= window.REVIEW_ITEMS.length) {
                currentReviewIndex = window.REVIEW_ITEMS.length - 1;
            }
            setDecisionLocked(false);
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
        setDecisionLocked(false);
        nextReviewFile();
    }).catch(function (err) {
        setDecisionLocked(false);
        alert((err && err.message) || 'Failed');
    });
}

let pendingAiCallback = null;
let isKeyModalRateLimit = false;

function openGeminiKeyModal(onSuccess, isRateLimit) {
    pendingAiCallback = onSuccess || null;
    isKeyModalRateLimit = !!isRateLimit;
    const modal = document.getElementById('geminiKeyModal');
    if (!modal) return;
    const notice = document.getElementById('geminiKeyRateLimitNotice');
    if (notice) {
        notice.style.display = isRateLimit ? 'block' : 'none';
    }
    const title = document.getElementById('geminiKeyModalTitle');
    if (title) {
        title.textContent = isRateLimit ? t('gemini_key_ratelimit_title') : t('gemini_key_modal_title');
    }
    const input = document.getElementById('modal_gemini_api_keys');
    if (input) {
        input.value = '';
    }
    modal.classList.add('active');
    if (input) {
        setTimeout(function () { input.focus(); }, 50);
    }
}

function closeGeminiKeyModal() {
    const modal = document.getElementById('geminiKeyModal');
    if (modal) modal.classList.remove('active');
    isKeyModalRateLimit = false;
    pendingAiCallback = null;
}

function askAiCurrent() {
    const file = currentFile();
    if (!file) return;
    if (file.status === 'QUARANTINED' || file.status === 'AI_QUARANTINED') return;
    if (!window.ZS_BOOT || !window.ZS_BOOT.has_ai) {
        openGeminiKeyModal(function () {
            askAiCurrent();
        });
        return;
    }
    const btn = document.getElementById('modalAskAiBtn');
    if (btn) btn.disabled = true;
    const fields = findingFields(file);
    fields.do_action = 'ask_ai';
    postForm(fields).then(function (data) {
        if (btn) btn.disabled = false;
        if (data.rate_limit_rotated) {
            showToast(t('gemini_key_rotated_notice'));
        }
        if (data.success && data.verdict) {
            if (data.verdict.error === 'no_api_key' || (typeof data.verdict.summary === 'string' && data.verdict.summary.indexOf('No Gemini API key configured') !== -1)) {
                openGeminiKeyModal(function () {
                    askAiCurrent();
                });
                return;
            }
            if (data.verdict.error === 'all_cooling') {
                openGeminiKeyModal(function () {
                    askAiCurrent();
                }, true);
                return;
            }
            file.ai_verdict = data.verdict;
            const aiBadge = document.getElementById('modalAiBadge');
            if (aiBadge) {
                aiBadge.style.display = 'inline-block';
                aiBadge.textContent = 'AI: ' + data.verdict.verdict + ' (' + Math.round((data.verdict.confidence || 0) * 100) + '%) — ' + t('ai_advisory_short');
            }
            showToast((data.verdict.summary || data.verdict.verdict) + ' (' + t('ai_advisory_short') + ')');
        } else {
            alert(data.message || t('err_ai_failed'));
        }
    }).catch(function () { if (btn) btn.disabled = false; });
}

let pathCopyTimer = null;
let codeCopyTimer = null;

function copyTextToClipboard(text, successMsg, onSuccess) {
    if (!text) return;
    function fallbackCopy() {
        try {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.setAttribute('readonly', '');
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            ta.style.left = '-9999px';
            ta.style.fontSize = '16px';
            document.body.appendChild(ta);
            if (ta.select) ta.select();
            if (ta.setSelectionRange) ta.setSelectionRange(0, text.length);
            let ok = false;
            try {
                ok = document.execCommand ? document.execCommand('copy') : false;
                if (ok === undefined) ok = true;
            } catch (err) {
                ok = false;
            }
            if (ta.parentNode) ta.parentNode.removeChild(ta);
            if (ok) {
                if (successMsg) showToast(successMsg);
                if (onSuccess) onSuccess();
            }
        } catch (e) {}
    }
    const clip = (typeof window !== 'undefined' && window.navigator && window.navigator.clipboard) ? window.navigator.clipboard : (typeof navigator !== 'undefined' ? navigator.clipboard : null);
    if (clip && (typeof window === 'undefined' || window.isSecureContext)) {
        clip.writeText(text).then(function () {
            if (successMsg) showToast(successMsg);
            if (onSuccess) onSuccess();
        }).catch(function () {
            fallbackCopy();
        });
    } else {
        fallbackCopy();
    }
}

function copyModalContent() {
    const codeEl = document.getElementById('modalFileContent');
    const text = codeEl ? codeEl.textContent : '';
    if (!text || text === t('modal_loading') || text === t('modal_err_read') || text === t('modal_err_network')) return;
    const btn = document.getElementById('btnCopyFloating');
    copyTextToClipboard(text, t('modal_copied'), function () {
        if (btn) {
            btn.classList.add('copied');
            if (codeCopyTimer) clearTimeout(codeCopyTimer);
            codeCopyTimer = setTimeout(function () { btn.classList.remove('copied'); }, 1500);
        }
    });
}

function copyFilePath() {
    const pathEl = document.getElementById('modalFilePath');
    const path = pathEl ? (pathEl.getAttribute('data-full-path') || pathEl.textContent || '').trim() : '';
    if (!path) return;
    copyTextToClipboard(path, t('path_copied'), function () {
        if (pathEl) {
            pathEl.classList.add('copied');
            if (pathCopyTimer) clearTimeout(pathCopyTimer);
            pathCopyTimer = setTimeout(function () { pathEl.classList.remove('copied'); }, 1500);
        }
    });
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
        openGeminiKeyModal(function () {
            startAutoAiReview();
        });
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
        if (data.error === 'no_api_key') {
            pauseAutoReview();
            document.getElementById('autoReviewProgressText').textContent = t('ai_need_key');
            openGeminiKeyModal(function () {
                resumeAutoReview();
            });
            return;
        }
        if (data.error === 'all_cooling') {
            const wait = (data.retry_after || 20) * 1000;
            document.getElementById('autoReviewProgressText').textContent = t('gemini_key_ratelimit_notice');
            pauseAutoReview();
            openGeminiKeyModal(function () {
                resumeAutoReview();
            }, true);
            return;
        }
        if (data.rate_limit_rotated) {
            showToast(t('gemini_key_rotated_notice'));
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
    currentReviewIndex = calculateInitialReviewIndex();
    updateActiveTableRow();

    const saved = loadSavedReviewState();
    if (saved && saved.modal_open && (window.REVIEW_ITEMS || []).length > 0) {
        startReviewMode();
    }

    document.querySelectorAll('[data-switch-lang]').forEach(function (btn) {
        btn.addEventListener('click', function () { switchLang(btn.getAttribute('data-switch-lang')); });
    });
    const startReview = document.getElementById('btnStartReview');
    if (startReview) startReview.addEventListener('click', function () { startReviewMode(); });
    const startAuto = document.getElementById('btnStartAuto');
    if (startAuto) startAuto.addEventListener('click', startAutoAiReview);
    document.querySelectorAll('[data-review-idx]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            const fid = btn.getAttribute('data-finding-id');
            if (fid) {
                startReviewMode(fid);
            } else {
                startReviewMode(parseInt(btn.getAttribute('data-review-idx'), 10));
            }
        });
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
    if (btnNextB) btnNextB.addEventListener('click', skipAndNext);
    if (btnPrev) btnPrev.addEventListener('click', prevReviewFile);
    const delBtn = document.getElementById('modalDeleteBtn');
    if (delBtn) delBtn.addEventListener('click', deleteAndNext);
    const markBtn = document.getElementById('btnMarkClean');
    if (markBtn) markBtn.addEventListener('click', markCleanCurrent);
    const askBtn = document.getElementById('modalAskAiBtn');
    if (askBtn) askBtn.addEventListener('click', askAiCurrent);
    const copyBtn = document.getElementById('btnCopyFloating');
    if (copyBtn) copyBtn.addEventListener('click', copyModalContent);
    const pathEl = document.getElementById('modalFilePath');
    if (pathEl) {
        pathEl.addEventListener('click', copyFilePath);
        pathEl.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' || e.key === ' ' || e.code === 'Space') {
                e.preventDefault();
                e.stopPropagation();
                copyFilePath();
            }
        });
    }

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

    const formKeyModal = document.getElementById('formGeminiKeyModal');
    if (formKeyModal) {
        formKeyModal.addEventListener('submit', function (e) {
            e.preventDefault();
            const input = document.getElementById('modal_gemini_api_keys');
            const val = input ? input.value.trim() : '';
            const validKeys = val.split(/[\r\n,]+/).map(function (s) { return s.trim(); }).filter(Boolean);
            if (validKeys.length === 0) {
                alert(t('gemini_key_required_prompt'));
                return;
            }
            const saveBtn = document.getElementById('btnSaveGeminiKeyModal');
            if (saveBtn) saveBtn.disabled = true;

            const postData = {
                do_action: 'save_settings',
                gemini_api_keys: val,
            };
            if (isKeyModalRateLimit) {
                postData.append_gemini_keys = '1';
            }

            postForm(postData).then(function (data) {
                if (saveBtn) saveBtn.disabled = false;
                if (data.success) {
                    if (window.ZS_BOOT) {
                        window.ZS_BOOT.has_ai = true;
                    }
                    const askBtn = document.getElementById('modalAskAiBtn');
                    if (askBtn) askBtn.disabled = false;
                    const autoBtn = document.getElementById('btnStartAuto');
                    if (autoBtn) autoBtn.disabled = false;

                    const cb = pendingAiCallback;
                    closeGeminiKeyModal();
                    showToast(data.message || t('settings_saved'));
                    if (typeof cb === 'function') {
                        cb();
                    }
                } else {
                    alert(data.message || t('err_ai_failed'));
                }
            }).catch(function () {
                if (saveBtn) saveBtn.disabled = false;
            });
        });
    }

    const cancelKeyModal = document.getElementById('btnCancelGeminiKeyModal');
    if (cancelKeyModal) cancelKeyModal.addEventListener('click', closeGeminiKeyModal);

    const closeKeyModalBtn = document.getElementById('btnCloseGeminiKeyModal');
    if (closeKeyModalBtn) closeKeyModalBtn.addEventListener('click', closeGeminiKeyModal);

    const keyModalOverlay = document.getElementById('geminiKeyModal');
    if (keyModalOverlay) {
        keyModalOverlay.addEventListener('click', function (e) {
            if (e.target.id === 'geminiKeyModal') closeGeminiKeyModal();
        });
    }
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
    const activeModals = document.querySelectorAll('.modal-overlay.active');
    const topModal = activeModals.length > 0 ? activeModals[activeModals.length - 1] : null;
    if (topModal && e.key === 'Tab') {
        trapFocus(topModal, e);
        return;
    }
    const tag = (e.target.tagName || '').toLowerCase();
    if (tag === 'input' || tag === 'textarea' || tag === 'select') return;
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    const key = e.key.toLowerCase();
    if (key === 'escape') {
        if (topModal) {
            if (topModal.id === 'geminiKeyModal') {
                closeGeminiKeyModal();
            } else if (topModal.id === 'fileViewerModal') {
                closeViewModal();
            } else {
                topModal.classList.remove('active');
            }
            return;
        }
        return;
    }
    const fvm = document.getElementById('fileViewerModal');
    if (!fvm || !fvm.classList.contains('active') || topModal !== fvm || decisionsLocked) return;
    if (e.code === 'Space') {
        e.preventDefault();
        skipAndNext();
        return;
    }
    if (key === 'c') copyModalContent();
    else if (key === 'd' || e.key === 'Delete') deleteAndNext();
    else if (key === 'n' || e.key === 'ArrowRight') skipAndNext();
    else if (key === 'p' || e.key === 'ArrowLeft') prevReviewFile();
    else if (key === 'b') markCleanCurrent();
    else if (key === 'a') askAiCurrent();
});

if (typeof window !== 'undefined') {
    window.highlightPhp = highlightPhp;
    window.copyFilePath = copyFilePath;
    window.copyModalContent = copyModalContent;
    window.copyTextToClipboard = copyTextToClipboard;
}
