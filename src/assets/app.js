let currentReviewIndex = 0;
let reviewCursor = 0;
let isModalActive = false;
let autoReviewActive = false;
let autoReviewPaused = false;
let previewAbort = null;
let previewTimer = null;
let decisionsLocked = false;
let lastFocused = null;

function abortPreviewFetch() {
    if (previewTimer && typeof clearTimeout !== 'undefined') {
        clearTimeout(previewTimer);
        previewTimer = null;
    }
    if (previewAbort) {
        try { previewAbort.abort(); } catch (e) {}
        previewAbort = null;
    }
}

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

function postForm(fields, timeoutMs) {
    const timeout = typeof timeoutMs === 'number' ? timeoutMs : 15000;
    const formData = new FormData();
    for (const k in fields) {
        if (Object.prototype.hasOwnProperty.call(fields, k) && fields[k] !== undefined && fields[k] !== null) {
            formData.append(k, fields[k]);
        }
    }
    formData.append('csrf_token', getCsrfToken());

    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    let timerId = null;
    if (controller && timeout > 0 && typeof setTimeout !== 'undefined') {
        timerId = setTimeout(function () {
            try { controller.abort(); } catch (e) {}
        }, timeout);
    }

    return fetch(window.location.pathname, {
        method: 'POST',
        headers: { 'X-CSRF-Token': getCsrfToken(), 'Accept': 'application/json' },
        body: formData,
        credentials: 'same-origin',
        signal: controller ? controller.signal : undefined,
    }).then(function (res) {
        if (timerId && typeof clearTimeout !== 'undefined') clearTimeout(timerId);
        return res.json().catch(function () {
            if (res.status === 401 || res.status === 403) {
                return { success: false, message: (typeof t === 'function' ? t('auth_required') : 'Authentication required.'), code: 'AUTH' };
            }
            return { success: false, message: (typeof t === 'function' ? t('err_server') : 'Server error') + ' (' + res.status + ')', code: 'SERVER_ERROR' };
        });
    }).catch(function (err) {
        if (timerId && typeof clearTimeout !== 'undefined') clearTimeout(timerId);
        if (err && err.name === 'AbortError') {
            throw new Error(typeof t === 'function' ? t('err_request_timeout') : 'Request timed out. Please check your connection and try again.');
        }
        throw err;
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
            sequential_index: currentReviewIndex,
            review_cursor: reviewCursor,
            modal_open: isModalActive,
            is_single_inspect: false,
            reviewed_ids: {}
        };
        if (overrides) {
            for (let k in overrides) {
                state[k] = overrides[k];
            }
        }
        if (typeof state.review_cursor === 'number') {
            reviewCursor = state.review_cursor;
            if (window.ZS_BOOT) {
                window.ZS_BOOT.review_cursor = state.review_cursor;
            }
        }
        localStorage.setItem(key, JSON.stringify(state));
    } catch (e) {}
}

function syncReviewCursor(idx, findingId) {
    if (!window.ZS_SESSION_ID || typeof idx !== 'number') return;
    postForm({
        do_action: 'set_review_cursor',
        finding_id: findingId || '',
        scan_session_id: window.ZS_SESSION_ID,
        index: idx
    }).then(function (data) {
        if (data && data.success && typeof data.review_cursor === 'number') {
            if (window.ZS_BOOT) window.ZS_BOOT.review_cursor = data.review_cursor;
            reviewCursor = Math.max(reviewCursor, data.review_cursor);
            saveReviewState({ review_cursor: reviewCursor });
        }
    }).catch(function () {});
}

function markItemReviewedInStorage(findingId) {
    if (!findingId) return;
    try {
        const key = getReviewStorageKey();
        let state = loadSavedReviewState() || {
            index: currentReviewIndex,
            sequential_index: currentReviewIndex,
            review_cursor: reviewCursor,
            modal_open: isModalActive,
            is_single_inspect: false,
            reviewed_ids: {}
        };
        if (!state.reviewed_ids || typeof state.reviewed_ids !== 'object') {
            state.reviewed_ids = {};
        }
        state.reviewed_ids[findingId] = true;
        localStorage.setItem(key, JSON.stringify(state));
    } catch (e) {}
}

function isTerminalStatus(status) {
    return status === 'QUARANTINED' || status === 'AI_QUARANTINED' ||
        status === 'CHANGED_SINCE_SCAN' || status === 'MISSING' ||
        status === 'FAILED_DELETE' || status === 'RESTORED' ||
        status === 'TRUSTED_HIDDEN' || status === 'TRUSTED';
}

function isFindingReviewed(item, savedReviewedIds) {
    if (!item) return false;
    if (item.reviewed) return true;
    if (item.finding_id && savedReviewedIds && savedReviewedIds[item.finding_id]) return true;
    const status = item.status || 'FOUND';
    return isTerminalStatus(status);
}

function calculateInitialReviewIndex() {
    const items = window.REVIEW_ITEMS || [];
    if (!items.length) return 0;

    const saved = loadSavedReviewState();
    const savedIds = (saved && saved.reviewed_ids && typeof saved.reviewed_ids === 'object')
        ? saved.reviewed_ids
        : {};

    const firstUnreviewed = items.findIndex(function (item) {
        return !isFindingReviewed(item, savedIds);
    });

    if (firstUnreviewed === -1) {
        return -1;
    }

    let cursorCandidate = 0;
    if (typeof reviewCursor === 'number' && reviewCursor >= 0) {
        cursorCandidate = Math.max(cursorCandidate, reviewCursor);
    }
    if (saved && typeof saved.review_cursor === 'number' && saved.review_cursor >= 0) {
        cursorCandidate = Math.max(cursorCandidate, saved.review_cursor);
    }
    if (saved && typeof saved.sequential_index === 'number' && saved.sequential_index >= 0) {
        cursorCandidate = Math.max(cursorCandidate, saved.sequential_index);
    }
    if (window.ZS_BOOT && typeof window.ZS_BOOT.review_cursor === 'number' && window.ZS_BOOT.review_cursor >= 0) {
        cursorCandidate = Math.max(cursorCandidate, window.ZS_BOOT.review_cursor);
    }

    if (saved && !saved.is_single_inspect && typeof saved.index === 'number' && saved.index >= 0) {
        cursorCandidate = Math.max(cursorCandidate, saved.index);
    }

    if (cursorCandidate >= items.length) {
        cursorCandidate = Math.max(0, items.length - 1);
    }

    for (let i = cursorCandidate; i < items.length; i++) {
        if (!isFindingReviewed(items[i], savedIds)) {
            return i;
        }
    }

    if (firstUnreviewed >= 0) {
        return firstUnreviewed;
    }

    return Math.min(cursorCandidate, items.length - 1);
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
    const isTerminal = !!(file && isTerminalStatus(file.status));
    ['modalDeleteBtn', 'btnMarkClean', 'modalAskAiBtn', 'btnNextBottom', 'btnPrevTop', 'btnNextTop'].forEach(function (id) {
        const el = document.getElementById(id);
        if (!el) return;
        if (locked) {
            el.disabled = true;
        } else {
            if (id === 'btnPrevTop') {
                el.disabled = currentReviewIndex === 0;
            } else if (id === 'modalDeleteBtn' || id === 'btnMarkClean' || id === 'modalAskAiBtn') {
                el.disabled = isTerminal;
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

function startReviewMode(startIndex, isSingleInspect) {
    const items = window.REVIEW_ITEMS || [];
    if (!items.length) {
        alert(t('no_threats_found'));
        return;
    }
    setDecisionLocked(false);
    let targetIdx = -1;
    if (typeof startIndex === 'string') {
        const pos = items.findIndex(function (it) { return it.finding_id === startIndex; });
        targetIdx = pos >= 0 ? pos : calculateInitialReviewIndex();
    } else if (typeof startIndex === 'number' && startIndex >= 0) {
        let pos = items.findIndex(function (it) { return it.idx === startIndex; });
        if (pos < 0 && startIndex < items.length) {
            pos = startIndex;
        }
        targetIdx = pos >= 0 ? pos : calculateInitialReviewIndex();
    } else {
        targetIdx = calculateInitialReviewIndex();
        if (targetIdx === -1) {
            showToast(t('all_items_reviewed'));
            return;
        }
    }
    if (targetIdx < 0 || targetIdx >= items.length) {
        targetIdx = 0;
    }
    currentReviewIndex = targetIdx;
    lastFocused = document.activeElement;
    const modal = document.getElementById('fileViewerModal');
    if (modal) {
        modal.classList.add('active');
        isModalActive = true;
        if (!isSingleInspect) {
            reviewCursor = Math.max(reviewCursor, currentReviewIndex);
            if (window.ZS_BOOT) {
                window.ZS_BOOT.review_cursor = reviewCursor;
            }
            saveReviewState({
                modal_open: true,
                index: currentReviewIndex,
                sequential_index: currentReviewIndex,
                review_cursor: reviewCursor,
                is_single_inspect: false
            });
            syncReviewCursor(reviewCursor);
        } else {
            saveReviewState({
                modal_open: true,
                inspect_index: currentReviewIndex,
                is_single_inspect: true
            });
        }
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
    const saved = loadSavedReviewState();
    if (saved && saved.is_single_inspect) {
        saveReviewState({ inspect_index: currentReviewIndex, finding_id: file.finding_id });
    } else {
        saveReviewState({
            index: currentReviewIndex,
            sequential_index: currentReviewIndex,
            review_cursor: reviewCursor,
            finding_id: file.finding_id
        });
    }
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
        if (pathEl.setAttribute) {
            pathEl.setAttribute('data-full-path', file.path || '');
            pathEl.setAttribute('aria-label', (file.path ? file.path + ' - ' : '') + t('copy_path_hint'));
        }
        pathEl.title = t('copy_path_hint');
        if (pathEl.classList && pathEl.classList.remove) pathEl.classList.remove('copied');
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
    const btnNextTop = document.getElementById('btnNextTop');
    if (btnNextTop) btnNextTop.disabled = (currentReviewIndex >= items.length - 1);
    const isTerminal = !!(file && isTerminalStatus(file.status));
    const delBtn = document.getElementById('modalDeleteBtn');
    if (delBtn) delBtn.disabled = isTerminal;
    const markBtn = document.getElementById('btnMarkClean');
    if (markBtn) markBtn.disabled = isTerminal;
    const askBtn = document.getElementById('modalAskAiBtn');
    if (askBtn) askBtn.disabled = isTerminal;

    const codeEl = document.getElementById('modalFileContent');
    if (codeEl) codeEl.textContent = t('modal_loading');
    const modalBody = (document.querySelector) ? document.querySelector('#fileViewerModal .modal-body') : null;
    if (modalBody) modalBody.scrollTop = 0;

    abortPreviewFetch();
    previewAbort = typeof AbortController !== 'undefined' ? new AbortController() : null;
    if (previewAbort && typeof setTimeout !== 'undefined') {
        previewTimer = setTimeout(function () {
            abortPreviewFetch();
        }, 15000);
    }
    const q = '?do_action=view_file&finding_id=' + encodeURIComponent(file.finding_id)
        + '&scan_session_id=' + encodeURIComponent(file.scan_session_id || window.ZS_SESSION_ID)
        + '&expected_raw=' + encodeURIComponent(file.raw_sha256 || '');
    const loadId = file.finding_id;
    fetch(q, { credentials: 'same-origin', signal: previewAbort ? previewAbort.signal : undefined, headers: { 'Accept': 'application/json' } })
        .then(function (res) {
            abortPreviewFetch();
            return res.json();
        })
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
                    const bDel = document.getElementById('modalDeleteBtn');
                    if (bDel) bDel.disabled = true;
                    const bClean = document.getElementById('btnMarkClean');
                    if (bClean) bClean.disabled = true;
                    const bAi = document.getElementById('modalAskAiBtn');
                    if (bAi) bAi.disabled = true;
                }
            } else {
                if (codeEl) codeEl.textContent = data.message || t('modal_err_read');
            }
        })
        .catch(function (e) {
            abortPreviewFetch();
            if (e && e.name === 'AbortError') return;
            if ((window.REVIEW_ITEMS[currentReviewIndex] || {}).finding_id !== loadId) return;
            if (codeEl) codeEl.textContent = t('modal_err_network');
        });
}

function nextReviewFile() {
    if (decisionsLocked) return;
    const items = window.REVIEW_ITEMS || [];
    if (!items.length) {
        closeViewModal();
        return;
    }

    const saved = loadSavedReviewState();
    const savedIds = (saved && saved.reviewed_ids && typeof saved.reviewed_ids === 'object') ? saved.reviewed_ids : {};

    let nextIdx = -1;
    for (let i = currentReviewIndex + 1; i < items.length; i++) {
        if (!isFindingReviewed(items[i], savedIds)) {
            nextIdx = i;
            break;
        }
    }

    if (nextIdx === -1) {
        showToast(t('all_items_reviewed'));
        closeViewModal();
        return;
    }

    currentReviewIndex = nextIdx;
    reviewCursor = Math.max(reviewCursor, currentReviewIndex);
    if (window.ZS_BOOT) {
        window.ZS_BOOT.review_cursor = reviewCursor;
    }
    saveReviewState({
        index: currentReviewIndex,
        sequential_index: currentReviewIndex,
        review_cursor: reviewCursor,
        is_single_inspect: false
    });
    syncReviewCursor(reviewCursor);
    loadCurrentFile();
}

function prevReviewFile() {
    if (decisionsLocked) return;
    if (currentReviewIndex > 0) {
        currentReviewIndex--;
        const saved = loadSavedReviewState();
        if (saved && saved.is_single_inspect) {
            saveReviewState({ inspect_index: currentReviewIndex });
        } else {
            saveReviewState({ index: currentReviewIndex, review_cursor: reviewCursor });
        }
        loadCurrentFile();
    }
}

function closeViewModal() {
    const modal = document.getElementById('fileViewerModal');
    if (modal) modal.classList.remove('active');
    isModalActive = false;
    const saved = loadSavedReviewState();
    if (saved && saved.is_single_inspect) {
        const resumeIdx = (typeof saved.sequential_index === 'number') ? saved.sequential_index : reviewCursor;
        saveReviewState({
            modal_open: false,
            is_single_inspect: false,
            index: resumeIdx
        });
    } else {
        saveReviewState({
            modal_open: false,
            is_single_inspect: false,
            index: currentReviewIndex,
            sequential_index: currentReviewIndex,
            review_cursor: reviewCursor
        });
    }
    updateActiveTableRow();
    abortPreviewFetch();
    setDecisionLocked(false);
    try {
        if (lastFocused && lastFocused.focus) lastFocused.focus();
    } catch (e) {}
}

function skipAndNext() {
    if (decisionsLocked) return;
    const file = currentFile();
    if (!file) return;
    file.reviewed = true;
    markItemReviewedInStorage(file.finding_id);
    const nextIdx = currentReviewIndex + 1;
    reviewCursor = Math.max(reviewCursor, nextIdx);
    if (window.ZS_BOOT) window.ZS_BOOT.review_cursor = reviewCursor;
    saveReviewState({
        index: nextIdx,
        sequential_index: nextIdx,
        review_cursor: reviewCursor,
        is_single_inspect: false
    });
    postForm({
        do_action: 'set_review_cursor',
        finding_id: file.finding_id,
        scan_session_id: file.scan_session_id || window.ZS_SESSION_ID,
        expected_raw: file.raw_sha256,
        index: nextIdx,
        skipped: '1'
    }).then(function (data) {
        if (data && data.success && typeof data.review_cursor === 'number') {
            if (window.ZS_BOOT) window.ZS_BOOT.review_cursor = data.review_cursor;
            reviewCursor = Math.max(reviewCursor, data.review_cursor);
            saveReviewState({ review_cursor: reviewCursor, sequential_index: reviewCursor });
        }
    }).catch(function () {});
    nextReviewFile();
}

function currentFile() {
    return window.REVIEW_ITEMS[currentReviewIndex];
}

function deleteAndNext() {
    if (decisionsLocked) return;
    const file = currentFile();
    if (!file) {
        closeViewModal();
        return;
    }
    if (isTerminalStatus(file.status)) {
        nextReviewFile();
        return;
    }
    setDecisionLocked(true);
    abortPreviewFetch();
    const fields = findingFields(file);
    fields.do_action = 'delete_single';
    let promise;
    try {
        promise = postForm(fields);
    } catch (e) {
        setDecisionLocked(false);
        try { alert((e && e.message) || t('err_delete_failed')); } catch (_) {}
        return;
    }
    promise.then(function (data) {
        if (data && data.success) {
            try {
                file.status = 'QUARANTINED';
                file.reviewed = true;
                markItemReviewedInStorage(file.finding_id);
                if (data && typeof data.review_cursor === 'number') {
                    if (window.ZS_BOOT) window.ZS_BOOT.review_cursor = data.review_cursor;
                    reviewCursor = Math.max(reviewCursor, data.review_cursor);
                    saveReviewState({ review_cursor: reviewCursor, sequential_index: reviewCursor, is_single_inspect: false });
                }
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
                        const badge = row.querySelector('.badge-status');
                        if (badge) {
                            badge.textContent = file.status;
                            badge.className = 'badge-status deleted';
                        }
                    }
                }
                const statQuar = document.getElementById('statQuarantined');
                if (statQuar && !data.already_quarantined) {
                    const cur = parseInt(statQuar.textContent.replace(/,/g, ''), 10) || 0;
                    statQuar.textContent = String(cur + 1);
                }
                showToast(data.message || t('toast_quarantined'));
            } catch (domErr) {
                console.error(domErr);
            }
            setDecisionLocked(false);
            nextReviewFile();
        } else {
            try {
                if (data && (data.code === 'CHANGED_SINCE_SCAN' || data.code === 'MISSING')) {
                    file.status = data.code;
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
                            const badge = row.querySelector('.badge-status');
                            if (badge) {
                                badge.textContent = file.status;
                                badge.className = 'badge-status deleted';
                            }
                        }
                    }
                    const mDel = document.getElementById('modalDeleteBtn');
                    if (mDel) mDel.disabled = true;
                    const mClean = document.getElementById('btnMarkClean');
                    if (mClean) mClean.disabled = true;
                    const mAi = document.getElementById('modalAskAiBtn');
                    if (mAi) mAi.disabled = true;

                    setDecisionLocked(false);
                    try { alert((data && data.message) || t('err_delete_failed')); } catch (_) {}
                    nextReviewFile();
                    return;
                }
            } catch (statusErr) {
                console.error(statusErr);
            }
            setDecisionLocked(false);
            try { alert((data && data.message) || t('err_delete_failed')); } catch (_) {}
        }
    }).catch(function (err) {
        setDecisionLocked(false);
        try { alert((err && err.message) || t('err_delete_failed')); } catch (_) {}
    });
}

function markCleanCurrent() {
    if (decisionsLocked) return;
    const file = currentFile();
    if (!file) return;
    if (isTerminalStatus(file.status)) {
        nextReviewFile();
        return;
    }
    setDecisionLocked(true);
    abortPreviewFetch();
    const fields = findingFields(file);
    fields.do_action = 'mark_clean';
    let promise;
    try {
        promise = postForm(fields);
    } catch (e) {
        setDecisionLocked(false);
        try { alert((e && e.message) || 'Failed'); } catch (_) {}
        return;
    }
    promise.then(function (data) {
        if (!data || !data.success) {
            setDecisionLocked(false);
            try { alert((data && data.message) || 'Failed'); } catch (_) {}
            return;
        }
        showToast(data.message);
        file.reviewed = true;
        markItemReviewedInStorage(file.finding_id);
        if (data && typeof data.review_cursor === 'number') {
            if (window.ZS_BOOT) window.ZS_BOOT.review_cursor = data.review_cursor;
            reviewCursor = Math.max(reviewCursor, data.review_cursor);
            saveReviewState({ review_cursor: reviewCursor, sequential_index: reviewCursor, is_single_inspect: false });
        }
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
            if (reviewCursor >= window.REVIEW_ITEMS.length) {
                reviewCursor = Math.max(0, window.REVIEW_ITEMS.length - 1);
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
        try { alert((err && err.message) || 'Failed'); } catch (_) {}
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

function saveGeminiKeyModal(e) {
    if (e && e.preventDefault) e.preventDefault();
    const input = document.getElementById('modal_gemini_api_keys');
    const val = input ? input.value.trim() : '';
    const validKeys = val.split(/[\r\n,]+/).map(function (s) {
        let clean = s.trim().replace(/^['"]+|['"]+$/g, '');
        const matchPrefix = clean.match(/^(?:gemini_api_keys?|api_key)\s*[:=]\s*(.+)$/i);
        if (matchPrefix) clean = matchPrefix[1].trim().replace(/^['"]+|['"]+$/g, '');
        return clean;
    }).filter(function (s) {
        return s !== '' && s.indexOf('•') === -1 && s.indexOf('*') === -1;
    });
    if (validKeys.length === 0) {
        alert(t('gemini_key_required_prompt'));
        return;
    }
    const saveBtn = document.getElementById('btnSaveGeminiKeyModal');
    if (saveBtn) saveBtn.disabled = true;

    const postData = {
        do_action: 'save_settings',
        gemini_api_keys: validKeys.join("\n"),
    };
    if (isKeyModalRateLimit) {
        postData.append_gemini_keys = '1';
    }

    return postForm(postData).then(function (data) {
        if (saveBtn) saveBtn.disabled = false;
        if (data && data.success) {
            const hasAi = (typeof data.has_ai !== 'undefined') ? !!data.has_ai : (validKeys.length > 0);
            if (window.ZS_BOOT) {
                window.ZS_BOOT.has_ai = hasAi;
            }
            window.CONFIG = window.CONFIG || {};
            window.CONFIG.has_ai = hasAi;

            const askBtn = document.getElementById('modalAskAiBtn');
            if (askBtn && hasAi) askBtn.disabled = false;
            const autoBtn = document.getElementById('btnStartAuto');
            if (autoBtn && hasAi) autoBtn.disabled = false;

            const cb = pendingAiCallback;
            closeGeminiKeyModal();
            showToast(data.message || t('settings_saved'));
            if (hasAi && typeof cb === 'function') {
                cb();
            }
            return data;
        } else {
            alert((data && data.message) || t('err_ai_failed'));
            return data;
        }
    }).catch(function (err) {
        if (saveBtn) saveBtn.disabled = false;
        alert((err && err.message) || t('err_ai_failed'));
    });
}
window.saveGeminiKeyModal = saveGeminiKeyModal;
window.askAiFile = askAiCurrent;

function askAiCurrent() {
    const file = currentFile();
    if (!file) return;
    if (isTerminalStatus(file.status)) return;
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

let scanActive = false;
let scanPaused = false;
let scanTimer = null;
let scanConsecutiveErrors = 0;

function clearScanTimer() {
    if (scanTimer) {
        clearTimeout(scanTimer);
        scanTimer = null;
    }
}

function appendFindingRow(f) {
    const tbody = document.getElementById('infectedTableBody');
    const table = document.getElementById('infectedTable');
    const noThreats = document.getElementById('noThreatsMsg');
    const btnReview = document.getElementById('btnStartReview');
    const btnAuto = document.getElementById('btnStartAuto');

    if (noThreats) noThreats.style.display = 'none';
    if (table) table.style.display = '';
    if (btnReview) btnReview.style.display = 'inline-block';
    if (btnAuto) btnAuto.style.display = 'inline-block';

    if (!tbody) return;
    if (document.getElementById(f.row_id)) return;

    const tr = document.createElement('tr');
    tr.id = f.row_id;

    // Checkbox cell
    const tdCheck = document.createElement('td');
    const chk = document.createElement('input');
    chk.type = 'checkbox';
    chk.className = 'share-select';
    chk.setAttribute('data-finding-id', f.finding_id);
    tdCheck.appendChild(chk);
    tr.appendChild(tdCheck);

    // Number cell
    const tdNum = document.createElement('td');
    tdNum.textContent = String(f.idx + 1);
    tr.appendChild(tdNum);

    // Path cell
    const tdPath = document.createElement('td');
    tdPath.className = 'dir-path';
    tdPath.textContent = f.path;
    tr.appendChild(tdPath);

    // Reason cell
    const tdReason = document.createElement('td');
    tdReason.className = 'reason-cell';
    let reasonText = f.reason;
    if (f.ai_verdict && f.ai_verdict.verdict) {
        reasonText += ' [AI: ' + f.ai_verdict.verdict + ' ' + Math.round((f.ai_verdict.confidence || 0) * 100) + '%]';
    }
    tdReason.textContent = reasonText;
    tr.appendChild(tdReason);

    // Actions cell
    const tdActions = document.createElement('td');
    tdActions.className = 'action-cell';

    const btnView = document.createElement('button');
    btnView.type = 'button';
    btnView.className = 'btn-view-single';
    btnView.setAttribute('data-finding-id', f.finding_id);
    btnView.setAttribute('data-review-idx', String(f.idx));
    btnView.textContent = t('btn_inspect');
    tdActions.appendChild(btnView);

    const textSpace = document.createTextNode(' ');
    tdActions.appendChild(textSpace);

    const btnDel = document.createElement('button');
    btnDel.type = 'button';
    btnDel.className = 'btn-del-single';
    btnDel.setAttribute('data-finding-id', f.finding_id);
    btnDel.setAttribute('data-raw', f.raw_sha256);
    btnDel.textContent = t('btn_delete');
    if (f.status === 'QUARANTINED' || f.status === 'AI_QUARANTINED') {
        btnDel.disabled = true;
    }
    tdActions.appendChild(btnDel);

    tr.appendChild(tdActions);
    tbody.appendChild(tr);
}

function updateModalProgress() {
    const items = window.REVIEW_ITEMS || [];
    if (!isModalActive || !items.length) return;
    const counterEl = document.getElementById('modalCounter');
    if (counterEl) counterEl.textContent = (currentReviewIndex + 1) + ' / ' + items.length;
    const progressFill = document.getElementById('reviewProgressFill');
    if (progressFill) progressFill.style.width = Math.round(((currentReviewIndex + 1) / items.length) * 100) + '%';
    const btnNextTop = document.getElementById('btnNextTop');
    if (btnNextTop && !decisionsLocked) {
        btnNextTop.disabled = (currentReviewIndex >= items.length - 1);
    }
}

function updateScanUi(data) {
    if (!data) return;

    const elScanned = document.getElementById('statScannedFiles');
    if (elScanned && typeof data.scanned_files === 'number') {
        elScanned.textContent = Number(data.scanned_files).toLocaleString();
    }
    const elDirs = document.getElementById('statScannedDirs');
    if (elDirs && typeof data.scanned_dirs === 'number') {
        elDirs.textContent = Number(data.scanned_dirs).toLocaleString();
    }
    const elBypassed = document.getElementById('statTrustedBypassed');
    if (elBypassed && typeof data.trusted_bypassed === 'number') {
        elBypassed.textContent = Number(data.trusted_bypassed).toLocaleString();
    }
    const elDir = document.getElementById('liveScanDir');
    if (elDir && data.current_dir) {
        elDir.textContent = data.current_dir;
    }

    if (Array.isArray(data.new_findings) && data.new_findings.length > 0) {
        data.new_findings.forEach(function (nf) {
            const exists = (window.REVIEW_ITEMS || []).some(function (it) {
                return it.finding_id === nf.finding_id;
            });
            if (!exists) {
                nf.idx = (window.REVIEW_ITEMS || []).length;
                window.REVIEW_ITEMS.push(nf);
                appendFindingRow(nf);
            }
        });
    }

    const totalThreats = (window.REVIEW_ITEMS || []).filter(function (it) {
        return it.status !== 'TRUSTED_HIDDEN' && it.status !== 'TRUSTED';
    }).length;

    const elInfected = document.getElementById('statInfectedFiles');
    if (elInfected) elInfected.textContent = String(totalThreats);
    const elHeaderCount = document.getElementById('headerInfectedCount');
    if (elHeaderCount) elHeaderCount.textContent = String(totalThreats);

    updateModalProgress();
}

function onScanCompleted(data) {
    const badge = document.getElementById('scanStatusBadge');
    if (badge) {
        badge.className = 'status completed';
        badge.textContent = t('status_completed');
    }
    const banner = document.getElementById('liveScanBanner');
    if (banner) {
        const spinner = banner.querySelector('.live-scan-spinner');
        if (spinner) spinner.style.display = 'none';
        const txt = document.getElementById('liveScanText');
        if (txt) txt.textContent = t('scan_live_completed');
        const toggleBtn = document.getElementById('btnToggleScan');
        if (toggleBtn) toggleBtn.style.display = 'none';
    }
    const totalFiles = (data && typeof data.scanned_files === 'number') ? data.scanned_files : 0;
    showToast(t('scan_live_completed') + ' (' + Number(totalFiles).toLocaleString() + ' ' + t('stat_scanned_files') + ')');
}

function runScanNextStep() {
    if (!scanActive || scanPaused) return;
    postForm({ do_action: 'scan_batch' }).then(function (data) {
        if (data.code === 'AUTH') {
            scanActive = false;
            clearScanTimer();
            alert(t('auto_ai_auth_expired'));
            return;
        }
        if (!data.success) {
            scanConsecutiveErrors++;
            if (scanConsecutiveErrors >= 5) {
                scanActive = false;
                clearScanTimer();
                showToast(t('err_scan_failed'));
                return;
            }
            scanTimer = setTimeout(function () {
                if (scanActive && !scanPaused) runScanNextStep();
            }, 3000);
            return;
        }
        scanConsecutiveErrors = 0;
        updateScanUi(data);

        if (data.is_completed) {
            scanActive = false;
            clearScanTimer();
            onScanCompleted(data);
            return;
        }

        scanTimer = setTimeout(function () {
            if (scanActive && !scanPaused) runScanNextStep();
        }, 100);
    }).catch(function () {
        scanConsecutiveErrors++;
        if (scanConsecutiveErrors >= 5) {
            scanActive = false;
            clearScanTimer();
            return;
        }
        scanTimer = setTimeout(function () {
            if (scanActive && !scanPaused) runScanNextStep();
        }, 3000);
    });
}

function toggleScanPause() {
    scanPaused = !scanPaused;
    const btn = document.getElementById('btnToggleScan');
    const txt = document.getElementById('liveScanText');
    if (scanPaused) {
        clearScanTimer();
        if (btn) btn.textContent = t('scan_btn_resume');
        if (txt) txt.textContent = t('scan_live_paused');
    } else {
        if (btn) btn.textContent = t('scan_btn_pause');
        if (txt) txt.textContent = t('scan_live_scanning');
        runScanNextStep();
    }
}

function bindUi() {
    fillTableText();
    if (window.ZS_BOOT && typeof window.ZS_BOOT.review_cursor === 'number') {
        reviewCursor = window.ZS_BOOT.review_cursor;
    }
    const saved = loadSavedReviewState();
    if (saved && typeof saved.review_cursor === 'number') {
        reviewCursor = Math.max(reviewCursor, saved.review_cursor);
    }
    if (saved && typeof saved.sequential_index === 'number') {
        reviewCursor = Math.max(reviewCursor, saved.sequential_index);
    }
    currentReviewIndex = calculateInitialReviewIndex();
    if (currentReviewIndex < 0) {
        currentReviewIndex = Math.max(0, (window.REVIEW_ITEMS || []).length - 1);
    }
    reviewCursor = Math.max(reviewCursor, currentReviewIndex);
    updateActiveTableRow();

    if (saved && saved.modal_open && (window.REVIEW_ITEMS || []).length > 0) {
        if (saved.is_single_inspect && saved.finding_id) {
            startReviewMode(saved.finding_id, true);
        } else if (saved.is_single_inspect && typeof saved.inspect_index === 'number') {
            startReviewMode(saved.inspect_index, true);
        } else {
            startReviewMode(undefined, false);
        }
    }

    document.querySelectorAll('[data-switch-lang]').forEach(function (btn) {
        btn.addEventListener('click', function () { switchLang(btn.getAttribute('data-switch-lang')); });
    });
    const startReview = document.getElementById('btnStartReview');
    if (startReview) {
        startReview.addEventListener('click', function () {
            startReviewMode(undefined, false);
        });
    }
    const startAuto = document.getElementById('btnStartAuto');
    if (startAuto) startAuto.addEventListener('click', startAutoAiReview);

    const toggleScanBtn = document.getElementById('btnToggleScan');
    if (toggleScanBtn) {
        toggleScanBtn.addEventListener('click', toggleScanPause);
    }
    if (window.ZS_BOOT && window.ZS_BOOT.scan_active) {
        scanActive = true;
        scanPaused = false;
        runScanNextStep();
    }

    const tableBody = document.getElementById('infectedTableBody');
    if (tableBody) {
        tableBody.addEventListener('click', function (e) {
            const viewBtn = e.target.closest('.btn-view-single');
            if (viewBtn) {
                const fid = viewBtn.getAttribute('data-finding-id');
                if (fid) {
                    startReviewMode(fid, true);
                } else {
                    startReviewMode(parseInt(viewBtn.getAttribute('data-review-idx'), 10), true);
                }
                return;
            }
            const delBtn = e.target.closest('.btn-del-single');
            if (delBtn) {
                if (!confirm(t('confirm_delete'))) return;
                const fid = delBtn.getAttribute('data-finding-id');
                const raw = delBtn.getAttribute('data-raw');
                postForm({ do_action: 'delete_single', finding_id: fid, scan_session_id: window.ZS_SESSION_ID, expected_raw: raw }).then(function (data) {
                    showToast(data.message || '');
                    if (data.success) {
                        delBtn.disabled = true;
                        const it = (window.REVIEW_ITEMS || []).find(function (f) { return f.finding_id === fid; });
                        if (it) {
                            it.status = 'QUARANTINED';
                            it.reviewed = true;
                            markItemReviewedInStorage(fid);
                        }
                        if (data && typeof data.review_cursor === 'number') {
                            if (window.ZS_BOOT) window.ZS_BOOT.review_cursor = data.review_cursor;
                            reviewCursor = Math.max(reviewCursor, data.review_cursor);
                            saveReviewState({ review_cursor: reviewCursor });
                        }
                        const statQuar = document.getElementById('statQuarantined');
                        if (statQuar) {
                            const cur = parseInt(statQuar.textContent.replace(/,/g, ''), 10) || 0;
                            statQuar.textContent = String(cur + 1);
                        }
                    }
                });
                return;
            }
            const tr = e.target.closest('tr');
            if (tr && !e.target.closest('button') && !e.target.closest('input') && !e.target.closest('a')) {
                const inspectBtn = tr.querySelector('.btn-view-single');
                if (inspectBtn) {
                    const fid = inspectBtn.getAttribute('data-finding-id');
                    if (fid) {
                        startReviewMode(fid, true);
                    } else {
                        startReviewMode(parseInt(inspectBtn.getAttribute('data-review-idx'), 10), true);
                    }
                }
            }
        });
    }
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
        const keysInput = document.getElementById('set_gemini_api_keys');
        const keysVal = keysInput ? keysInput.value.trim() : '';
        const chkClear = document.getElementById('chkClearKeys');
        const isClear = chkClear && chkClear.checked;
        const newKeyInput = document.getElementById('set_new_access_key');
        const newKeyVal = newKeyInput ? newKeyInput.value.trim() : '';

        const postData = {
            do_action: 'save_settings',
            gemini_api_keys: keysVal,
            gemini_model: document.getElementById('set_gemini_model') ? document.getElementById('set_gemini_model').value : '',
            github_repo: document.getElementById('set_github_repo') ? document.getElementById('set_github_repo').value : '',
            rules_sync_url: document.getElementById('set_rules_sync_url') ? document.getElementById('set_rules_sync_url').value : '',
            clear_gemini_keys: isClear ? '1' : '',
        };
        if (newKeyVal !== '') {
            postData.new_access_key = newKeyVal;
        }

        postForm(postData).then(function (data) {
            if (data && data.success) {
                if (window.ZS_BOOT && typeof data.has_ai !== 'undefined') {
                    window.ZS_BOOT.has_ai = !!data.has_ai;
                }
                window.CONFIG = window.CONFIG || {};
                if (typeof data.has_ai !== 'undefined') {
                    window.CONFIG.has_ai = !!data.has_ai;
                }
                showToast(data.message || t('settings_saved'));
                setTimeout(function () { window.location.reload(); }, 600);
            } else {
                alert((data && data.message) || t('err_ai_failed'));
            }
        }).catch(function (err) {
            alert((err && err.message) || 'Save failed');
        });
    });

    const formKeyModal = document.getElementById('formGeminiKeyModal');
    if (formKeyModal) {
        formKeyModal.addEventListener('submit', saveGeminiKeyModal);
    }

    const keyModalInput = document.getElementById('modal_gemini_api_keys');
    if (keyModalInput) {
        keyModalInput.addEventListener('keydown', function (e) {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                e.preventDefault();
                saveGeminiKeyModal(e);
            }
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
        const keysInput = document.getElementById('set_gemini_api_keys');
        const keysVal = keysInput ? keysInput.value.trim() : '';
        const postData = { do_action: 'test_gemini' };
        if (keysVal !== '') {
            postData.gemini_api_keys = keysVal;
        }
        postForm(postData).then(function (data) { showToast(data.message || JSON.stringify(data)); });
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
