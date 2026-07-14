// ============================================================
// Secret Encrypter — App Logic
// Algorithms: XOR + Base64 (basic) | AES-256-GCM via PBKDF2 (secure)
// ============================================================

document.addEventListener('DOMContentLoaded', () => {

    // ── Encrypt panel ───────────────────────────────────────
    const encryptionKey       = document.getElementById('encryptionKey');
    const toggleKeyVisibility = document.getElementById('toggleKeyVisibility');
    const fileUpload          = document.getElementById('fileUpload');
    const fileNameBadge       = document.getElementById('fileName');
    const encryptInput        = document.getElementById('encryptInput');
    const encryptBtn          = document.getElementById('encryptBtn');
    const encryptOutput       = document.getElementById('encryptOutput');

    // ── Decrypt panel ───────────────────────────────────────
    const decryptionKey          = document.getElementById('decryptionKey');
    const toggleDecKeyVisibility = document.getElementById('toggleDecKeyVisibility');
    const decryptInput           = document.getElementById('decryptInput');
    const decryptBtn             = document.getElementById('decryptBtn');
    const decryptOutput          = document.getElementById('decryptOutput');

    // ── Navbar ──────────────────────────────────────────────
    const textsNavBtn = document.getElementById('textsNavBtn');
    const exportBtn   = document.getElementById('exportBtn');

    // ── Texts Drawer ────────────────────────────────────────
    const textsDrawer          = document.getElementById('textsDrawer');
    const closeDrawerBtn       = document.getElementById('closeDrawer');
    const drawerOverlay        = document.getElementById('drawerOverlay');
    const storedTextsContainer = document.getElementById('storedTextsContainer');
    const textViewer           = document.getElementById('textViewer');
    const closeViewerBtn       = document.getElementById('closeViewer');
    const viewedText           = document.getElementById('viewedText');
    const copyViewerText       = document.getElementById('copyViewerText');
    const wipeAllBtn           = document.getElementById('wipeAllBtn');

    // ── Algorithm selector ──────────────────────────────────
    const algoPills    = document.querySelectorAll('.algo-pill');
    const algoInfo     = document.getElementById('algoInfo');
    const encAlgoBadge = document.getElementById('encAlgoBadge');
    const decAlgoBadge = document.getElementById('decAlgoBadge');
    const dualPanel    = document.querySelector('.dual-panel');

    const STORAGE_KEY = 'encrypted_texts';
    let currentAlgo   = 'xor'; // 'xor' | 'aesgcm'

    const ALGO_META = {
        xor: {
            info:      'Simple XOR cipher with Base64 encoding — fast, casual use only',
            badgeText: 'XOR',
            isAes:     false,
        },
        aesgcm: {
            info:      'AES-256-GCM with PBKDF2 key derivation — strong, authenticated encryption',
            badgeText: 'AES-GCM',
            isAes:     true,
        },
    };

    // ============================================================
    // ALGORITHM SELECTOR
    // ============================================================
    algoPills.forEach(pill => {
        pill.addEventListener('click', () => {
            algoPills.forEach(p => p.classList.remove('active'));
            pill.classList.add('active');
            currentAlgo = pill.dataset.algo;

            const meta = ALGO_META[currentAlgo];

            // Update info text
            if (algoInfo) algoInfo.textContent = meta.info;

            // Update card-header badges
            [encAlgoBadge, decAlgoBadge].forEach(badge => {
                if (!badge) return;
                badge.textContent = meta.badgeText;
                badge.classList.toggle('is-aes', meta.isAes);
            });

            // Toggle CSS class on dual-panel for border highlights
            if (dualPanel) {
                dualPanel.classList.toggle('algo-aesgcm', meta.isAes);
            }

            // Clear stale outputs when switching
            encryptOutput.innerHTML = '';
            decryptOutput.innerHTML = '';
        });
    });

    // ============================================================
    // CIPHER — XOR + Base64 (UTF-8 safe via TextEncoder)
    // ============================================================
    function xorEncrypt(text, key) {
        try {
            const enc   = new TextEncoder();
            const textB = enc.encode(text);
            const keyB  = enc.encode(key);
            const out   = new Uint8Array(textB.length);
            for (let i = 0; i < textB.length; i++) {
                out[i] = textB[i] ^ keyB[i % keyB.length];
            }
            return btoa(Array.from(out, b => String.fromCharCode(b)).join(''));
        } catch { return null; }
    }

    function xorDecrypt(encryptedText, key) {
        try {
            const raw  = atob(encryptedText);
            const keyB = new TextEncoder().encode(key);
            const encB = new Uint8Array(raw.length);
            for (let i = 0; i < raw.length; i++) encB[i] = raw.charCodeAt(i);
            const out = new Uint8Array(encB.length);
            for (let i = 0; i < encB.length; i++) out[i] = encB[i] ^ keyB[i % keyB.length];
            return new TextDecoder().decode(out);
        } catch { return null; }
    }

    // ============================================================
    // CIPHER — AES-256-GCM with PBKDF2 key derivation
    // Format: Base64( salt[16] + iv[12] + ciphertext )
    // ============================================================
    const PBKDF2_ITERATIONS = 100_000;

    async function deriveAESKey(password, salt, usage) {
        const enc         = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw', enc.encode(password),
            { name: 'PBKDF2' }, false, ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            [usage]
        );
    }

    async function aesEncrypt(text, password) {
        try {
            const enc        = new TextEncoder();
            const salt       = crypto.getRandomValues(new Uint8Array(16));
            const iv         = crypto.getRandomValues(new Uint8Array(12));
            const key        = await deriveAESKey(password, salt, 'encrypt');
            const ciphertext = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv }, key, enc.encode(text)
            );
            // Pack: salt(16) + iv(12) + ciphertext
            const combined = new Uint8Array(16 + 12 + ciphertext.byteLength);
            combined.set(salt, 0);
            combined.set(iv, 16);
            combined.set(new Uint8Array(ciphertext), 28);
            return btoa(Array.from(combined, b => String.fromCharCode(b)).join(''));
        } catch { return null; }
    }

    async function aesDecrypt(encryptedText, password) {
        try {
            const combined = Uint8Array.from(atob(encryptedText), c => c.charCodeAt(0));
            if (combined.length < 29) return null; // too short to be valid
            const salt       = combined.slice(0, 16);
            const iv         = combined.slice(16, 28);
            const ciphertext = combined.slice(28);
            const key        = await deriveAESKey(password, salt, 'decrypt');
            const plain      = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv }, key, ciphertext
            );
            return new TextDecoder().decode(plain);
        } catch {
            // AES-GCM throws when key is wrong or data is tampered
            return null;
        }
    }

    // ============================================================
    // HELPERS
    // ============================================================
    function escapeHtml(str) {
        const d = document.createElement('div');
        d.textContent = str;
        return d.innerHTML;
    }

    function setTemporary(btn, tempText, bg, color, ms = 2000) {
        const origHTML = btn.innerHTML;
        const origBg   = btn.style.background;
        const origClr  = btn.style.color;
        btn.textContent      = tempText;
        btn.style.background = bg;
        btn.style.color      = color;
        setTimeout(() => {
            btn.innerHTML        = origHTML;
            btn.style.background = origBg;
            btn.style.color      = origClr;
        }, ms);
    }

    function setLoadingState(btn, loading, label = '') {
        if (loading) {
            btn.classList.add('loading');
            btn.setAttribute('data-orig', btn.innerHTML);
            btn.innerHTML = `<span>${label}</span>`;
        } else {
            btn.classList.remove('loading');
            btn.innerHTML = btn.getAttribute('data-orig') || btn.innerHTML;
        }
    }

    // ── Toggle password visibility ────────────────────────────
    function setupVisibilityToggle(btn, input) {
        if (!btn || !input) return;
        const eyeOpen = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>`;
        const eyeOff  = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>`;
        btn.addEventListener('click', () => {
            const show = input.type === 'password';
            input.type    = show ? 'text' : 'password';
            btn.innerHTML = show ? eyeOff : eyeOpen;
        });
    }

    setupVisibilityToggle(toggleKeyVisibility,    encryptionKey);
    setupVisibilityToggle(toggleDecKeyVisibility, decryptionKey);

    // ============================================================
    // FILE UPLOAD → populate encrypt textarea
    // ============================================================
    if (fileUpload) {
        fileUpload.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (!file) return;
            if (!file.name.toLowerCase().endsWith('.txt')) {
                fileNameBadge.textContent = '⚠ Only .txt files supported';
                fileNameBadge.style.color = '#ff6b6b';
                fileUpload.value = '';
                return;
            }
            fileNameBadge.style.color = '';
            fileNameBadge.textContent = file.name;
            const reader = new FileReader();
            reader.onload  = ev => { encryptInput.value = ev.target.result; encryptInput.focus(); };
            reader.onerror = () => { fileNameBadge.textContent = '⚠ Failed to read file'; fileNameBadge.style.color = '#ff6b6b'; };
            reader.readAsText(file, 'UTF-8');
        });
    }

    // ============================================================
    // VALIDATE INPUTS (shared)
    // ============================================================
    function validateInputs(text, key, outputEl, mode) {
        if (!text) {
            outputEl.innerHTML = `<span class="error">Please enter or upload text to ${mode}.</span>`;
            return false;
        }
        if (!key) {
            outputEl.innerHTML = `<span class="error">Please enter a${mode === 'encrypt' ? 'n encryption' : ' decryption'} key.</span>`;
            return false;
        }
        if (key.length < 4) {
            outputEl.innerHTML = `<span class="error">Key must be at least 4 characters (you entered ${key.length}).</span>`;
            return false;
        }
        return true;
    }

    // ============================================================
    // RENDER OUTPUT
    // ============================================================
    function renderSuccess(outputEl, label, result, showSave) {
        const safe = escapeHtml(result);
        outputEl.innerHTML = `
            <div class="success">
                <strong>${label}</strong>
                <code>${safe}</code>
                <div class="output-actions">
                    <button class="btn-copy" data-result="${safe}">Copy</button>
                    ${showSave ? `<button class="btn-save" data-result="${safe}">Save to Texts</button>` : ''}
                </div>
            </div>`;

        outputEl.querySelector('.btn-copy').addEventListener('click', function () {
            navigator.clipboard.writeText(result).then(() =>
                setTemporary(this, 'Copied!', 'var(--primary-green)', 'var(--bg-dark)'));
        });

        if (showSave) {
            outputEl.querySelector('.btn-save').addEventListener('click', function () {
                const texts = getStoredTexts();
                texts.push(result);
                saveStoredTexts(texts);
                setTemporary(this, 'Saved! ✓', 'var(--primary-green)', 'var(--bg-dark)');
            });
        }
    }

    // ============================================================
    // ENCRYPT BUTTON
    // ============================================================
    if (encryptBtn) {
        encryptBtn.addEventListener('click', async () => {
            const text = encryptInput.value.trim();
            const key  = encryptionKey.value.trim();

            if (!validateInputs(text, key, encryptOutput, 'encrypt')) return;

            let result;

            if (currentAlgo === 'aesgcm') {
                setLoadingState(encryptBtn, true, 'Encrypting…');
                result = await aesEncrypt(text, key);
                setLoadingState(encryptBtn, false);
            } else {
                result = xorEncrypt(text, key);
            }

            if (result) {
                renderSuccess(encryptOutput, 'Encrypted', result, true);
            } else {
                encryptOutput.innerHTML = '<span class="error">Encryption failed. Please try again.</span>';
            }
        });
    }

    // ============================================================
    // DECRYPT BUTTON
    // ============================================================
    if (decryptBtn) {
        decryptBtn.addEventListener('click', async () => {
            const text = decryptInput.value.trim();
            const key  = decryptionKey.value.trim();

            if (!validateInputs(text, key, decryptOutput, 'decrypt')) return;

            let result;

            if (currentAlgo === 'aesgcm') {
                setLoadingState(decryptBtn, true, 'Decrypting…');
                result = await aesDecrypt(text, key);
                setLoadingState(decryptBtn, false);
            } else {
                result = xorDecrypt(text, key);
            }

            if (result !== null) {
                renderSuccess(decryptOutput, 'Decrypted', result, false);
            } else {
                const hint = currentAlgo === 'aesgcm'
                    ? 'AES-GCM: wrong key or corrupted/tampered data.'
                    : 'XOR: check that the encrypted text is valid Base64.';
                decryptOutput.innerHTML = `<span class="error">Decryption failed — ${hint}</span>`;
            }
        });
    }

    // ============================================================
    // LOCAL STORAGE HELPERS
    // ============================================================
    function getStoredTexts() {
        try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]'); }
        catch { return []; }
    }

    function saveStoredTexts(texts) {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(texts));
    }

    // ============================================================
    // TEXTS DRAWER
    // ============================================================
    function openDrawer() {
        renderStoredTexts();
        textsDrawer.classList.add('open');
        textsDrawer.setAttribute('aria-hidden', 'false');
        drawerOverlay.classList.add('visible');
        textsNavBtn.classList.add('active');
        if (textViewer)           textViewer.style.display = 'none';
        if (storedTextsContainer) storedTextsContainer.style.display = 'flex';
    }

    function closeDrawerFn() {
        textsDrawer.classList.remove('open');
        textsDrawer.setAttribute('aria-hidden', 'true');
        drawerOverlay.classList.remove('visible');
        textsNavBtn.classList.remove('active');
    }

    if (textsNavBtn)    textsNavBtn.addEventListener('click',  () =>
        textsDrawer.classList.contains('open') ? closeDrawerFn() : openDrawer());
    if (closeDrawerBtn) closeDrawerBtn.addEventListener('click', closeDrawerFn);
    if (drawerOverlay)  drawerOverlay.addEventListener('click',  closeDrawerFn);

    // ── Render stored texts list ──────────────────────────────
    function renderStoredTexts() {
        const texts = getStoredTexts();
        if (texts.length === 0) {
            storedTextsContainer.innerHTML = '<p class="no-texts-message">No encrypted texts stored yet.</p>';
        } else {
            storedTextsContainer.innerHTML = texts.map((text, i) => `
                <div class="text-card" data-index="${i}">
                    <div class="text-card-preview" onclick="viewStoredText(${i})">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                            <polyline points="14 2 14 8 20 8"></polyline>
                        </svg>
                        <span class="text-preview">${escapeHtml(text.substring(0, 65))}${text.length > 65 ? '…' : ''}</span>
                    </div>
                    <button class="btn-delete" onclick="deleteStoredText(${i})" title="Delete">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="3 6 5 6 21 6"></polyline>
                            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                        </svg>
                    </button>
                </div>`).join('');
        }
    }

    window.viewStoredText = (index) => {
        const texts = getStoredTexts();
        if (!texts[index]) return;
        viewedText.textContent             = texts[index];
        storedTextsContainer.style.display = 'none';
        textViewer.style.display           = 'block';
    };

    window.deleteStoredText = (index) => {
        if (!confirm('Delete this encrypted text? This cannot be undone.')) return;
        const texts = getStoredTexts();
        texts.splice(index, 1);
        saveStoredTexts(texts);
        renderStoredTexts();
    };

    if (closeViewerBtn) {
        closeViewerBtn.addEventListener('click', () => {
            textViewer.style.display           = 'none';
            storedTextsContainer.style.display = 'flex';
        });
    }

    if (copyViewerText) {
        copyViewerText.addEventListener('click', function () {
            navigator.clipboard.writeText(viewedText.textContent).then(() =>
                setTemporary(this, 'Copied!', 'var(--primary-green)', 'var(--bg-dark)'));
        });
    }

    if (wipeAllBtn) {
        wipeAllBtn.addEventListener('click', () => {
            if (!confirm('⚠️ WARNING: Permanently delete ALL stored encrypted texts?')) return;
            localStorage.removeItem(STORAGE_KEY);
            renderStoredTexts();
            if (textViewer) textViewer.style.display = 'none';
            if (storedTextsContainer) storedTextsContainer.style.display = 'flex';
        });
    }

    // ============================================================
    // EXPORT ALL SECRETS → .txt file
    // ============================================================
    if (exportBtn) {
        exportBtn.addEventListener('click', () => {
            const texts = getStoredTexts();
            if (texts.length === 0) {
                alert('No stored secrets to export. Save some encrypted texts first.');
                return;
            }

            const now     = new Date().toLocaleString();
            const divider = '─'.repeat(50);
            const header  = [
                '╔══════════════════════════════════════════════════╗',
                '║        SECRET ENCRYPTER — EXPORTED SECRETS       ║',
                '╚══════════════════════════════════════════════════╝',
                `Exported on  : ${now}`,
                `Algorithm    : ${ALGO_META[currentAlgo].badgeText}`,
                `Total secrets: ${texts.length}`,
                divider, ''
            ].join('\n');

            const body = texts.map((t, i) =>
                `[Secret #${String(i + 1).padStart(2, '0')}]\n${t}\n${divider}\n`
            ).join('\n');

            const blob = new Blob([header + body], { type: 'text/plain;charset=utf-8' });
            const url  = URL.createObjectURL(blob);
            const a    = Object.assign(document.createElement('a'), { href: url, download: `secrets-${Date.now()}.txt` });
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            setTemporary(exportBtn, '✓ Exported!', 'rgba(0,212,255,0.15)', 'var(--accent-cyan)');
        });
    }

});
