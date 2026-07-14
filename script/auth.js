// ============================================================
// Secret Encrypter — Auth Module
// Handles: SHA-256 hashing, session checks, login, logout,
//          live form validation, password reset
// ============================================================

class Auth {
    constructor() {
        this.STORAGE_KEY = 'user_credentials';
    }

    // Hash password using SHA-256
    async hashPassword(password) {
        const data = new TextEncoder().encode(password);
        const hash = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(hash))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    credentialsExist() {
        return localStorage.getItem(this.STORAGE_KEY) !== null;
    }

    async saveCredentials(password) {
        localStorage.setItem(this.STORAGE_KEY, await this.hashPassword(password));
    }

    async verifyPassword(password) {
        const stored = localStorage.getItem(this.STORAGE_KEY);
        return stored !== null && (await this.hashPassword(password)) === stored;
    }

    clearCredentials() {
        localStorage.removeItem(this.STORAGE_KEY);
    }

    // Guard: redirect if not authenticated / already authed
    checkAuth() {
        const path        = window.location.pathname;
        const isLoginPage = path.includes('login.html');

        if (!this.credentialsExist() && !isLoginPage) {
            window.location.href = 'pages/login.html';
        } else if (this.credentialsExist() && isLoginPage) {
            window.location.href = '../index.html';
        }
    }
}

// Singleton
const auth = new Auth();

// ── Run auth guard on every page ──────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    auth.checkAuth();
});

// ============================================================
// LOGIN PAGE
// ============================================================
if (window.location.pathname.includes('login.html')) {
    document.addEventListener('DOMContentLoaded', () => {

        const loginForm            = document.getElementById('loginForm');
        const passwordInput        = document.getElementById('password');
        const confirmPasswordInput = document.getElementById('confirmPassword');
        const confirmPasswordGroup = document.getElementById('confirmPasswordGroup');
        const loginMessage         = document.getElementById('loginMessage');
        const submitBtn            = document.getElementById('submitBtn');
        const errorMessage         = document.getElementById('errorMessage');
        const togglePassword       = document.getElementById('togglePassword');
        const toggleConfirmPassword= document.getElementById('toggleConfirmPassword');
        const resetSection         = document.getElementById('resetSection');
        const resetBtn             = document.getElementById('resetBtn');
        const passwordHint         = document.getElementById('passwordHint');
        const confirmHint          = document.getElementById('confirmHint');

        const isNewUser = !auth.credentialsExist();

        // ── Adapt UI for new vs returning user ────────────────
        if (isNewUser) {
            confirmPasswordGroup.style.display = 'block';
            loginMessage.textContent           = 'Create a password to get started';
            submitBtn.textContent              = 'Create Password';
            resetSection.style.display         = 'none';
        } else {
            loginMessage.textContent   = 'Enter your password to continue';
            submitBtn.textContent      = 'Login';
            resetSection.style.display = 'block';
        }

        // ── Helper: show/hide field hint ──────────────────────
        function setHint(el, msg, type) {
            if (!el) return;
            el.textContent  = msg;
            el.className    = 'field-hint' + (type ? ' field-hint--' + type : '');
        }

        function clearHint(el) {
            if (el) { el.textContent = ''; el.className = 'field-hint'; }
        }

        // ── Live validation — password length ─────────────────
        if (isNewUser && passwordInput && passwordHint) {
            passwordInput.addEventListener('input', () => {
                const len = passwordInput.value.length;
                if (len === 0) {
                    clearHint(passwordHint);
                } else if (len < 6) {
                    setHint(passwordHint,
                        `${len}/6 characters — needs ${6 - len} more`,
                        'error');
                } else {
                    setHint(passwordHint, `✓ Password length OK (${len} chars)`, 'success');
                }
            });
        }

        // ── Live validation — passwords match ─────────────────
        if (isNewUser && confirmPasswordInput && confirmHint) {
            const checkMatch = () => {
                if (!confirmPasswordInput.value) {
                    clearHint(confirmHint);
                    return;
                }
                if (confirmPasswordInput.value === passwordInput.value) {
                    setHint(confirmHint, '✓ Passwords match', 'success');
                } else {
                    setHint(confirmHint, '✗ Passwords do not match', 'error');
                }
            };
            confirmPasswordInput.addEventListener('input', checkMatch);
            passwordInput.addEventListener('input', checkMatch);
        }

        // ── Toggle password visibility ────────────────────────
        function setupEyeToggle(btn, input) {
            if (!btn || !input) return;
            const open = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>`;
            const off  = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>`;
            btn.addEventListener('click', () => {
                const show = input.type === 'password';
                input.type    = show ? 'text' : 'password';
                btn.innerHTML = show ? off : open;
            });
        }

        setupEyeToggle(togglePassword,        passwordInput);
        setupEyeToggle(toggleConfirmPassword, confirmPasswordInput);

        // ── Show error ────────────────────────────────────────
        function showError(msg) {
            errorMessage.textContent = msg;
            // Force reflow to re-trigger shake animation
            errorMessage.style.animation = 'none';
            void errorMessage.offsetWidth;
            errorMessage.style.animation = '';
        }

        function clearError() {
            errorMessage.textContent = '';
        }

        // ── Reset / Forgot password ───────────────────────────
        if (resetBtn) {
            resetBtn.addEventListener('click', () => {
                if (confirm('⚠️ WARNING: This will delete your current password AND all stored encrypted texts. You will need to create a new password. Are you sure?')) {
                    auth.clearCredentials();
                    localStorage.removeItem('encrypted_texts');
                    window.location.reload();
                }
            });
        }

        // ── Form submit ───────────────────────────────────────
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            clearError();

            const password        = passwordInput.value;
            const confirmPassword = confirmPasswordInput ? confirmPasswordInput.value : '';

            if (isNewUser) {
                // ── New user: validate and create password ────
                if (password.length === 0) {
                    showError('Please enter a password.');
                    passwordInput.focus();
                    return;
                }
                if (password.length < 6) {
                    showError(`Password too short — must be at least 6 characters (you entered ${password.length}).`);
                    passwordInput.focus();
                    return;
                }
                if (!confirmPassword) {
                    showError('Please confirm your password.');
                    confirmPasswordInput.focus();
                    return;
                }
                if (password !== confirmPassword) {
                    showError('Passwords do not match. Please re-enter both fields.');
                    confirmPasswordInput.value = '';
                    confirmPasswordInput.focus();
                    clearHint(confirmHint);
                    return;
                }

                await auth.saveCredentials(password);
                window.location.href = '../index.html';

            } else {
                // ── Returning user: verify password ───────────
                if (!password) {
                    showError('Please enter your password.');
                    passwordInput.focus();
                    return;
                }

                submitBtn.textContent = 'Checking…';
                submitBtn.disabled    = true;

                const isValid = await auth.verifyPassword(password);

                submitBtn.textContent = 'Login';
                submitBtn.disabled    = false;

                if (isValid) {
                    window.location.href = '../index.html';
                } else {
                    showError('Incorrect password. Please try again.');
                    passwordInput.value = '';
                    passwordInput.focus();
                }
            }
        });
    });
}

// ============================================================
// HOME PAGE — Logout
// ============================================================
if (window.location.pathname.includes('index.html') ||
    window.location.pathname.endsWith('/')) {
    document.addEventListener('DOMContentLoaded', () => {
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => {
                if (confirm('Are you sure you want to logout?')) {
                    auth.clearCredentials();
                    window.location.href = 'pages/login.html';
                }
            });
        }
    });
}
