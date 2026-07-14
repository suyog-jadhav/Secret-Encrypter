# Secret Encrypter

**Live Demo:** [https://danishsayyad.github.io/Secret-Encrypter/](https://danishsayyad.github.io/Secret-Encrypter/)

A privacy-focused, client-side text encryption and decryption web application. Everything happens locally in your browser — no data ever leaves your device.

---

## Features

### 🔐 Two Encryption Algorithms

| Algorithm | Strength | Description |
|---|---|---|
| **XOR** | Basic | XOR cipher + Base64 encoding. Fast, suitable for casual use |
| **AES-256-GCM** | Secure | Industry-standard authenticated encryption via Web Crypto API. Uses PBKDF2 key derivation with a random salt and IV per message |

Switch between algorithms using the pill selector above the panels. The active algorithm is shown as a badge in each panel header.

> ⚠️ Text encrypted with XOR cannot be decrypted with AES-GCM and vice versa.

### ↔️ Side-by-Side Panels

Encrypt and Decrypt panels are always visible at the same time — no mode toggling needed.

### 📁 File Upload

Upload any `.txt` file directly into the Encrypt panel to encrypt file contents in one click.

### 💾 Stored Texts

Save encrypted outputs for later reference. Accessible via the **Texts** button in the navbar, which opens a slide-in drawer with your saved secrets.

### 📤 Export Secrets

Download all stored encrypted texts as a formatted `.txt` file using the **Export** button in the navbar.

### 🔒 Authentication

- Master password hashed with **SHA-256** via the Web Crypto API
- Stored only in browser `localStorage` — never transmitted
- First-time setup with password confirmation
- Live validation hints (character counter, match indicator) as you type
- Password reset clears all stored data

---

## Screenshots

### Login Page
![Login Page](assets/Screenshots/login.png)

### Main Interface (Dual Panel)
![Encryption Interface](assets/Screenshots/encrypt.png)

### Stored Texts Drawer
![Stored Texts](assets/Screenshots/texts.png)

---

## How to Use

### Encrypting Text
1. Choose an algorithm (**XOR** or **AES-GCM**) from the selector
2. Enter an encryption key (minimum 4 characters — **remember this key!**)
3. Type or paste text, or upload a `.txt` file
4. Click **Encrypt**
5. Copy or **Save to Texts** for later

### Decrypting Text
1. Select the **same algorithm** used during encryption
2. Paste the encrypted text into the Decrypt panel
3. Enter the **same key** used to encrypt
4. Click **Decrypt**

### Managing Stored Texts
- Click **Texts** in the navbar to open the drawer
- Click any entry to view the full encrypted text
- Delete individual entries or **Wipe All**
- Click **Export** in the navbar to download all secrets as a `.txt` file

---

## Security Notes

| Topic | Detail |
|---|---|
| **Master password** | Hashed with SHA-256. There is no recovery mechanism — do not forget it |
| **Encryption keys** | Keys are **never stored**. You must remember the key used for each text |
| **AES-GCM** | Authenticated encryption — decryption will fail cleanly if the key is wrong or data is tampered with |
| **XOR cipher** | Suitable for casual obfuscation, not for sensitive data |
| **Local storage** | All data is in browser local storage. Clearing browser data deletes everything |
| **No network** | Works fully offline after initial load. Zero server communication |

---

## Technology Stack

| Layer | Technology |
|---|---|
| Structure | HTML5 (semantic) |
| Styling | Vanilla CSS3 — Inter font, dark theme, glassmorphism |
| Logic | Vanilla JavaScript (ES2020+) |
| Encryption | Web Crypto API — AES-256-GCM, PBKDF2, SHA-256 |
| Storage | Browser `localStorage` |
| Build | None — zero build step, open the file and it works |

---

## Browser Compatibility

Requires Web Crypto API support (available in all modern browsers):

- Chrome / Edge 60+
- Firefox 57+
- Safari 11+
- Opera 47+

---

## Project Structure

```
Secret-Encrypter/
├── index.html              # Main app — dual-panel encrypt/decrypt
├── assets/
│   ├── icon.svg
│   ├── icon-small.svg      # Favicon
│   └── Screenshots/
├── pages/
│   ├── login.html          # Auth page (setup + login)
│   └── about.html          # About page
├── script/
│   ├── app.js              # Cipher logic, file upload, export, drawer
│   └── auth.js             # Auth class, session guard, live validation
└── style/
    ├── main.css            # Home page styles
    ├── auth.css            # Login page styles
    └── about.css           # About page styles
```

---

## Privacy Policy

Secret Encrypter is committed to your privacy:

- Does **not** collect any personal information
- Does **not** transmit any data to external servers
- Does **not** use cookies or tracking
- Does **not** require an internet connection after initial load
- All processing happens entirely in your browser

---


## Developer

**Danish Sayyad** — [GitHub](https://github.com/DanishSayyad)

## License

MIT License — open source and free to use.

---

> **Remember:** For highly sensitive information, use enterprise-grade encryption solutions with proper key management.
