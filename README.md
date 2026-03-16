# CIPHER//NET

A self-hosted, single-page end-to-end encrypted chat application. No accounts, no servers, no tracking — just cryptographic keypairs, signed messages, and post-quantum encryption.

Built to run on [OnionShare](https://onionshare.org/), installable as a PWA, and deployable to any static web host.

---

## Features

### Identity & Authentication
- **Keypair identity** — your account is a cryptographic keypair generated entirely in your browser. No email, no password, no server.
- **Private key shown once** — your signing private key is displayed at registration and immediately discarded from memory. It is never stored anywhere.
- **Lock screen gate** — the entire chat UI is hidden until you authenticate with a valid keypair. Nothing is accessible without a key.
- **Returning user detection** — if a fingerprint is found in localStorage, the import tab opens automatically with your handle pre-filled.
- **Password-protected key export** — optionally encrypt your private key before copying. AES-256-GCM, PBKDF2-SHA-256, 300,000 iterations. Stored as `CIPHER-ENC:v1:...` — useless without the password. Import tab detects encrypted keys automatically.

### Encryption
- **Channel encryption** — all channel messages encrypted with AES-256-GCM. A shared passphrase is required to read or send. Key derived via PBKDF2 (200,000 iterations, SHA-256) with a deterministic per-channel salt.
- **Post-quantum DM encryption** — DMs use ML-KEM-768 (FIPS 203) key encapsulation by default. Alice encapsulates to Bob's public key, Bob decapsulates — no shared secret is ever transmitted. Shared secret fed through HKDF-SHA256 → AES-256-GCM.
- **Classical DM encryption** — ECDH P-256 key exchange for classical-mode users. Both parties independently derive the same AES-256-GCM key.
- **Message signing** — every message is signed with your private key and verified on receipt. Displays ✓ SIGNED or ✗ INVALID. Default: ML-DSA-65 (FIPS 204). Classical: ECDSA P-256/P-384 or RSA-PSS 2048.
- **Messages locked without key** — history without the passphrase shows `[encrypted — key required to read]`. Wrong passphrase shows `[decryption failed]`.

### Post-Quantum Cryptography
- **ML-DSA-65** (FIPS 204) — default signing algorithm. Quantum-resistant. ~AES-192 security level. Keys exported as `PQ-SK:<base64>`.
- **ML-KEM-768** (FIPS 203) — default DM key encapsulation. Quantum-resistant. ~AES-192 security level.
- Loaded automatically from [esm.sh](https://esm.sh) CDN via `@noble/post-quantum`. No local file required for online deployments.
- Classical algorithms (ECDSA, RSA-PSS) still available and fully supported for import of older keys.

### PGP / GPG / Kleopatra
- **Export PGP keypair** — generate an RSA-4096 OpenPGP keypair tied to your handle. Export `.asc` files importable directly into GPG or Kleopatra. Optional passphrase protection.
- **Import existing GPG key** — paste any armored GPG private key (RSA, ECC, protected or unprotected).
- **Encrypt & decrypt messages** — PGP-encrypt for any recipient (paste their public key), signed with your key. Decrypt with signature verification. Fully interoperable with GPG, Kleopatra, Thunderbird.
- Requires `openpgp.min.js` — see `GET_OPENPGP.md`.

### Privacy Deterrents
- **No text selection** — chat content cannot be selected or copied.
- **Right-click blocked** — context menu suppressed on the entire page.
- **Screen blanking** — screen goes black when the window loses focus (alt-tab, switching apps). Returns instantly on refocus.
- **PrintScreen warning** — `// SCREENSHOT DETECTED` overlay on Print Screen. Note: OS-level screenshots cannot be blocked — this is a deterrent only.
- **Keyboard shortcuts suppressed** — Ctrl+S, Ctrl+U, Ctrl+P, F12 blocked.

### Identity Management
- **Export public identity** — share your handle, public signing key, and DM public key as JSON. Safe to distribute.
- **Export full backup** — all encrypted message history, public keys, and DM threads as JSON. Private key never included.
- **Import / restore** — drag and drop a backup or identity file, then paste your private key. Works across devices.
- **DM key persistence** — signing and DM keys stored encrypted in localStorage (PBKDF2-wrapped AES-GCM) and restored automatically on import.

### Progressive Web App
- Installable to home screen on Android (Chrome) and iOS (Safari).
- Runs fullscreen with no browser chrome.
- Service worker caches all assets — works fully offline after first load.
- Safe area insets for notched phones.

---

## Files

```
index.html           — markup only, no inline scripts or styles
app.css              — all styles
app.js               — all application logic and crypto
sw.js                — service worker: offline caching
manifest.json        — PWA manifest: name, icons, display mode
icon-192.png         — home screen icon (192×192)
icon-512.png         — high-res icon / splash screen (512×512)
embed-fonts.py       — optional: bakes fonts as base64 for fully offline use
openpgp.min.js       — OpenPGP.js v5 (download separately — see GET_OPENPGP.md)
GET_OPENPGP.md       — download instructions for openpgp.min.js
README.md            — this file
landing.html         — GitHub Pages landing page (rename to index.html in repo root)
```

> **Post-quantum library** (`@noble/post-quantum`) loads automatically from esm.sh CDN — no local file required for online deployments. For offline/OnionShare use, see `GET_OPENPGP.md`.

---

## Hosting on OnionShare

1. Open OnionShare → **Publish website**
2. Add `index.html`, `app.css`, `app.js`, and `openpgp.min.js`
3. Start — share the `.onion` address

No Python, no Node, no configuration. Zero external requests. Fully compliant with OnionShare's strict Content Security Policy (`default-src 'self'`).

> **Note:** Post-quantum crypto requires internet access to load from esm.sh CDN. On OnionShare/offline, select a classical algorithm (ECDSA P-256, P-384, or RSA-PSS) instead.

> Use **Publish website** mode, not "Serve files".

---

## Hosting elsewhere

Any static file server works: GitHub Pages, Nginx, Caddy, Apache, `python3 -m http.server`.

> **Web Crypto API requires HTTPS, localhost, or a .onion address.** Plain HTTP will not work.

---

## Installing as PWA

### Android
1. Open in Chrome → three-dot menu → **Add to Home screen**

### iPhone / iPad
1. Open in **Safari** → Share → **Add to Home Screen**
> Chrome on iOS cannot install PWAs.

### Desktop
Chrome and Edge show an install icon (⊕) in the address bar. Click to install.

---

## Embedding fonts (optional)

By default the app uses a system monospace font stack. To embed [Share Tech Mono](https://fonts.google.com/specimen/Share+Tech+Mono) and [VT323](https://fonts.google.com/specimen/VT323) as base64 for fully offline/consistent use:

```bash
python3 embed-fonts.py
```

Makes a one-time request from your machine to Google Fonts, then splices the fonts into `app.css`. After that, zero network requests.

---

## Cryptographic architecture

### Signing algorithms

| Algorithm | Security | Quantum-resistant | Format | Notes |
|---|---|---|---|---|
| **ML-DSA-65** | ~AES-192 | ✅ FIPS 204 | `PQ-SK:<base64>` | **Default** |
| ECDSA P-256 | 128-bit | ❌ | PKCS#8 PEM | Classical |
| ECDSA P-384 | 192-bit | ❌ | PKCS#8 PEM | Classical |
| RSA-PSS 2048 | ~112-bit | ❌ | PKCS#8 PEM | Classical |

### DM key exchange

| Mode | Algorithm | Security | Quantum-resistant |
|---|---|---|---|
| **Default** | ML-KEM-768 (FIPS 203) | ~AES-192 | ✅ |
| Classical | ECDH P-256 | 128-bit | ❌ |

### Channel encryption

PBKDF2-SHA-256 (200,000 iterations) derives an AES-256-GCM key from a shared passphrase. Salt: `SHA-256("cipher-channel:<channel>")`. Each message has a fresh random 12-byte IV. The entire signed envelope is encrypted — only the author hint (6 hex chars of fingerprint) is stored in plaintext.

### Password-protected key export

`CIPHER-ENC:v1:<base64(16-byte-salt + 12-byte-iv + ciphertext)>`

PBKDF2-SHA-256, 300,000 iterations → AES-256-GCM. The app detects the prefix on paste and shows the password field automatically. Works for both classical (PEM) and PQ (`PQ-SK:`) keys.

### Post-quantum key sizes

| | ML-DSA-65 | ECDSA P-256 |
|---|---|---|
| Secret key | 4,032 bytes | 32 bytes |
| Public key | 1,952 bytes | 64 bytes |
| Signature | 3,309 bytes | 64 bytes |

| | ML-KEM-768 | ECDH P-256 |
|---|---|---|
| Public key | 1,184 bytes | 64 bytes |
| Secret key | 2,400 bytes | 32 bytes |
| Ciphertext | 1,088 bytes | 64 bytes |

Larger keys are inherent to lattice-based PQ cryptography — this is expected.

### Security model

| Property | Status |
|---|---|
| Channel encryption | ✓ AES-256-GCM · PBKDF2-SHA-256 · 200k iterations |
| DM encryption (default) | ✓ ML-KEM-768 + HKDF + AES-256-GCM · quantum-resistant |
| DM encryption (classical) | ✓ ECDH P-256 + AES-256-GCM |
| Message signing (default) | ✓ ML-DSA-65 · FIPS 204 · quantum-resistant |
| Message signing (classical) | ✓ ECDSA P-256/P-384 or RSA-PSS 2048 |
| Private signing key storage | ✗ Never stored — shown once, then discarded |
| DM key storage | ✓ Encrypted in localStorage (PBKDF2-wrapped AES-GCM) |
| Password-protected export | ✓ AES-256-GCM · PBKDF2-SHA-256 · 300k iterations |
| PGP interoperability | ✓ OpenPGP.js v5 · RSA-4096 · GPG/Kleopatra compatible |
| Quantum resistance | ✓ ML-DSA-65 + ML-KEM-768 (NIST FIPS 203/204) |
| Transport security | Depends on host — use HTTPS or .onion |
| Anonymity | Depends on host — use OnionShare + Tor Browser |
| Screenshot prevention | ⚠ Deterrents only — OS capture cannot be blocked |
| Offline capability | ✓ Service worker caches all assets after first load |

---

## Recovering your identity

**Signing back in (same device):**
1. Go to the **Import Key** tab
2. Paste your signing private key — PEM for classical, `PQ-SK:...` for post-quantum
3. If password-protected, enter your export password — the field appears automatically
4. Your fingerprint, DM key, and message history restore from localStorage

**Moving to another device:**
1. Export a **Full Backup** from the sidebar
2. On the new device, drop the backup JSON onto the Import tab
3. Paste your private signing key (and password if set)
4. All history, user records, and DM threads are restored

---

## Browser support

Requires Web Crypto API: Firefox, Chrome, Brave, Safari, Tor Browser.

- **Tor Browser:** Security level must be **Standard** or **Safer**. Safest disables JavaScript.
- **Firefox:** Key import uses a JWK round-trip for full compatibility across all key types.
- **Extensions:** Wallet extensions running SES lockdown (e.g. MetaMask) may interfere. Disable on the page if crypto operations fail.
- **Post-quantum:** Loads from esm.sh CDN — requires internet. Classical algorithms work fully offline.

---

## PGP / GPG / Kleopatra

Requires `openpgp.min.js` — see `GET_OPENPGP.md` for download instructions. The sidebar shows four PGP buttons once signed in:

**PGP EXPORT KEYPAIR** — generates RSA-4096 OpenPGP keypair. Optional UID and passphrase. Downloads `public.asc` and `secret.asc`.
- Kleopatra: File → Import → `secret.asc`
- GPG: `gpg --import secret.asc`

**PGP IMPORT GPG KEY** — paste any `-----BEGIN PGP PRIVATE KEY BLOCK-----` armored key. Supports RSA, ECC, passphrase-protected.

**PGP ENCRYPT MSG** — paste recipient's public key, type message, click ENCRYPT & SIGN. Output is a standard PGP message block decryptable by any OpenPGP client.

**PGP DECRYPT MSG** — paste any PGP message encrypted to your key. Optionally paste sender's public key for signature verification (✓/✗).

---

## localStorage schema

| Key | Contents |
|---|---|
| `cipher_users` | Public key registry: handle, public key, fingerprint, algo, DM public key |
| `cipher_msgs_<channel>` | Up to 200 encrypted messages per channel |
| `cipher_dm_<fpA>_<fpB>` | DM thread (fingerprints sorted, order-independent) |
| `cipher_dh_<fingerprint>` | ECDH private key — classical DM encryption (AES-GCM wrapped) |
| `cipher_pqkem_<fingerprint>` | ML-KEM-768 secret key — PQ DM encryption (AES-GCM wrapped) |
| `cipher_my_fingerprint` | Last authenticated fingerprint (for returning user detection) |

All message content is stored as ciphertext. Public keys and fingerprints are in plaintext.

---


