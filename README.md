# ZeroShell — WordPress Malware Scanner & Reviewer

[English](README.md) | [فارسی (Persian)](README_FA.md)

A drop-in, single-file PHP 7.4+ security tool for **finding, reviewing, and safely cleaning suspicious PHP files and webshells** on compromised WordPress sites or generic PHP directories. ZeroShell operates independently without loading WordPress, requires no Composer, database, Node, or external dependencies, and is designed to run directly in your **web browser** on restricted shared hosting (as well as via CLI).

> [!NOTE]
> No malware scanner can guarantee that a site is clean. ZeroShell is a focused review and cleanup assistant, not an absolute guarantee.

---

## ⚡ Quick Start / TL;DR (Browser & Shared Hosting)

The primary and recommended way to use ZeroShell on shared hosts (cPanel, DirectAdmin, Plesk, LiteSpeed, Apache, Nginx):

### 1. Upload & Claim Host Ownership
1. Upload **`malware-cleaner.php`** (available in the repository root or under `dist/`) into your site root directory (e.g., `public_html/`).
2. Create a new text file named **`zs-setup.secret`** in that same directory and write a short random token inside it (e.g., `mysecret123`).
   *(This step proves you have write access to the host, preventing unauthorized visitors from claiming the cleaner).*

### 2. Initial Setup in Browser
3. Open your browser and navigate to:
   ```text
   https://your-domain.com/malware-cleaner.php
   ```
4. In the **Setup secret** field, enter the token you placed in `zs-setup.secret`.
5. Enter a custom **Security Key** (min 12 characters) or save the auto-generated key shown on screen.
6. Click **Save Key & Launch Scanner**. ZeroShell saves protected configuration and automatically removes `zs-setup.secret` from the server.

### 3. Scan & Interactive Review
7. Scanning starts automatically in your browser in small batches (max 500 files or 5 seconds each) with automatic refreshes, avoiding shared-host execution timeouts.
8. When scanning finishes, the interactive findings dashboard is displayed:
   - **View Source**: Inspect file contents safely as plain text (read-only, never executed).
   - **Quarantine**: Securely backs up the infected file to a protected directory outside web access, verifies SHA-256 byte integrity, and removes the original.
   - **Mark Clean**: Marks false positives as safe. Two independent confirmations across sessions or paths promote the file's raw checksum to permanent whitelist trust.
   - **Ask AI** (Optional): Request an advisory second opinion from Google Gemini.
   - **Auto-Review** (Optional): Automatically analyzes eligible findings with AI and quarantines high-confidence threats (confidence ≥ 0.85).

### 4. Adding Gemini API Key (Optional AI Second Opinion)
> [!IMPORTANT]
> **Never commit your API key to Git!** Keep your repository clean. Add your key after deployment using either:
> 1. **In Browser (Recommended)**: Click **Settings** in the top bar ➔ paste your key from [Google AI Studio](https://aistudio.google.com/) into **Google Gemini API Keys** ➔ click **Save Settings**. *(You can paste multiple keys, one per line, for automatic failover pooling).*
> 2. **Via `.htaccess` or Environment**: Add the following line to your site's `.htaccess` file on the server:
>    ```apache
>    SetEnv GEMINI_API_KEY "AIzaSy..."
>    ```

### 5. Subsequent Logins & Key Recovery
- **Logging back in**: When returning to `malware-cleaner.php`, enter your Security Key on the login card (`Access Denied`), or visit `https://your-domain.com/malware-cleaner.php?key=YOUR_SECURITY_KEY`.
- **Forgot your key?**: In your hosting File Manager or FTP, navigate to `malware_cleaner_data/` (or the sibling `.zsdata_*` directory outside `public_html`) and delete `config.php`. Re-create `zs-setup.secret` and refresh the page to set a new key.
- **Done cleaning?**: Delete `malware-cleaner.php` from your server once finished. Quarantined backups remain safely preserved in the data directory.

---

## What you install

One file: `malware-cleaner.php` (also published as `dist/malware-cleaner.php`). No Composer, no Phar, no `src/` tree required at runtime.

Runtime still needs a **writable data directory** for config, scan session, knowledge, and quarantine. That is separate from the single install file. Do not expect the scanner to store state inside itself.

## What it scans (v1)

- Extensions: `php`, `phtml`, `php3`–`php8`, `phar`, `suspected`, `bak`, and names containing `.php`
- Not scanned: JavaScript, HTML, `.htaccess`, `.user.ini`, the database, media binaries
- Directory traversal does not follow symlinks and stays inside the site root
- Work is split into batches of at most **500 files or 5 seconds** per request (or CLI `--one-batch`) so shared-host timeouts are less likely. This is **not** “zero timeout” and not “the whole site in under a minute.”

No findings ≠ a clean site. The UI states that explicitly.

## Security model

- First-run setup requires a **setup secret** in `zs-setup.secret` next to the script, or env `ZS_SETUP_SECRET`. Whoever can write that file can claim the scanner.
- Access key is hashed. Sessions use HttpOnly cookies (`SameSite=Lax`). Mutating actions need CSRF.
- Quarantine lives under the data directory (outside the web root when the parent of the site is writable). Samples are stored in a PHP envelope that exits 403 if requested over HTTP; they are not `include`d.
- Restore refuses to overwrite an existing file and refuses symlink/parent escapes.
- Trust, AI cache, and delete decisions are bound to the **raw SHA-256** of the bytes on disk. A file that changes after scan is not deleted from an old cache entry.
- Gemini output is **advisory**. Automatic quarantine happens only for a valid JSON verdict, `malicious`, confidence in `[0, 1]` ≥ 0.85, `recommended_action=quarantine`, **full** file coverage, and a matching raw hash. Partial reads and uncertain/error results are skipped.
- Stored API keys are never echoed back into HTML. Leave the key field empty to keep the current key.

## AI (optional)

Manual review works without an API key. To enable Gemini second opinions and auto-review:

1. Create a free key in [Google AI Studio](https://aistudio.google.com/)
2. Paste it in Settings (or set `GEMINI_API_KEY` / `GEMINI_API_KEYS`)
3. Default model: `gemini-2.5-flash` (changeable).
4. Code snippets (redacted for credentials) are sent to Google.

Rate limits are per Google project, not “N keys = N× quota.”

## Quarantine & restore

Quarantine copies the file into an envelope, verifies the hash, then unlinks the original. Restore writes back only if the destination does not already exist and the backup hash still matches. Keep the data directory; deleting it drops backups.

## CLI

```bash
# Full scan from command line
php malware-cleaner.php

# Reset scan session (keeps knowledge, whitelist, and quarantine intact)
php malware-cleaner.php --reset

# Run exactly one batch (ideal for shared host cron jobs)
php malware-cleaner.php --one-batch
```

## Development

```bash
php tests/run.php
php bin/build.php
```

`bin/build.php` writes a temp file, runs `php -l`, then replaces `dist/malware-cleaner.php` and `malware-cleaner.php`. A lint failure leaves the previous artifacts in place.

Do not commit API keys, `zs-setup.secret`, `malware_cleaner_data/`, `.zsdata_*`, quarantine trees, or live malware samples.

## Limits you should assume

- Signature hits can be wrong (noisy tokens are labelled suspicious).
- AI can be wrong. Treat it as a second opinion.
- Files the scanner never opened cannot be classified.
- PHP 7.4 compatibility is a source constraint; run tests on 7.4 in CI before calling a release supported.

License: MIT.
