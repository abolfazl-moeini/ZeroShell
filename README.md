# ZeroShell — WordPress malware scanner & reviewer

A drop-in PHP 7.4+ tool for **finding and reviewing suspicious PHP-like files** on a compromised WordPress (or generic PHP) host. It is not a guarantee that a site is clean.

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

Manual review and auto-review work without an API key. To enable Gemini:

1. Create a key in Google AI Studio
2. Paste it in Settings (or set `GEMINI_API_KEY` / `GEMINI_API_KEYS`)
3. Default model: `gemini-2.5-flash` (changeable). Confirm the id against [Google’s model list](https://ai.google.dev/gemini-api/docs/models) before a release; ids are retired.
4. Snippets (redacted) are sent to Google. Confirm the prompt in the UI first.

Rate limits are per Google project, not “N keys = N× quota.”

## Quarantine & restore

Quarantine copies the file into an envelope, verifies the hash, then unlinks the original. Restore writes back only if the destination does not already exist and the backup hash still matches. Keep the data directory; deleting it drops backups.

## CLI

```bash
php malware-cleaner.php
php malware-cleaner.php --reset
```

Reset is a new scan session only. It does not delete quarantine, config, or the trusted list.

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
