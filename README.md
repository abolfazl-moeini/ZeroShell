# ZeroShell — WordPress Malware Scanner & Cleaner

[![PHP Version](https://img.shields.io/badge/PHP-7.4%20to%208.3%2B-777bb4?logo=php&logoColor=white)](https://php.net)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Standalone)-blue.svg)](#)
[![Format](https://img.shields.io/badge/Format-Single--File%20PHP-orange.svg)](#)
[![AI Supported](https://img.shields.io/badge/AI-Google%20Gemini%20Flash-4285F4?logo=google&logoColor=white)](#)

> **ZeroShell** is a lightning-fast, zero-timeout, standalone malware cleaner and sequential code reviewer for WordPress and PHP environments. Packaged as a **solitary drop-in PHP file** (`malware-cleaner.php`), it requires **no Composer, no Phar, and zero server dependencies**. Even if your WordPress site is showing the White Screen of Death (WSOD) or has broken core files, ZeroShell runs independently to detect, isolate, and eradicate web shells, backdoors, and SEO injection trojans.

---

## ⚡ TL;DR — 30-Second Quick Start

Get your site cleaned in under a minute without installing anything:

### 1. Download & Deploy

#### Option A: Server Terminal (SSH)
```bash
# Navigate to your WordPress root (next to wp-config.php)
cd /path/to/wordpress

# Download the solitary cleaner script
curl -O https://raw.githubusercontent.com/OWNER/REPO/main/malware-cleaner.php
# or: wget https://raw.githubusercontent.com/OWNER/REPO/main/malware-cleaner.php
```

#### Option B: cPanel / FTP
Download [`malware-cleaner.php`](malware-cleaner.php) and upload it directly into your WordPress root directory.

---

### 2. Run the Cleaner

#### Via Web Browser
1. Visit `https://your-site.com/malware-cleaner.php`.
2. Follow the 1-step **Setup Wizard** to generate or set your private 32-character access key.
3. The scanner immediately sweeps the filesystem in non-blocking 5-second micro-batches.
4. Review suspicious files with keyboard hotkeys (`D` delete, `B` whitelist, `A` ask AI) or click **⚡ Auto AI Review**.

#### Via Server CLI
```bash
# Start deep scan in terminal
php malware-cleaner.php

# Or reset an existing session and scan from scratch
php malware-cleaner.php --reset
```

---

## 🛡️ Why ZeroShell?

Most security plugins (Wordfence, Sucuri) fail when you need them most:
- **Timeouts & Memory Exhaustion:** On LiteSpeed, Nginx, or shared hosting, long scans trigger HTTP 504 Gateway Timeouts or hit `max_execution_time`.
- **WordPress Boot Dependency:** If an attacker injected code into `wp-config.php` or `wp-settings.php`, the WordPress framework won't boot, rendering standard security plugins inaccessible.
- **Polymorphic Evasion:** Modern backdoors (such as Nirmala and Hesperion) pad comments with random hashes and variable names on every injection to evade naive checksum scanners.

**ZeroShell solves all three:**
- **Zero-Timeout Architecture:** Work is chopped into 5-second / 500-file micro-batches that automatically self-resume using HTTP meta-refreshes or CLI recursive execution.
- **Pure Standalone Execution:** Zero reliance on database connections or WordPress core files.
- **Normalized Checksum Engine:** Heuristically strips polymorphic padding before calculating SHA-256 hashes to reliably hunt self-mutating shells.

---

## ✨ Key Capabilities

### 1. 🗄️ Antivirus-Style Rule Database (SOLID / OCP)
- Signatures, hashes, structural heuristics, and path rules are declaratively decoupled into `rules/database.json`.
- **Open for Extension, Closed for Modification:** Add new malware definitions without modifying a single line of PHP scanner code.
- **1-Click Online Sync:** Tap **"Sync Rules from GitHub"** in the Settings toolbar to update your scanner with the community's latest threat signatures over HTTPS.

### 2. 🤖 Google Gemini Flash AI Integration
- **Interactive Ask AI:** Press `A` in the manual review modal to have Google Gemini Flash audit the suspicious code.
- **Automated AI Review:** Click **"⚡ Start Auto AI Review"** to stream batch analysis across all detected threats. Malicious files with confidence >= 85% are automatically quarantined.
- **Multi-Token Pooling & Automatic Failover:** Add multiple Google AI Studio API keys. If a key hits Google's free-tier rate limit (`HTTP 429`), ZeroShell puts it on a 60-second cooldown and instantly fails over to the next key, scaling throughput linearly (e.g. 3 keys = 45 requests/min).
- **Persistent Versioned Cache:** Checksums and analysis verdicts are cached permanently. Rescans never waste API calls or quota on previously analyzed files.
- **Privacy First (Secret Redaction):** Database passwords (`DB_PASSWORD`), WordPress salts (`AUTH_KEY`, `NONCE_KEY`), and server absolute filesystem paths are automatically scrubbed (`[REDACTED]`) before snippets leave your server.

### 3. 🧠 Two-Strike Benign Memory
- **Eliminates False Positives:** Pressing `B` marks an ambiguous file as legitimate (Strike 1 candidate). If a second file sharing that normalized checksum is marked legitimate (or confirmed in a later session), it is promoted to the permanent **Trusted Whitelist**.
- **Accidental Skip Protection:** Skipping a file with `N` or `Space` keeps the file but does **not** whitelist it.
- **Conflict Handling:** If a Strike 1 candidate is later identified as malicious by Gemini or quarantined by the user, candidate status is instantly revoked.
- **Trust Management:** Inspect or revoke trusted whitelists at any time in the Settings tab.

### 4. 📦 Safe Quarantine & 1-Click Rollback
- Zero blind file deletions. Every removed file is copied to an isolated directory (`wp-content/malware_quarantine/` or data folder) with `.htaccess` and `index.php` 403 blocks.
- If a legitimate file was quarantined by accident, restore it back to its original location with a single click.
- Critical core files (`wp-config.php`, the scanner script itself, and files outside root jail) are strictly protected against deletion.

### 5. 🌐 Bilingual UI with Full RTL Support
- Built-in internationalization (`en` default, `fa` Persian).
- Full Right-to-Left (RTL) layout with tailored typography.
- Persists user language preference via `localStorage` and secure cookies.

### 6. 🤝 Community Threat Sharing CTA
- Once cleaning finishes, an anonymized threat card lets administrators submit sanitized malware signatures to the upstream GitHub repository.
- Automatic clipboard fallback avoids browser `HTTP 414 Request-URI Too Large` errors when generating GitHub issues.
- One-click anonymized JSON bundle download for manual inspection or security research.

---

## ⌨️ Review Modal Keyboard Shortcuts

Fly through hundreds of suspicious files in minutes without touching your mouse:

| Key | Action | Description |
|:---:|:---|:---|
| <kbd>D</kbd> / <kbd>Delete</kbd> | **Quarantine & Next** | Backs up file to quarantine, unlinks original, and loads next item |
| <kbd>N</kbd> / <kbd>Space</kbd> / <kbd>→</kbd> | **Skip / Keep** | Keeps file as-is and advances without modifying whitelist |
| <kbd>P</kbd> / <kbd>←</kbd> | **Previous** | Returns to previously reviewed item in queue |
| <kbd>B</kbd> | **Mark Legitimate** | Registers a strike toward permanent whitelist promotion |
| <kbd>A</kbd> | **Ask Gemini AI** | Queries Google Gemini Flash for immediate threat verdict |
| <kbd>C</kbd> | **Copy Code** | Copies complete file source to system clipboard |
| <kbd>Esc</kbd> | **Close Modal** | Closes review window and returns to results table |

---

## ⚙️ Configuration & Architecture

ZeroShell separates transient scan state from durable threat intelligence so that restarting a scan never loses your learned whitelists or AI cache:

```
$data_dir/
├── config.php                      # Password hash, Gemini key pool, sync URL
├── rules_override.json             # Synced or locally dropped rule definitions
├── malware_scan_session.json       # Volatile scan queue & counters (wiped on reset)
├── malware_cleaner_knowledge.json  # Persistent whitelist, candidates & AI cache (retained forever)
└── quarantine/                     # Isolated backups named md5(path)_basename
```

### Environment Variables (Optional)
You can configure ZeroShell via your server environment or web server config:
- `GEMINI_API_KEY` or `GEMINI_API_KEYS`: Comma-separated Google AI Studio keys.
- `MALWARE_CLEANER_DATA_DIR`: Custom path for state storage (recommended outside web root).
- `REPORT_ENDPOINT`: Custom HTTPS endpoint for automated maintainer reporting.

---

## 🛠️ Development & Building

The repository source code is structured as clean, single-responsibility classes in `src/`. The production release is compiled into a solitary, standalone file using the internal bundler.

### Project Layout
```text
ZeroShell/
├── bin/build.php            # Standalone PHP concatenator & inliner
├── rules/database.json      # Declarative virus rules (OCP surface)
├── src/
│   ├── bootstrap.php        # Entrypoint (CLI vs Web SAPI router)
│   ├── Config.php           # ZS_Config (Jail security, token pool, paths)
│   ├── I18n.php             # ZS_I18n (Translations & RTL handler)
│   ├── Store.php            # ZS_Store (Session, knowledge & flock manager)
│   ├── Hash.php             # ZS_Hash (Raw & normalized SHA-256)
│   ├── Quarantine.php       # ZS_Quarantine (Backup, jail & rollback)
│   ├── Engine.php           # ZS_Engine (Heuristics & rule evaluation)
│   ├── Rules.php            # ZS_Rules (Bundled fallback & dynamic loader)
│   ├── Gemini.php           # ZS_Gemini (API client, token pool & redaction)
│   ├── Share.php            # ZS_Share (Anonymization & GitHub formatting)
│   ├── Http.php             # ZS_Http (Actions, CSRF, batch scanner)
│   ├── Ui.php               # ZS_Ui (Dark-theme UI renderer)
│   ├── i18n/                # Language dictionaries (en.php, fa.php)
│   └── assets/              # Inlined CSS & client-side JavaScript
├── tests/
│   ├── run.php              # Comprehensive CLI test runner (18 tests)
│   └── fixtures/            # Harmless synthetic test files
├── dist/malware-cleaner.php # Compiled single-file distribution
├── malware-cleaner.php      # Root drop-in artifact (synced with dist)
└── malware-cleaner.md       # Architectural specification & plan
```

### Building from Source
Recompile the single-file artifact:
```bash
php bin/build.php
```
The script will validate JSON rules, inline CSS/JS and language dictionaries, concatenate all classes in dependency order, write `malware-cleaner.php`, and verify syntax via `php -l`.

### Running Tests
Execute the self-contained test suite:
```bash
php tests/run.php
```

---

## 🔒 Security Best Practices

1. **Delete After Use:** Once your site is clean and restored, delete `malware-cleaner.php` from your web root.
2. **Outside Web Root:** For long-term monitoring, set `MALWARE_CLEANER_DATA_DIR` outside `public_html`.
3. **Keep Rules Synced:** Regularly tap **"Sync Rules from GitHub"** to receive the latest signature updates.

---

## 📄 License

This project is licensed under the **MIT License**. Created as an open-source security utility for WordPress webmasters, hosting engineers, and developers worldwide.
