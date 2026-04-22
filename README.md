# SafeMail

A self-hosted email client with integrated phishing analysis. SafeMail connects to existing mailboxes via IMAP, renders messages in a sandboxed environment, and triages potential threats using VirusTotal and rule-based heuristics.

> **Status:** Active development. APIs and schemas may change without notice.

## Motivation

Most email clients prioritize convenience over safety: they auto-load remote content, render HTML with full DOM privileges, and surface attachments without analysis. SafeMail inverts these defaults. Every message is rendered inside a sandboxed `iframe` with restricted capabilities, attachments and URLs can be submitted to VirusTotal on demand, and the UI surfaces threat signals (sender reputation, SPF/DKIM results, suspicious links) before the user interacts with message content.

## Features

- **IMAP synchronization** with RFC 6154 `SPECIAL-USE` flag detection for correct folder mapping (Inbox, Sent, Drafts, Trash, Junk) across providers
- **Sandboxed message rendering** in an `iframe` with a restrictive `sandbox` attribute; a pre-render filter rewrites styles for dark-mode compatibility without executing remote content
- **Scan triage UI** with threat score badges, filter chips (clean / suspicious / malicious / unscanned), and a progress bar for long-running VirusTotal batch submissions
- **VirusTotal integration** for URL and attachment analysis, with results cached to avoid rate-limit exhaustion
- **CSRF protection** via Flask-WTF `CSRFProtect`, with HTMX requests carrying the token through `hx-headers`
- **Session-based authentication** via Flask-Login

## Tech Stack

| Layer         | Choice                                                 |
| ------------- | ------------------------------------------------------ |
| Backend       | Python 3.11+, Flask, SQLAlchemy                        |
| Frontend      | HTMX, Tailwind CSS 4 (via CDN), Lucide Icons           |
| Auth          | Flask-Login, Flask-WTF (CSRF)                          |
| IMAP          | [imap_tools](https://github.com/ikvk/imap_tools)       |
| External APIs | VirusTotal v3                                          |
| Build         | `npm` (Tailwind watcher), `uv` (Python env + runner)   |

## Architecture

```
┌─────────────┐     HTMX      ┌──────────────┐    IMAP    ┌──────────────┐
│   Browser   │ ────────────▶ │  Flask app   │ ─────────▶ │  Mail server │
│  (sandbox   │               │              │            │              │
│   iframe)   │ ◀──── HTML ── │  SQLAlchemy  │            └──────────────┘
└─────────────┘               │              │
                              │              │   HTTPS    ┌──────────────┐
                              │              │ ─────────▶ │  VirusTotal  │
                              └──────────────┘            └──────────────┘
                                     │
                                     ▼
                              ┌──────────────┐
                              │   SQLite     │
                              │ (dev)        │
                              └──────────────┘
```

Message HTML is never injected directly into the main document. It is written to a data URL and loaded inside an `iframe sandbox="allow-same-origin"` — no script execution, no top-level navigation, no form submission. A server-side filter rewrites inline styles for dark-mode support before the content leaves Flask.

## Getting Started

### Prerequisites

- Python 3.11+
- Node.js 18+ (for the Tailwind watcher)
- [`uv`](https://docs.astral.sh/uv/) for Python environment management
- A VirusTotal API key (free tier is sufficient for development)

### Setup

```bash
git clone https://github.com/janduettmann/safemail.git
cd safemail

# Python dependencies
uv sync

# Node dependencies (Tailwind watcher, concurrently)
npm install

# Configuration
cp .env.example .env
# Edit .env — see "Configuration" below
```

### Running

```bash
npm run dev
```

This starts the Tailwind watcher and the Flask development server in parallel via `concurrently`. The app will be available at `http://localhost:5000`.

To run only the Flask server (e.g., when CSS is already built):

```bash
uv run run.py
```

## Configuration

SafeMail reads configuration from environment variables. At minimum:

```dotenv
FLASK_SECRET_KEY=<generate with: python -c "import secrets; print(secrets.token_hex(32))">
DATABASE_URL=sqlite:///safemail.db
VIRUSTOTAL_API_KEY=<your VirusTotal v3 key>
```

IMAP credentials are entered per-user through the UI and stored encrypted in the database. They are **not** read from environment variables.

## License

[MIT](LICENSE)
