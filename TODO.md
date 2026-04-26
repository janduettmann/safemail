# SafeMail TODO

## Settings-Page
- [ ] Neuer Blueprint `settings_bp` in `app/routes/settings.py`
- [ ] Routes: `GET /settings` (Full-Page, default = account) + `GET /settings/<section>` (HTMX-Swap)
- [ ] Section-Slugs: `account`, `mail`, `scan`, `other`
- [ ] HTMX-Pattern: `hx-get`, `hx-target="#settings-content"`, `hx-swap="innerHTML"`, `hx-push-url="true"`
- [ ] Templates: `settings.html` + `components/settings_sidebar.html` + 4× `components/settings_section_*.html`
- [ ] Mockup als Vorlage: `/home/jandu/Downloads/safemail-settings-v1-rose.html`
- [ ] CSS: alles auf Tailwind portieren (CDN)
- [ ] Entscheiden: base_app.html nutzen oder eigenständige Seite (Variante A/B/C klären)
- [ ] Section App-Account: Profil, Passwort ändern, Account löschen (Danger-Zone)
- [ ] Section Mail-Accounts: IMAP-Liste (Gitea-SSH-Stil), Add-Form, Edit/Test/Remove
- [ ] Section Scan-Verhalten: Auto-Scan-Toggles, eigener VT-API-Key, Schwellwerte
- [ ] Section Sonstiges: Theme, Sprache, Logout, Alle-Sitzungen-Logout
- [ ] Erstmal nur Design, Backend-Verdrahtung kommt später

## Features
- [ ] Filter-Tabs in `triage.html` (Alle / Gefährlich / Verdächtig / Sicher / Ungescannt) — JS toggelt `display:none` auf `.mail-row` via `data-threat`, Counts vom Backend
- [ ] Analytics-Seite mit Detail-Stats (`worst_verdict`, `total_engines`, malicious/suspicious/harmless/undetected pro Mail)

## Bugs / Tech-Debt
- [ ] `github.io`-Fall in `ingest.py` fixen — `tldextract.TLDExtract(include_psl_private_domains=True)` als Modul-Level-Instanz
- [ ] IP-Handling — IPs in `CanonicalUrl`-Tabelle, `not suffix`-Guard lockern, `tldextract.ipv4` nutzen, VT-IP-Endpoint ohne Submit-Flow
- [ ] `full_scan()` in `app/routes/scan.py` ruft `scan_mail()` nie auf
- [ ] Race Conditions in `app/routes/triage.py` — globale Dicts `sync_status` und `page_uids` ohne Lock
