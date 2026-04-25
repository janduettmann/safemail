# SafeMail TODO

## In Arbeit

### 1. Verdict-Aggregation auf `Mail`-Row
Nach jedem Scan die Worst-Case-Werte aus den Children (`CanonicalUrl`, `CanonicalFile`) auf die Mail-Row schreiben, damit das Badge im Mail-List-Template korrekte Daten hat.

**Konzept-Entscheidungen bisher:**
- Worst-case wins: `MALICIOUS > SUSPICIOUS > BENIGN > UNKNOWN`
- Severity als `@property` am `Verdict`-Enum (in `app/enums.py`), gestützt durch privates `_SEVERITY`-Dict
- Auswahl mit `max(children, key=lambda c: c.verdict.severity)`
- Empty-case (Mail ohne URLs/Files): `scan_status=COMPLETED`, `verdict=BENIGN`, `worst_verdict=0`, `total_engines=0`
- Badge zeigt nur Icon (kein `X/Y`) — Detailzahlen wandern später auf Analytics-Seite

**Nächste Schritte:**
- Children-Query implementieren (zwei separate Selects + Listen verketten)
- FAILED-Aggregation entscheiden
- `RUNNING`-Status am Anfang von `scan_mail()` setzen
- `aggregate_mail_verdict()` am Ende von `scan_mail()` aufrufen
- Commit-Strategie

## Geplant

### 2. Auto-Reload Mail-Liste nach Scan
Mail-Liste aktualisiert sich nicht von selbst, wenn ein Scan fertig ist.
**Plan:** `HX-Trigger`-Header → Custom-Event `scanComplete` → `#mail-list` lauscht via `hx-trigger="scanComplete from:body"`. Im `ScanQueue` ein One-Shot-Notify-Flag, der vom Status-Endpoint konsumiert wird.

### 3. UI Verdict-Badges
Badges im Mail-List-Template gemäß Mockup (`/home/jandu/Downloads/safemail-triage-v3.html`).
- Jinja-Macro `verdict_badge(mail)` mit allen Zuständen
- `data-threat`-Attribut auf den Mail-Rows (für spätere Filter-Tabs)
- Hinweis: `animate-scan-pulse` ist KEINE Tailwind-Builtin-Klasse → `animate-pulse` nehmen
- Pro neuer User-Entscheidung: nur Icon, kein `X/Y`

### 4. Filter-Tabs (Alle/Gefährlich/Verdächtig/Sicher/Ungescannt)
Tabs in `triage.html`, JS toggelt `display:none` auf `.mail-row` basierend auf `data-threat`. Counts pro Kategorie kommen vom Backend.

## Bugs / Tech-Debt

### `github.io`-Fall in `ingest.py`
Default `tldextract` hat PSL-Private-Domains aus → `alice.github.io` und `bob.github.io` kollabieren auf `github.io` (gleicher Bug wie `.co.uk` vorher).
**Fix:** `tldextract.TLDExtract(include_psl_private_domains=True)` als Modul-Level-Instanz.

### IP-Handling
Entscheidung: IPs in bestehender `CanonicalUrl`-Tabelle speichern. `not suffix`-Guard lockern, `tldextract.ipv4`-Attribut nutzen. VT-IP-Endpoint braucht keinen Submit-Flow (immer 200).

### `full_scan()` scannt nicht
`app/routes/scan.py` instanziiert `MailScanService`, ruft aber `scan_mail()` nie auf. Aktuell nur `single_scan` über `scan_queue` funktional.

### Race Conditions in `triage.py`
Globale Dicts `sync_status` und `page_uids` werden ohne Lock von Worker-Threads beschrieben.

### Analytics-Seite
Detail-Stats (`worst_verdict`, `total_engines`, malicious/suspicious/harmless/undetected pro Mail) anzeigen — sobald Aggregation steht.
