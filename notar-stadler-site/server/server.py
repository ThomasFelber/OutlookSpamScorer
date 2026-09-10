#!/usr/bin/env python3
"""Server des Notariats: statische Seite + Annahme der Fragebögen.

- Liefert dist/ aus.
- POST /api/formular/<slug>: prüft Eingaben gegen das Schema, verschlüsselt sie mit dem
  öffentlichen Schlüssel des Notariats, speichert sie in SQLite, schickt dem Notariat eine
  E-Mail ohne Mandantendaten (nur Formular, Zeit, Vorgangsnummer) und zeigt eine Bestätigungsseite.
- GET /api/eingaenge?ab=<id>: verschlüsselte Eingänge für abholen.py (Bearer-Token).
- DELETE /api/eingaenge/<id>: Eingang nach dem Abholen löschen (Bearer-Token).

Konfiguration über Umgebungsvariablen, siehe config.example.env. Betrieb hinter Caddy oder nginx (TLS).
Abhängigkeiten: Python 3.11+, cryptography.
"""
import os, sys, re, json, html, sqlite3, smtplib, hmac, time, threading, logging, mimetypes, datetime
from collections import deque
from email.message import EmailMessage
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, "..", "src"))
import krypto
import formulare as F
import en as EN

CFG = {
    "HOST": os.environ.get("HOST", "127.0.0.1"),
    "PORT": int(os.environ.get("PORT", "8080")),
    "DIST": os.environ.get("DIST", os.path.join(HERE, "..", "dist")),
    "DB": os.environ.get("DB", os.path.join(HERE, "eingaenge.sqlite")),
    "SITE_ORIGIN": os.environ.get("SITE_ORIGIN", "https://notar-stadler.de"),
    "OEFFENTLICHER_SCHLUESSEL": os.environ.get("OEFFENTLICHER_SCHLUESSEL", ""),
    "ABHOL_TOKEN": os.environ.get("ABHOL_TOKEN", ""),
    "SMTP_HOST": os.environ.get("SMTP_HOST", ""),
    "SMTP_PORT": int(os.environ.get("SMTP_PORT", "465")),
    "SMTP_USER": os.environ.get("SMTP_USER", ""),
    "SMTP_PASS": os.environ.get("SMTP_PASS", ""),
    "MAIL_VON": os.environ.get("MAIL_VON", "website@notar-stadler.de"),
    "MAIL_AN": os.environ.get("MAIL_AN", "info@notar-stadler.de"),
    "TRUST_PROXY": os.environ.get("TRUST_PROXY", "1") == "1",
    "RATE_PRO_STUNDE": int(os.environ.get("RATE_PRO_STUNDE", "10")),
    "MAX_BODY": 64 * 1024,
    "MAX_FELD": 4000,
}
log = logging.getLogger("notariat")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# ---------- Datenbank ----------
_db_lock = threading.Lock()

def db():
    c = sqlite3.connect(CFG["DB"], check_same_thread=False)
    c.execute("""CREATE TABLE IF NOT EXISTS eingaenge(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nummer TEXT UNIQUE NOT NULL,
        formular TEXT NOT NULL,
        zeit TEXT NOT NULL,
        eph TEXT NOT NULL, nonce TEXT NOT NULL, ct TEXT NOT NULL)""")
    c.execute("CREATE TABLE IF NOT EXISTS zaehler(jahr_kurz TEXT PRIMARY KEY, n INTEGER NOT NULL)")
    return c

def naechste_nummer(c, kurz):
    jahr = datetime.date.today().year
    key = f"{jahr}-{kurz}"
    with _db_lock:
        row = c.execute("SELECT n FROM zaehler WHERE jahr_kurz=?", (key,)).fetchone()
        n = (row[0] if row else 0) + 1
        c.execute("INSERT OR REPLACE INTO zaehler(jahr_kurz,n) VALUES(?,?)", (key, n))
        c.commit()
    return f"{kurz}-{jahr}-{n:04d}"

# ---------- Rate-Limit ----------
_rate = {}
_rate_lock = threading.Lock()

def rate_ok(ip):
    now = time.time()
    with _rate_lock:
        q = _rate.setdefault(ip, deque())
        while q and q[0] < now - 3600: q.popleft()
        if len(q) >= CFG["RATE_PRO_STUNDE"]: return False
        q.append(now); return True

# ---------- Prüfung ----------
def pruefe(form, daten, lang="de"):
    """Gibt (bereinigte_daten, fehler) zurück. Unbekannte Felder sind ein Fehler."""
    idx = F.field_index(form)
    L = lambda s: (EN.T.get(s, s) if lang == "en" else s)
    M = {"de": ("Unbekanntes Feld", "Zu lang", "Ungültige Auswahl", "Pflichtfeld fehlt", "Datenschutzhinweis nicht bestätigt"),
         "en": ("Unknown field", "Too long", "Invalid choice", "Required field missing", "Privacy notice not confirmed")}[lang]
    sauber, fehler = {}, []
    for k, v in daten.items():
        if k in ("datenschutz", "firma_web"): continue
        if k not in idx: fehler.append(f"{M[0]}: {k}"); continue
        v = (v or "").strip()
        if len(v) > CFG["MAX_FELD"]: fehler.append(f"{M[1]}: {L(idx[k]['label'])}"); continue
        fl = idx[k]
        if fl["type"] == "select" and v and v not in fl["options"]: fehler.append(f"{M[2]}: {L(fl['label'])}"); continue
        if fl["type"] == "checkbox": v = "ja" if v else ""
        if v: sauber[k] = v
    for name, fl in idx.items():
        if fl.get("required") and not sauber.get(name): fehler.append(f"{M[3]}: {L(fl['label'])}")
    if daten.get("datenschutz") != "ja": fehler.append(M[4])
    return sauber, fehler

# ---------- E-Mail ----------
def benachrichtige(form, nummer, zeit):
    """E-Mail an das Notariat: nur Formular, Zeit, Vorgangsnummer. Keine Mandantendaten."""
    if not CFG["SMTP_HOST"]:
        log.info("SMTP nicht konfiguriert, keine E-Mail. %s %s", form["title"], nummer); return
    m = EmailMessage()
    m["From"] = CFG["MAIL_VON"]; m["To"] = CFG["MAIL_AN"]
    m["Subject"] = f"Neuer Fragebogen: {form['title']} ({nummer})"
    m.set_content(f"""Über die Website ist ein Fragebogen eingegangen.

Formular:        {form['title']}
Vorgangsnummer:  {nummer}
Eingegangen:     {zeit}

Abholen und entschlüsseln im Büro mit:  python3 abholen.py
Diese Nachricht enthält absichtlich keine Angaben aus dem Fragebogen.
""")
    try:
        if CFG["SMTP_PORT"] == 465:
            s = smtplib.SMTP_SSL(CFG["SMTP_HOST"], CFG["SMTP_PORT"], timeout=20)
        else:
            s = smtplib.SMTP(CFG["SMTP_HOST"], CFG["SMTP_PORT"], timeout=20); s.starttls()
        with s:
            if CFG["SMTP_USER"]: s.login(CFG["SMTP_USER"], CFG["SMTP_PASS"])
            s.send_message(m)
        log.info("E-Mail gesendet: %s", nummer)
    except Exception as e:
        log.error("E-Mail fehlgeschlagen für %s: %s", nummer, e)

# ---------- HTML ----------
TXT = {
 "de": {"eyebrow": "Fragebogen", "home": "Zur Startseite", "all": "Alle Fragebögen", "home_url": "/", "all_url": "/fragebogen.html",
        "abgelehnt": "Übermittlung abgelehnt", "herkunft": "Die Anfrage kam nicht von der Website des Notariats.",
        "zuviel": "Zu viele Anfragen", "spaeter": "Bitte versuchen Sie es später erneut oder rufen Sie an.", "gross": "Die Eingabe ist zu groß.",
        "danke": "Vielen Dank", "eingegangen": "Ihr Fragebogen ist eingegangen.", "pruefen": "Bitte prüfen Sie Ihre Angaben",
        "nicht": "Der Fragebogen konnte nicht angenommen werden:", "zurueck": "Gehen Sie mit dem Zurück-Knopf des Browsers zum Fragebogen; Ihre Eingaben bleiben erhalten.",
        "ok1": "Ihr Fragebogen <strong>{t}</strong> ist beim Notariat eingegangen.", "ok2": "Vorgangsnummer: <strong>{n}</strong>. Bitte nennen Sie diese Nummer bei Rückfragen.",
        "ok3": "Das Büro meldet sich bei Ihnen. Einen Termin vereinbaren Sie telefonisch unter <a href=\"tel:+497761926170\">07761 92617-0</a>.",
        "ok4": "Ihre Angaben wurden verschlüsselt gespeichert und sind nur für das Notariat lesbar."},
 "en": {"eyebrow": "Questionnaire", "home": "Back to home", "all": "All questionnaires", "home_url": "/en/index.html", "all_url": "/en/fragebogen.html",
        "abgelehnt": "Submission rejected", "herkunft": "The request did not come from the notary's website.",
        "zuviel": "Too many requests", "spaeter": "Please try again later or call us.", "gross": "The input is too large.",
        "danke": "Thank you", "eingegangen": "Your questionnaire has been received.", "pruefen": "Please check your entries",
        "nicht": "The questionnaire could not be accepted:", "zurueck": "Use your browser's back button to return to the questionnaire; your entries are kept.",
        "ok1": "Your questionnaire <strong>{t}</strong> has reached the notary's office.", "ok2": "Reference number: <strong>{n}</strong>. Please quote it in any query.",
        "ok3": "The office will contact you. Appointments are made by telephone: <a href=\"tel:+497761926170\">+49 7761 92617-0</a>.",
        "ok4": "Your details were stored in encrypted form and can only be read by the notary's office."},
}

def seite(titel, inhalt, status=200, lang="de"):
    x = TXT[lang]
    return status, f"""<!doctype html><html lang="{lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex"><title>{html.escape(titel)} · Notar Stadler</title><link rel="stylesheet" href="/style.css"></head>
<body><div class="shell"><main id="inhalt"><section class="page-hero"><div class="wrap"><div><p class="eyebrow">{x["eyebrow"]}</p><h1>{html.escape(titel)}</h1></div></div></section>
<section><div class="wrap prose">{inhalt}<p style="margin-top:24px"><a href="{x["home_url"]}">{x["home"]}</a> · <a href="{x["all_url"]}">{x["all"]}</a></p></div></section></main></div></body></html>"""

# ---------- Handler ----------
class H(BaseHTTPRequestHandler):
    server_version = "notariat/1"

    def log_message(self, fmt, *a): log.info("%s %s", self.client_ip(), fmt % a)

    def client_ip(self):
        if CFG["TRUST_PROXY"]:
            xf = self.headers.get("X-Forwarded-For")
            if xf: return xf.split(",")[0].strip()
        return self.client_address[0]

    def send(self, status, body, ctype="text/html; charset=utf-8", extra=None):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff"); self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store" if ctype.startswith("text/html") and self.path.startswith("/api") else "public, max-age=600")
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(data)

    def token_ok(self):
        auth = self.headers.get("Authorization", "")
        return CFG["ABHOL_TOKEN"] and auth.startswith("Bearer ") and hmac.compare_digest(auth[7:], CFG["ABHOL_TOKEN"])

    # --- statisch ---
    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/eingaenge":
            if not self.token_ok(): return self.send(401, "unauthorized", "text/plain")
            ab = int(parse_qs(urlsplit(self.path).query).get("ab", ["0"])[0])
            c = db(); rows = c.execute("SELECT id,nummer,formular,zeit,eph,nonce,ct FROM eingaenge WHERE id>? ORDER BY id", (ab,)).fetchall()
            out = [dict(zip(["id", "nummer", "formular", "zeit", "eph", "nonce", "ct"], r)) for r in rows]
            return self.send(200, json.dumps(out), "application/json", {"Cache-Control": "no-store"})
        if path.startswith("/api/"): return self.send(404, "not found", "text/plain")
        if path == "/": path = "/index.html"
        if not re.fullmatch(r"/[\w.-]+(/[\w.-]+)*", path): return self.send(404, "not found", "text/plain")
        fp = os.path.normpath(os.path.join(CFG["DIST"], path.lstrip("/")))
        if not fp.startswith(os.path.normpath(CFG["DIST"])) or not os.path.isfile(fp):
            return self.send(404, seite("Seite nicht gefunden", "<p>Diese Seite gibt es nicht.</p>")[1])
        ctype = mimetypes.guess_type(fp)[0] or "application/octet-stream"
        if ctype.startswith("text/"): ctype += "; charset=utf-8"
        with open(fp, "rb") as fh: self.send(200, fh.read(), ctype)

    def do_DELETE(self):
        m = re.fullmatch(r"/api/eingaenge/(\d+)", urlsplit(self.path).path)
        if not m: return self.send(404, "not found", "text/plain")
        if not self.token_ok(): return self.send(401, "unauthorized", "text/plain")
        c = db(); c.execute("DELETE FROM eingaenge WHERE id=?", (int(m.group(1)),)); c.commit()
        self.send(200, "ok", "text/plain")

    # --- Fragebogen ---
    def do_POST(self):
        m = re.fullmatch(r"/api/formular/([a-z-]+)", urlsplit(self.path).path)
        if not m or m.group(1) not in F.BY_SLUG: return self.send(404, "not found", "text/plain")
        form = F.BY_SLUG[m.group(1)]
        lang = "en" if parse_qs(urlsplit(self.path).query).get("lang", [""])[0] == "en" else "de"
        x = TXT[lang]
        origin = self.headers.get("Origin") or ""
        referer = self.headers.get("Referer") or ""
        if not (origin == CFG["SITE_ORIGIN"] or referer.startswith(CFG["SITE_ORIGIN"] + "/")):
            return self.send(*seite(x["abgelehnt"], f"<p>{x['herkunft']}</p>", 403, lang))
        if not rate_ok(self.client_ip()):
            return self.send(*seite(x["zuviel"], f"<p>{x['spaeter']}</p>", 429, lang))
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > CFG["MAX_BODY"]: return self.send(*seite(x["abgelehnt"], f"<p>{x['gross']}</p>", 413, lang))
        raw = self.rfile.read(n).decode("utf-8", "replace")
        daten = {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}
        if daten.get("firma_web"):  # Honeypot: Menschen sehen das Feld nicht
            return self.send(*seite(x["danke"], f"<p>{x['eingegangen']}</p>", 200, lang))
        sauber, fehler = pruefe(form, daten, lang)
        if fehler:
            li = "".join(f"<li>{html.escape(x)}</li>" for x in fehler)
            return self.send(*seite(x["pruefen"], f"<p>{x['nicht']}</p><ul>{li}</ul><p>{x['zurueck']}</p>", 400, lang))
        c = db()
        nummer = naechste_nummer(c, form["kurz"])
        zeit = datetime.datetime.now().astimezone().strftime("%d.%m.%Y %H:%M")
        klartext = json.dumps({"formular": form["slug"], "titel": form["title"], "nummer": nummer, "zeit": zeit, "felder": sauber}, ensure_ascii=False).encode()
        paket = krypto.verschluesseln(CFG["OEFFENTLICHER_SCHLUESSEL"], klartext, nummer.encode())
        with _db_lock:
            c.execute("INSERT INTO eingaenge(nummer,formular,zeit,eph,nonce,ct) VALUES(?,?,?,?,?,?)",
                      (nummer, form["slug"], zeit, paket["eph"], paket["nonce"], paket["ct"])); c.commit()
        log.info("Fragebogen gespeichert: %s %s", form["slug"], nummer)
        threading.Thread(target=benachrichtige, args=(form, nummer, zeit), daemon=True).start()
        titel = EN.T.get(form["title"], form["title"]) if lang == "en" else form["title"]
        self.send(*seite(x["danke"], "<p>" + x["ok1"].format(t=html.escape(titel)) + "</p><p>" + x["ok2"].format(n=nummer) + f"</p><p>{x['ok3']}</p><p>{x['ok4']}</p>", 200, lang))

def main():
    if not CFG["OEFFENTLICHER_SCHLUESSEL"] or len(CFG["OEFFENTLICHER_SCHLUESSEL"]) != 64:
        print("OEFFENTLICHER_SCHLUESSEL fehlt oder ist ungültig (64 Hex-Zeichen). Siehe schluessel.py."); sys.exit(1)
    if not CFG["ABHOL_TOKEN"] or len(CFG["ABHOL_TOKEN"]) < 32:
        print("ABHOL_TOKEN fehlt oder ist zu kurz (mindestens 32 Zeichen)."); sys.exit(1)
    db()
    srv = ThreadingHTTPServer((CFG["HOST"], CFG["PORT"]), H)
    log.info("Notariat-Server auf http://%s:%s, dist=%s, db=%s", CFG["HOST"], CFG["PORT"], CFG["DIST"], CFG["DB"])
    srv.serve_forever()

if __name__ == "__main__":
    main()
