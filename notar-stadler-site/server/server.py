#!/usr/bin/env python3
"""Server des Notariats: statische Seite, Annahme von Fragebögen und Anfragen, Verwaltung.

- Liefert dist/ und /verwaltung/ aus.
- POST /api/formular/<slug>: prüft gegen das Schema, verschlüsselt mit dem öffentlichen Schlüssel
  des Notariats, speichert in SQLite, E-Mail ohne Mandantendaten, Bestätigung mit Referenz.
- /api/verwaltung/...: Einrichtung und Anmeldung mit Passwort + YubiKey (WebAuthn, PRF-Erweiterung),
  Liste der Eingänge. Entschlüsselt wird im Browser des Notariats; der Server sieht keinen Klartext.
- GET /api/eingaenge, DELETE /api/eingaenge/<id>: Abholung per Token für abholen.py (Sicherungsweg).

Konfiguration über Umgebungsvariablen, siehe config.example.env. Betrieb hinter Caddy oder nginx (TLS).
Abhängigkeiten: Python 3.11+, cryptography.
"""
import os, sys, re, json, html, sqlite3, smtplib, hmac, time, threading, logging, mimetypes, datetime, secrets, hashlib, base64
from collections import deque
from email.message import EmailMessage
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, "..", "src"))
import krypto, webauthn
import formulare as F
import en as EN

CFG = {
    "HOST": os.environ.get("HOST", "127.0.0.1"),
    "PORT": int(os.environ.get("PORT", "8080")),
    "DIST": os.environ.get("DIST", os.path.join(HERE, "..", "dist")),
    "DB": os.environ.get("DB", os.path.join(HERE, "eingaenge.sqlite")),
    "SITE_ORIGIN": os.environ.get("SITE_ORIGIN", "https://notar-stadler.de"),
    "RP_ID": os.environ.get("RP_ID", ""),  # leer: aus SITE_ORIGIN
    "OEFFENTLICHER_SCHLUESSEL": os.environ.get("OEFFENTLICHER_SCHLUESSEL", ""),  # Sicherungsweg ohne Verwaltung
    "SETUP_TOKEN": os.environ.get("SETUP_TOKEN", ""),
    "ABHOL_TOKEN": os.environ.get("ABHOL_TOKEN", ""),
    "SMTP_HOST": os.environ.get("SMTP_HOST", ""),
    "SMTP_PORT": int(os.environ.get("SMTP_PORT", "465")),
    "SMTP_USER": os.environ.get("SMTP_USER", ""),
    "SMTP_PASS": os.environ.get("SMTP_PASS", ""),
    "MAIL_VON": os.environ.get("MAIL_VON", "website@notar-stadler.de"),
    "MAIL_AN": os.environ.get("MAIL_AN", "info@notar-stadler.de"),
    "TRUST_PROXY": os.environ.get("TRUST_PROXY", "1") == "1",
    "RATE_PRO_STUNDE": int(os.environ.get("RATE_PRO_STUNDE", "10")),
    "SITZUNG_MINUTEN": int(os.environ.get("SITZUNG_MINUTEN", "30")),
    "MAX_BODY": 64 * 1024,
    "MAX_FELD": 4000,
}
if not CFG["RP_ID"]:
    CFG["RP_ID"] = urlsplit(CFG["SITE_ORIGIN"]).hostname or "localhost"
log = logging.getLogger("notariat")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# ---------- Datenbank ----------
_db_lock = threading.Lock()

def db():
    c = sqlite3.connect(CFG["DB"], check_same_thread=False)
    c.execute("""CREATE TABLE IF NOT EXISTS eingaenge(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        referenz TEXT UNIQUE NOT NULL,
        formular TEXT NOT NULL,
        zeit TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'neu',
        eph TEXT NOT NULL, nonce TEXT NOT NULL, ct TEXT NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS verwaltung(
        id INTEGER PRIMARY KEY CHECK(id=1),
        pw_salt TEXT NOT NULL, pw_hash TEXT NOT NULL,
        cred_id TEXT NOT NULL, cred_pub TEXT NOT NULL, zaehler INTEGER NOT NULL DEFAULT 0,
        enc_pub TEXT NOT NULL, wrapped_priv TEXT NOT NULL,
        prf_salt TEXT NOT NULL, kdf_salt TEXT NOT NULL, angelegt TEXT NOT NULL)""")
    c.execute("CREATE TABLE IF NOT EXISTS sitzungen(token TEXT PRIMARY KEY, ablauf REAL NOT NULL)")
    return c

def verwaltung(c):
    r = c.execute("SELECT pw_salt,pw_hash,cred_id,cred_pub,zaehler,enc_pub,wrapped_priv,prf_salt,kdf_salt FROM verwaltung WHERE id=1").fetchone()
    return dict(zip(["pw_salt", "pw_hash", "cred_id", "cred_pub", "zaehler", "enc_pub", "wrapped_priv", "prf_salt", "kdf_salt"], r)) if r else None

def oeffentlicher_schluessel(c):
    v = verwaltung(c)
    return v["enc_pub"] if v else CFG["OEFFENTLICHER_SCHLUESSEL"]

def neue_referenz(c):
    with _db_lock:
        while True:
            r = krypto.neue_referenz()
            if not c.execute("SELECT 1 FROM eingaenge WHERE referenz=?", (r,)).fetchone():
                return r

def pw_hash(pw, salt_hex):
    return hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt_hex), n=2**15, r=8, p=1, dklen=32, maxmem=64 * 1024 * 1024).hex()

# ---------- Rate-Limit ----------
_rate = {}
_rate_lock = threading.Lock()

def rate_ok(key, limit, fenster=3600):
    now = time.time()
    with _rate_lock:
        q = _rate.setdefault(key, deque())
        while q and q[0] < now - fenster: q.popleft()
        if len(q) >= limit: return False
        q.append(now); return True

# ---------- Challenges und Sitzungen ----------
_challenges = {}  # challenge -> (zweck, ablauf)
_ch_lock = threading.Lock()

def neue_challenge(zweck):
    ch = webauthn.b64url_encode(os.urandom(32))
    with _ch_lock:
        for k in [k for k, v in _challenges.items() if v[1] < time.time()]: del _challenges[k]
        _challenges[ch] = (zweck, time.time() + 300)
    return ch

def challenge_einloesen(ch, zweck):
    with _ch_lock:
        v = _challenges.pop(ch, None)
    return bool(v) and v[0] == zweck and v[1] >= time.time()

def sitzung_anlegen(c):
    tok = secrets.token_urlsafe(32)
    with _db_lock:
        c.execute("DELETE FROM sitzungen WHERE ablauf<?", (time.time(),))
        c.execute("INSERT INTO sitzungen(token,ablauf) VALUES(?,?)", (tok, time.time() + 60 * CFG["SITZUNG_MINUTEN"])); c.commit()
    return tok

def sitzung_ok(c, tok):
    if not tok: return False
    r = c.execute("SELECT ablauf FROM sitzungen WHERE token=?", (tok,)).fetchone()
    if not r or r[0] < time.time(): return False
    with _db_lock:
        c.execute("UPDATE sitzungen SET ablauf=? WHERE token=?", (time.time() + 60 * CFG["SITZUNG_MINUTEN"], tok)); c.commit()
    return True

# ---------- Prüfung ----------
def pruefe(form, daten, lang="de"):
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
def benachrichtige(form, referenz, zeit):
    """E-Mail an das Notariat: nur Art, Zeit, Referenz. Keine Mandantendaten."""
    if not CFG["SMTP_HOST"]:
        log.info("SMTP nicht konfiguriert, keine E-Mail. %s %s", form["title"], referenz); return
    m = EmailMessage()
    m["From"] = CFG["MAIL_VON"]; m["To"] = CFG["MAIL_AN"]
    m["Subject"] = f"Neuer Eingang: {form['title']} ({referenz})"
    m.set_content(f"""Über die Website ist ein Eingang angekommen.

Art:         {form['title']}
Referenz:    {referenz}
Eingegangen: {zeit}

Ansehen: {CFG['SITE_ORIGIN']}/verwaltung/  (Passwort und YubiKey)
Diese Nachricht enthält absichtlich keine Angaben aus dem Eingang.
""")
    try:
        if CFG["SMTP_PORT"] == 465:
            s = smtplib.SMTP_SSL(CFG["SMTP_HOST"], CFG["SMTP_PORT"], timeout=20)
        else:
            s = smtplib.SMTP(CFG["SMTP_HOST"], CFG["SMTP_PORT"], timeout=20); s.starttls()
        with s:
            if CFG["SMTP_USER"]: s.login(CFG["SMTP_USER"], CFG["SMTP_PASS"])
            s.send_message(m)
        log.info("E-Mail gesendet: %s", referenz)
    except Exception as e:
        log.error("E-Mail fehlgeschlagen für %s: %s", referenz, e)

# ---------- HTML ----------
TXT = {
 "de": {"eyebrow": "Fragebogen", "home": "Zur Startseite", "all": "Alle Fragebögen", "home_url": "/", "all_url": "/fragebogen.html",
        "abgelehnt": "Übermittlung abgelehnt", "herkunft": "Die Anfrage kam nicht von der Website des Notariats.",
        "zuviel": "Zu viele Anfragen", "spaeter": "Bitte versuchen Sie es später erneut oder rufen Sie an.", "gross": "Die Eingabe ist zu groß.",
        "danke": "Vielen Dank", "eingegangen": "Ihre Nachricht ist eingegangen.", "pruefen": "Bitte prüfen Sie Ihre Angaben",
        "nicht": "Die Eingabe konnte nicht angenommen werden:", "zurueck": "Gehen Sie mit dem Zurück-Knopf des Browsers zurück; Ihre Eingaben bleiben erhalten.",
        "ok1": "<strong>{t}</strong> ist beim Notariat eingegangen.", "ok2": "Ihre Referenz: <strong class=\"ref\">{n}</strong>. Bitte nennen Sie sie bei Rückfragen.",
        "ok3": "Das Büro meldet sich bei Ihnen. Einen Termin vereinbaren Sie telefonisch unter <a href=\"tel:+497761926170\">07761 92617-0</a>.",
        "ok4": "Ihre Angaben wurden verschlüsselt gespeichert und sind nur für das Notariat lesbar."},
 "en": {"eyebrow": "Questionnaire", "home": "Back to home", "all": "All questionnaires", "home_url": "/en/index.html", "all_url": "/en/fragebogen.html",
        "abgelehnt": "Submission rejected", "herkunft": "The request did not come from the notary's website.",
        "zuviel": "Too many requests", "spaeter": "Please try again later or call us.", "gross": "The input is too large.",
        "danke": "Thank you", "eingegangen": "Your message has been received.", "pruefen": "Please check your entries",
        "nicht": "The input could not be accepted:", "zurueck": "Use your browser's back button; your entries are kept.",
        "ok1": "<strong>{t}</strong> has reached the notary's office.", "ok2": "Your reference: <strong class=\"ref\">{n}</strong>. Please quote it in any query.",
        "ok3": "The office will contact you. Appointments are made by telephone: <a href=\"tel:+497761926170\">+49 7761 92617-0</a>.",
        "ok4": "Your details were stored in encrypted form and can only be read by the notary's office."},
}

def seite(titel, inhalt, status=200, lang="de"):
    x = TXT[lang]
    return status, f"""<!doctype html><html lang="{lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex"><title>{html.escape(titel)} · Notar Stadler</title><link rel="stylesheet" href="/style.css"><style>.ref{{font-family:ui-monospace,monospace;font-size:1.3em;letter-spacing:.12em}}</style></head>
<body><div class="shell"><main id="inhalt"><section class="page-hero"><div class="wrap"><div><p class="eyebrow">{x["eyebrow"]}</p><h1>{html.escape(titel)}</h1></div></div></section>
<section><div class="wrap prose">{inhalt}<p style="margin-top:24px"><a href="{x["home_url"]}">{x["home"]}</a> · <a href="{x["all_url"]}">{x["all"]}</a></p></div></section></main></div></body></html>"""

def schema_export():
    """Bezeichnungen für die Verwaltung (Anzeige der entschlüsselten Felder)."""
    out = {}
    for x in F.FORMS + [F.ANFRAGE]:
        out[x["slug"]] = {"title": x["title"], "sections": [{"title": s["title"], "fields": [{"name": fl["name"], "label": fl["label"], "type": fl["type"]} for fl in s["fields"]]} for s in x["sections"]]}
    return out

# ---------- Handler ----------
class H(BaseHTTPRequestHandler):
    server_version = "notariat/2"

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
        p = urlsplit(self.path).path
        self.send_header("Cache-Control", "no-store" if p.startswith("/api") or p.startswith("/verwaltung") else "public, max-age=600")
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(data)

    def json(self, status, obj, extra=None):
        self.send(status, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8", extra)

    def body_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > CFG["MAX_BODY"]: return None
        try: return json.loads(self.rfile.read(n).decode("utf-8"))
        except Exception: return None

    def token_ok(self):
        auth = self.headers.get("Authorization", "")
        return bool(CFG["ABHOL_TOKEN"]) and auth.startswith("Bearer ") and hmac.compare_digest(auth[7:], CFG["ABHOL_TOKEN"])

    def cookie(self, name):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name: return v
        return None

    def sitzung(self, c):
        return sitzung_ok(c, self.cookie("verwaltung"))

    def herkunft_ok(self):
        origin = self.headers.get("Origin") or ""
        referer = self.headers.get("Referer") or ""
        return origin == CFG["SITE_ORIGIN"] or referer.startswith(CFG["SITE_ORIGIN"] + "/")

    # ---------------- GET ----------------
    def do_GET(self):
        path = urlsplit(self.path).path
        c = db()
        if path == "/api/eingaenge":
            if not self.token_ok(): return self.send(401, "unauthorized", "text/plain")
            ab = int(parse_qs(urlsplit(self.path).query).get("ab", ["0"])[0])
            rows = c.execute("SELECT id,referenz,formular,zeit,eph,nonce,ct FROM eingaenge WHERE id>? ORDER BY id", (ab,)).fetchall()
            return self.json(200, [dict(zip(["id", "nummer", "formular", "zeit", "eph", "nonce", "ct"], r)) for r in rows])
        if path == "/api/verwaltung/status":
            v = verwaltung(c)
            return self.json(200, {"eingerichtet": bool(v), "rpId": CFG["RP_ID"], "angemeldet": bool(v) and self.sitzung(c)})
        if path == "/api/verwaltung/eingaenge":
            if not self.sitzung(c): return self.json(401, {"fehler": "nicht angemeldet"})
            rows = c.execute("SELECT id,referenz,formular,zeit,status,eph,nonce,ct FROM eingaenge ORDER BY id DESC").fetchall()
            return self.json(200, [dict(zip(["id", "referenz", "formular", "zeit", "status", "eph", "nonce", "ct"], r)) for r in rows])
        if path == "/api/verwaltung/schema":
            if not self.sitzung(c): return self.json(401, {"fehler": "nicht angemeldet"})
            return self.json(200, schema_export())
        if path.startswith("/api/"): return self.send(404, "not found", "text/plain")
        if path in ("/verwaltung", "/verwaltung/"): path = "/verwaltung/index.html"
        if path == "/": path = "/index.html"
        if not re.fullmatch(r"/[\w.-]+(/[\w.-]+)*", path): return self.send(404, "not found", "text/plain")
        root = os.path.join(HERE, "verwaltung") if path.startswith("/verwaltung/") else CFG["DIST"]
        rel = path[len("/verwaltung/"):] if path.startswith("/verwaltung/") else path.lstrip("/")
        fp = os.path.normpath(os.path.join(root, rel))
        if not fp.startswith(os.path.normpath(root)) or not os.path.isfile(fp):
            return self.send(404, seite("Seite nicht gefunden", "<p>Diese Seite gibt es nicht.</p>")[1])
        ctype = mimetypes.guess_type(fp)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype == "application/javascript": ctype += "; charset=utf-8"
        with open(fp, "rb") as fh: self.send(200, fh.read(), ctype)

    # ---------------- DELETE ----------------
    def do_DELETE(self):
        path = urlsplit(self.path).path
        c = db()
        m = re.fullmatch(r"/api/eingaenge/(\d+)", path)
        if m:
            if not self.token_ok(): return self.send(401, "unauthorized", "text/plain")
            with _db_lock: c.execute("DELETE FROM eingaenge WHERE id=?", (int(m.group(1)),)); c.commit()
            return self.send(200, "ok", "text/plain")
        m = re.fullmatch(r"/api/verwaltung/eingaenge/(\d+)", path)
        if m:
            if not self.sitzung(c): return self.json(401, {"fehler": "nicht angemeldet"})
            if not self.herkunft_ok(): return self.json(403, {"fehler": "Herkunft"})
            with _db_lock: c.execute("DELETE FROM eingaenge WHERE id=?", (int(m.group(1)),)); c.commit()
            return self.json(200, {"ok": True})
        self.send(404, "not found", "text/plain")

    # ---------------- POST ----------------
    def do_POST(self):
        path = urlsplit(self.path).path
        if path.startswith("/api/verwaltung/"): return self.post_verwaltung(path)
        m = re.fullmatch(r"/api/formular/([a-z-]+)", path)
        if not m or m.group(1) not in F.BY_SLUG: return self.send(404, "not found", "text/plain")
        form = F.BY_SLUG[m.group(1)]
        lang = "en" if parse_qs(urlsplit(self.path).query).get("lang", [""])[0] == "en" else "de"
        x = TXT[lang]
        if not self.herkunft_ok():
            return self.send(*seite(x["abgelehnt"], f"<p>{x['herkunft']}</p>", 403, lang))
        if not rate_ok("f:" + self.client_ip(), CFG["RATE_PRO_STUNDE"]):
            return self.send(*seite(x["zuviel"], f"<p>{x['spaeter']}</p>", 429, lang))
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > CFG["MAX_BODY"]: return self.send(*seite(x["abgelehnt"], f"<p>{x['gross']}</p>", 413, lang))
        raw = self.rfile.read(n).decode("utf-8", "replace")
        daten = {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}
        if daten.get("firma_web"):
            return self.send(*seite(x["danke"], f"<p>{x['eingegangen']}</p>", 200, lang))
        sauber, fehler = pruefe(form, daten, lang)
        if fehler:
            li = "".join(f"<li>{html.escape(e)}</li>" for e in fehler)
            return self.send(*seite(x["pruefen"], f"<p>{x['nicht']}</p><ul>{li}</ul><p>{x['zurueck']}</p>", 400, lang))
        c = db()
        pub = oeffentlicher_schluessel(c)
        if not pub:
            return self.send(*seite(x["abgelehnt"], "<p>Die Annahme ist noch nicht eingerichtet.</p>", 503, lang))
        referenz = neue_referenz(c)
        zeit = datetime.datetime.now().astimezone().strftime("%d.%m.%Y %H:%M")
        klartext = json.dumps({"formular": form["slug"], "titel": form["title"], "referenz": referenz, "zeit": zeit, "sprache": lang, "felder": sauber}, ensure_ascii=False).encode()
        paket = krypto.verschluesseln(pub, klartext, referenz.encode())
        with _db_lock:
            c.execute("INSERT INTO eingaenge(referenz,formular,zeit,eph,nonce,ct) VALUES(?,?,?,?,?,?)",
                      (referenz, form["slug"], zeit, paket["eph"], paket["nonce"], paket["ct"])); c.commit()
        log.info("Eingang gespeichert: %s %s", form["slug"], referenz)
        threading.Thread(target=benachrichtige, args=(form, referenz, zeit), daemon=True).start()
        titel = EN.T.get(form["title"], form["title"]) if lang == "en" else form["title"]
        self.send(*seite(x["danke"], "<p>" + x["ok1"].format(t=html.escape(titel)) + "</p><p>" + x["ok2"].format(n=referenz) + f"</p><p>{x['ok3']}</p><p>{x['ok4']}</p>", 200, lang))

    def post_verwaltung(self, path):
        c = db()
        if not self.herkunft_ok(): return self.json(403, {"fehler": "Herkunft"})
        d = self.body_json()
        if d is None: return self.json(400, {"fehler": "JSON erwartet"})
        ip = self.client_ip()
        v = verwaltung(c)

        if path == "/api/verwaltung/einrichten/start":
            if v: return self.json(409, {"fehler": "bereits eingerichtet"})
            if not CFG["SETUP_TOKEN"] or not hmac.compare_digest(d.get("setup_token", ""), CFG["SETUP_TOKEN"]): return self.json(403, {"fehler": "Einrichtungs-Token falsch"})
            if not rate_ok("s:" + ip, 5, 900): return self.json(429, {"fehler": "zu viele Versuche"})
            ch = neue_challenge("create")
            return self.json(200, {"challenge": ch, "rp": {"id": CFG["RP_ID"], "name": "Notariat Stadler"},
                                   "user": {"id": webauthn.b64url_encode(b"notariat-verwaltung"), "name": "notariat", "displayName": "Notariat Stadler"},
                                   "prfSalt": webauthn.b64url_encode(os.urandom(32)), "kdfSalt": webauthn.b64url_encode(os.urandom(16))})

        if path == "/api/verwaltung/einrichten/abschluss":
            if v: return self.json(409, {"fehler": "bereits eingerichtet"})
            if not CFG["SETUP_TOKEN"] or not hmac.compare_digest(d.get("setup_token", ""), CFG["SETUP_TOKEN"]): return self.json(403, {"fehler": "Einrichtungs-Token falsch"})
            pw = d.get("password", "")
            if len(pw) < 12: return self.json(400, {"fehler": "Passwort mindestens 12 Zeichen"})
            if not d.get("prfEnabled"): return self.json(400, {"fehler": "Der Sicherheitsschlüssel unterstützt die PRF-Erweiterung nicht"})
            if not challenge_einloesen(d.get("challenge", ""), "create"): return self.json(400, {"fehler": "Challenge ungültig oder abgelaufen"})
            try:
                cred_id, cred_pub, counter = webauthn.registrierung_pruefen(CFG["RP_ID"], d["challenge"], CFG["SITE_ORIGIN"], d["clientDataJSON"], d["attestationObject"])
                enc_pub = d["encPub"]; bytes.fromhex(enc_pub); assert len(enc_pub) == 130
                wrapped = json.dumps(d["wrappedPriv"]); assert set(d["wrappedPriv"]) >= {"iv", "ct"}
            except (ValueError, KeyError, AssertionError) as e:
                return self.json(400, {"fehler": f"Registrierung ungültig: {e}"})
            salt = os.urandom(16).hex()
            with _db_lock:
                c.execute("INSERT INTO verwaltung(id,pw_salt,pw_hash,cred_id,cred_pub,zaehler,enc_pub,wrapped_priv,prf_salt,kdf_salt,angelegt) VALUES(1,?,?,?,?,?,?,?,?,?,?)",
                          (salt, pw_hash(pw, salt), cred_id, cred_pub, counter, enc_pub, wrapped, d["prfSalt"], d["kdfSalt"], datetime.datetime.now().isoformat()))
                c.commit()
            log.info("Verwaltung eingerichtet")
            return self.json(200, {"ok": True})

        if path == "/api/verwaltung/login":
            if not v: return self.json(409, {"fehler": "nicht eingerichtet"})
            if not rate_ok("l:" + ip, 5, 900): return self.json(429, {"fehler": "zu viele Versuche, 15 Minuten warten"})
            if not hmac.compare_digest(pw_hash(d.get("password", ""), v["pw_salt"]), v["pw_hash"]):
                log.warning("Verwaltung: falsches Passwort von %s", ip)
                return self.json(401, {"fehler": "Passwort falsch"})
            ch = neue_challenge("get")
            return self.json(200, {"challenge": ch, "rpId": CFG["RP_ID"], "credentialId": v["cred_id"], "prfSalt": v["prf_salt"]})

        if path == "/api/verwaltung/login/abschluss":
            if not v: return self.json(409, {"fehler": "nicht eingerichtet"})
            if not challenge_einloesen(d.get("challenge", ""), "get"): return self.json(400, {"fehler": "Challenge ungültig oder abgelaufen"})
            if d.get("credentialId") != v["cred_id"]: return self.json(401, {"fehler": "Unbekannter Sicherheitsschlüssel"})
            try:
                counter = webauthn.anmeldung_pruefen(CFG["RP_ID"], d["challenge"], CFG["SITE_ORIGIN"], v["cred_pub"], v["zaehler"], d["clientDataJSON"], d["authenticatorData"], d["signature"])
            except (ValueError, KeyError) as e:
                log.warning("Verwaltung: FIDO-Anmeldung fehlgeschlagen von %s: %s", ip, e)
                return self.json(401, {"fehler": f"Sicherheitsschlüssel abgelehnt: {e}"})
            with _db_lock: c.execute("UPDATE verwaltung SET zaehler=? WHERE id=1", (counter,)); c.commit()
            tok = sitzung_anlegen(c)
            secure = "; Secure" if CFG["SITE_ORIGIN"].startswith("https") else ""
            log.info("Verwaltung: Anmeldung von %s", ip)
            return self.json(200, {"ok": True, "wrappedPriv": json.loads(v["wrapped_priv"]), "kdfSalt": v["kdf_salt"], "encPub": v["enc_pub"]},
                             {"Set-Cookie": f"verwaltung={tok}; Path=/; HttpOnly; SameSite=Strict{secure}; Max-Age={60 * CFG['SITZUNG_MINUTEN']}"})

        if path == "/api/verwaltung/logout":
            tok = self.cookie("verwaltung")
            if tok:
                with _db_lock: c.execute("DELETE FROM sitzungen WHERE token=?", (tok,)); c.commit()
            return self.json(200, {"ok": True}, {"Set-Cookie": "verwaltung=; Path=/; HttpOnly; Max-Age=0"})

        m = re.fullmatch(r"/api/verwaltung/eingaenge/(\d+)/status", path)
        if m:
            if not self.sitzung(c): return self.json(401, {"fehler": "nicht angemeldet"})
            st = d.get("status")
            if st not in ("neu", "in Arbeit", "erledigt"): return self.json(400, {"fehler": "Status"})
            with _db_lock: c.execute("UPDATE eingaenge SET status=? WHERE id=?", (st, int(m.group(1)))); c.commit()
            return self.json(200, {"ok": True})
        return self.json(404, {"fehler": "unbekannt"})

def main():
    if not CFG["ABHOL_TOKEN"] or len(CFG["ABHOL_TOKEN"]) < 32:
        print("ABHOL_TOKEN fehlt oder ist zu kurz (mindestens 32 Zeichen)."); sys.exit(1)
    c = db()
    if not verwaltung(c) and not CFG["SETUP_TOKEN"] and not CFG["OEFFENTLICHER_SCHLUESSEL"]:
        print("Weder Verwaltung eingerichtet noch SETUP_TOKEN oder OEFFENTLICHER_SCHLUESSEL gesetzt."); sys.exit(1)
    srv = ThreadingHTTPServer((CFG["HOST"], CFG["PORT"]), H)
    log.info("Notariat-Server auf http://%s:%s, dist=%s, db=%s, rpId=%s", CFG["HOST"], CFG["PORT"], CFG["DIST"], CFG["DB"], CFG["RP_ID"])
    srv.serve_forever()

if __name__ == "__main__":
    main()
