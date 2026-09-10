#!/usr/bin/env python3
"""Ende-zu-Ende-Test: Annahme, Referenzen, Verwaltung mit simuliertem YubiKey, Entschlüsselung, Abholung."""
import os, sys, json, threading, tempfile, urllib.request, urllib.parse, urllib.error, pathlib, subprocess, hashlib, struct, base64, http.cookiejar
HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(HERE.parent / "src"))
import krypto, webauthn
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

tmp = tempfile.mkdtemp()
B = "http://127.0.0.1:8765"
os.environ.update({"HOST": "127.0.0.1", "PORT": "8765", "DIST": str(HERE.parent / "dist"), "DB": f"{tmp}/db.sqlite",
                   "SITE_ORIGIN": B, "RP_ID": "127.0.0.1", "SETUP_TOKEN": "einrichtung-test-token", "ABHOL_TOKEN": "t" * 40, "SMTP_HOST": ""})
import server
srv = server.ThreadingHTTPServer(("127.0.0.1", 8765), server.H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

ok = True
def check(cond, msg):
    global ok
    print(("OK  " if cond else "FEHLER ") + msg); ok = ok and cond

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

def post_form(slug, daten, origin=B, lang=""):
    body = urllib.parse.urlencode(daten).encode()
    req = urllib.request.Request(f"{B}/api/formular/{slug}{lang}", data=body, headers={"Origin": origin} if origin else {})
    try:
        with urllib.request.urlopen(req) as r: return r.status, r.read().decode()
    except urllib.error.HTTPError as e: return e.code, e.read().decode()

def api(path, body=None, method=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{B}/api/verwaltung/{path}", data=data, method=method or ("POST" if body is not None else "GET"),
                                 headers={"Origin": B, "Content-Type": "application/json"})
    try:
        with opener.open(req) as r: return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read().decode() or "{}")

# ---- Simulierter YubiKey (Software-Authenticator mit PRF) ----
def cbor(v):
    if isinstance(v, int) and v >= 0: return _hd(0, v)
    if isinstance(v, int): return _hd(1, -1 - v)
    if isinstance(v, bytes): return _hd(2, len(v)) + v
    if isinstance(v, str): b = v.encode(); return _hd(3, len(b)) + b
    if isinstance(v, list): return _hd(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict): return _hd(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())
    raise TypeError(v)
def _hd(mt, n):
    if n < 24: return bytes([(mt << 5) | n])
    if n < 256: return bytes([(mt << 5) | 24, n])
    if n < 65536: return bytes([(mt << 5) | 25]) + struct.pack(">H", n)
    return bytes([(mt << 5) | 26]) + struct.pack(">I", n)

class SoftKey:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1()); self.cred_id = os.urandom(16); self.counter = 0; self.prf_secret = os.urandom(32)
    def prf(self, salt):
        import hmac as _h; return _h.new(self.prf_secret, salt, hashlib.sha256).digest()
    def create(self, rp_id, challenge, origin):
        nums = self.key.public_key().public_numbers()
        cose = {1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")}
        auth = hashlib.sha256(rp_id.encode()).digest() + bytes([0x45]) + struct.pack(">I", 0) + b"\0" * 16 + struct.pack(">H", len(self.cred_id)) + self.cred_id + cbor(cose)
        att = cbor({"fmt": "none", "attStmt": {}, "authData": auth})
        cd = json.dumps({"type": "webauthn.create", "challenge": challenge, "origin": origin}).encode()
        return webauthn.b64url_encode(cd), webauthn.b64url_encode(att)
    def get(self, rp_id, challenge, origin):
        self.counter += 1
        auth = hashlib.sha256(rp_id.encode()).digest() + bytes([0x05]) + struct.pack(">I", self.counter)
        cd = json.dumps({"type": "webauthn.get", "challenge": challenge, "origin": origin}).encode()
        sig = self.key.sign(auth + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        return webauthn.b64url_encode(cd), webauthn.b64url_encode(auth), webauthn.b64url_encode(sig)

def unwrap_key(prf, password, kdf_salt):
    pw = PBKDF2HMAC(hashes.SHA256(), 32, kdf_salt, 200000).derive(password.encode())
    return HKDF(hashes.SHA256(), 32, kdf_salt, b"verwaltung-unwrap-v1").derive(prf + pw)

# ---- Vor der Einrichtung: Annahme verweigert ----
daten = {"vk_name": "Erika Mustermann", "kf_name": "Max Muster", "ob_adr": "Rheinstraße 1, Bad Säckingen", "kp_betrag": "300000",
         "kp_fin": "Eigenmittel", "rf_name": "Max Muster", "rf_tel": "0170 0000000", "rf_bem": "Zeile 1\nZeile 2", "datenschutz": "ja"}
check(post_form("kaufvertrag", daten)[0] == 503, "Ohne eingerichteten Schlüssel wird nichts angenommen")

# ---- Einrichtung mit simuliertem YubiKey ----
yk = SoftKey(); PW = "Notariat-Sicher-2026!"
check(api("einrichten/start", {"setup_token": "falsch"})[0] == 403, "Falsches Einrichtungs-Token abgelehnt")
st, o = api("einrichten/start", {"setup_token": "einrichtung-test-token"}); check(st == 200 and o["rp"]["id"] == "127.0.0.1", "Einrichtung gestartet")
cd, att = yk.create(o["rp"]["id"], o["challenge"], B)
prf = yk.prf(webauthn.b64url_decode(o["prfSalt"]))
priv_hex, pub_hex = krypto.neues_schluesselpaar()
wk = unwrap_key(prf, PW, webauthn.b64url_decode(o["kdfSalt"]))
iv = os.urandom(12); wrapped = {"iv": base64.b64encode(iv).decode(), "ct": base64.b64encode(AESGCM(wk).encrypt(iv, priv_hex.encode(), None)).decode()}
payload = {"setup_token": "einrichtung-test-token", "challenge": o["challenge"], "clientDataJSON": cd, "attestationObject": att, "prfEnabled": True,
           "password": PW, "encPub": pub_hex, "wrappedPriv": wrapped, "prfSalt": o["prfSalt"], "kdfSalt": o["kdfSalt"]}
check(api("einrichten/abschluss", {**payload, "password": "kurz"})[0] == 400, "Kurzes Passwort abgelehnt")
st, r = api("einrichten/abschluss", {**payload, "challenge": o["challenge"]})
check(st == 200, f"Einrichtung abgeschlossen ({st} {r})")
check(api("einrichten/start", {"setup_token": "einrichtung-test-token"})[0] == 409, "Zweite Einrichtung abgelehnt")

# ---- Annahme: Fragebogen und Kontaktanfrage, Referenzformat ----
st, body = post_form("kaufvertrag", daten)
check(st == 200 and "Referenz" in body and "Erika" not in body, f"Fragebogen angenommen ({st}), Bestätigung ohne Daten")
ref = body.split('class="ref">')[1].split("<")[0]
check(len(ref) == 6 and all(ch in krypto.REF_ZEICHEN for ch in ref) and not set(ref) & set("0O1IL"), f"Referenz sechsstellig ohne verwechselbare Zeichen: {ref}")
st, body = post_form("anfrage", {"an_name": "Anna Beispiel", "an_tel": "0761 1", "an_anliegen": "Beglaubigung", "an_text": "Frage", "datenschutz": "ja"}, lang="?lang=en")
check(st == 200 and "Your reference" in body, "Kontaktanfrage angenommen, englische Bestätigung")
check(post_form("kaufvertrag", {**daten, "datenschutz": ""})[0] == 400, "Ohne Datenschutz-Haken abgelehnt")
check(post_form("kaufvertrag", {**daten, "kp_fin": "Bargeld"})[0] == 400, "Ungültige Auswahl abgelehnt")
check(post_form("kaufvertrag", daten, origin="https://boese.example")[0] == 403, "Fremde Herkunft abgelehnt")
st, body = post_form("kaufvertrag", {**daten, "firma_web": "spam"}); check(st == 200 and "Referenz:" not in body, "Honeypot: nicht gespeichert")

# ---- Verwaltung: Anmeldung ----
check(api("eingaenge")[0] == 401, "Liste ohne Anmeldung gesperrt")
check(api("login", {"password": "falsch"})[0] == 401, "Falsches Passwort abgelehnt")
st, o = api("login", {"password": PW}); check(st == 200 and o["credentialId"], "Passwort akzeptiert, FIDO-Challenge erhalten")
cd, ad, sig = yk.get(o["rpId"], o["challenge"], B)
st, r = api("login/abschluss", {"challenge": o["challenge"], "credentialId": o["credentialId"], "clientDataJSON": cd, "authenticatorData": ad, "signature": sig})
check(st == 200 and r["wrappedPriv"]["ct"] == wrapped["ct"], f"YubiKey-Anmeldung akzeptiert, verpackter Schlüssel erhalten ({st})")
check(api("login/abschluss", {"challenge": o["challenge"], "credentialId": o["credentialId"], "clientDataJSON": cd, "authenticatorData": ad, "signature": sig})[0] == 400, "Wiederverwendete Challenge abgelehnt")
# Entpacken wie im Browser
prf2 = yk.prf(webauthn.b64url_decode(o["prfSalt"]))
wk2 = unwrap_key(prf2, PW, webauthn.b64url_decode(r["kdfSalt"]))
priv2 = AESGCM(wk2).decrypt(base64.b64decode(r["wrappedPriv"]["iv"]), base64.b64decode(r["wrappedPriv"]["ct"]), None).decode()
check(priv2 == priv_hex, "Privater Schlüssel mit PRF + Passwort entpackt")
try: AESGCM(unwrap_key(prf2, "anderes-Passwort-123", webauthn.b64url_decode(r["kdfSalt"]))).decrypt(base64.b64decode(r["wrappedPriv"]["iv"]), base64.b64decode(r["wrappedPriv"]["ct"]), None); check(False, "Falsches Passwort entpackt")
except Exception: check(True, "Ohne richtiges Passwort kein Entpacken")
try: AESGCM(unwrap_key(os.urandom(32), PW, webauthn.b64url_decode(r["kdfSalt"]))).decrypt(base64.b64decode(r["wrappedPriv"]["iv"]), base64.b64decode(r["wrappedPriv"]["ct"]), None); check(False, "Fremder YubiKey entpackt")
except Exception: check(True, "Ohne richtigen YubiKey kein Entpacken")

# ---- Liste, Entschlüsselung, Status, Löschen ----
st, rows = api("eingaenge"); check(st == 200 and len(rows) == 2, "Zwei Eingänge in der Verwaltung")
check("Erika" not in json.dumps(rows) and "Anna" not in json.dumps(rows), "Liste enthält keinen Klartext")
row = [x for x in rows if x["referenz"] == ref][0]
klar = json.loads(krypto.entschluesseln(priv2, row, ref.encode()))
check(klar["felder"]["vk_name"] == "Erika Mustermann" and klar["referenz"] == ref, "Eingang mit entpacktem Schlüssel entschlüsselt")
st, sch = api("schema"); check(st == 200 and "anfrage" in sch and sch["kaufvertrag"]["sections"][0]["fields"][0]["label"] == "Vor- und Nachname", "Schema für die Anzeige")
check(api(f"eingaenge/{row['id']}/status", {"status": "erledigt"})[0] == 200, "Status gesetzt")
check([x for x in api("eingaenge")[1] if x["id"] == row["id"]][0]["status"] == "erledigt", "Status gespeichert")
check(api("logout", {})[0] == 200 and api("eingaenge")[0] == 401, "Abmeldung beendet die Sitzung")

# ---- Sicherungsweg abholen.py mit dem gesicherten privaten Schlüssel ----
(pathlib.Path(tmp) / "privat.key").write_text(priv_hex)
env = {**os.environ, "SERVER_URL": B, "ABHOL_TOKEN": "t" * 40, "PRIVATER_SCHLUESSEL_DATEI": f"{tmp}/privat.key", "AUSGABE": f"{tmp}/eingaenge"}
out = subprocess.run([sys.executable, str(HERE / "abholen.py"), "--loeschen"], env=env, capture_output=True, text=True)
txt = (pathlib.Path(tmp) / "eingaenge" / f"{ref}.txt").read_text()
check(ref in out.stdout and "Erika Mustermann" in txt and "Rückfragen" in txt, "abholen.py entschlüsselt mit Sicherungsschlüssel")
req = urllib.request.Request(f"{B}/api/eingaenge", headers={"Authorization": "Bearer " + "t" * 40})
check(json.load(urllib.request.urlopen(req)) == [], "Nach --loeschen ist der Server leer")

# ---- Rate-Limit ----
codes = [post_form("beglaubigung", {"do_art": "Beglaubigte Kopie", "rf_name": "A", "rf_tel": "1", "datenschutz": "ja"})[0] for _ in range(12)]
check(429 in codes, "Rate-Limit greift")
srv.shutdown()
print("\nERGEBNIS:", "alle Tests bestanden" if ok else "FEHLER")
sys.exit(0 if ok else 1)
