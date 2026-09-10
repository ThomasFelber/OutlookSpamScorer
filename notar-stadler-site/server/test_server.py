#!/usr/bin/env python3
"""Ende-zu-Ende-Test: Server starten, Fragebogen senden, abholen, entschlüsseln."""
import os, sys, json, threading, tempfile, urllib.request, urllib.parse, urllib.error, pathlib, subprocess
HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(HERE.parent / "src"))
import krypto

tmp = tempfile.mkdtemp()
priv, pub = krypto.neues_schluesselpaar()
os.environ.update({"HOST": "127.0.0.1", "PORT": "8765", "DIST": str(HERE.parent / "dist"), "DB": f"{tmp}/db.sqlite",
                   "SITE_ORIGIN": "http://127.0.0.1:8765", "OEFFENTLICHER_SCHLUESSEL": pub, "ABHOL_TOKEN": "t" * 40, "SMTP_HOST": ""})
import server
srv = server.ThreadingHTTPServer(("127.0.0.1", 8765), server.H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
B = "http://127.0.0.1:8765"

def post(slug, daten, origin=B):
    body = urllib.parse.urlencode(daten).encode()
    req = urllib.request.Request(f"{B}/api/formular/{slug}", data=body, headers={"Origin": origin} if origin else {})
    try:
        with urllib.request.urlopen(req) as r: return r.status, r.read().decode()
    except urllib.error.HTTPError as e: return e.code, e.read().decode()

ok = True
def check(cond, msg):
    global ok
    print(("OK  " if cond else "FEHLER ") + msg); ok = ok and cond

# statische Seite
with urllib.request.urlopen(f"{B}/") as r: check(r.status == 200 and "Notar in Bad Säckingen" in r.read().decode(), "Startseite wird ausgeliefert")
try:
    urllib.request.urlopen(f"{B}/../server/server.py"); check(False, "Pfad-Ausbruch")
except urllib.error.HTTPError as e: check(e.code == 404, "Pfad-Ausbruch abgewehrt")

# Fragebogen gültig
daten = {"vk_name": "Erika Mustermann", "kf_name": "Max Muster", "ob_adr": "Rheinstraße 1, Bad Säckingen", "kp_betrag": "300000",
         "kp_fin": "Eigenmittel", "rf_name": "Max Muster", "rf_tel": "0170 0000000", "rf_bem": "Zeile 1\nZeile 2", "datenschutz": "ja"}
st, body = post("kaufvertrag", daten)
check(st == 200 and "KV-" in body and "Erika" not in body, f"Gültiger Fragebogen angenommen ({st}), Bestätigung ohne Daten")
nummer = body.split("Vorgangsnummer: <strong>")[1].split("<")[0]

# Fehlerfälle
check(post("kaufvertrag", {**daten, "datenschutz": ""})[0] == 400, "Ohne Datenschutz-Haken abgelehnt")
check(post("kaufvertrag", {**daten, "rf_tel": ""})[0] == 400, "Fehlendes Pflichtfeld abgelehnt")
check(post("kaufvertrag", {**daten, "kp_fin": "Bargeld"})[0] == 400, "Ungültige Auswahl abgelehnt")
check(post("kaufvertrag", {**daten, "hacker": "x"})[0] == 400, "Unbekanntes Feld abgelehnt")
check(post("kaufvertrag", daten, origin="https://boese.example")[0] == 403, "Fremde Herkunft abgelehnt")
st, body = post("kaufvertrag", {**daten, "firma_web": "spam"}); check(st == 200 and "Vorgangsnummer" not in body, "Honeypot: scheinbar angenommen, nicht gespeichert")
check(post("gibtesnicht", daten)[0] == 404, "Unbekanntes Formular 404")

# Abholen
req = urllib.request.Request(f"{B}/api/eingaenge", headers={"Authorization": "Bearer " + "t" * 40})
rows = json.load(urllib.request.urlopen(req))
check(len(rows) == 1 and rows[0]["nummer"] == nummer, "Genau ein Eingang gespeichert")
check("Erika" not in json.dumps(rows), "Datenbankinhalt enthält keinen Klartext")
klar = json.loads(krypto.entschluesseln(priv, rows[0], nummer.encode()))
check(klar["felder"]["vk_name"] == "Erika Mustermann" and klar["felder"]["rf_bem"] == "Zeile 1\nZeile 2", "Entschlüsselung mit privatem Schlüssel korrekt")
_, pub2 = krypto.neues_schluesselpaar(); priv2, _ = krypto.neues_schluesselpaar()
try: krypto.entschluesseln(priv2, rows[0], nummer.encode()); check(False, "Fremder Schlüssel")
except Exception: check(True, "Fremder Schlüssel kann nicht entschlüsseln")
try: urllib.request.urlopen(f"{B}/api/eingaenge"); check(False, "Abholen ohne Token")
except urllib.error.HTTPError as e: check(e.code == 401, "Abholen ohne Token abgelehnt")

# abholen.py als Programm
(pathlib.Path(tmp) / "privat.key").write_text(priv)
env = {**os.environ, "SERVER_URL": B, "ABHOL_TOKEN": "t" * 40, "PRIVATER_SCHLUESSEL_DATEI": f"{tmp}/privat.key", "AUSGABE": f"{tmp}/eingaenge"}
out = subprocess.run([sys.executable, str(HERE / "abholen.py"), "--loeschen"], env=env, capture_output=True, text=True).stdout
txt = (pathlib.Path(tmp) / "eingaenge" / f"{nummer}.txt").read_text()
check(nummer in out and "Erika Mustermann" in txt and "Rückfragen" in txt, "abholen.py schreibt lesbare Datei")
rows = json.load(urllib.request.urlopen(req)); check(rows == [], "Nach --loeschen ist der Server leer")

# Rate-Limit
codes = [post("beglaubigung", {"do_art": "Beglaubigte Kopie", "rf_name": "A", "rf_tel": "1", "datenschutz": "ja"})[0] for _ in range(12)]
check(429 in codes, "Rate-Limit greift")
srv.shutdown()
print("\nERGEBNIS:", "alle Tests bestanden" if ok else "FEHLER")
sys.exit(0 if ok else 1)
