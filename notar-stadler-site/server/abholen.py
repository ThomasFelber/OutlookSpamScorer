#!/usr/bin/env python3
"""Holt neue Fragebögen vom Server und entschlüsselt sie im Büro.

  python3 abholen.py [--loeschen] [--ab ID]

Liest Umgebungsvariablen (oder abholen.env im gleichen Ordner):
  SERVER_URL       https://notar-stadler.de
  ABHOL_TOKEN      wie auf dem Server
  PRIVATER_SCHLUESSEL_DATEI  Pfad zu privat.key
  AUSGABE          Ordner für die entschlüsselten Fragebögen (Standard: eingaenge/)

Je Eingang entstehen NUMMER.txt (lesbar, druckbar) und NUMMER.json.
Mit --loeschen wird ein Eingang nach erfolgreichem Entschlüsseln vom Server gelöscht.
"""
import os, sys, json, pathlib, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import krypto
import formulare as F

def lade_env():
    p = pathlib.Path(__file__).with_name("abholen.env")
    if p.exists():
        for line in p.read_text().splitlines():
            if "=" in line and not line.strip().startswith("#"):
                k, v = line.split("=", 1); os.environ.setdefault(k.strip(), v.strip())

def lesbar(d):
    form = F.BY_SLUG.get(d["formular"])
    out = [f"{d['titel']}  ·  {d['nummer']}  ·  eingegangen {d['zeit']}", "=" * 70, ""]
    if form:
        for sec in form["sections"]:
            zeilen = [(fl["label"], d["felder"][fl["name"]]) for fl in sec["fields"] if d["felder"].get(fl["name"])]
            if not zeilen: continue
            out.append(sec["title"]); out.append("-" * len(sec["title"]))
            for label, wert in zeilen:
                out.append(f"  {label}: {wert}" if "\n" not in wert else f"  {label}:\n    " + wert.replace("\n", "\n    "))
            out.append("")
    else:
        for k, v in d["felder"].items(): out.append(f"  {k}: {v}")
    return "\n".join(out)

def main():
    lade_env()
    url = os.environ["SERVER_URL"].rstrip("/"); token = os.environ["ABHOL_TOKEN"]
    priv = pathlib.Path(os.environ.get("PRIVATER_SCHLUESSEL_DATEI", "privat.key")).read_text().strip()
    ausgabe = pathlib.Path(os.environ.get("AUSGABE", "eingaenge")); ausgabe.mkdir(exist_ok=True)
    loeschen = "--loeschen" in sys.argv
    ab = int(sys.argv[sys.argv.index("--ab") + 1]) if "--ab" in sys.argv else 0
    req = urllib.request.Request(f"{url}/api/eingaenge?ab={ab}", headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=30) as r: rows = json.load(r)
    if not rows: print("Keine neuen Eingänge."); return
    for row in rows:
        try:
            klar = krypto.entschluesseln(priv, row, row["nummer"].encode())
        except Exception as e:
            print(f"{row['nummer']}: Entschlüsselung fehlgeschlagen ({e})"); continue
        d = json.loads(klar)
        (ausgabe / f"{row['nummer']}.json").write_text(json.dumps(d, ensure_ascii=False, indent=2))
        (ausgabe / f"{row['nummer']}.txt").write_text(lesbar(d))
        print(f"{row['nummer']}  {d['titel']}  ({d['zeit']})  -> {ausgabe / (row['nummer'] + '.txt')}")
        if loeschen:
            dreq = urllib.request.Request(f"{url}/api/eingaenge/{row['id']}", method="DELETE", headers={"Authorization": f"Bearer {token}"})
            urllib.request.urlopen(dreq, timeout=30).read()

if __name__ == "__main__":
    main()
