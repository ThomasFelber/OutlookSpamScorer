#!/usr/bin/env python3
"""Erzeugt das Schlüsselpaar des Notariats.

  python3 schluessel.py erzeugen [verzeichnis]

Schreibt privat.key (bleibt im Büro, nie auf den Server) und oeffentlich.key (kommt in die Server-Konfiguration).
"""
import sys, os, pathlib
sys.path.insert(0, os.path.dirname(__file__))
import krypto

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] != "erzeugen":
        print(__doc__); sys.exit(1)
    d = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else ".")
    d.mkdir(parents=True, exist_ok=True)
    if (d / "privat.key").exists():
        print("privat.key existiert bereits, Abbruch."); sys.exit(1)
    priv, pub = krypto.neues_schluesselpaar()
    (d / "privat.key").write_text(priv + "\n"); os.chmod(d / "privat.key", 0o600)
    (d / "oeffentlich.key").write_text(pub + "\n")
    print("privat.key      -> im Büro aufbewahren, Sicherungskopie anlegen, NIE auf den Server")
    print("oeffentlich.key -> Wert als OEFFENTLICHER_SCHLUESSEL in die Server-Konfiguration")
    print("Öffentlicher Schlüssel:", pub)
