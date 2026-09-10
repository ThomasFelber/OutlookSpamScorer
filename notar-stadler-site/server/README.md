# Fragebogen-Annahme

Eigener Server statt notar-formulare.de. Ein Python-Prozess liefert die statische Seite aus und nimmt die Fragebögen an.

## Ablauf einer Übermittlung

1. Der Mandant sendet den Fragebogen als normales HTML-Formular (kein JavaScript, keine Cookies).
2. Der Server prüft die Felder gegen das Schema in `src/formulare.py` (Pflichtfelder, erlaubte Auswahlwerte, Längen), Honeypot, Herkunft (Origin) und Rate-Limit.
3. Die Angaben werden mit dem **öffentlichen Schlüssel des Notariats** verschlüsselt (X25519 + AES-256-GCM) und in SQLite gespeichert. Der Server kann sie danach selbst nicht mehr lesen.
4. Das Notariat erhält eine E-Mail: Formular, Zeit, Vorgangsnummer. Keine Mandantendaten.
5. Der Mandant sieht eine Bestätigungsseite mit der Vorgangsnummer.
6. Im Büro holt `abholen.py` die Eingänge ab und entschlüsselt sie mit dem privaten Schlüssel zu lesbaren Textdateien.

## Einrichtung

```
# im Büro, einmalig
python3 schluessel.py erzeugen ~/notariat-schluessel
# privat.key bleibt im Büro (Sicherungskopie!), oeffentlich.key kommt in config.env

# auf dem Server (Debian/Ubuntu)
apt install python3 python3-cryptography caddy
adduser --system --group notariat
mkdir -p /srv/notariat/daten && chown notariat /srv/notariat/daten
# Repository-Ordner nach /srv/notariat kopieren, python3 build.py ausführen
cp server/config.example.env server/config.env   # ausfüllen
cp server/notariat.service /etc/systemd/system/ && systemctl enable --now notariat
cp server/Caddyfile /etc/caddy/Caddyfile && systemctl reload caddy
```

Caddy besorgt das TLS-Zertifikat automatisch und setzt die Sicherheits-Header.

## Abholen im Büro

```
# abholen.env neben abholen.py:
SERVER_URL=https://notar-stadler.de
ABHOL_TOKEN=...
PRIVATER_SCHLUESSEL_DATEI=/pfad/zu/privat.key
AUSGABE=/pfad/zu/eingaenge

python3 abholen.py            # neue Eingänge entschlüsseln
python3 abholen.py --loeschen # zusätzlich vom Server löschen
```

## Datenschutz

- Übertragung TLS, Speicherung verschlüsselt, Schlüssel nur im Büro.
- Keine Cookies, keine Sitzungen, keine Drittanbieter.
- Server-Protokoll enthält IP, Zeit, Formular und Vorgangsnummer, keine Feldinhalte.
- Eingänge werden nach dem Abholen gelöscht (`--loeschen`); Aufbewahrung danach nach Notarrecht im Büro.

## Test

```
python3 server/test_server.py
```
