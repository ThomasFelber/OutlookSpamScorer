# Annahme und Verwaltung der Eingänge

Eigener Server statt notar-formulare.de. Ein Python-Prozess liefert die Seite aus, nimmt Fragebögen und Kontaktanfragen an und stellt dem Notariat die Verwaltungsoberfläche unter `/verwaltung/` bereit.

## Ablauf einer Übermittlung

1. Der Mandant sendet Fragebogen oder Kontaktanfrage als normales HTML-Formular (kein JavaScript, keine Cookies).
2. Der Server prüft gegen das Schema in `src/formulare.py` (Pflichtfelder, Auswahlwerte, Längen), Honeypot, Herkunft und Rate-Limit.
3. Die Angaben werden mit dem **öffentlichen Schlüssel des Notariats** verschlüsselt (ECDH P-256 + HKDF + AES-256-GCM) und in SQLite gespeichert. Der Server kann sie danach nicht mehr lesen.
4. Der Mandant erhält eine **sechsstellige Referenz** (Buchstaben und Ziffern ohne 0, O, 1, I, L), zum Beispiel `WBAB9F`.
5. Das Notariat erhält eine E-Mail: Art, Zeit, Referenz. Keine Mandantendaten.
6. Im Büro öffnet das Notariat `/verwaltung/`, meldet sich mit **Passwort und YubiKey** an und liest die Eingänge. Entschlüsselt wird im Browser; der Server sieht keinen Klartext.

## Verwaltung: Passwort und YubiKey

- Anmeldung nach WebAuthn (FIDO2) mit Nutzerverifikation (PIN am YubiKey) und der **PRF-Erweiterung**: Der YubiKey leitet aus einem gespeicherten Geheimnis einen Wert ab, der zusammen mit dem Passwort den privaten Entschlüsselungsschlüssel entpackt. Ohne YubiKey oder ohne Passwort bleibt der Schlüssel verschlossen, auch für jemanden mit Zugriff auf Server und Datenbank.
- Der private Schlüssel entsteht bei der Einrichtung im Browser und liegt auf dem Server nur verpackt. Die Einrichtung zeigt ihn einmal als **Sicherungskopie** an: ausdrucken, in den Tresor. Er ist der einzige Weg, die Eingänge nach Verlust des YubiKeys zu lesen.
- Voraussetzungen: YubiKey 5 (hmac-secret) und ein aktueller Browser mit PRF-Unterstützung (Chrome, Edge, Firefox 135+, Safari 18+), HTTPS.
- Sitzung: Cookie `verwaltung`, HttpOnly, SameSite=Strict, 30 Minuten Inaktivität. Fünf Fehlversuche je 15 Minuten und IP.
- Funktionen: Liste mit Suche nach Referenz, Status neu / in Arbeit / erledigt, Anzeige mit Feldbezeichnungen, Drucken, Löschen vom Server.

## Einrichtung

```
# auf dem Server (Debian/Ubuntu)
apt install python3 python3-cryptography caddy
adduser --system --group notariat
mkdir -p /srv/notariat/daten && chown notariat /srv/notariat/daten
# Repository nach /srv/notariat kopieren, python3 build.py ausführen
cp server/config.example.env server/config.env      # SETUP_TOKEN, ABHOL_TOKEN, SMTP ausfüllen
cp server/notariat.service /etc/systemd/system/ && systemctl enable --now notariat
cp server/Caddyfile /etc/caddy/Caddyfile && systemctl reload caddy

# im Büro, einmalig: https://notar-stadler.de/verwaltung/ öffnen, Einrichtungs-Token und Passwort
# eingeben, YubiKey registrieren, Sicherungskopie des Schlüssels drucken.
# Danach SETUP_TOKEN aus config.env entfernen und den Dienst neu starten.
```

## Sicherungsweg ohne Browser

`abholen.py` holt die Eingänge per `ABHOL_TOKEN` ab und entschlüsselt sie mit der Sicherungskopie des privaten Schlüssels zu lesbaren Textdateien:

```
SERVER_URL=https://notar-stadler.de ABHOL_TOKEN=... PRIVATER_SCHLUESSEL_DATEI=/pfad/privat.key python3 abholen.py [--loeschen]
```

`schluessel.py erzeugen` erzeugt ein Schlüsselpaar für den Betrieb ganz ohne Verwaltungsoberfläche (`OEFFENTLICHER_SCHLUESSEL` in der Konfiguration).

## Datenschutz

- Übertragung TLS, Speicherung verschlüsselt, Entschlüsselung nur im Browser des Notariats.
- Besucherseite ohne Cookies; nur die Verwaltung setzt ein Sitzungs-Cookie für das Notariat.
- Server-Protokoll enthält IP, Zeit, Art und Referenz, keine Feldinhalte.
- Eingänge nach Übernahme in die Akte vom Server löschen; Aufbewahrung danach nach Notarrecht im Büro.

## Test

```
python3 server/test_server.py
```

31 Prüfungen: Annahme, Referenzformat, Ablehnungen, Einrichtung und Anmeldung mit simuliertem YubiKey, Entpacken des Schlüssels, Entschlüsselung, Status, Abmeldung, Abholung, Rate-Limit.
