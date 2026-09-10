# Musterseite Notariat Stadler, Bad Säckingen

Statische Musterseite als Vorschlag für den neuen Internetauftritt. Kein CMS, keine Dienste Dritter, keine externen Schriften oder Skripte, kein JavaScript. Build nur mit Python-Standardbibliothek; der Annahme-Server braucht zusätzlich `cryptography`.

## Aufbau

- `src/pages/*.html` – Inhalt je Seite (Fragment ohne Kopf und Fuß)
- `src/style.css` – Gestaltung, Farben und Schriften als Tokens am Dateianfang
- `build.py` – erzeugt `dist/` (eine Datei je Seite, `sitemap.xml`, `robots.txt`) und `preview.html` (alle Seiten in einer Datei mit Hash-Navigation, zur Vorschau)

```
python3 build.py
```

## Fragebögen und Server

`src/formulare.py` beschreibt alle 14 Fragebögen als Schema; `build.py` erzeugt daraus die Seiten. `server/` enthält den Annahme-Server (verschlüsselte Speicherung, E-Mail ohne Mandantendaten, Abholwerkzeug für das Büro), siehe `server/README.md`.

## Seiten

Start · Leistungen (Immobilien, Vererben, Schenken, Vorsorge, Familie, Unternehmen, Beglaubigungen und Schweiz) · Ablauf & Unterlagen · Fragebögen (Kaufvertrag, GmbH, Vorsorgevollmacht) · Kosten · Glossar · Kanzlei · Offene Stellen · Kontakt · Impressum · Datenschutz

## Platzhalter

Alles in eckigen Klammern (ocker hinterlegt) ist vor Veröffentlichung zu ersetzen oder zu prüfen: Etage und Zugang, Gehzeit vom Bahnhof, Hosting-Anbieter, Datenschutzbeauftragter, Zuordnung der Team-Porträts, Formulierung zur Streitbeilegung.

## Fotos

`src/img/photos/` enthält die Aufnahmen der bisherigen Seite (Kanzlei, Notar, Team, Landeswappen), neu komprimiert und umbenannt. Die Zuordnung der Team-Porträts zu Namen folgt der Reihenfolge auf der bisherigen Team-Seite und ist vor Veröffentlichung zu prüfen. Fünf Mitarbeitende haben dort kein Foto.

`{{img:datei.jpg|Alt-Text|object-position}}` in einem Seitenfragment wird zu `<img>`; in `preview.html` sind die Bilder als Daten-URIs eingebettet, in `dist/img/` liegen sie als Dateien.

## Vor Veröffentlichung

- Kontaktformular an einen Mailversand auf dem eigenen Server anbinden (die Fragebögen sind bereits über `server/` angebunden)
- Liste der Fragebögen mit dem bisherigen Bereich auf notar-formulare.de/stadler abgleichen
- Texte durch den Notar auf Berufsrecht prüfen (§ 29 BNotO, Richtlinien der Notarkammer Baden-Württemberg)
- Kostenbeispiele gegen aktuelle GNotKG-Tabelle prüfen
- 301-Weiterleitungen: www → Domain, alter Strato-Alias → Domain, alte Pfade `/Leistungen/...` → neue Seiten
