# Musterseite Notariat Stadler, Bad Säckingen

Statische Musterseite als Vorschlag für den neuen Internetauftritt. Keine Datenbank, kein CMS, keine Dienste Dritter, keine externen Schriften oder Skripte. Build nur mit Python-Standardbibliothek.

## Aufbau

- `src/pages/*.html` – Inhalt je Seite (Fragment ohne Kopf und Fuß)
- `src/style.css` – Gestaltung, Farben und Schriften als Tokens am Dateianfang
- `build.py` – erzeugt `dist/` (eine Datei je Seite, `sitemap.xml`, `robots.txt`) und `preview.html` (alle Seiten in einer Datei mit Hash-Navigation, zur Vorschau)

```
python3 build.py
```

## Seiten

Start · Leistungen (Immobilien, Vererben, Schenken, Vorsorge, Familie, Unternehmen, Beglaubigungen und Schweiz) · Ablauf & Unterlagen · Kosten · Glossar · Kanzlei · Kontakt · Impressum · Datenschutz

## Platzhalter

Alles in eckigen Klammern (rot hinterlegt) ist vor Veröffentlichung zu ersetzen: E-Mail, Fax, USt-IdNr., Werdegang, Team, Zugang und Parken, Fotos, Anfahrtsskizze, Anschriften von Aufsichtsbehörde und Kammer, Hosting-Anbieter.

Assets der bestehenden Seite (Logo, Fotos) konnten nicht übernommen werden, weil die Domain aus der Build-Umgebung nicht erreichbar war. Bildflächen sind als schraffierte Platzhalter markiert.

## Vor Veröffentlichung

- Kontaktformular an einen Mailversand auf dem eigenen Server anbinden
- Texte durch den Notar auf Berufsrecht prüfen (§ 29 BNotO, Richtlinien der Notarkammer Baden-Württemberg)
- Kostenbeispiele gegen aktuelle GNotKG-Tabelle prüfen
- 301-Weiterleitungen: www → Domain, alter Strato-Alias → Domain, alte Pfade `/Leistungen/...` → neue Seiten
