#!/usr/bin/env python3
"""Baut die statische Musterseite für das Notariat Stadler.

  python3 build.py            -> dist/  (eine HTML-Datei je Seite, sitemap, robots)
                                 preview.html (alle Seiten in einer Datei, Hash-Navigation)
"""
import re, html, pathlib, datetime, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent / "src"))
import formulare as F
import en as EN

def tr(s, lang):
    """Übersetzt einen Schema- oder UI-String; meldet fehlende Übersetzungen."""
    if lang == "de" or not s: return s
    r = EN.T.get(s) or EN.UI.get(s)
    if r is None:
        print("FEHLENDE ÜBERSETZUNG:", s); return s
    return r

ROOT = pathlib.Path(__file__).parent
SRC = ROOT / "src"
DIST = ROOT / "dist"
DOMAIN = "https://notar-stadler.de"

# slug, Navigationstitel, <title>, Meta-Description
PAGES = [
    ("index",         "Start",               "Notar Kai-Christoph Stadler · Bad Säckingen",              "Notar in Bad Säckingen: Beurkundungen und Beratung bei Immobilien, Erbe, Vorsorge, Familie und Unternehmen. Scheffelstraße 23, Telefon 07761 92617-0."),
    ("leistungen",    "Leistungen",          "Leistungen · Notar Stadler, Bad Säckingen",                "Überblick: Wobei ein Notar hilft. Immobilien, Vererben, Schenken, Vorsorge, Familie, Unternehmen, Beglaubigungen."),
    ("immobilien",    None,                  "Immobilien · Notar Stadler, Bad Säckingen",                "Kauf und Verkauf von Haus, Wohnung und Grundstück: Ablauf, Unterlagen, Grundschuld, Übertragung in der Familie."),
    ("vererben",      None,                  "Testament und Erbvertrag · Notar Stadler",                 "Testament, Erbvertrag, Erbschein, Pflichtteil: verständlich erklärt. Beurkundung in Bad Säckingen."),
    ("schenken",      None,                  "Schenken und Übergabe · Notar Stadler",                    "Schenkung und vorweggenommene Erbfolge: Haus zu Lebzeiten übertragen, Wohnrecht, Nießbrauch, Rückforderungsrechte."),
    ("vorsorge",      None,                  "Vorsorgevollmacht und Patientenverfügung · Notar Stadler", "Vorsorgevollmacht, Patientenverfügung, Betreuungsverfügung: was sie regeln und wie die Beurkundung abläuft."),
    ("familie",       None,                  "Ehevertrag und Familie · Notar Stadler",                   "Ehevertrag, Scheidungsfolgenvereinbarung, Adoption, Vaterschaftsanerkennung: notarielle Beurkundung in Bad Säckingen."),
    ("unternehmen",   None,                  "Unternehmen und Gesellschaften · Notar Stadler",           "GmbH-Gründung, Geschäftsanteile, Handelsregister, Online-Beurkundung: notarielle Leistungen für Unternehmen."),
    ("beglaubigungen",None,                  "Beglaubigungen und Schweiz · Notar Stadler",               "Unterschriftsbeglaubigung, Abschriften, Apostille, Dokumente für die Schweiz und das Ausland."),
    ("ablauf",        "Ablauf & Unterlagen", "Ablauf und Unterlagen · Notar Stadler",                    "So läuft ein Termin beim Notar ab und was Sie mitbringen: Checklisten für Kauf, Testament, Vollmacht, Gründung."),
    ("fragebogen",    "Fragebögen",          "Fragebögen · Notar Stadler",                                "Alle Fragebögen zur Terminvorbereitung: Kaufvertrag, Wohnung, Grundschuld, Übergabe, Testament, Erbschein, Vollmacht, Ehevertrag, Scheidung, GmbH, Anteile, Handelsregister, Verein, Beglaubigung."),
] + [
    (f"fragebogen-{x['slug']}", None, f"Fragebogen {x['title']} · Notar Stadler", x["lead"]) for x in F.FORMS
] + [
    ("kosten",        "Kosten",              "Kosten · Notar Stadler, Bad Säckingen",                    "Notarkosten sind gesetzlich festgelegt (GNotKG) und bei jedem Notar gleich. Beispiele und Erklärung."),
    ("glossar",       None,                  "Glossar · Notar Stadler",                                  "Begriffe aus dem Notariat verständlich erklärt: Beurkundung, Beglaubigung, Auflassung, Pflichtteil, Grundschuld und mehr."),
    ("kanzlei",       "Kanzlei",             "Kanzlei · Notar Stadler, Bad Säckingen",                   "Notar Kai-Christoph Stadler, Amtssitz Bad Säckingen. Räume, Anfahrt, Öffnungszeiten, Zugang."),
    ("kontakt",       "Kontakt",             "Kontakt und Termin · Notar Stadler",                       "Termin anfragen: Scheffelstraße 23, 79713 Bad Säckingen, Telefon 07761 92617-0. Öffnungszeiten und Anfahrt."),
    ("stellen",       None,                  "Offene Stellen · Notar Stadler",                           "Notarfachangestellte (m/w/d) gesucht, Vollzeit, unbefristet, Bad Säckingen."),
    ("impressum",     None,                  "Impressum · Notar Stadler",                                "Impressum mit den Pflichtangaben für Notare."),
    ("datenschutz",   None,                  "Datenschutz · Notar Stadler",                              "Datenschutzerklärung. Diese Seite setzt keine Cookies und bindet keine Drittanbieter ein."),
]
EN_META = {
    "index":        ("Home",                 "Notary Kai-Christoph Stadler · Bad Säckingen",        "Notary in Bad Säckingen, Germany, near the Swiss border: real estate, wills, powers of attorney, family and company law. English-speaking service."),
    "leistungen":   ("Services",             "Services · Notary Stadler, Bad Säckingen",            "What a German notary does: property, inheritance, gifts, powers of attorney, family, companies, certifications."),
    "immobilien":   (None,                   "Real Estate · Notary Stadler",                        "Buying and selling property in Germany: procedure, documents, land charge, transfers within the family."),
    "vererben":     (None,                   "Wills and Inheritance · Notary Stadler",              "Wills, inheritance contracts, certificates of inheritance and compulsory portions under German law, explained."),
    "schenken":     (None,                   "Gifts and Transfers · Notary Stadler",                "Transferring property during your lifetime: right of residence, usufruct, reclaim rights."),
    "vorsorge":     (None,                   "Powers of Attorney · Notary Stadler",                 "Lasting power of attorney, living will and guardianship directive under German law."),
    "familie":      (None,                   "Family · Notary Stadler",                             "Marriage contracts, divorce settlements, adoption and paternity: notarisation in Bad Säckingen."),
    "unternehmen":  (None,                   "Companies · Notary Stadler",                          "GmbH formation, share transfers, commercial register filings, online notarisation."),
    "beglaubigungen":(None,                  "Certifications and Switzerland · Notary Stadler",     "Certified signatures and copies, apostille, documents for Switzerland and abroad."),
    "ablauf":       ("Procedure & Documents","Procedure and Documents · Notary Stadler",            "How an appointment with a German notary works and what to bring: checklists for purchase, will, power of attorney, company formation."),
    "fragebogen":   ("Questionnaires",       "Questionnaires · Notary Stadler",                     "All questionnaires to prepare your appointment, in English."),
    "kosten":       ("Fees",                 "Fees · Notary Stadler",                               "Notary fees in Germany are fixed by law (GNotKG) and identical at every notary."),
    "glossar":      (None,                   "Glossary · Notary Stadler",                           "German notarial terms explained in English."),
    "kanzlei":      ("Office",               "Office · Notary Stadler, Bad Säckingen",              "Notary Kai-Christoph Stadler, team, premises, directions, opening hours."),
    "kontakt":      ("Contact",              "Contact · Notary Stadler",                            "Request an appointment: Scheffelstraße 23, 79713 Bad Säckingen, phone +49 7761 92617-0."),
    "stellen":      (None,                   "Vacancies · Notary Stadler",                          "Vacancies at the notary's office (German)."),
    "impressum":    (None,                   "Legal Notice · Notary Stadler",                       "Legal notice with the mandatory information for notaries."),
    "datenschutz":  (None,                   "Privacy · Notary Stadler",                            "Privacy notice. No cookies, no third-party services."),
}

def pages_for(lang):
    if lang == "de": return PAGES
    out = []
    for slug, label, title, desc in PAGES:
        if slug.startswith("fragebogen-"):
            x = F.BY_SLUG[slug[len("fragebogen-"):]]
            out.append((slug, None, f"Questionnaire {tr(x['title'], 'en')} · Notary Stadler", tr(x["lead"], "en")))
        else:
            m = EN_META[slug]; out.append((slug, m[0], m[1], m[2]))
    return out

SLUGS = [p[0] for p in PAGES]
SERVICES = [("immobilien","Immobilien"),("vererben","Vererben"),("schenken","Schenken"),("vorsorge","Vorsorge"),
            ("familie","Familie"),("unternehmen","Unternehmen"),("beglaubigungen","Beglaubigungen & Schweiz")]

SERVICES_EN = {"immobilien": "Real Estate", "vererben": "Inheritance", "schenken": "Gifts", "vorsorge": "Powers of Attorney", "familie": "Family", "unternehmen": "Companies", "beglaubigungen": "Certifications & Switzerland"}

def siblings(slug, mode, lang="de"):
    if slug not in dict(SERVICES):
        return ""
    items = []
    for s, label in SERVICES:
        href = href_for(s, mode, lang)
        cur = ' aria-current="page"' if s == slug else ""
        items.append(f'<a href="{href}"{cur}>{SERVICES_EN[s] if lang == "en" else label}</a>')
    lbl = "Services:" if lang == "en" else "Leistungen:"
    return f'<nav class="siblings" aria-label="{"More services" if lang == "en" else "Weitere Leistungen"}"><div class="wrap"><span>{lbl}</span>' + "".join(items) + "</div></nav>\n"

HEAD = """<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<meta name="description" content="{desc}">
<link rel="canonical" href="{canonical}">
<meta property="og:title" content="{title}">
<meta property="og:description" content="{desc}">
<meta property="og:type" content="website">
<meta property="og:locale" content="de_DE">
"""

JSONLD = """<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "Notary",
  "name": "Notar Kai-Christoph Stadler",
  "url": "https://notar-stadler.de/",
  "telephone": "+49 7761 926170",
  "address": {"@type": "PostalAddress", "streetAddress": "Scheffelstraße 23", "postalCode": "79713", "addressLocality": "Bad Säckingen", "addressCountry": "DE"},
  "areaServed": ["Bad Säckingen", "Wehr", "Laufenburg", "Murg", "Rickenbach", "Herrischried", "Landkreis Waldshut"],
  "openingHoursSpecification": [
    {"@type": "OpeningHoursSpecification", "dayOfWeek": ["Monday","Tuesday","Wednesday","Thursday"], "opens": "08:00", "closes": "12:00"},
    {"@type": "OpeningHoursSpecification", "dayOfWeek": ["Monday","Tuesday","Wednesday","Thursday"], "opens": "13:00", "closes": "17:00"},
    {"@type": "OpeningHoursSpecification", "dayOfWeek": "Friday", "opens": "08:00", "closes": "12:00"}
  ]
}
</script>"""

def href_for(slug, mode, lang):
    if mode == "preview": return f"#{'en-' if lang == 'en' else ''}{slug}"
    return f"{slug}.html"

def nav_html(active, mode, lang="de"):
    items = []
    for slug, label, *_ in pages_for(lang):
        if not label:
            continue
        href = href_for(slug, mode, lang)
        cls = ' class="active"' if slug == active else ""
        cur = ' aria-current="page"' if slug == active else ""
        items.append(f'<li><a href="{href}"{cls}{cur} data-slug="{("en-" if lang == "en" else "") + slug}">{label}</a></li>')
    return "\n".join(items)

def wappen_img(mode, lang="de"):
    _MODE["mode"] = mode
    return IMG_RE.sub(inline_img, "{{img:wappen-bw.png|" + tr("Landeswappen Baden-Württemberg", lang) + "}}")

def header(active, mode, lang="de"):
    wappen = wappen_img(mode, lang)
    home = href_for("index", mode, lang)
    kontakt = href_for("kontakt", mode, lang)
    other = "de" if lang == "en" else "en"
    if mode == "preview":
        switch = f"#{'en-' if other == 'en' else ''}{active}"
    else:
        switch = f"en/{active}.html" if other == "en" else f"../{active}.html"
    switch_label = "English" if other == "en" else "Deutsch"
    u = lambda s: tr(s, lang)
    return f"""<a class="skip" href="#inhalt">{u("Zum Inhalt springen")}</a>
<div class="topbar"><div class="wrap">
  <span>Scheffelstraße 23 · 79713 Bad Säckingen</span>
  <span>{u("Mo–Do 8–12 und 13–17 Uhr · Fr 8–12 Uhr")}</span>
  <a href="tel:+497761926170">{"+49 7761 92617-0" if lang == "en" else "07761 92617-0"}</a>
  <a class="lang" href="{switch}" lang="{other}" hreflang="{other}" data-switch="{other}">{switch_label}</a>
</div></div>
<header class="site-header"><div class="wrap">
  <a class="brand" href="{home}">
    <span class="brand-mark">{wappen}</span>
    <span class="brand-text"><strong>Notar Kai-Christoph Stadler</strong><span>Bad Säckingen</span></span>
  </a>
  <nav aria-label="{u("Hauptnavigation")}"><ul>
{nav_html(active, mode, lang)}
  </ul></nav>
  <a class="btn btn-primary btn-header" href="{kontakt}">{u("Termin anfragen")}</a>
</div></header>"""

def footer(mode, lang="de"):
    def h(s): return href_for(s, mode, lang)
    u = lambda s: tr(s, lang)
    return f"""<footer class="site-footer"><div class="wrap">
  <div class="cols">
    <div>
      <p class="f-title">Notar Kai-Christoph Stadler</p>
      <p>Scheffelstraße 23<br>79713 Bad Säckingen</p>
      <p><a href="tel:+497761926170">07761 92617-0</a><br><a href="mailto:info@notar-stadler.de">info@notar-stadler.de</a></p>
    </div>
    <div>
      <p class="f-title">{u("Öffnungszeiten")}</p>
      <p>{u("Montag bis Donnerstag")}<br>{u("8–12 Uhr und 13–17 Uhr")}</p>
      <p>{u("Freitag")}<br>{u("8–12 Uhr")}</p>
      <p>{u("Termine nach Vereinbarung.")}</p>
    </div>
    <div>
      <p class="f-title">{u("Seiten")}</p>
      <p><a href="{h('leistungen')}">{u("Leistungen")}</a><br><a href="{h('ablauf')}">{u("Ablauf & Unterlagen").replace("&", "&amp;")}</a><br><a href="{h('fragebogen')}">{u("Fragebögen")}</a><br><a href="{h('kosten')}">{u("Kosten")}</a><br><a href="{h('glossar')}">{u("Glossar")}</a><br><a href="{h('kanzlei')}">{u("Kanzlei")}</a><br><a href="{h('kontakt')}">{u("Kontakt")}</a></p>
    </div>
    <div>
      <p class="f-title">{u("Rechtliches")}</p>
      <p><a href="{h('impressum')}">{u("Impressum")}</a><br><a href="{h('datenschutz')}">{u("Datenschutz")}</a><br><a href="{h('stellen')}">{u("Offene Stellen")}</a></p>
      <p><a href="https://www.notarkammer-baden-wuerttemberg.de/" rel="noopener">{u("Notarkammer Baden-Württemberg")}</a><br><a href="https://www.bnotk.de/" rel="noopener">{u("Bundesnotarkammer")}</a></p>
    </div>
  </div>
  <p class="f-note">{u("Der Notar übt ein öffentliches Amt aus. Er ist zur Unparteilichkeit und Verschwiegenheit verpflichtet. Die Gebühren sind gesetzlich festgelegt (GNotKG). Diese Seite setzt keine Cookies und bindet keine Dienste Dritter ein.")}</p>
</div></footer>"""

SVG_RE = re.compile(r"\{\{svg:([\w-]+)(?:\|([^}]*))?\}\}")

def inline_svg(m):
    """{{svg:name|Alt-Text}} -> Inline-SVG. Ohne Alt-Text dekorativ (aria-hidden)."""
    name, alt = m.group(1), (m.group(2) or "").strip()
    svg = (SRC / "img" / f"{name}.svg").read_text(encoding="utf-8").strip()
    attrs = f' role="img" aria-label="{html.escape(alt)}"' if alt else ' aria-hidden="true" focusable="false"'
    return svg.replace("<svg ", f"<svg{attrs} ", 1)

IMG_RE = re.compile(r"\{\{img:([\w.-]+)\|([^|}]*)(?:\|([^}]*))?\}\}")
_MODE = {"mode": "dist"}

def inline_img(m):
    """{{img:datei.jpg|Alt-Text|object-position}} -> <img>. In der Vorschau als Daten-URI eingebettet."""
    import base64, mimetypes
    name, alt, pos = m.group(1), m.group(2).strip(), (m.group(3) or "").strip()
    style = f' style="object-position:{pos}"' if pos else ""
    if _MODE["mode"] == "preview":
        data = (SRC / "img" / "photos" / name).read_bytes()
        mime = mimetypes.guess_type(name)[0] or "image/jpeg"
        src = f"data:{mime};base64,{base64.b64encode(data).decode()}"
    else:
        src = ("../img/" if _MODE.get("lang") == "en" else "img/") + name
    return f'<img src="{src}" alt="{html.escape(alt)}" loading="lazy"{style}>'

def render_field(fl, form_slug, lang="de"):
    u = lambda s: tr(s, lang)
    fid = f"{form_slug}-{fl['name']}"
    name = fl["name"]; typ = fl["type"]; req = " required" if fl.get("required") else ""
    label = html.escape(u(fl["label"])) + (" <small>*</small>" if fl.get("required") else "")
    hint = f'<small>{html.escape(u(fl["hint"]))}</small>' if fl.get("hint") else ""
    ph = f' placeholder="{html.escape(u(fl["placeholder"]))}"' if fl.get("placeholder") else ""
    if typ == "checkbox":
        return f'<label class="chk" for="{fid}"><input id="{fid}" name="{name}" type="checkbox" value="ja"><span>{label}</span></label>'
    if typ == "select":
        opts = "".join(f'<option value="{html.escape(o)}">{html.escape(u(o))}</option>' for o in fl["options"])
        ctl = f'<select id="{fid}" name="{name}"{req}>{opts}</select>'
    elif typ == "textarea":
        ctl = f'<textarea id="{fid}" name="{name}"{req}{ph}></textarea>'
    else:
        extra = ' inputmode="decimal" step="any" min="0"' if typ == "number" else ""
        ctl = f'<input id="{fid}" name="{name}" type="{typ}"{extra}{req}{ph}>'
    return f'<label for="{fid}"><span class="lt">{label}</span>{hint}{ctl}</label>'

def render_form(x, mode, lang="de"):
    """Fragebogen-Seite aus dem Schema. dist: POST an /api/formular/<slug>; preview: ohne Server."""
    u = lambda s: tr(s, lang)
    slug = x["slug"]
    out = []
    for sec in x["sections"]:
        note = f'<p class="hint">{html.escape(u(sec["note"]))}</p>' if sec.get("note") else ""
        rows, row = [], []
        for fl in sec["fields"]:
            if fl["w"] == 2 or fl["type"] == "checkbox":
                if row: rows.append(row); row = []
                rows.append([fl])
            else:
                row.append(fl)
                if len(row) == 2: rows.append(row); row = []
        if row: rows.append(row)
        body = []
        checks = [r[0] for r in rows if len(r) == 1 and r[0]["type"] == "checkbox"]
        for r in rows:
            if len(r) == 1 and r[0]["type"] == "checkbox":
                continue
            if len(r) == 1:
                body.append(render_field(r[0], slug, lang))
            else:
                body.append('<div class="row">' + "".join(render_field(fl, slug, lang) for fl in r) + "</div>")
        if checks:
            body.append('<div class="checks">' + "".join(render_field(fl, slug, lang) for fl in checks) + "</div>")
        out.append(f'<fieldset><legend>{html.escape(u(sec["title"]))}</legend>{note}' + "\n".join(body) + "</fieldset>")
    action = "#" if mode == "preview" else f"/api/formular/{slug}" + ("?lang=en" if lang == "en" else "")
    ds = href_for("datenschutz", mode, lang)
    ueb = href_for("fragebogen", mode, lang)
    abl = href_for("ablauf", mode, lang)
    hint = u('Musterseite: Der Versand ist in der Vorschau nicht angebunden.') if mode == "preview" else u('Ihre Angaben werden verschlüsselt übertragen und verschlüsselt gespeichert. Nur das Notariat kann sie lesen. Das Notariat erhält eine Nachricht, dass ein Fragebogen eingegangen ist, ohne Ihre Daten.')
    return f"""<section class="page-hero"><div class="wrap">
  <div>
  <p class="crumbs"><a href="{ueb}">{u("Fragebögen")}</a> · {html.escape(u(x["gruppe"]))}</p>
  <h1>{u("Fragebogen")} {html.escape(u(x["title"]))}</h1>
  <p class="lead">{html.escape(u(x["lead"]))}</p>
  </div>
  <div class="art">{{{{svg:{x["icon"]}}}}}</div>
</div></section>
<section><div class="wrap split">
  <form class="contact fragebogen" action="{action}" method="post" id="fb-{slug}" accept-charset="utf-8">
  {"".join(out)}
  <div class="hp" aria-hidden="true"><label for="{slug}-firma_web">Firma Web<input id="{slug}-firma_web" name="firma_web" type="text" tabindex="-1" autocomplete="off"></label></div>
  <label for="{slug}-ds" class="chk"><input id="{slug}-ds" name="datenschutz" type="checkbox" value="ja" required><span>{u("Die Angaben dienen der Vorbereitung eines Entwurfs und werden nur dafür verwendet.")} <a href="{ds}">{u("Datenschutzhinweise")}</a> <small>*</small></span></label>
  <div class="actions">
    <button class="btn btn-primary" type="submit">{u("An das Notariat senden")}</button>
    <button class="btn" type="button" onclick="window.print()">{u("Ausdrucken und mitbringen")}</button>
  </div>
  <p class="hint">* {u("Pflichtfeld")}. {hint}</p>
  </form>
  <aside>
    <div class="box">
      <h3>{u("So geht es weiter")}</h3>
      <ol>
        <li>{u("Sie füllen aus, was Sie wissen. Lücken sind in Ordnung.")}</li>
        <li>{u("Das Büro prüft die Angaben und ruft bei Unklarheiten zurück.")}</li>
        <li>{u("Sie erhalten den Entwurf zum Lesen, dann wird ein Termin vereinbart.")}</li>
      </ol>
    </div>
    <div class="box" style="margin-top:18px">
      <h3>{u("Wichtig")}</h3>
      <p>{u("Die Angaben werden im Entwurf verwendet. Bitte prüfen Sie Namen, Geburtsdaten und Beträge.")}</p>
      <p style="margin:0">{u("Bringen Sie zum Termin die")} <a href="{abl}">{u("Unterlagen aus der Checkliste")}</a> {u("mit.")}</p>
    </div>
  </aside>
</div></section>"""

def render_contact(mode, lang="de"):
    """Kontaktformular aus F.ANFRAGE, gleiche Annahme wie die Fragebögen."""
    u = lambda s: tr(s, lang)
    x = F.ANFRAGE
    out = []
    for sec in x["sections"]:
        rows, row = [], []
        for fl in sec["fields"]:
            if fl["w"] == 2:
                if row: rows.append(row); row = []
                rows.append([fl])
            else:
                row.append(fl)
                if len(row) == 2: rows.append(row); row = []
        if row: rows.append(row)
        for r in rows:
            out.append(render_field(r[0], "anfrage", lang) if len(r) == 1 else '<div class="row">' + "".join(render_field(fl, "anfrage", lang) for fl in r) + "</div>")
    action = "#" if mode == "preview" else "/api/formular/anfrage" + ("?lang=en" if lang == "en" else "")
    ds = href_for("datenschutz", mode, lang)
    note = ("Musterseite: Das Formular ist in der Vorschau nicht angebunden." if lang == "de" else "Sample site: the form is not connected in this preview.") if mode == "preview" else \
           ("Verschlüsselt an das Notariat. Sie erhalten eine sechsstellige Referenz für Rückfragen." if lang == "de" else "Encrypted to the notary's office. You receive a six-character reference for queries.")
    return f"""<form class="contact" action="{action}" method="post" accept-charset="utf-8">
      {"".join(out)}
      <div class="hp" aria-hidden="true"><label for="anfrage-firma_web">Firma Web<input id="anfrage-firma_web" name="firma_web" type="text" tabindex="-1" autocomplete="off"></label></div>
      <label for="anfrage-ds" class="chk" style="display:flex; gap:10px; align-items:flex-start; font-weight:400"><input id="anfrage-ds" name="datenschutz" type="checkbox" value="ja" required style="width:auto; margin-top:6px"><span>{u("Ich habe die")} <a href="{ds}">{u("Datenschutzhinweise")}</a>{u("gelesen. Meine Angaben werden nur zur Bearbeitung der Anfrage verwendet.") if lang == "en" else " gelesen. Meine Angaben werden nur zur Bearbeitung der Anfrage verwendet."}</span></label>
      <div><button class="btn btn-primary" type="submit">{u("Anfrage senden")}</button></div>
      <p style="font-size:16px; color:var(--muted); margin:0">{note}</p>
    </form>"""

def render_form_index(mode, lang="de"):
    def h(s): return href_for(s, mode, lang)
    u = lambda s: tr(s, lang)
    groups = {}
    for x in F.FORMS:
        if not x.get("intern"): groups.setdefault(x["gruppe"], []).append(x)
    parts = []
    for g, items in groups.items():
        cards = "".join(f'<a class="card" href="{h("fragebogen-"+x["slug"])}"><span class="icon">{{{{svg:{x["icon"]}}}}}</span><h3>{html.escape(u(x["title"]))}</h3><p>{html.escape(u(x["lead"]).split(". ")[0].rstrip("."))}.</p><span class="more">{u("Fragebogen öffnen")}</span></a>' for x in items)
        parts.append(f'<section><div class="wrap"><div class="section-head"><h2>{html.escape(u(g))}</h2></div><div class="grid">{cards}</div></div></section>')
    return f"""<section class="page-hero"><div class="wrap">
  <div>
  <p class="eyebrow">{u("Fragebögen")}</p>
  <h1>{u("Fragebögen zur Terminvorbereitung")}</h1>
  <p class="lead">{u("Sie tragen die Eckdaten ein, das Notariat erstellt den Entwurf. Ausfüllen am Bildschirm oder ausdrucken. Ihre Angaben werden verschlüsselt an das Notariat übermittelt und dort gespeichert, ohne Dienst eines Drittanbieters. Einen Termin vereinbaren Sie telefonisch.")}</p>
  </div>
  <div class="art">{{{{svg:feder}}}}</div>
</div></section>
{"".join(parts)}"""

def read_page(slug, lang="de"):
    _MODE["lang"] = lang
    if slug == "fragebogen":
        body = render_form_index(_MODE["mode"], lang)
    elif slug.startswith("fragebogen-"):
        body = render_form(F.BY_SLUG[slug[len("fragebogen-"):]], _MODE["mode"], lang)
    else:
        p = SRC / "pages" / ("en/" if lang == "en" else "") / f"{slug}.html"
        body = p.read_text(encoding="utf-8")
    body = body.replace("{{form:anfrage}}", render_contact(_MODE["mode"], lang))
    body = SVG_RE.sub(inline_svg, body)
    return IMG_RE.sub(inline_img, body)

def to_preview_links(body, lang="de"):
    # a.html -> #a bzw. #en-a ; ../a.html -> #a ; en/a.html -> #en-a
    body = re.sub(r'href="\.\./(' + "|".join(SLUGS) + r')\.html"', lambda m: f'href="#{m.group(1)}"', body)
    body = re.sub(r'href="en/(' + "|".join(SLUGS) + r')\.html"', lambda m: f'href="#en-{m.group(1)}"', body)
    pat = re.compile(r'href="(' + "|".join(SLUGS) + r')\.html(#[\w-]+)?"')
    pre = "en-" if lang == "en" else ""
    return pat.sub(lambda m: f'href="#{pre}{m.group(1)}"', body)

def build_dist():
    import shutil
    _MODE["mode"] = "dist"
    DIST.mkdir(exist_ok=True)
    (DIST / "img").mkdir(exist_ok=True)
    for f in (SRC / "img" / "photos").iterdir():
        shutil.copy(f, DIST / "img" / f.name)
    css = (SRC / "style.css").read_text(encoding="utf-8")
    (DIST / "style.css").write_text(css, encoding="utf-8")
    today = datetime.date.today().isoformat()
    urls = []
    (DIST / "en").mkdir(exist_ok=True)
    for lang in ("de", "en"):
        for slug, label, title, desc in pages_for(lang):
            _MODE["mode"] = "dist"
            body = read_page(slug, lang)
            de_url = f"{DOMAIN}/" if slug == "index" else f"{DOMAIN}/{slug}.html"
            en_url = f"{DOMAIN}/en/{slug}.html"
            canonical = de_url if lang == "de" else en_url
            head = HEAD.format(title=html.escape(title), desc=html.escape(desc), canonical=canonical)
            head += f'<link rel="alternate" hreflang="de" href="{de_url}">\n<link rel="alternate" hreflang="en" href="{en_url}">\n<link rel="alternate" hreflang="x-default" href="{de_url}">\n'
            head += '<link rel="stylesheet" href="' + ("../" if lang == "en" else "") + 'style.css">\n'
            if slug == "index":
                head += JSONLD + "\n"
            doc = f"""<!doctype html>
<html lang="{lang}">
<head>
{head}</head>
<body class="page-{slug} lang-{lang}">
<div class="shell">
{header(slug, "dist", lang)}
<main id="inhalt">
{siblings(slug, "dist", lang)}{body}
</main>
{footer("dist", lang)}
</div>
</body>
</html>
"""
            out = DIST / ("en" if lang == "en" else "") / f"{slug}.html"
            out.write_text(doc, encoding="utf-8")
            urls.append(f"  <url><loc>{canonical}</loc><lastmod>{today}</lastmod></url>")
    (DIST / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + "\n".join(urls) + "\n</urlset>\n", encoding="utf-8")
    (DIST / "robots.txt").write_text(f"User-agent: *\nAllow: /\nSitemap: {DOMAIN}/sitemap.xml\n", encoding="utf-8")

def build_preview():
    _MODE["mode"] = "preview"
    css = (SRC / "style.css").read_text(encoding="utf-8")
    sections = []
    for lang in ("de", "en"):
        for slug, label, title, desc in pages_for(lang):
            _MODE["mode"] = "preview"
            body = to_preview_links(read_page(slug, lang), lang)
            sid = ("en-" if lang == "en" else "") + slug
            sections.append(f'<section class="pv-page page-{slug} lang-{lang}" id="{sid}" lang="{lang}" data-title="{html.escape(title)}" hidden>\n{siblings(slug, "preview", lang)}{body}\n</section>')
    first = PAGES[0]
    js = """
<script>
(function(){
  var pages = Array.prototype.slice.call(document.querySelectorAll('.pv-page'));
  var links = Array.prototype.slice.call(document.querySelectorAll('nav a[data-slug]'));
  function show(){
    var slug = (location.hash || '#index').slice(1);
    if(!document.getElementById(slug)) slug = 'index';
    var lang = slug.indexOf('en-') === 0 ? 'en' : 'de';
    var base = lang === 'en' ? slug.slice(3) : slug;
    document.documentElement.lang = lang;
    Array.prototype.forEach.call(document.querySelectorAll('.pv-chrome'), function(c){ c.hidden = c.getAttribute('data-lang') !== lang; });
    Array.prototype.forEach.call(document.querySelectorAll('a.lang'), function(a){ a.setAttribute('href', '#' + (a.getAttribute('data-switch') === 'en' ? 'en-' : '') + base); });
    pages.forEach(function(p){ p.hidden = (p.id !== slug); });
    links.forEach(function(a){
      var on = a.getAttribute('data-slug') === slug;
      a.classList.toggle('active', on);
      if(on) a.setAttribute('aria-current','page'); else a.removeAttribute('aria-current');
    });
    var t = document.getElementById(slug).getAttribute('data-title');
    if(t) document.title = t;
    window.scrollTo(0,0);
    var sh = document.querySelector('.shell'); if(sh) sh.scrollTop = 0;
  }
  window.addEventListener('hashchange', show);
  show();
  var tgl = document.getElementById('pv-toggle');
  tgl.addEventListener('click', function(){
    var on = !document.body.classList.contains('pv-phone');
    document.body.classList.toggle('pv-phone', on);
    tgl.textContent = on ? 'Bildschirm-Ansicht' : 'Handy-Ansicht';
    tgl.setAttribute('aria-pressed', on ? 'true' : 'false');
  });
})();
</script>"""
    doc = f"""<title>{html.escape(first[2])}</title>
<meta name="description" content="{html.escape(first[3])}">
<style>
{css}
</style>
<div class="pv-banner"><span><strong>Musterseite, nicht die Originalseite von notar-stadler.de.</strong> Entwurf eines neuen Auftritts. Farbig markierte Angaben werden vor Veröffentlichung ersetzt.</span><button type="button" id="pv-toggle" aria-pressed="false">Handy-Ansicht</button></div>
<div class="shell">
<div class="pv-chrome" data-lang="de">{header("index", "preview", "de")}</div>
<div class="pv-chrome" data-lang="en" hidden>{header("index", "preview", "en")}</div>
<main id="inhalt">
{chr(10).join(sections)}
</main>
<div class="pv-chrome" data-lang="de">{footer("preview", "de")}</div>
<div class="pv-chrome" data-lang="en" hidden>{footer("preview", "en")}</div>
</div>
{js}
"""
    (ROOT / "preview.html").write_text(doc, encoding="utf-8")

if __name__ == "__main__":
    build_dist()
    build_preview()
    print("dist/ und preview.html erzeugt:", ", ".join(SLUGS))
