#!/usr/bin/env python3
"""Baut die statische Musterseite für das Notariat Stadler.

  python3 build.py            -> dist/  (eine HTML-Datei je Seite, sitemap, robots)
                                 preview.html (alle Seiten in einer Datei, Hash-Navigation)
"""
import re, html, pathlib, datetime, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent / "src"))
import formulare as F

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
    ("fragebogen",    None,                  "Fragebögen · Notar Stadler",                                "Alle Fragebögen zur Terminvorbereitung: Kaufvertrag, Wohnung, Grundschuld, Übergabe, Testament, Erbschein, Vollmacht, Ehevertrag, Scheidung, GmbH, Anteile, Handelsregister, Verein, Beglaubigung."),
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
SLUGS = [p[0] for p in PAGES]
SERVICES = [("immobilien","Immobilien"),("vererben","Vererben"),("schenken","Schenken"),("vorsorge","Vorsorge"),
            ("familie","Familie"),("unternehmen","Unternehmen"),("beglaubigungen","Beglaubigungen & Schweiz")]

def siblings(slug, mode):
    if slug not in dict(SERVICES):
        return ""
    items = []
    for s, label in SERVICES:
        href = f"#{s}" if mode == "preview" else f"{s}.html"
        cur = ' aria-current="page"' if s == slug else ""
        items.append(f'<a href="{href}"{cur}>{label}</a>')
    return '<nav class="siblings" aria-label="Weitere Leistungen"><div class="wrap"><span>Leistungen:</span>' + "".join(items) + "</div></nav>\n"

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

def nav_html(active, mode):
    items = []
    for slug, label, *_ in PAGES:
        if not label:
            continue
        href = f"#{slug}" if mode == "preview" else f"{slug}.html"
        cls = ' class="active"' if slug == active else ""
        cur = ' aria-current="page"' if slug == active else ""
        items.append(f'<li><a href="{href}"{cls}{cur} data-slug="{slug}">{label}</a></li>')
    return "\n".join(items)

def wappen_img(mode):
    _MODE["mode"] = mode
    return IMG_RE.sub(inline_img, "{{img:wappen-bw.png|Landeswappen Baden-Württemberg}}")

def header(active, mode):
    wappen = wappen_img(mode)
    home = "#index" if mode == "preview" else "index.html"
    kontakt = "#kontakt" if mode == "preview" else "kontakt.html"
    return f"""<a class="skip" href="#inhalt">Zum Inhalt springen</a>
<div class="topbar"><div class="wrap">
  <span>Scheffelstraße 23 · 79713 Bad Säckingen</span>
  <span>Mo–Do 8–12 und 13–17 Uhr · Fr 8–12 Uhr</span>
  <a href="tel:+497761926170">07761 92617-0</a>
</div></div>
<header class="site-header"><div class="wrap">
  <a class="brand" href="{home}">
    <span class="brand-mark">{wappen}</span>
    <span class="brand-text"><strong>Notar Kai-Christoph Stadler</strong><span>Bad Säckingen</span></span>
  </a>
  <nav aria-label="Hauptnavigation"><ul>
{nav_html(active, mode)}
  </ul></nav>
  <a class="btn btn-primary btn-header" href="{kontakt}">Termin anfragen</a>
</div></header>"""

def footer(mode):
    def h(s): return f"#{s}" if mode == "preview" else f"{s}.html"
    return f"""<footer class="site-footer"><div class="wrap">
  <div class="cols">
    <div>
      <p class="f-title">Notar Kai-Christoph Stadler</p>
      <p>Scheffelstraße 23<br>79713 Bad Säckingen</p>
      <p><a href="tel:+497761926170">07761 92617-0</a><br><a href="mailto:info@notar-stadler.de">info@notar-stadler.de</a></p>
    </div>
    <div>
      <p class="f-title">Öffnungszeiten</p>
      <p>Montag bis Donnerstag<br>8–12 Uhr und 13–17 Uhr</p>
      <p>Freitag<br>8–12 Uhr</p>
      <p>Termine nach Vereinbarung.</p>
    </div>
    <div>
      <p class="f-title">Seiten</p>
      <p><a href="{h('leistungen')}">Leistungen</a><br><a href="{h('ablauf')}">Ablauf &amp; Unterlagen</a><br><a href="{h('fragebogen')}">Fragebögen</a><br><a href="{h('kosten')}">Kosten</a><br><a href="{h('glossar')}">Glossar</a><br><a href="{h('kanzlei')}">Kanzlei</a><br><a href="{h('kontakt')}">Kontakt</a></p>
    </div>
    <div>
      <p class="f-title">Rechtliches</p>
      <p><a href="{h('impressum')}">Impressum</a><br><a href="{h('datenschutz')}">Datenschutz</a><br><a href="{h('stellen')}">Offene Stellen</a></p>
      <p><a href="https://www.notarkammer-baden-wuerttemberg.de/" rel="noopener">Notarkammer Baden-Württemberg</a><br><a href="https://www.bnotk.de/" rel="noopener">Bundesnotarkammer</a></p>
    </div>
  </div>
  <p class="f-note">Der Notar übt ein öffentliches Amt aus. Er ist zur Unparteilichkeit und Verschwiegenheit verpflichtet. Die Gebühren sind gesetzlich festgelegt (GNotKG). Diese Seite setzt keine Cookies und bindet keine Dienste Dritter ein.</p>
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
        src = f"img/{name}"
    return f'<img src="{src}" alt="{html.escape(alt)}" loading="lazy"{style}>'

def render_field(fl, form_slug):
    fid = f"{form_slug}-{fl['name']}"
    name = fl["name"]; typ = fl["type"]; req = " required" if fl.get("required") else ""
    label = html.escape(fl["label"]) + (" <small>*</small>" if fl.get("required") else "")
    hint = f'<small>{html.escape(fl["hint"])}</small>' if fl.get("hint") else ""
    ph = f' placeholder="{html.escape(fl["placeholder"])}"' if fl.get("placeholder") else ""
    if typ == "checkbox":
        return f'<label class="chk" for="{fid}"><input id="{fid}" name="{name}" type="checkbox" value="ja"><span>{label}</span></label>'
    if typ == "select":
        opts = "".join(f"<option>{html.escape(o)}</option>" for o in fl["options"])
        ctl = f'<select id="{fid}" name="{name}"{req}>{opts}</select>'
    elif typ == "textarea":
        ctl = f'<textarea id="{fid}" name="{name}"{req}{ph}></textarea>'
    else:
        extra = ' inputmode="decimal" step="any" min="0"' if typ == "number" else ""
        ctl = f'<input id="{fid}" name="{name}" type="{typ}"{extra}{req}{ph}>'
    return f'<label for="{fid}">{label} {hint}{ctl}</label>'

def render_form(x, mode):
    """Fragebogen-Seite aus dem Schema. dist: POST an /api/formular/<slug>; preview: ohne Server."""
    slug = x["slug"]
    out = []
    for sec in x["sections"]:
        note = f'<p class="hint">{html.escape(sec["note"])}</p>' if sec.get("note") else ""
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
                body.append(render_field(r[0], slug))
            else:
                body.append('<div class="row">' + "".join(render_field(fl, slug) for fl in r) + "</div>")
        if checks:
            body.append('<div class="checks">' + "".join(render_field(fl, slug) for fl in checks) + "</div>")
        out.append(f'<fieldset><legend>{html.escape(sec["title"])}</legend>{note}' + "\n".join(body) + "</fieldset>")
    action = "#" if mode == "preview" else f"/api/formular/{slug}"
    ds = "#datenschutz" if mode == "preview" else "datenschutz.html"
    ueb = "#fragebogen" if mode == "preview" else "fragebogen.html"
    hint = ('Musterseite: Der Versand ist in der Vorschau nicht angebunden.' if mode == "preview"
            else 'Ihre Angaben werden verschlüsselt übertragen und verschlüsselt gespeichert. Nur das Notariat kann sie lesen. Das Notariat erhält eine Nachricht, dass ein Fragebogen eingegangen ist, ohne Ihre Daten.')
    return f"""<section class="page-hero"><div class="wrap">
  <div>
  <p class="crumbs"><a href="{ueb}">Fragebögen</a> · {html.escape(x["gruppe"])}</p>
  <h1>Fragebogen {html.escape(x["title"])}</h1>
  <p class="lead">{html.escape(x["lead"])}</p>
  </div>
  <div class="art">{{{{svg:{x["icon"]}}}}}</div>
</div></section>
<section><div class="wrap split">
  <form class="contact fragebogen" action="{action}" method="post" id="fb-{slug}" accept-charset="utf-8">
  {"".join(out)}
  <div class="hp" aria-hidden="true"><label for="{slug}-firma_web">Firma Web<input id="{slug}-firma_web" name="firma_web" type="text" tabindex="-1" autocomplete="off"></label></div>
  <label for="{slug}-ds" class="chk"><input id="{slug}-ds" name="datenschutz" type="checkbox" value="ja" required><span>Die Angaben dienen der Vorbereitung eines Entwurfs und werden nur dafür verwendet. <a href="{ds}">Datenschutzhinweise</a> <small>*</small></span></label>
  <div class="actions">
    <button class="btn btn-primary" type="submit">An das Notariat senden</button>
    <button class="btn" type="button" onclick="window.print()">Ausdrucken und mitbringen</button>
  </div>
  <p class="hint">* Pflichtfeld. {hint}</p>
  </form>
  <aside>
    <div class="box">
      <h3>So geht es weiter</h3>
      <ol>
        <li>Sie füllen aus, was Sie wissen. Lücken sind in Ordnung.</li>
        <li>Das Büro prüft die Angaben und ruft bei Unklarheiten zurück.</li>
        <li>Sie erhalten den Entwurf zum Lesen, dann wird ein Termin vereinbart.</li>
      </ol>
    </div>
    <div class="box" style="margin-top:18px">
      <h3>Wichtig</h3>
      <p>Die Angaben werden im Entwurf verwendet. Bitte prüfen Sie Namen, Geburtsdaten und Beträge.</p>
      <p style="margin:0">Bringen Sie zum Termin die <a href="{"#ablauf" if mode == "preview" else "ablauf.html"}">Unterlagen aus der Checkliste</a> mit.</p>
    </div>
  </aside>
</div></section>"""

def render_form_index(mode):
    def h(s): return f"#{s}" if mode == "preview" else f"{s}.html"
    groups = {}
    for x in F.FORMS: groups.setdefault(x["gruppe"], []).append(x)
    parts = []
    for g, items in groups.items():
        cards = "".join(f'<a class="card" href="{h("fragebogen-"+x["slug"])}"><span class="icon">{{{{svg:{x["icon"]}}}}}</span><h3>{html.escape(x["title"])}</h3><p>{html.escape(x["lead"].split(". ")[0])}.</p><span class="more">Fragebogen öffnen</span></a>' for x in items)
        parts.append(f'<section><div class="wrap"><div class="section-head"><h2>{html.escape(g)}</h2></div><div class="grid">{cards}</div></div></section>')
    return f"""<section class="page-hero"><div class="wrap">
  <div>
  <p class="eyebrow">Fragebögen</p>
  <h1>Fragebögen zur Terminvorbereitung</h1>
  <p class="lead">Sie tragen die Eckdaten ein, das Notariat erstellt den Entwurf. Ausfüllen am Bildschirm oder ausdrucken. Ihre Angaben werden verschlüsselt an das Notariat übermittelt und dort gespeichert, ohne Dienst eines Drittanbieters. Einen Termin vereinbaren Sie telefonisch.</p>
  </div>
  <div class="art">{{{{svg:feder}}}}</div>
</div></section>
{"".join(parts)}"""

def read_page(slug):
    if slug == "fragebogen":
        body = render_form_index(_MODE["mode"])
    elif slug.startswith("fragebogen-"):
        body = render_form(F.BY_SLUG[slug[len("fragebogen-"):]], _MODE["mode"])
    else:
        body = (SRC / "pages" / f"{slug}.html").read_text(encoding="utf-8")
    body = SVG_RE.sub(inline_svg, body)
    return IMG_RE.sub(inline_img, body)

def to_preview_links(body):
    # a.html -> #a ; a.html#x -> #a (Ankersprung innerhalb der Vorschau nicht nötig)
    pat = re.compile(r'href="(' + "|".join(SLUGS) + r')\.html(#[\w-]+)?"')
    return pat.sub(lambda m: f'href="#{m.group(1)}"', body)

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
    for slug, label, title, desc in PAGES:
        _MODE["mode"] = "dist"
        body = read_page(slug)
        canonical = f"{DOMAIN}/" if slug == "index" else f"{DOMAIN}/{slug}.html"
        head = HEAD.format(title=html.escape(title), desc=html.escape(desc), canonical=canonical)
        head += '<link rel="stylesheet" href="style.css">\n'
        if slug == "index":
            head += JSONLD + "\n"
        doc = f"""<!doctype html>
<html lang="de">
<head>
{head}</head>
<body class="page-{slug}">
<div class="shell">
{header(slug, "dist")}
<main id="inhalt">
{siblings(slug, "dist")}{body}
</main>
{footer("dist")}
</div>
</body>
</html>
"""
        (DIST / f"{slug}.html").write_text(doc, encoding="utf-8")
        urls.append(f"  <url><loc>{canonical}</loc><lastmod>{today}</lastmod></url>")
    (DIST / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + "\n".join(urls) + "\n</urlset>\n", encoding="utf-8")
    (DIST / "robots.txt").write_text(f"User-agent: *\nAllow: /\nSitemap: {DOMAIN}/sitemap.xml\n", encoding="utf-8")

def build_preview():
    _MODE["mode"] = "preview"
    css = (SRC / "style.css").read_text(encoding="utf-8")
    sections = []
    for slug, label, title, desc in PAGES:
        _MODE["mode"] = "preview"
        body = to_preview_links(read_page(slug))
        sections.append(f'<section class="pv-page page-{slug}" id="{slug}" data-title="{html.escape(title)}" hidden>\n{siblings(slug, "preview")}{body}\n</section>')
    first = PAGES[0]
    js = """
<script>
(function(){
  var pages = Array.prototype.slice.call(document.querySelectorAll('.pv-page'));
  var links = Array.prototype.slice.call(document.querySelectorAll('nav a[data-slug]'));
  function show(){
    var slug = (location.hash || '#index').slice(1);
    if(!document.getElementById(slug)) slug = 'index';
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
{header("index", "preview")}
<main id="inhalt">
{chr(10).join(sections)}
</main>
{footer("preview")}
</div>
{js}
"""
    (ROOT / "preview.html").write_text(doc, encoding="utf-8")

if __name__ == "__main__":
    build_dist()
    build_preview()
    print("dist/ und preview.html erzeugt:", ", ".join(SLUGS))
