#!/usr/bin/env python3
"""Baut die statische Musterseite für das Notariat Stadler.

  python3 build.py            -> dist/  (eine HTML-Datei je Seite, sitemap, robots)
                                 preview.html (alle Seiten in einer Datei, Hash-Navigation)
"""
import re, html, pathlib, datetime

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
    ("kosten",        "Kosten",              "Kosten · Notar Stadler, Bad Säckingen",                    "Notarkosten sind gesetzlich festgelegt (GNotKG) und bei jedem Notar gleich. Beispiele und Erklärung."),
    ("glossar",       "Glossar",             "Glossar · Notar Stadler",                                  "Begriffe aus dem Notariat verständlich erklärt: Beurkundung, Beglaubigung, Auflassung, Pflichtteil, Grundschuld und mehr."),
    ("kanzlei",       "Kanzlei",             "Kanzlei · Notar Stadler, Bad Säckingen",                   "Notar Kai-Christoph Stadler, Amtssitz Bad Säckingen. Räume, Anfahrt, Öffnungszeiten, Zugang."),
    ("kontakt",       "Kontakt",             "Kontakt und Termin · Notar Stadler",                       "Termin anfragen: Scheffelstraße 23, 79713 Bad Säckingen, Telefon 07761 92617-0. Öffnungszeiten und Anfahrt."),
    ("impressum",     None,                  "Impressum · Notar Stadler",                                "Impressum mit den Pflichtangaben für Notare."),
    ("datenschutz",   None,                  "Datenschutz · Notar Stadler",                              "Datenschutzerklärung. Diese Seite setzt keine Cookies und bindet keine Drittanbieter ein."),
]
SLUGS = [p[0] for p in PAGES]

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

def header(active, mode):
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
    <span class="brand-seal" aria-hidden="true"></span>
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
      <p><a href="tel:+497761926170">07761 92617-0</a><br><span class="ph">[Fax]</span><br><span class="ph">[E-Mail-Adresse]</span></p>
    </div>
    <div>
      <p class="f-title">Öffnungszeiten</p>
      <p>Montag bis Donnerstag<br>8–12 Uhr und 13–17 Uhr</p>
      <p>Freitag<br>8–12 Uhr</p>
      <p>Termine nach Vereinbarung.</p>
    </div>
    <div>
      <p class="f-title">Seiten</p>
      <p><a href="{h('leistungen')}">Leistungen</a><br><a href="{h('ablauf')}">Ablauf &amp; Unterlagen</a><br><a href="{h('kosten')}">Kosten</a><br><a href="{h('glossar')}">Glossar</a><br><a href="{h('kanzlei')}">Kanzlei</a><br><a href="{h('kontakt')}">Kontakt</a></p>
    </div>
    <div>
      <p class="f-title">Rechtliches</p>
      <p><a href="{h('impressum')}">Impressum</a><br><a href="{h('datenschutz')}">Datenschutz</a></p>
      <p><a href="https://www.notarkammer-bw.de/" rel="noopener">Notarkammer Baden-Württemberg</a><br><a href="https://www.bnotk.de/" rel="noopener">Bundesnotarkammer</a></p>
    </div>
  </div>
  <p class="f-note">Der Notar übt ein öffentliches Amt aus. Er ist zur Unparteilichkeit und Verschwiegenheit verpflichtet. Die Gebühren sind gesetzlich festgelegt (GNotKG). Diese Seite setzt keine Cookies und bindet keine Dienste Dritter ein.</p>
</div></footer>"""

def read_page(slug):
    return (SRC / "pages" / f"{slug}.html").read_text(encoding="utf-8")

def to_preview_links(body):
    # a.html -> #a ; a.html#x -> #a (Ankersprung innerhalb der Vorschau nicht nötig)
    pat = re.compile(r'href="(' + "|".join(SLUGS) + r')\.html(#[\w-]+)?"')
    return pat.sub(lambda m: f'href="#{m.group(1)}"', body)

def build_dist():
    DIST.mkdir(exist_ok=True)
    css = (SRC / "style.css").read_text(encoding="utf-8")
    (DIST / "style.css").write_text(css, encoding="utf-8")
    today = datetime.date.today().isoformat()
    urls = []
    for slug, label, title, desc in PAGES:
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
{header(slug, "dist")}
<main id="inhalt">
{body}
</main>
{footer("dist")}
</body>
</html>
"""
        (DIST / f"{slug}.html").write_text(doc, encoding="utf-8")
        urls.append(f"  <url><loc>{canonical}</loc><lastmod>{today}</lastmod></url>")
    (DIST / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + "\n".join(urls) + "\n</urlset>\n", encoding="utf-8")
    (DIST / "robots.txt").write_text(f"User-agent: *\nAllow: /\nSitemap: {DOMAIN}/sitemap.xml\n", encoding="utf-8")

def build_preview():
    css = (SRC / "style.css").read_text(encoding="utf-8")
    sections = []
    for slug, label, title, desc in PAGES:
        body = to_preview_links(read_page(slug))
        sections.append(f'<section class="pv-page page-{slug}" id="{slug}" data-title="{html.escape(title)}" hidden>\n{body}\n</section>')
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
  }
  window.addEventListener('hashchange', show);
  show();
})();
</script>"""
    doc = f"""<title>{html.escape(first[2])}</title>
<meta name="description" content="{html.escape(first[3])}">
<style>
{css}
</style>
<div class="pv-banner">Musterseite (statische Vorschau). Platzhalter in eckigen Klammern werden vor Veröffentlichung ersetzt.</div>
{header("index", "preview")}
<main id="inhalt">
{chr(10).join(sections)}
</main>
{footer("preview")}
{js}
"""
    (ROOT / "preview.html").write_text(doc, encoding="utf-8")

if __name__ == "__main__":
    build_dist()
    build_preview()
    print("dist/ und preview.html erzeugt:", ", ".join(SLUGS))
