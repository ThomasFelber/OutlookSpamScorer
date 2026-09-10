"""Fragebögen des Notariats als Schema.

Aus diesem Schema erzeugt build.py die HTML-Seiten und server.py prüft die Eingaben.
Feldtypen: text, date, tel, email, number, select, textarea, checkbox.
w=2: volle Breite, sonst halbe Breite (zwei Felder je Zeile).
"""

def f(name, label, type="text", options=None, hint=None, required=False, w=1, placeholder=None):
    d = {"name": name, "label": label, "type": type, "w": w, "required": required}
    if options: d["options"] = options
    if hint: d["hint"] = hint
    if placeholder: d["placeholder"] = placeholder
    return d

def person(prefix, title, note=None, steuer_id=False, familienstand=False, extra=None):
    fields = [
        f(f"{prefix}_name", "Vor- und Nachname", required=True),
        f(f"{prefix}_geb", "Geburtsdatum", "date"),
        f(f"{prefix}_adr", "Anschrift", w=2),
        f(f"{prefix}_tel", "Telefon", "tel"),
        f(f"{prefix}_mail", "E-Mail", "email"),
    ]
    if steuer_id:
        fields.append(f(f"{prefix}_stid", "Steuer-Identifikationsnummer", hint="11 Ziffern, steht auf dem Einkommensteuerbescheid"))
    if familienstand:
        fields.append(f(f"{prefix}_fam", "Familienstand", "select", ["ledig", "verheiratet", "geschieden", "verwitwet", "eingetragene Lebenspartnerschaft"]))
    if extra:
        fields += extra
    return {"title": title, "note": note, "fields": fields}

def objekt(prefix="ob", mit_art=True):
    fields = [f(f"{prefix}_adr", "Anschrift des Objekts", w=2, required=True)]
    if mit_art:
        fields.append(f(f"{prefix}_art", "Art", "select", ["Einfamilienhaus", "Doppelhaushälfte, Reihenhaus", "Eigentumswohnung", "Mehrfamilienhaus", "Unbebautes Grundstück", "Gewerbe", "Landwirtschaft"]))
    fields += [
        f(f"{prefix}_gb", "Grundbuch von, Blatt, Flurstück", hint="falls bekannt"),
        f(f"{prefix}_last", "Eingetragene Belastungen", w=2, hint="Grundschulden, Wohnrechte, Wegerechte; falls bekannt"),
    ]
    return {"title": "Objekt", "fields": fields}

RUECKFRAGEN = {"title": "Rückfragen", "fields": [
    f("rf_name", "Ansprechperson", required=True),
    f("rf_tel", "Telefon", "tel", required=True),
    f("rf_zeit", "Erreichbar", placeholder="z. B. vormittags"),
    f("rf_bem", "Besonderheiten, Wünsche, Fragen", "textarea", w=2),
]}

FORMS = [
 # ---------------- Immobilien ----------------
 {"slug": "kaufvertrag", "kurz": "KV", "gruppe": "Immobilien", "title": "Kaufvertrag Haus oder Grundstück", "icon": "haus",
  "lead": "Für den Entwurf eines Kaufvertrags über ein Haus, ein Grundstück oder eine Wohnung. Ausfüllen kann der Verkäufer, der Käufer oder der Makler.",
  "sections": [
    person("vk", "Verkäufer", "Bei mehreren Eigentümern bitte alle nennen, weitere unter Besonderheiten.", steuer_id=True, familienstand=True),
    person("kf", "Käufer", "Bei Erwerb zu mehreren: alle Käufer und das gewünschte Verhältnis, etwa je zur Hälfte.", steuer_id=True, familienstand=True,
           extra=[f("kf_verh", "Erwerbsverhältnis bei mehreren Käufern", placeholder="z. B. je 1/2")]),
    objekt(),
    {"title": "Nutzung und Inventar", "fields": [
        f("nu_miet", "Vermietet?", "select", ["Nein", "Ja, Mietvertrag geht über", "Ja, wird vor Übergabe beendet"]),
        f("nu_inv", "Mitverkauftes Inventar", placeholder="Küche, Möbel, Wert"),
        f("nu_maengel", "Bekannte Mängel", w=2, hint="Der Verkäufer muss bekannte Mängel offenlegen."),
    ]},
    {"title": "Kaufpreis und Zahlung", "fields": [
        f("kp_betrag", "Kaufpreis in Euro", "number", required=True),
        f("kp_inv", "Davon für Inventar in Euro", "number"),
        f("kp_fin", "Finanzierung", "select", ["Eigenmittel", "Bankdarlehen, Grundschuld nötig", "Teils, teils"]),
        f("kp_bank", "Bank und Höhe der Grundschuld"),
        f("kp_ueb", "Gewünschte Übergabe", "date"),
        f("kp_makler", "Makler", placeholder="Name, oder: keiner"),
    ]},
    RUECKFRAGEN]},
 {"slug": "wohnung", "kurz": "ETW", "gruppe": "Immobilien", "title": "Kaufvertrag Eigentumswohnung", "icon": "haus",
  "lead": "Für den Kauf oder Verkauf einer Eigentumswohnung. Zusätzlich zum Haus-Fragebogen werden Angaben zur Gemeinschaft und zum Verwalter gebraucht.",
  "sections": [
    person("vk", "Verkäufer", steuer_id=True, familienstand=True),
    person("kf", "Käufer", steuer_id=True, familienstand=True, extra=[f("kf_verh", "Erwerbsverhältnis bei mehreren Käufern", placeholder="z. B. je 1/2")]),
    {"title": "Wohnung", "fields": [
        f("wo_adr", "Anschrift, Lage im Haus", w=2, required=True),
        f("wo_nr", "Wohnungs-Nummer laut Teilungserklärung"),
        f("wo_mea", "Miteigentumsanteil", placeholder="z. B. 125/1000"),
        f("wo_stell", "Stellplatz, Garage, Keller", w=2, hint="mit Nummern, falls Sondereigentum oder Sondernutzungsrecht"),
        f("wo_verw", "Verwalter mit Anschrift", w=2),
        f("wo_hausgeld", "Monatliches Hausgeld in Euro", "number"),
        f("wo_ruecklage", "Stand der Erhaltungsrücklage in Euro", "number"),
        f("wo_beschl", "Beschlossene Sonderumlagen oder Sanierungen", w=2),
        f("wo_miet", "Vermietet?", "select", ["Nein", "Ja, Mietvertrag geht über", "Ja, wird vor Übergabe beendet"]),
    ]},
    {"title": "Kaufpreis und Zahlung", "fields": [
        f("kp_betrag", "Kaufpreis in Euro", "number", required=True),
        f("kp_inv", "Davon für Inventar in Euro", "number"),
        f("kp_fin", "Finanzierung", "select", ["Eigenmittel", "Bankdarlehen, Grundschuld nötig", "Teils, teils"]),
        f("kp_bank", "Bank und Höhe der Grundschuld"),
        f("kp_ueb", "Gewünschte Übergabe", "date"),
        f("kp_makler", "Makler", placeholder="Name, oder: keiner"),
    ]},
    RUECKFRAGEN]},
 {"slug": "grundschuld", "kurz": "GS", "gruppe": "Immobilien", "title": "Grundschuldbestellung", "icon": "haus",
  "lead": "Für die Bestellung einer Grundschuld zugunsten einer Bank, etwa zur Finanzierung eines Kaufs oder Umbaus. Das Grundschuldformular der Bank bitte zum Termin mitbringen.",
  "sections": [
    person("eg", "Eigentümer", "Alle im Grundbuch eingetragenen Eigentümer.", familienstand=True),
    objekt(mit_art=False),
    {"title": "Grundschuld", "fields": [
        f("gs_bank", "Bank mit Anschrift", w=2, required=True),
        f("gs_betrag", "Grundschuldbetrag in Euro", "number", required=True),
        f("gs_zins", "Grundschuldzins in Prozent", "number", hint="steht im Bankformular, meist 12 bis 18"),
        f("gs_anlass", "Anlass", "select", ["Kauf", "Neubau", "Umbau, Sanierung", "Umschuldung", "Sonstiges"]),
        f("gs_bearb", "Ansprechperson bei der Bank", ),
        f("gs_frist", "Gewünschter Termin bis", "date"),
    ]},
    RUECKFRAGEN]},
 {"slug": "uebergabe", "kurz": "UEB", "gruppe": "Immobilien", "title": "Übergabe und Schenkung", "icon": "schluessel",
  "lead": "Für die Übertragung eines Hauses, einer Wohnung oder eines Grundstücks zu Lebzeiten, meist an Kinder. Mit Wohnrecht, Nießbrauch, Pflege und Rückforderungsrechten.",
  "sections": [
    person("ug", "Übergeber", "Alle Eigentümer.", steuer_id=True, familienstand=True),
    person("un", "Übernehmer", "Bei mehreren: alle und das Verhältnis.", steuer_id=True, familienstand=True,
           extra=[f("un_verw", "Verwandtschaft zum Übergeber", "select", ["Kind", "Enkel", "Ehegatte", "Sonstige"])]),
    objekt(),
    {"title": "Absicherung des Übergebers", "fields": [
        f("ab_wohn", "Wohnrecht oder Nießbrauch", "select", ["Wohnrecht an bestimmten Räumen", "Nießbrauch am ganzen Objekt", "Keines"]),
        f("ab_raeume", "Räume für das Wohnrecht", placeholder="z. B. Erdgeschoss"),
        f("ab_pflege", "Pflegeverpflichtung des Übernehmers", "select", ["Ja", "Nein", "Bitte erklären"]),
        f("ab_rente", "Zahlung an den Übergeber", placeholder="einmalig oder monatlich, Betrag"),
        f("ab_rueck", "Rückforderungsrechte", "select", ["Übliche (Verkauf, Insolvenz, Scheidung, Vorversterben)", "Bitte erklären", "Keine"]),
        f("ab_wert", "Ungefährer Wert des Objekts in Euro", "number"),
    ]},
    {"title": "Geschwister und Ausgleich", "fields": [
        f("ge_gesch", "Weitere Kinder des Übergebers", w=2, placeholder="Namen"),
        f("ge_ausgl", "Ausgleich", "select", ["Abfindung in Geld", "Pflichtteilsverzicht", "Anrechnung auf Erbteil", "Kein Ausgleich", "Bitte erklären"]),
        f("ge_betrag", "Abfindungsbetrag in Euro", "number"),
    ]},
    RUECKFRAGEN]},
 # ---------------- Erben ----------------
 {"slug": "testament", "kurz": "TE", "gruppe": "Erben und Vererben", "title": "Testament und Erbvertrag", "icon": "testament",
  "lead": "Für den Entwurf eines Einzeltestaments, eines gemeinschaftlichen Testaments von Ehegatten oder eines Erbvertrags.",
  "sections": [
    person("e1", "Erblasser", familienstand=True),
    person("e2", "Ehegatte oder zweiter Erblasser", "Nur bei gemeinschaftlichem Testament oder Erbvertrag."),
    {"title": "Familie", "fields": [
        f("fa_kinder", "Kinder mit Geburtsdatum", "textarea", w=2, hint="auch aus früheren Beziehungen"),
        f("fa_enkel", "Enkel", "textarea", w=2),
        f("fa_ehev", "Ehevertrag vorhanden?", "select", ["Nein", "Ja, Gütertrennung", "Ja, modifizierte Zugewinngemeinschaft", "Ja, sonstiges"]),
        f("fa_frueh", "Frühere Testamente oder Erbverträge", "select", ["Keine", "Ja, sollen aufgehoben werden", "Ja, sollen bestehen bleiben"]),
    ]},
    {"title": "Vermögen", "note": "Ungefähre Angaben genügen. Sie bestimmen den Geschäftswert und die Beratung zu Pflichtteil und Steuer.", "fields": [
        f("ve_immo", "Immobilien", "textarea", w=2, placeholder="Anschrift, ungefährer Wert, Eigentümer"),
        f("ve_geld", "Bankguthaben, Wertpapiere in Euro", "number"),
        f("ve_betrieb", "Unternehmen, Beteiligungen"),
        f("ve_schulden", "Verbindlichkeiten in Euro", "number"),
        f("ve_ausland", "Vermögen im Ausland", placeholder="Land, Art"),
    ]},
    {"title": "Wünsche", "fields": [
        f("wu_erben", "Wer soll erben, in welchem Verhältnis?", "textarea", w=2, required=True),
        f("wu_schluss", "Bei Ehegatten: Wer erbt nach dem Tod des Längerlebenden?", "textarea", w=2),
        f("wu_verm", "Vermächtnisse", "textarea", w=2, hint="einzelne Gegenstände oder Beträge an bestimmte Personen"),
        f("wu_tv", "Testamentsvollstreckung gewünscht?", "select", ["Nein", "Ja", "Bitte erklären"]),
        f("wu_tvperson", "Testamentsvollstrecker"),
        f("wu_ersatz", "Ersatzerben, falls ein Erbe vorverstirbt", w=2),
    ]},
    RUECKFRAGEN]},
 {"slug": "erbschein", "kurz": "EB", "gruppe": "Erben und Vererben", "title": "Erbschein und Erbausschlagung", "icon": "testament",
  "lead": "Nach einem Todesfall: Antrag auf Erbschein, Erbausschlagung oder Auseinandersetzung unter Erben.",
  "sections": [
    {"title": "Anliegen", "fields": [
        f("an_art", "Was wird gebraucht?", "select", ["Erbschein", "Erbausschlagung", "Erbauseinandersetzung", "Europäisches Nachlasszeugnis", "Weiß ich nicht"], required=True),
    ]},
    {"title": "Verstorbene Person", "fields": [
        f("vs_name", "Name", required=True),
        f("vs_geb", "Geburtsdatum", "date"),
        f("vs_tod", "Sterbedatum", "date", required=True),
        f("vs_wohn", "Letzter Wohnsitz", w=2),
        f("vs_fam", "Familienstand beim Tod", "select", ["ledig", "verheiratet", "geschieden", "verwitwet"]),
        f("vs_test", "Testament oder Erbvertrag vorhanden?", "select", ["Nein", "Ja, notariell", "Ja, handschriftlich", "Unbekannt"]),
        f("vs_ausland", "Staatsangehörigkeit, Vermögen im Ausland"),
    ]},
    person("as", "Antragsteller", "Die Person, die den Antrag stellt oder ausschlägt."),
    {"title": "Angehörige und Nachlass", "fields": [
        f("na_erben", "Ehegatte, Kinder, ggf. Eltern und Geschwister des Verstorbenen", "textarea", w=2, hint="Name, Geburtsdatum, Anschrift; auch vorverstorbene Kinder mit deren Kindern"),
        f("na_wert", "Ungefährer Nachlasswert in Euro", "number"),
        f("na_immo", "Immobilien im Nachlass", w=2),
        f("na_grund", "Bei Ausschlagung: Grund", placeholder="z. B. Überschuldung"),
    ]},
    RUECKFRAGEN]},
 # ---------------- Vorsorge ----------------
 {"slug": "vollmacht", "kurz": "VV", "gruppe": "Vorsorge", "title": "Vorsorgevollmacht und Patientenverfügung", "icon": "schirm",
  "lead": "Für den Entwurf von Vorsorgevollmacht, Patientenverfügung und Betreuungsverfügung. Für Ehegatten bitte je einen Bogen.",
  "sections": [
    person("vg", "Vollmachtgeber", familienstand=True),
    person("b1", "Bevollmächtigte Person 1"),
    person("b2", "Bevollmächtigte Person 2", "Ersatz oder gemeinsam."),
    {"title": "Ausgestaltung", "fields": [
        f("au_art", "Handeln die Bevollmächtigten", "select", ["Jeder allein", "Nur gemeinsam", "Person 2 nur, wenn Person 1 verhindert"]),
        f("au_ab", "Gilt die Vollmacht", "select", ["Sofort, mit interner Absprache", "Bitte erklären"]),
        f("au_verm", "Vermögen, Bank, Verträge", "checkbox"),
        f("au_immo", "Immobilien, Grundbuch", "checkbox"),
        f("au_ges", "Gesundheit, Ärzte, Pflege", "checkbox"),
        f("au_auf", "Aufenthalt, Heim, Wohnung", "checkbox"),
        f("au_post", "Post, Behörden, Gerichte", "checkbox"),
        f("au_dig", "Digitales, Konten im Internet", "checkbox"),
        f("au_pv", "Patientenverfügung", "select", ["Ja, mit beurkunden", "Liegt bereits vor", "Nein"]),
        f("au_bv", "Betreuungsverfügung", "select", ["Ja, gleiche Personen", "Ja, andere Person", "Nein"]),
        f("au_reg", "Eintragung im Zentralen Vorsorgeregister gewünscht", "checkbox"),
        f("au_wert", "Immobilien und größere Vermögenswerte", w=2, hint="kurz, für den Geschäftswert"),
    ]},
    RUECKFRAGEN]},
 # ---------------- Familie ----------------
 {"slug": "ehevertrag", "kurz": "EV", "gruppe": "Familie", "title": "Ehevertrag", "icon": "ringe",
  "lead": "Vor oder während der Ehe: Güterstand, Unterhalt, Versorgungsausgleich, Schutz eines Betriebs.",
  "sections": [
    person("p1", "Partner 1", steuer_id=False),
    person("p2", "Partner 2"),
    {"title": "Ehe und Vermögen", "fields": [
        f("eh_stand", "Stand", "select", ["Heirat geplant am", "Bereits verheiratet seit"]),
        f("eh_datum", "Datum", "date"),
        f("eh_kinder", "Gemeinsame Kinder, Kinder aus früheren Beziehungen", "textarea", w=2),
        f("eh_verm1", "Vermögen Partner 1", "textarea", w=2, placeholder="Immobilien, Betrieb, Ersparnisse, Schulden, ungefähr"),
        f("eh_verm2", "Vermögen Partner 2", "textarea", w=2),
        f("eh_eink", "Einkommen beider, ungefähr", w=2),
        f("eh_ausland", "Ausländische Staatsangehörigkeit oder Wohnsitz", w=2),
    ]},
    {"title": "Wünsche", "fields": [
        f("wu_guet", "Güterstand", "select", ["Gütertrennung", "Zugewinngemeinschaft mit Änderungen, etwa Betrieb ausnehmen", "Weiß ich nicht, bitte beraten"]),
        f("wu_unt", "Nachehelicher Unterhalt", "select", ["Gesetzliche Regelung", "Verzicht", "Begrenzung", "Bitte beraten"]),
        f("wu_va", "Versorgungsausgleich", "select", ["Gesetzliche Regelung", "Ausschluss", "Bitte beraten"]),
        f("wu_sonst", "Sonstige Wünsche", "textarea", w=2),
    ]},
    RUECKFRAGEN]},
 {"slug": "scheidung", "kurz": "SF", "gruppe": "Familie", "title": "Scheidungsfolgenvereinbarung", "icon": "ringe",
  "lead": "Bei Trennung und Scheidung: Vermögen, Wohnung, Unterhalt, Versorgungsausgleich und Kinder einvernehmlich regeln.",
  "sections": [
    person("p1", "Ehegatte 1"),
    person("p2", "Ehegatte 2"),
    {"title": "Ehe", "fields": [
        f("eh_heirat", "Heiratsdatum", "date"),
        f("eh_trenn", "Getrennt seit", "date"),
        f("eh_verf", "Scheidungsverfahren", "select", ["Noch nicht eingereicht", "Eingereicht", "Anwalt beauftragt"]),
        f("eh_kinder", "Gemeinsame Kinder mit Geburtsdatum", "textarea", w=2),
    ]},
    {"title": "Zu regeln", "fields": [
        f("re_wohn", "Ehewohnung", "select", ["Gemeinsames Eigentum, ein Ehegatte übernimmt", "Gemeinsames Eigentum, Verkauf", "Mietwohnung", "Eigentum eines Ehegatten"]),
        f("re_immo", "Immobilien", "textarea", w=2, placeholder="Anschrift, Eigentümer, Wert, Darlehen"),
        f("re_zug", "Zugewinnausgleich", "select", ["Verzicht beiderseits", "Zahlung eines Betrags", "Bitte beraten"]),
        f("re_betrag", "Ausgleichsbetrag in Euro", "number"),
        f("re_unt", "Unterhalt Ehegatte", "select", ["Verzicht", "Betrag vereinbaren", "Bitte beraten"]),
        f("re_kind", "Kindesunterhalt, Umgang", "textarea", w=2),
        f("re_va", "Versorgungsausgleich", "select", ["Gesetzliche Durchführung", "Ausschluss", "Bitte beraten"]),
        f("re_haus", "Hausrat, Fahrzeuge, Konten", "textarea", w=2),
    ]},
    RUECKFRAGEN]},
 # ---------------- Unternehmen ----------------
 {"slug": "gmbh", "kurz": "GG", "gruppe": "Unternehmen", "title": "GmbH- oder UG-Gründung", "icon": "gebaeude",
  "lead": "Für Gesellschaftsvertrag oder Musterprotokoll, Gesellschafterliste und Handelsregisteranmeldung. Gilt auch für die Unternehmergesellschaft (haftungsbeschränkt).",
  "sections": [
    {"title": "Gesellschaft", "fields": [
        f("ge_firma", "Gewünschter Firmenname", w=2, required=True, hint="mit Rechtsformzusatz, gern zwei Alternativen"),
        f("ge_sitz", "Sitz (Gemeinde)", required=True),
        f("ge_adr", "Geschäftsanschrift"),
        f("ge_gegen", "Unternehmensgegenstand", "textarea", w=2, required=True, hint="was die Gesellschaft tut, ein bis zwei Sätze"),
        f("ge_kap", "Stammkapital in Euro", "number", required=True, hint="GmbH mindestens 25.000, UG ab 1"),
        f("ge_form", "Grundlage", "select", ["Musterprotokoll (bis 3 Gesellschafter, 1 Geschäftsführer)", "Eigener Gesellschaftsvertrag", "Weiß ich noch nicht"]),
        f("ge_gj", "Geschäftsjahr", "select", ["Kalenderjahr", "Abweichend"]),
        f("ge_online", "Beurkundung", "select", ["In der Kanzlei", "Online per Video, falls möglich"]),
    ]},
    person("g1", "Gesellschafter 1", extra=[f("g1_anteil", "Anteil am Stammkapital in Euro", "number"), f("g1_gf", "Auch Geschäftsführer?", "select", ["Ja", "Nein"])]),
    person("g2", "Gesellschafter 2", "Falls vorhanden. Weitere unter Besonderheiten.", extra=[f("g2_anteil", "Anteil am Stammkapital in Euro", "number"), f("g2_gf", "Auch Geschäftsführer?", "select", ["Nein", "Ja"])]),
    {"title": "Geschäftsführung", "fields": [
        f("gf_name", "Geschäftsführer, falls nicht Gesellschafter", w=2, placeholder="Name, Geburtsdatum, Anschrift"),
        f("gf_vert", "Vertretung", "select", ["Einzelvertretung", "Gemeinsam mit einem weiteren Geschäftsführer"]),
        f("gf_181", "Befreiung von § 181 BGB", "select", ["Ja", "Nein", "Bitte erklären"], hint="Geschäfte mit sich selbst"),
        f("gf_wb", "Wirtschaftlich Berechtigte", w=2, hint="natürliche Personen mit mehr als 25 % Anteil oder Kontrolle"),
    ]},
    RUECKFRAGEN]},
 {"slug": "anteile", "kurz": "GA", "gruppe": "Unternehmen", "title": "Übertragung von Geschäftsanteilen", "icon": "gebaeude",
  "lead": "Verkauf oder Schenkung von GmbH-Anteilen, auch Eintritt oder Ausscheiden eines Gesellschafters.",
  "sections": [
    {"title": "Gesellschaft", "fields": [
        f("ge_firma", "Firma", w=2, required=True),
        f("ge_hrb", "Handelsregister, HRB-Nummer"),
        f("ge_sitz", "Sitz"),
        f("ge_kap", "Stammkapital in Euro", "number"),
        f("ge_liste", "Aktuelle Gesellschafterliste vorhanden?", "select", ["Ja, bringe ich mit", "Bitte vom Register abrufen"]),
    ]},
    person("ve", "Veräußerer"),
    person("er", "Erwerber", extra=[f("er_wb", "Wirtschaftlich Berechtigte des Erwerbers, falls Gesellschaft", w=2)]),
    {"title": "Anteile und Gegenleistung", "fields": [
        f("an_nr", "Übertragene Anteile", w=2, placeholder="laufende Nummern und Nennbeträge laut Gesellschafterliste"),
        f("an_art", "Art", "select", ["Verkauf", "Schenkung", "Einbringung", "Sonstiges"]),
        f("an_preis", "Kaufpreis in Euro", "number"),
        f("an_stichtag", "Wirtschaftlicher Übergang", "date"),
        f("an_gf", "Änderung der Geschäftsführung?", "select", ["Nein", "Ja, bitte erklären"]),
        f("an_zust", "Zustimmung der Gesellschaft erforderlich?", "select", ["Weiß ich nicht", "Ja", "Nein"]),
    ]},
    RUECKFRAGEN]},
 {"slug": "handelsregister", "kurz": "HR", "gruppe": "Unternehmen", "title": "Handelsregisteranmeldung", "icon": "gebaeude",
  "lead": "Änderungen bei GmbH, UG, Einzelkaufleuten und Personengesellschaften: Geschäftsführerwechsel, Sitzverlegung, Satzungsänderung, Prokura, Liquidation.",
  "sections": [
    {"title": "Unternehmen", "fields": [
        f("un_firma", "Firma", w=2, required=True),
        f("un_reg", "Registergericht und Nummer", placeholder="z. B. AG Freiburg HRB 12345"),
        f("un_form", "Rechtsform", "select", ["GmbH", "UG (haftungsbeschränkt)", "Einzelkaufmann", "OHG", "KG", "GmbH & Co. KG", "Sonstige"]),
    ]},
    {"title": "Anmeldung", "fields": [
        f("an_art", "Was soll angemeldet werden?", "select", ["Geschäftsführerwechsel", "Änderung der Vertretungsbefugnis", "Sitzverlegung", "Änderung der Geschäftsanschrift", "Satzungsänderung", "Kapitalerhöhung", "Prokura", "Auflösung, Liquidation", "Ersteintragung Einzelkaufmann oder Personengesellschaft", "Sonstiges"], required=True),
        f("an_text", "Einzelheiten", "textarea", w=2, required=True, placeholder="Wer scheidet aus, wer kommt hinzu, neue Anschrift, neuer Wortlaut"),
        f("an_beschl", "Gesellschafterbeschluss vorhanden?", "select", ["Ja", "Nein, bitte entwerfen"]),
        f("an_frist", "Gewünschter Termin bis", "date"),
    ]},
    person("am", "Anmeldende Person", "Geschäftsführer, Inhaber oder Gesellschafter, der unterschreibt."),
    RUECKFRAGEN]},
 {"slug": "verein", "kurz": "VE", "gruppe": "Unternehmen", "title": "Vereinsgründung und Vereinsregister", "icon": "gebaeude",
  "lead": "Anmeldung eines neuen Vereins oder Änderung von Vorstand und Satzung beim Vereinsregister.",
  "sections": [
    {"title": "Verein", "fields": [
        f("ve_name", "Name des Vereins", w=2, required=True),
        f("ve_sitz", "Sitz"),
        f("ve_vr", "Vereinsregister-Nummer, falls eingetragen"),
        f("ve_art", "Anliegen", "select", ["Neugründung", "Vorstandswechsel", "Satzungsänderung", "Sonstiges"], required=True),
        f("ve_zweck", "Vereinszweck", "textarea", w=2),
        f("ve_datum", "Datum der Gründungs- oder Mitgliederversammlung", "date"),
        f("ve_unterlagen", "Protokoll und Satzung vorhanden?", "select", ["Ja, bringe ich mit", "Nein, bitte beraten"]),
    ]},
    {"title": "Vorstand", "fields": [
        f("vo_mitgl", "Vorstandsmitglieder nach § 26 BGB", "textarea", w=2, required=True, hint="Name, Geburtsdatum, Anschrift, Amt"),
        f("vo_vert", "Vertretungsregelung laut Satzung", w=2),
    ]},
    person("am", "Anmeldende Person"),
    RUECKFRAGEN]},
 # ---------------- Beglaubigungen ----------------
 {"slug": "beglaubigung", "kurz": "BG", "gruppe": "Beglaubigungen", "title": "Beglaubigung", "icon": "stempel",
  "lead": "Unterschriftsbeglaubigung oder beglaubigte Abschrift. Kurzer Vorgang, meist ohne langen Termin.",
  "sections": [
    person("pe", "Person, die unterschreibt"),
    {"title": "Dokument", "fields": [
        f("do_art", "Art", "select", ["Unterschrift unter Vollmacht", "Unterschrift unter Handelsregisteranmeldung", "Unterschrift unter Grundbucherklärung", "Beglaubigte Kopie", "Sonstiges"], required=True),
        f("do_land", "Verwendung im Land", placeholder="Deutschland, Schweiz, anderes"),
        f("do_apost", "Apostille nötig?", "select", ["Weiß ich nicht", "Ja", "Nein"]),
        f("do_sprache", "Sprache des Dokuments", placeholder="Deutsch, andere"),
        f("do_anz", "Anzahl Dokumente oder Seiten", "number"),
        f("do_termin", "Gewünschter Zeitpunkt"),
    ]},
    RUECKFRAGEN]},
]

BY_SLUG = {x["slug"]: x for x in FORMS}

def field_index(form):
    """name -> Feld, über alle Abschnitte."""
    return {fl["name"]: fl for sec in form["sections"] for fl in sec["fields"]}
