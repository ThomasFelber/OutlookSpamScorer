'use strict';

// ─── Spam Analyzer ────────────────────────────────────────────────────────────
// Pure logic — no DOM or Office dependencies.

class SpamAnalyzer {
  analyze(headers, bodyHtml, subject, senderEmail) {
    const reasons = [];
    const hScore = headers ? this._analyzeHeaders(headers, reasons) : 0;
    const bScore = this._analyzeBody(bodyHtml, subject, reasons);
    const hiddenText = this._extractHiddenText(bodyHtml);
    return {
      score: Math.min(10, Math.round(hScore + bScore)),
      reasons,
      hiddenText,
    };
  }

  _analyzeHeaders(headers, reasons) {
    let score = 0;

    // Authentication-Results (RFC 8601) — core email security checks
    const authLine = this._getHeader(headers, 'Authentication-Results')
                  || this._getHeader(headers, 'ARC-Authentication-Results')
                  || '';

    if (authLine) {
      if (/spf=fail/i.test(authLine))     { score += 1.5; reasons.push('SPF: FAIL'); }
      else if (/spf=softfail/i.test(authLine)) { score += 0.75; reasons.push('SPF: SOFTFAIL'); }

      if (/dkim=fail/i.test(authLine))    { score += 1.5; reasons.push('DKIM: FAIL'); }

      if (/dmarc=fail/i.test(authLine))   { score += 2;   reasons.push('DMARC: FAIL'); }

      // compauth=fail — Microsoft Composite Auth failed despite individual checks
      const compAuth = (authLine.match(/compauth=(pass|fail|softpass)/i) || [])[1]?.toLowerCase() ?? null;
      if (compAuth === 'fail') { score += 2; reasons.push('compauth=fail — Microsoft Composite Auth versagt'); }
    }

    // authFullyPasses: all three + compauth pass → likely legitimate bulk mail via ESP
    const compAuth = authLine ? (authLine.match(/compauth=(pass|fail|softpass)/i) || [])[1]?.toLowerCase() ?? null : null;
    const authFullyPasses = authLine
      ? /spf=pass/i.test(authLine) && /dkim=pass/i.test(authLine)
        && /dmarc=pass/i.test(authLine) && compAuth === 'pass'
      : false;

    // Server-side spam verdicts from common MTA headers
    const xSpamStatus = this._getHeader(headers, 'X-Spam-Status') || '';
    const xSpamFlag   = this._getHeader(headers, 'X-Spam-Flag')   || '';
    if (/^\s*yes/i.test(xSpamStatus)) { score += 2; reasons.push('Server: als Spam markiert (X-Spam-Status)'); }
    if (/yes/i.test(xSpamFlag))       { score += 1; reasons.push('Server: X-Spam-Flag gesetzt'); }

    // Microsoft Exchange spam intelligence signals
    // SCL (Spam Confidence Level): 0–4 = clean, 5–6 = junk, 7–9 = spam
    const scl = parseInt(this._getHeader(headers, 'X-MS-Exchange-Organization-SCL') || '', 10);
    if (!isNaN(scl)) {
      if (authFullyPasses) {
        // Legitimate ESPs often get SCL 5–6; only flag SCL 7+ even with full auth
        if (scl >= 7) { score += 1; reasons.push(`Microsoft SCL ${scl} (Spam-Score trotz vollständiger Authentifizierung)`); }
      } else {
        if (scl >= 7)      { score += 2.5; reasons.push(`Microsoft SCL ${scl}: als Spam eingestuft`); }
        else if (scl >= 5) { score += 1.5; reasons.push(`Microsoft SCL ${scl}: als Junk eingestuft`); }
      }
    }

    // BCL (Bulk Complaint Level) in X-Microsoft-Antispam: 0 = not bulk, 4–7 = bulk, 8–9 = high complaints
    const msAntispam = this._getHeader(headers, 'X-Microsoft-Antispam') || '';
    const bclM = msAntispam.match(/BCL:(\d+)/);
    if (bclM) {
      const bcl = parseInt(bclM[1], 10);
      if (bcl >= 8)      { score += 2;   reasons.push(`Microsoft BCL ${bcl}: sehr hohe Beschwerderate`); }
      else if (bcl >= 7) { score += 2.5; reasons.push(`Microsoft BCL ${bcl}: hohe Beschwerderate (Bulk-Mail)`); }
      else if (bcl >= 4) { score += 0.8; reasons.push(`Microsoft BCL ${bcl}: erhöhte Beschwerderate`); }
    }

    // dest:J = Exchange delivered to Junk — the server already classified it as spam
    const msDelivery = this._getHeader(headers, 'X-Microsoft-Antispam-Mailbox-Delivery') || '';
    if (/dest:J/i.test(msDelivery)) {
      if (authFullyPasses) {
        score += 0.5; reasons.push('Microsoft Exchange: Junk-Zustellung (aber vollständige Authentifizierung — evtl. ESP)');
      } else {
        score += 2; reasons.push('Microsoft Exchange: an Junk-Ordner zugestellt');
      }
    }

    // OFR:SpamFilterAuthJ = Exchange spam filter explicitly overrode an auth-based pass decision.
    // Strong signal: the server identified spam characteristics despite clean auth.
    if (/OFR:SpamFilter/i.test(msDelivery)) {
      score += 1;
      reasons.push('Microsoft Exchange: Spam-Filter hat Auth-Pass überstimmt (OFR:SpamFilter)');
    }

    // Reply-To domain differs from From domain — classic phishing pattern.
    // Use root-domain comparison so subdomain senders (noreply@mail.company.com) replying
    // to the parent domain (support@company.com) are not falsely flagged.
    const fromHeader    = this._getHeader(headers, 'From')     || '';
    const replyToHeader = this._getHeader(headers, 'Reply-To') || '';
    if (fromHeader && replyToHeader) {
      const fromDomain    = this._extractDomain(fromHeader);
      const replyToDomain = this._extractDomain(replyToHeader);
      const fromRoot      = this._extractRootDomain(fromDomain);
      const replyToRoot   = this._extractRootDomain(replyToDomain);
      if (fromRoot && replyToRoot && fromRoot !== replyToRoot) {
        score += 1;
        reasons.push(`Reply-To-Domain abweichend (${replyToDomain} ≠ ${fromDomain})`);
      }
    }

    // Return-Path domain mismatch — bounce addresses on a subdomain are normal
    // (e.g. bounce.mail.company.com for a sender at mail.company.com).
    const returnPath = this._getHeader(headers, 'Return-Path') || '';
    if (fromHeader && returnPath) {
      const fromDomain       = this._extractDomain(fromHeader);
      const returnPathDomain = this._extractDomain(returnPath);
      const fromRoot         = this._extractRootDomain(fromDomain);
      const returnPathRoot   = this._extractRootDomain(returnPathDomain);
      if (fromRoot && returnPathRoot && fromRoot !== returnPathRoot) {
        score += 0.5;
        reasons.push(`Return-Path-Domain abweichend (${returnPathDomain})`);
      }
    }

    // HELO domain mismatch — connecting server's HELO name doesn't match envelope From domain.
    // Known ESP hostnames are whitelisted. When auth fully passes, apply reduced penalty
    // (spammers increasingly register throwaway domains with valid SPF/DKIM/DMARC but still
    // use unrelated sending infrastructure, e.g. HELO=pitchbook.com for a .web.id sender).
    const espHelo = /\.(mailgun\.net|sendgrid\.net|amazonses\.com|sparkpostmail\.com|exacttarget\.com|salesforceemails\.com|campaignmonitor\.com|createsend\.com|mandrill\.com|postmarkapp\.com|mimecast\.com|proofpoint\.com|constantcontact\.com|hubspot\.com|marketo\.net|klaviyo\.com|brevo\.com|mailjet\.com|elasticemail\.com)$/i;
    const receivedSpf = this._getHeader(headers, 'Received-SPF') || '';
    const heloM = receivedSpf.match(/helo=([\w.-]+)/i);
    if (heloM) {
      const heloDomain  = heloM[1].toLowerCase();
      const fromDomainH = this._extractDomain(fromHeader);
      if (fromDomainH && heloDomain !== fromDomainH
          && !heloDomain.endsWith('.' + fromDomainH)
          && !fromDomainH.endsWith('.' + heloDomain)
          && !espHelo.test(heloDomain)) {
        if (authFullyPasses) {
          score += 0.5;
          reasons.push(`HELO-Domain abweichend (${heloDomain} ≠ ${fromDomainH}) — trotz vollst. Auth`);
        } else {
          score += 1;
          reasons.push(`HELO-Domain abweichend (${heloDomain} ≠ ${fromDomainH})`);
        }
      }
    }

    // DKIM signing domain ≠ From domain — but skip known relay services that legitimately re-sign.
    const dkimRelayWhitelist = /privaterelay\.appleid\.com|icloud\.com|groups\.google\.com/i;
    const dkimSig   = this._getHeader(headers, 'DKIM-Signature') || '';
    const dkimDomM  = dkimSig.match(/\bd=([\w.-]+)/i);
    if (dkimDomM) {
      const dkimDomain  = dkimDomM[1].toLowerCase();
      const fromDomainD = this._extractDomain(fromHeader);
      if (fromDomainD && dkimDomain !== fromDomainD && !dkimRelayWhitelist.test(dkimDomain)) {
        score += 1.5;
        reasons.push(`DKIM-Signatur-Domain abweichend (${dkimDomain} ≠ ${fromDomainD})`);
      }
    }

    // Multiple DKIM signatures from different domains → relaying through unrelated infrastructure.
    // Exclude known infrastructure providers (Amazon SES, SendGrid, …) that co-sign transactional
    // email on behalf of the real sender, and same-org subdomains.
    const allDkimSigs = headers.match(/^DKIM-Signature:.+(?:\r?\n[ \t].+)*/gim) || [];
    if (allDkimSigs.length > 1) {
      const dkimDomains = new Set(
        allDkimSigs.map(s => (s.match(/\bd=([\w.-]+)/i) || [])[1]?.toLowerCase()).filter(Boolean)
      );
      const fromDomainC     = this._extractDomain(fromHeader);
      const fromRootDomainC = this._extractRootDomain(fromDomainC);
      const dkimInfraRe = /amazonses\.com|sendgrid\.net|mailgun\.net|sparkpostmail\.com|mandrill\.com|exacttarget\.com|postmarkapp\.com|brevo\.com|mailjet\.com|elasticemail\.com|klaviyo\.com/i;
      const foreignDoms = [...dkimDomains].filter(d =>
        d !== fromDomainC &&
        this._extractRootDomain(d) !== fromRootDomainC &&
        !dkimInfraRe.test(d) &&
        !dkimRelayWhitelist.test(d)
      );
      if (dkimDomains.size > 1 && foreignDoms.length > 0) {
        score += 1.5;
        reasons.push(`Mehrere DKIM-Signaturen aus verschiedenen Domains: ${[...dkimDomains].join(', ')}`);
      }
    }

    // Suspicious sender domain patterns
    const fromDomain = this._extractDomain(fromHeader);
    if (fromDomain) {
      if (/\d{5,}/.test(fromDomain))                  { score += 0.5; reasons.push('Absender-Domain enthält viele Ziffern'); }
      if (/[a-z]{18,}/.test(fromDomain.split('.')[0])) { score += 0.3; reasons.push('Sehr langer Sub-Domain-Name'); }
    }

    // Bulk/junk precedence header
    const precedence = this._getHeader(headers, 'Precedence') || '';
    if (/bulk|junk/i.test(precedence)) { score += 0.3; reasons.push('Precedence: bulk/junk'); }

    // Excessive mail hops — overly forwarded / obfuscated routing.
    // Threshold is 12: large enterprise environments (Exchange, Domino) and multi-region
    // transactional relay chains legitimately produce 9–11 hops.
    const hopCount = (headers.match(/^Received:/gim) || []).length;
    if (hopCount > 12) { score += 0.5; reasons.push(`Viele Mail-Hops (${hopCount} Received-Zeilen)`); }

    // postmaster@ is a system address — never sends newsletters or commercial mail
    const fromEmail = (fromHeader.match(/<([^>]+)>/) || [])[1] || fromHeader.trim();
    if (/^postmaster@/i.test(fromEmail)) {
      score += 0.5;
      reasons.push('Absender postmaster@ — System-Adresse, kein legitimer Newsletter-Absender');
    }

    // Spam keywords in the From email's local part (e.g. "Casino-angebot_2026@…").
    // Legitimate senders never encode campaign names in their address.
    const fromLocalPart = fromEmail.split('@')[0] || '';
    if (/^(casino|jackpot|lotto|freispiel|gluck|glueck|wett|winn|gewinn|slot[-_]?s?|roulette|blackjack)/i.test(fromLocalPart)) {
      score += 1.5;
      reasons.push(`Spam-Keyword im Absender-Nutzernamen: "${fromLocalPart}"`);
    }

    // Expose authFullyPasses to _analyzeBody via instance state (avoids parameter threading)
    this._lastAuthFullyPasses = authFullyPasses;

    return score;
  }

  _analyzeBody(bodyHtml, subject, reasons) {
    let score = 0;

    // Read auth state set by _analyzeHeaders — used to reduce penalties for
    // authenticated bulk/transactional senders (e.g. Deutsche Bahn, Anthropic invoices)
    const authFullyPasses = this._lastAuthFullyPasses || false;

    const plainText   = this._stripHtml(bodyHtml || '');
    const fullText    = (subject || '') + ' ' + plainText;
    const fullLower   = fullText.toLowerCase();

    // Spam keyword patterns (German + English)
    const patterns = [
      { re: /gewinn(en|er|t)|lotterie|jackpot|millionen?\s*euro|preis\s*gewonnen/i,        w: 2,   label: 'Gewinnversprechen' },
      { re: /nigeria|prince|inheritance|erbschaft|million[s]?\s*dollar/i,                  w: 2.5, label: 'Nigeria-/Vorschussbetrug' },
      { re: /viagra|cialis|levitra|pharmacy|apotheke\s*ohne\s*rezept/i,                    w: 2.5, label: 'Pharma-Spam' },
      { re: /casino|online.?wett(en|büro)|glücksspiel|freispiel(e)?|\bslots?\b|roulette|blackjack|poker\s*bonus/i, w: 1.5, label: 'Glücksspiel/Casino' },
      { re: /ihr\s+(konto|paypal|amazon|apple|microsoft).{0,30}(gesperrt|deaktiviert)/i,   w: 2,   label: 'Phishing: Konto gesperrt' },
      { re: /passwort\s*(ablaufen|bestätigen|verifizieren|erneuern|expired)/i,             w: 2,   label: 'Phishing: Passwort-Anfrage' },
      { re: /klicken\s*sie\s*hier|click\s*here|jetzt\s*klicken/i,                         w: 0.5, label: 'Generische Klick-Aufforderung' },
      { re: /dringend|urgent|sofort\s*handeln|act\s*now|limited\s*time|angebot\s*(endet|läuft)|läuft\s*(heute\s*)?ab|bald\s*nicht\s*mehr\s*verfügbar|bonus\s*(endet|läuft|expires)|angebot\s+endet\s+bald/i, w: 0.5, label: 'Künstliche Dringlichkeit' },
      { re: /100\s*%\s*(kostenlos|gratis|free)|völlig\s*kostenlos/i,                      w: 0.8, label: 'Gratis-Versprechen' },
      { re: /sie\s*wurden\s*ausgewählt|you\s*have\s*been\s*selected/i,                    w: 1.5, label: 'Pseudo-Auszeichnung' },
      { re: /\bcrypto|bitcoin|kryptowährun|invest.{0,30}(rendite|gewinne?|robot)|hohe\s*rendite|trading.{0,20}(auto|bot|signal)|warum\s+alle.{0,20}invest|fibonacci|forex\s+signal/i, w: 1.5, label: 'Crypto/Investment-Spam' },
      { re: /ihre\s*(daten|informationen)\s*(wurden\s*)?bestätigen|verify\s*your\s*info/i, w: 1.5, label: 'Datenmissbrauch-Phishing' },
      { re: /lions?\s*(mane|spray)|körper\s*reset|nahrungsergänzung|supplement\b|fettverbrenner|schlank(heits)?|kräuter.{0,25}(spray|tropfen|kapsel)|testosteron.{0,20}boost|abnehm/i, w: 1.5, label: 'Supplement/Gesundheits-Spam' },
      { re: /wechat|微信|telegram\s*(channel|contact|group|id)|whatsapp\s*(contact|number|group)|line\s*id\s*:/i, w: 1.5, label: 'Messenger-Kontakt-Solicitation (WeChat/Telegram/WhatsApp)' },
      { re: /bundeszentralamt|finanzamt\b|bundeszoll|steuerpr[üu]fung.*krypto|amtliche?\s+(mahnung|aufforderung|mitteilung).*steuer/i, w: 2.5, label: 'Behörden-Impersonation (Finanzamt/BZSt)' },
      { re: /\b(UPS|DHL|FedEx|Hermes|DPD|GLS|Yodel|Evri)\b.{0,40}(paket|lieferung|sendung|delivery|tracking|notification|nicht\s*zugestellt)/i, w: 1.5, label: 'Kurierdienst-Erwähnung (auf Domain-Mismatch prüfen)' },
    ];

    for (const p of patterns) {
      if (p.re.test(fullLower)) { score += p.w; reasons.push(p.label); }
    }

    // ALL-CAPS abuse (only meaningful if there are enough words)
    const words = plainText.split(/\s+/).filter(w => w.length > 3);
    if (words.length > 5) {
      const capsCount = words.filter(w => w === w.toUpperCase() && /[A-ZÄÖÜ]/.test(w)).length;
      const capsRatio = capsCount / words.length;
      if (capsRatio > 0.2) {
        score += Math.min(1, capsRatio * 2);
        reasons.push(`${Math.round(capsRatio * 100)}% Wörter in Großbuchstaben`);
      }
    }

    // Exclamation mark abuse
    const exclCount = (fullText.match(/!/g) || []).length;
    if (exclCount > 3) {
      score += Math.min(0.5, (exclCount - 3) * 0.08);
      reasons.push(`${exclCount} Ausrufezeichen`);
    }

    // Link analysis — inspect URLs textually, never follow them.
    // Also extract originalsrc from Microsoft Safe Links to get the REAL destination URL.
    const rawLinks   = (bodyHtml || '').match(/https?:\/\/[^\s"'<>)]+/gi) || [];
    const origSrcRe  = /originalsrc="([^"]+)"/gi;
    const origSrcs   = [];
    let osm;
    while ((osm = origSrcRe.exec(bodyHtml || '')) !== null) origSrcs.push(osm[1]);
    // Combine, de-duplicate; prefer originalsrc for TLD/shortener checks
    const links      = [...new Set([...rawLinks, ...origSrcs])];
    const linkCount  = rawLinks.length;   // count visible links, not originalsrc copies

    // URL shorteners hide destination — always suspicious
    const shortenerRe = /bit\.ly\/|tinyurl\.com\/|t\.co\/|goo\.gl\/|ow\.ly\/|cutt\.ly\/|rb\.gy\//i;
    if (links.some(l => shortenerRe.test(l))) {
      score += 1;
      reasons.push('URL-Verkürzer gefunden (versteckt Ziel-URL)');
    }

    // Suspicious free/throwaway TLDs — also checked on unwrapped originalsrc
    const suspiciousTLD = /\.(tk|cf|ga|ml|gq|xyz|top|click|download|stream|loan|win|racing|buzz|la)\//i;
    if (links.some(l => suspiciousTLD.test(l))) {
      const match = links.find(l => suspiciousTLD.test(l)) || '';
      const tld   = (match.match(/\.([\w]+)\//) || [])[1] || '?';
      score += 1;
      reasons.push(`Verdächtige Link-TLD (.${tld}) — auch in Safe-Link-Original`);
    }

    if (linkCount > 0) {
      const textLen = plainText.length;
      if (textLen < 80 && linkCount >= 2) {
        score += 1;
        reasons.push('Sehr kurzer Text mit mehreren Links');
      } else if (textLen > 0 && (linkCount / (textLen / 100)) > 0.4) {
        // Reduce link-density penalty for fully-authenticated senders (transactional mail
        // legitimately contains many tracked links)
        const raw     = Math.min(1, linkCount * 0.12);
        const penalty = authFullyPasses ? raw * 0.3 : raw;
        if (penalty >= 0.1) {
          score += penalty;
          reasons.push(`Hohe Link-Dichte (${linkCount} Links)`);
        }
      }
    }

    // Hidden / invisible text — classic spam obfuscation technique.
    // Distinguish: substantial hidden text → strong signal regardless of auth;
    // minimal hidden content (tracking pixel etc.) → only penalise unauthenticated senders.
    if (/color\s*:\s*(white|#fff\b|#ffffff)|font-size\s*:\s*[01]px|display\s*:\s*none|visibility\s*:\s*hidden/i.test(bodyHtml || '')) {
      const hiddenContent = this._extractHiddenText(bodyHtml || '');
      if (hiddenContent.length > 60) {
        score += 1.5;
        reasons.push('Versteckter/unsichtbarer Text gefunden (substantiell)');
      } else if (!authFullyPasses) {
        score += 0.5;
        reasons.push('Versteckte Elemente gefunden (Tracking-Pixel o.ä.)');
      }
      // authFullyPasses + minimal hidden content → no penalty (normal transactional mail)
    }

    // Quoted-Printable obfuscation in HTML body — spam pipelines encode content to evade filters
    // Legitimate email rarely has dense QP encoding embedded in HTML markup
    const qpMatches = ((bodyHtml || '').match(/=[0-9A-Fa-f]{2}/g) || []).length;
    const htmlLen   = (bodyHtml || '').length;
    if (qpMatches > 30 && htmlLen > 0 && (qpMatches / (htmlLen / 100)) > 1.5) {
      score += 1;
      reasons.push(`Quoted-Printable-Verschlüsselung im HTML (${qpMatches} Sequenzen) — Spam-Pipeline-Merkmal`);
    }

    // Image-only body — no visible text, just image links (common for image-spam evading text filters)
    const imgCount = ((bodyHtml || '').match(/<img\b/gi) || []).length;
    if (imgCount >= 2 && plainText.length < 60) {
      score += 1.5;
      reasons.push(`Nur-Bild-E-Mail (${imgCount} Bilder, kaum Text) — umgeht Text-basierte Spamfilter`);
    }

    // Unsubstituted merge tag in subject, e.g. {Name}, {Felber} — bulk mailer didn't replace placeholder
    if (/\{[A-Za-z][^}]{0,25}\}/.test(subject)) {
      score += 2;
      reasons.push('Nicht ersetzter Platzhalter im Betreff (z.B. {Name}) — Massen-E-Mail bestätigt');
    }

    // Unicode Mathematical Bold/Sans-serif Bold obfuscation (𝗔𝗯𝗻𝗲𝗵𝗺𝗲𝗻, 𝙱𝚘𝚕𝚍)
    // Spam senders use these to bypass text-based filters — plain text readers see styled glyphs
    if (/[\u{1D400}-\u{1D7FF}]/u.test(fullText)) {
      score += 1.5;
      reasons.push('Unicode-Styling-Obfuskation (𝗕𝗼𝗹𝗱/𝗜𝘁𝗮𝗹𝗶𝗰 Glyphen) — Spam-Filter-Umgehung');
    }

    // Fake countdown / expiry urgency — stronger than generic "dringend"
    if (/expires?\s+in\s+\d+\s*(minute|hour|stunde|min\b)|abläuft\s+in\s+\d+|(\d{2,3})\s*%\s*(voll|full|capacity)|status\s+expires|storage\s+(almost\s+)?full/i.test(fullText)) {
      score += 1.5;
      reasons.push('Gefälschter Countdown / Ablauf-Zeitdruck ("expires in X minutes", "99% voll")');
    }

    // Broken UTF-8 rendered as Latin-1 — common in spam pipelines (Ã¶=ö, Ã¼=ü, Ã¤=ä)
    if (/Ã¶|Ã¼|Ã¤|Ã–|Ã/.test((bodyHtml || '') + subject)) {
      score += 1;
      reasons.push('Kaputte Zeichenkodierung (UTF-8/Latin-1) — typisch für Spam-Versand-Pipelines');
    }

    // CAN-SPAM-compliant virtual mailbox address (e.g. "Ste 744 #511") — not a real business office
    if (/\bSte\.?\s+\d+\s*#\s*\d+|\bPMB\s*\d+|\bBox\s*#\d+/i.test(plainText)) {
      score += 0.8;
      reasons.push('CAN-SPAM-Adresse: virtueller Briefkasten (kein echtes Büro)');
    }

    // Affiliate-spam responsibility deflection: "advertiser does not manage your subscription"
    if (/verwaltet\s+(ihr|dein)\s+abonnement\s+nicht|does\s+not\s+manage\s+your\s+subscri/i.test(plainText)) {
      score += 0.8;
      reasons.push('Affiliate-Spam-Disclaimer: Verantwortungs-Ablehnung für Abonnement');
    }

    return score;
  }

  // Extract text content from hidden/invisible elements — for the expander UI
  _extractHiddenText(html) {
    if (!html) return '';
    try {
      const tmp = document.createElement('div');
      tmp.innerHTML = html;
      const texts = [];
      tmp.querySelectorAll('[style]').forEach(el => {
        const st = el.style;
        const isHidden =
          st.visibility === 'hidden' ||
          st.display    === 'none'   ||
          parseInt(st.fontSize, 10) <= 1 ||
          /^(?:white|#fff|#ffffff)$/i.test(st.color);
        if (isHidden) {
          const t = el.textContent.replace(/\s+/g, ' ').trim();
          if (t.length > 3) texts.push(t);
        }
      });
      return [...new Set(texts)].join('\n').trim();
    } catch { return ''; }
  }

  // Clean body for display / copy — removes MIME artifacts, QP encoding, hidden blocks
  _cleanBody(html) {
    if (!html) return '';

    // Truncate at first MIME multipart boundary (base64 bleed-through, PDF attachments, etc.)
    html = html.replace(/(\r?\n|^)(--[A-Za-z0-9][A-Za-z0-9_.-]{6,})[\s\S]*$/m, '');

    // Remove visibility:hidden and display:none blocks (obfuscation content not relevant for copy)
    // Match opening tag + content + matching closing tag (up to 60 KB, non-greedy)
    html = html
      .replace(/<[^>]+style\s*=\s*"[^"]*visibility\s*:\s*hidden[^"]*"[^>]*>[\s\S]{0,60000}?<\/(?:div|span|td|section|p)>/gi, ' ')
      .replace(/<[^>]+style\s*=\s*"[^"]*display\s*:\s*none[^"]*"[^>]*>[\s\S]{0,60000}?<\/(?:div|span|td|section|p)>/gi, ' ');

    // Decode Quoted-Printable: soft line breaks first, then encoded chars
    html = html
      .replace(/=\r?\n/g, '')
      .replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));

    return this._stripHtml(html);
  }

  // Handles RFC 2822 header folding (continuation lines starting with whitespace)
  _getHeader(headers, name) {
    const re = new RegExp(`^${name}:\\s*(.+(?:\\r?\\n[ \\t].+)*)`, 'im');
    const m = headers.match(re);
    if (!m) return null;
    return m[1].replace(/\r?\n[ \t]+/g, ' ').trim();
  }

  _extractDomain(str) {
    const m = str.match(/@([\w.-]+)/);
    return m ? m[1].toLowerCase() : null;
  }

  // Return the eTLD+1 root domain (e.g. mail.anthropic.com → anthropic.com)
  // Handles common multi-part TLDs (co.uk, com.au, etc.) to avoid false mismatches
  // between subdomains of the same organisation.
  _extractRootDomain(domain) {
    if (!domain) return null;
    const multiTld = /\.(co\.(uk|jp|nz|za|in)|com\.(au|br|mx)|net\.(au|nz)|org\.(uk|nz)|web\.id|my\.id|biz\.id|sch\.id)$/i;
    if (multiTld.test(domain)) {
      const m = domain.match(/[^.]+\.[^.]+\.[^.]+$/);
      return m ? m[0] : domain;
    }
    const parts = domain.split('.');
    return parts.length >= 2 ? parts.slice(-2).join('.') : domain;
  }

  _stripHtml(html) {
    return html
      .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, ' ')
      .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, ' ')
      .replace(/<[^>]+>/g, ' ')
      .replace(/&nbsp;/gi, ' ')
      .replace(/&amp;/gi, '&')
      .replace(/&lt;/gi, '<')
      .replace(/&gt;/gi, '>')
      .replace(/&quot;/gi, '"')
      .replace(/&#39;/gi, "'")
      .replace(/\s{2,}/g, ' ')
      .trim();
  }
}

// ─── Global state ──────────────────────────────────────────────────────────────

const VERSION    = '1.9.2';
const WORKER_URL = 'https://spam-scorer-ai.felber.workers.dev';

const analyzer = new SpamAnalyzer();
let currentScore    = null;
let lastHeaders     = '';
let lastBodyHtml    = '';   // raw HTML — for originalsrc extraction sent to worker
let lastBodyText    = '';   // cleaned plain text — for copy button
let lastHiddenText  = '';   // text extracted from hidden elements
let lastAnalysis    = null; // { score, reasons, hiddenText }
let lastClaudeResult = null;

// ─── Office init ───────────────────────────────────────────────────────────────

Office.onReady(info => {
  if (info.host !== Office.HostType.Outlook) return;

  document.getElementById('btn-apply').addEventListener('click', applyCategory);
  document.getElementById('btn-retry').addEventListener('click', analyzeCurrentItem);
  document.getElementById('btn-copy-headers').addEventListener('click', () => copyToClipboard(lastHeaders, 'Header kopiert'));
  document.getElementById('btn-copy-body').addEventListener('click',    () => copyToClipboard(lastBodyText, 'Body-Text kopiert'));
  document.getElementById('btn-claude').addEventListener('click', runClaudeCheck);
  document.getElementById('btn-toggle-hidden').addEventListener('click', toggleHiddenText);
  document.getElementById('btn-advice').addEventListener('click', runAdviceCheck);

  initPinHint();
  document.getElementById('version-label').textContent = 'v' + VERSION;

  // Stay open automatically for every email from now on
  if (Office.addin?.setStartupBehavior) {
    Office.addin.setStartupBehavior(Office.StartupBehavior.load).catch(() => {});
  }

  // Re-analyze when user navigates to a different email (pinned pane)
  Office.context.mailbox.addHandlerAsync(Office.EventType.ItemChanged, () => {
    hidePinHint();
    resetClaudeResult();
    resetAdviceResult();
    analyzeCurrentItem();
  });

  analyzeCurrentItem();
});

// ─── Analyze current item ──────────────────────────────────────────────────────

function analyzeCurrentItem() {
  showState('loading');
  currentScore  = null;
  lastAnalysis  = null;
  lastHiddenText = '';

  // Reset hidden text expander
  const htSection = document.getElementById('hidden-text-section');
  const htContent = document.getElementById('hidden-text-content');
  const htBtn     = document.getElementById('btn-toggle-hidden');
  if (htSection) htSection.classList.add('hidden');
  if (htContent) { htContent.classList.add('hidden'); htContent.textContent = ''; }
  if (htBtn)     { htBtn.setAttribute('aria-expanded', 'false'); htBtn.querySelector('.expander-icon').textContent = '▶'; }

  const item = Office.context.mailbox.item;
  if (!item) { showState('no-item'); return; }

  const subject     = item.subject || '';
  const senderEmail = item.from?.emailAddress || '';
  const senderName  = item.from?.displayName  || '';

  Promise.all([
    // Headers (Mailbox 1.8+; gracefully skip if unavailable)
    new Promise(resolve => {
      if (typeof item.getAllInternetHeadersAsync !== 'function') { resolve(''); return; }
      item.getAllInternetHeadersAsync(r =>
        resolve(r.status === Office.AsyncResultStatus.Succeeded ? r.value : ''));
    }),
    // Body as HTML
    new Promise((resolve, reject) => {
      item.body.getAsync(Office.CoercionType.Html, r => {
        if (r.status === Office.AsyncResultStatus.Succeeded) resolve(r.value);
        else reject(new Error(r.error?.message || 'Body nicht lesbar'));
      });
    }),
  ]).then(([headers, bodyHtml]) => {
    lastHeaders    = headers;
    lastBodyHtml   = bodyHtml;
    lastBodyText   = analyzer._cleanBody(bodyHtml);
    const result   = analyzer.analyze(headers, bodyHtml, subject, senderEmail);
    currentScore   = result.score;
    lastAnalysis   = result;
    lastHiddenText = result.hiddenText;
    renderResult(result, headers, subject, senderName || senderEmail);
    showState('result');
  }).catch(err => {
    document.getElementById('error-message').textContent = 'Fehler: ' + err.message;
    showState('error');
  });
}

// ─── Apply category ────────────────────────────────────────────────────────────

async function applyCategory() {
  if (currentScore === null) return;

  const btn         = document.getElementById('btn-apply');
  const newCategory = `Spam: ${currentScore}`;
  const item        = Office.context.mailbox.item;

  if (!item?.categories) {
    showToast('Kategorien nicht verfügbar (Mailbox API 1.8+ erforderlich)', true);
    return;
  }

  btn.disabled    = true;
  btn.textContent = 'Speichern…';

  try {
    // 1. Ensure the category exists in the master list (required before adding to item)
    if (Office.context.mailbox.masterCategories) {
      await new Promise(resolve => {
        Office.context.mailbox.masterCategories.addAsync(
          [{ displayName: newCategory, color: Office.MailboxEnums.CategoryColor.Preset0 }],
          () => resolve()   // ignore "already exists" error
        );
      });
    }

    // 2. Read existing Spam: categories on this item
    const existing = await new Promise((resolve, reject) => {
      item.categories.getAsync(r => {
        if (r.status === Office.AsyncResultStatus.Succeeded) resolve(r.value);
        else reject(new Error(r.error?.message || 'Kategorien konnten nicht gelesen werden'));
      });
    });

    // 3. Remove any previous Spam: N category
    const oldSpam = existing
      .filter(c => /^Spam: \d+$/.test(c.displayName))
      .map(c => c.displayName);

    if (oldSpam.length > 0) {
      await new Promise(resolve => item.categories.removeAsync(oldSpam, () => resolve()));
    }

    // 4. Add the new category
    await new Promise((resolve, reject) => {
      item.categories.addAsync([newCategory], r => {
        if (r.status === Office.AsyncResultStatus.Succeeded) resolve();
        else reject(new Error(r.error?.message || 'Kategorie konnte nicht gesetzt werden'));
      });
    });

    showToast(`Kategorie "${newCategory}" gesetzt`, false);
  } catch (err) {
    showToast('Fehler: ' + err.message, true);
  } finally {
    btn.disabled    = false;
    btn.textContent = 'Als Kategorie speichern';
  }
}

// ─── Rendering ─────────────────────────────────────────────────────────────────

function renderResult(result, headers, subject, senderDisplay) {
  const scoreNum  = document.getElementById('score-number');
  const scoreBar  = document.getElementById('score-bar-fill');
  const scoreWrap = document.getElementById('score-wrap');
  const verdict   = document.getElementById('score-verdict');

  scoreNum.textContent    = result.score;
  scoreBar.style.width    = `${result.score * 10}%`;
  const lvl               = scoreLevel(result.score);
  scoreWrap.className     = `score-wrap lvl-${lvl}`;
  scoreBar.className      = `score-bar-fill lvl-${lvl}`;
  verdict.textContent     = verdictText(result.score);
  scoreBar.setAttribute('aria-valuenow', result.score);

  const list = document.getElementById('reasons-list');
  list.innerHTML = '';
  if (result.reasons.length === 0) {
    const li = document.createElement('li');
    li.className   = 'reason-ok';
    li.textContent = 'Keine Spam-Indikatoren gefunden';
    list.appendChild(li);
  } else {
    result.reasons.forEach(r => {
      const li = document.createElement('li');
      li.textContent = r;
      list.appendChild(li);
    });
  }

  // Hidden text expander — show only when content was found
  const htSection = document.getElementById('hidden-text-section');
  if (result.hiddenText) {
    document.getElementById('hidden-text-content').textContent = result.hiddenText;
    htSection.classList.remove('hidden');
  } else {
    htSection.classList.add('hidden');
  }

  const auth = buildAuthBadges(headers);
  document.getElementById('auth-section').classList.toggle('hidden', auth.allPass);
  document.getElementById('auth-summary').innerHTML = auth.html;
}

function buildAuthBadges(headers) {
  const none = { html: '', allPass: false };
  if (!headers) return none;

  // ── SPF / DKIM / DMARC results ─────────────────────────────────────────────
  const authLine = headers.match(/^Authentication-Results:(.+(?:\r?\n[ \t].+)*)/im)
                || headers.match(/^ARC-Authentication-Results:(.+(?:\r?\n[ \t].+)*)/im);

  if (!authLine) return none;

  const str    = authLine[1];
  const checks = [
    { label: 'SPF',   re: /spf=(pass|fail|softfail|neutral|none)/i },
    { label: 'DKIM',  re: /dkim=(pass|fail|none)/i },
    { label: 'DMARC', re: /dmarc=(pass|fail|none|bestguesspass)/i },
  ];

  const results = checks.map(({ label, re }) => {
    const m   = str.match(re);
    const val = m ? m[1].toLowerCase() : null;
    return { label, val };
  });

  // If every result that exists is 'pass' → hide the whole section
  const allPass = results.every(r => r.val === 'pass');
  if (allPass) return { html: '', allPass: true };

  const badgesHtml = results.map(({ label, val }) => {
    if (!val) return `<span class="auth-badge auth-none">${label} —</span>`;
    const cls = val === 'pass'     ? 'auth-pass'
              : val === 'softfail' ? 'auth-softfail'
              : val === 'fail'     ? 'auth-fail'
              :                     'auth-warn';
    return `<span class="auth-badge ${cls}">${label} ${val.toUpperCase()}</span>`;
  }).join('');

  // ── Domain-path alignment ───────────────────────────────────────────────────
  const hdr = name => {
    const re = new RegExp(`^${name}:\\s*(.+(?:\\r?\\n[ \\t].+)*)`, 'im');
    const m  = headers.match(re);
    return m ? m[1].replace(/\r?\n[ \t]+/g, ' ').trim() : '';
  };
  const dom = str => { const m = str.match(/@([\w.-]+)/); return m ? m[1].toLowerCase() : null; };

  const fromDomain       = dom(hdr('From'));
  const returnPathDomain = dom(hdr('Return-Path'));
  const replyToDomain    = dom(hdr('Reply-To'));
  const dkimDomain       = (hdr('DKIM-Signature').match(/\bd=([\w.-]+)/i) || [])[1]?.toLowerCase() ?? null;

  const rows = [
    { label: 'Von (From)',   domain: fromDomain,       ref: true },
    { label: 'Return-Path',  domain: returnPathDomain, ref: false },
    { label: 'DKIM d=',      domain: dkimDomain,       ref: false },
    { label: 'Reply-To',     domain: replyToDomain,    ref: false },
  ].filter(r => r.domain);

  let alignHtml = '';
  if (rows.length > 1) {
    const rowsHtml = rows.map(r => {
      if (r.ref) return `<tr><td class="ap-label">Von (From)</td><td class="ap-domain">${escapeHtml(r.domain)}</td><td class="ap-icon ap-ref">—</td></tr>`;
      const ok  = r.domain === fromDomain;
      return `<tr class="${ok ? 'ap-ok' : 'ap-warn'}">
        <td class="ap-label">${r.label}</td>
        <td class="ap-domain">${escapeHtml(r.domain)}</td>
        <td class="ap-icon">${ok ? '✓' : '⚠'}</td>
      </tr>`;
    }).join('');
    alignHtml = `<table class="auth-paths">${rowsHtml}</table>`;
  }

  return { html: badgesHtml + alignHtml, allPass: false };
}

// ─── Hidden text toggle ────────────────────────────────────────────────────────

function toggleHiddenText() {
  const btn     = document.getElementById('btn-toggle-hidden');
  const content = document.getElementById('hidden-text-content');
  const icon    = btn.querySelector('.expander-icon');
  const expanded = btn.getAttribute('aria-expanded') === 'true';

  btn.setAttribute('aria-expanded', String(!expanded));
  icon.textContent = expanded ? '▶' : '▼';
  btn.querySelector('span:last-child')
    ? (btn.lastChild.textContent = expanded ? ' Anzeigen' : ' Ausblenden')
    : null;

  content.classList.toggle('hidden', expanded);
}

// ─── UI helpers ────────────────────────────────────────────────────────────────

function showState(state) {
  document.getElementById('state-loading').classList.toggle('hidden', state !== 'loading');
  document.getElementById('state-no-item').classList.toggle('hidden', state !== 'no-item');
  document.getElementById('state-error').classList.toggle('hidden',   state !== 'error');
  document.getElementById('state-result').classList.toggle('hidden',  state !== 'result');
}

function showToast(msg, isError) {
  const toast     = document.getElementById('toast');
  toast.textContent = msg;
  toast.className   = `toast visible ${isError ? 'err' : 'ok'}`;
  setTimeout(() => toast.classList.remove('visible'), 3000);
}

// ─── Pure helpers ──────────────────────────────────────────────────────────────

function scoreLevel(score) {
  if (score <= 2) return 'low';
  if (score <= 5) return 'medium';
  if (score <= 7) return 'high';
  return 'critical';
}

function verdictText(score) {
  if (score === 0) return 'Kein Spam';
  if (score <= 2)  return 'Wahrscheinlich kein Spam';
  if (score <= 4)  return 'Leicht verdächtig';
  if (score <= 6)  return 'Verdächtig';
  if (score <= 8)  return 'Wahrscheinlich Spam';
  return 'Sehr wahrscheinlich Spam';
}

// ─── Claude AI check ───────────────────────────────────────────────────────────

async function runClaudeCheck() {
  const btn      = document.getElementById('btn-claude');
  const resultEl = document.getElementById('claude-result');

  if (!lastHeaders && !lastBodyText) {
    showToast('Keine E-Mail-Daten verfügbar — bitte zuerst analysieren', true);
    return;
  }

  btn.disabled    = true;
  btn.textContent = 'Claude analysiert…';
  resultEl.classList.add('hidden');
  resultEl.innerHTML = '';

  const item        = Office.context.mailbox.item;
  const subject     = item?.subject      || '';
  const senderEmail = item?.from?.emailAddress || '';

  try {
    // Extract real URLs from Microsoft Safe Links (originalsrc attribute)
    const origSrcRe2  = /originalsrc="([^"]+)"/gi;
    const origSrcUrls = [];
    let osm2;
    while ((osm2 = origSrcRe2.exec(lastBodyHtml)) !== null) origSrcUrls.push(osm2[1]);

    const res = await fetch(WORKER_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ headers: lastHeaders, bodyText: lastBodyText, subject, senderEmail, origSrcUrls }),
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Worker-Fehler ${res.status}: ${errText}`);
    }

    const data = await res.json();
    if (data.error) throw new Error(data.error);

    lastClaudeResult = data;
    renderClaudeResult(data, subject, senderEmail);

    // Reveal the advice section after a successful Claude analysis
    document.getElementById('advice-section').classList.remove('hidden');
  } catch (err) {
    resultEl.innerHTML = `<p class="claude-error">⚠ ${escapeHtml(err.message)}</p>`;
    resultEl.classList.remove('hidden');
  } finally {
    btn.disabled    = false;
    btn.textContent = 'Mit Claude AI prüfen';
  }
}

function renderClaudeResult(data, subject, senderEmail) {
  const resultEl = document.getElementById('claude-result');

  const cls   = data.verdict === 'spam'     ? 'claude-spam'
              : data.verdict === 'ham'       ? 'claude-ham'
              :                               'claude-uncertain';

  const label = data.verdict === 'spam'     ? '🚨 Spam'
              : data.verdict === 'ham'       ? '✅ Kein Spam'
              : data.verdict === 'uncertain' ? '⚠️ Unsicher'
              :                               '❓ Unbekannt';

  const signalsHtml = (data.signals || []).length
    ? '<ul class="claude-signals">' +
        data.signals.map(s => `<li>${escapeHtml(s)}</li>`).join('') +
      '</ul>'
    : '';

  const aiScore    = data.score ?? null;
  const addinScore = currentScore ?? null;

  // Score comparison row
  let comparisonHtml = '';
  if (aiScore !== null && addinScore !== null) {
    const diff = Math.abs(aiScore - addinScore);
    const diffCls = diff <= 1 ? 'score-diff-agree'
                  : diff <= 3 ? 'score-diff-warn'
                  :             'score-diff-danger';
    const diffLabel = diff <= 1  ? '≈ übereinstimmend'
                    : aiScore > addinScore ? `⬆ KI ${diff} Punkte höher`
                    :                        `⬇ KI ${diff} Punkte niedriger`;
    comparisonHtml = `
      <div class="score-comparison">
        Add-in: <strong>${addinScore}/10</strong> · KI: <strong>${aiScore}/10</strong>
        <span class="${diffCls}">${diffLabel}</span>
      </div>`;
  }

  // Improvement prompt for copy
  const promptText = buildImprovementPrompt(data, subject, senderEmail);
  const promptHtml = `
    <details class="improvement-prompt">
      <summary>LLM-Prompt zur Verbesserung der Logik</summary>
      <div class="prompt-box" id="improvement-prompt-box">${escapeHtml(promptText)}</div>
      <button class="btn-copy-prompt" id="btn-copy-prompt">📋 Prompt kopieren</button>
    </details>`;

  resultEl.innerHTML = `
    <div class="claude-verdict ${cls}">
      <strong>${label}</strong>
      <span class="claude-confidence">${data.confidence ?? '—'}% Konfidenz</span>
      ${aiScore !== null ? `<span class="claude-score">Score: ${aiScore}/10</span>` : ''}
    </div>
    ${comparisonHtml}
    ${data.summary ? `<p class="claude-summary">${escapeHtml(data.summary)}</p>` : ''}
    ${signalsHtml}
    ${promptHtml}
  `;

  // Wire up the copy button after inserting HTML
  document.getElementById('btn-copy-prompt')?.addEventListener('click', () => {
    copyToClipboard(promptText, 'Prompt kopiert');
  });

  resultEl.classList.remove('hidden');
}

function buildImprovementPrompt(claudeData, subject, senderEmail) {
  const addinScore  = currentScore ?? '?';
  const aiScore     = claudeData.score ?? '?';
  const addinVerdict = currentScore !== null ? verdictText(currentScore) : '?';
  const signals     = (lastAnalysis?.reasons || []).map(r => `  - ${r}`).join('\n') || '  (keine)';
  const aiSignals   = (claudeData.signals || []).map(s => `  - ${s}`).join('\n') || '  (keine)';

  const caseType = (currentScore !== null && claudeData.score !== null)
    ? currentScore < claudeData.score
      ? 'False Negative (Add-in zu nachsichtig — erkennt Spam nicht)'
      : currentScore > claudeData.score
        ? 'False Positive (Add-in zu streng — legitime E-Mail als Spam eingestuft)'
        : 'Scores stimmen überein — Signals zur Überprüfung'
    : 'Unbekannte Abweichung';

  return `Du reviewst die Spam-Scoring-Logik eines Outlook Add-ins (taskpane.js, SpamAnalyzer-Klasse).
Analysiere den folgenden Fall und schlage konkrete Verbesserungen vor.

## E-Mail-Kontext
Betreff  : ${subject || '(unbekannt)'}
Absender : ${senderEmail || '(unbekannt)'}

## Scoring-Ergebnis
Add-in Score  : ${addinScore}/10 (${addinVerdict})
Claude KI Score: ${aiScore}/10 — Verdict: ${claudeData.verdict ?? '?'} (${claudeData.confidence ?? '?'}% Konfidenz)
Falltyp       : ${caseType}

## Add-in Signale (gefundene Indikatoren)
${signals}

## Claude KI Signale
${aiSignals}

## Claude Zusammenfassung
${claudeData.summary || '(keine)'}

## Aufgabe
Schlage spezifische Verbesserungen für die SpamAnalyzer-Klasse in taskpane.js vor:

1. Welche bestehenden Signal-Gewichte sollten angepasst werden und warum?
2. Welche neuen Regex-Muster (mit konkretem JavaScript-Code) sollten ergänzt werden?
3. Welche Bedingungen sollten den Score SENKEN (False-Positive-Prävention)?
4. Welche Bedingungen sollten den Score ERHÖHEN (False-Negative-Prävention)?

Berücksichtige dabei sowohl False Positives (legitime E-Mails als Spam) als auch
False Negatives (Spam-E-Mails nicht erkannt). Liefere konkreten JavaScript-Code.`;
}

function resetClaudeResult() {
  const el = document.getElementById('claude-result');
  if (el) { el.innerHTML = ''; el.classList.add('hidden'); }
  lastClaudeResult = null;
}

// ─── Reputation advice ─────────────────────────────────────────────────────────

async function runAdviceCheck() {
  const btn      = document.getElementById('btn-advice');
  const resultEl = document.getElementById('advice-result');

  btn.disabled    = true;
  btn.textContent = 'Generiere Vorschläge…';
  resultEl.classList.add('hidden');
  resultEl.innerHTML = '';

  const item        = Office.context.mailbox.item;
  const subject     = item?.subject             || '';
  const senderEmail = item?.from?.emailAddress  || '';

  try {
    const res = await fetch(WORKER_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mode:         'advice',
        headers:      lastHeaders,
        bodyText:     lastBodyText,
        subject,
        senderEmail,
        addinScore:   currentScore,
        addinSignals: lastAnalysis?.reasons || [],
        claudeResult: lastClaudeResult,
      }),
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Worker-Fehler ${res.status}: ${errText}`);
    }

    const data = await res.json();
    if (data.error) throw new Error(data.error);

    renderAdviceResult(data);
  } catch (err) {
    resultEl.innerHTML = `<p class="advice-error">⚠ ${escapeHtml(err.message)}</p>`;
    resultEl.classList.remove('hidden');
  } finally {
    btn.disabled    = false;
    btn.textContent = 'Verbesserungsvorschläge generieren';
  }
}

function renderAdviceResult(data) {
  const resultEl = document.getElementById('advice-result');

  const summaryHtml = data.summary
    ? `<p class="advice-summary">${escapeHtml(data.summary)}</p>`
    : '';

  const recs = data.recommendations || [];
  const recsHtml = recs.length
    ? '<ul class="advice-list">' + recs.map(r => {
        const prioClass = (r.priority || '').toLowerCase() === 'hoch'    ? 'prio-hoch'
                        : (r.priority || '').toLowerCase() === 'mittel'  ? 'prio-mittel'
                        :                                                   'prio-niedrig';
        return `<li class="advice-item ${prioClass}">
          <div class="advice-item-header">
            <span class="advice-category">${escapeHtml(r.category || '')}</span>
            <span class="advice-priority">${escapeHtml(r.priority || '')}</span>
          </div>
          <div class="advice-title">${escapeHtml(r.title || '')}</div>
          <div class="advice-action">${escapeHtml(r.action || '')}</div>
        </li>`;
      }).join('') + '</ul>'
    : '<p class="advice-action">Keine Empfehlungen gefunden.</p>';

  resultEl.innerHTML = summaryHtml + recsHtml;
  resultEl.classList.remove('hidden');
}

function resetAdviceResult() {
  const section  = document.getElementById('advice-section');
  const resultEl = document.getElementById('advice-result');
  if (section)  section.classList.add('hidden');
  if (resultEl) { resultEl.innerHTML = ''; resultEl.classList.add('hidden'); }
}

// ─── Pin hint ──────────────────────────────────────────────────────────────────

function initPinHint() {
  const hint = document.getElementById('pin-hint');
  if (!hint) return;
  if (localStorage.getItem('pinHintDismissed')) { hint.classList.add('hidden'); return; }
  document.getElementById('pin-hint-dismiss').addEventListener('click', () => {
    localStorage.setItem('pinHintDismissed', '1');
    hint.classList.add('hidden');
  });
}

function hidePinHint() {
  const hint = document.getElementById('pin-hint');
  if (hint) hint.classList.add('hidden');
}

// ─── Clipboard ────────────────────────────────────────────────────────────────

function copyToClipboard(text, successMsg) {
  if (!text) { showToast('Keine Daten verfügbar', true); return; }
  navigator.clipboard.writeText(text).then(
    ()  => showToast(successMsg, false),
    ()  => showToast('Kopieren fehlgeschlagen', true)
  );
}

function escapeHtml(str) {
  const d = document.createElement('div');
  d.textContent = String(str);
  return d.innerHTML;
}
