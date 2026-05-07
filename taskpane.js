'use strict';

// ─── Spam Analyzer ────────────────────────────────────────────────────────────
// Pure logic — no DOM or Office dependencies.

class SpamAnalyzer {
  analyze(headers, bodyHtml, subject, senderEmail) {
    const reasons    = [];
    const hScore     = headers ? this._analyzeHeaders(headers, reasons) : 0;
    const bScore     = this._analyzeBody(bodyHtml, subject, reasons);
    const hiddenText = this._extractHiddenTextFiltered(bodyHtml || '');

    // Deliverability notes: observations the score MAY have softened (because
    // the recipient's reading experience is not affected) but which the sender
    // must address — spam filters can't execute CSS, don't grant ESP-exemptions
    // for engagement signals, and look at headers Microsoft already filled in.
    const deliverabilityNotes = this._collectDeliverabilityNotes(headers || '', bodyHtml || '');

    return {
      score: Math.min(10, Math.round(hScore + bScore)),
      reasons,
      hiddenText,
      deliverabilityNotes,
    };
  }

  // Surface findings that we may have softened in the score but remain real
  // deliverability problems for the sender. Two source classes:
  //   1. Microsoft direct measurements (dest:J, OFR, SCL, BCL) — Microsoft has
  //      already classified the email. Auth-quality doesn't undo that.
  //   2. Structural patterns spam filters key on (display:none + media query,
  //      pervasive white text) — these don't affect the recipient because
  //      modern mail clients render correctly, but naive filters do not.
  _collectDeliverabilityNotes(headers, bodyHtml) {
    const notes = [];

    // ── Microsoft Exchange signals ──────────────────────────────────────────
    if (headers) {
      const delivery = this._getHeader(headers, 'X-Microsoft-Antispam-Mailbox-Delivery') || '';

      if (/dest:J/i.test(delivery)) {
        // Concise signal — Claude writes the full explanation in its recommendation
        notes.push('dest:J: Exchange-Junk trotz Auth — Engagement, Content-Muster oder IP-Reputation.');
      }

      if (/OFR:SpamFilter/i.test(delivery)) {
        notes.push('OFR:SpamFilterAuthJ: Auth-Pass überstimmt — Content-Muster oder Sender-Reputation.');
      }

      const sclMatch = headers.match(/^X-MS-Exchange-Organization-SCL:\s*(\d+)/im);
      if (sclMatch) {
        const scl = parseInt(sclMatch[1], 10);
        if (scl >= 5) {
          notes.push(`SCL=${scl} (Junk-Schwelle ≥5) — Microsoft bewertet Inhalt oder Reputation negativ.`);
        }
      }

      const antispam = this._getHeader(headers, 'X-Microsoft-Antispam') || '';
      const bclMatch = antispam.match(/BCL:(\d+)/);
      if (bclMatch) {
        const bcl = parseInt(bclMatch[1], 10);
        if (bcl >= 4) {
          notes.push(`BCL=${bcl} (Beschwerderate erhöht ≥4) — Empfänger markieren E-Mails zu häufig als Spam.`);
        }
      }

      // HELO mismatch (we may whitelist common ESPs and reduce penalty —
      // but the underlying mismatch is still a filter signal)
      const receivedSpf = this._getHeader(headers, 'Received-SPF') || '';
      const fromHeader  = this._getHeader(headers, 'From')         || '';
      const heloM       = receivedSpf.match(/helo=([\w.-]+)/i);
      const fromDom     = this._extractDomain(fromHeader);
      if (heloM && fromDom) {
        const helo = heloM[1].toLowerCase();
        if (helo !== fromDom
            && !helo.endsWith('.' + fromDom)
            && !fromDom.endsWith('.' + helo)) {
          const fromRoot = this._extractRootDomain(fromDom);
          const heloRoot = this._extractRootDomain(helo);
          if (fromRoot !== heloRoot) {
            notes.push(`HELO-Mismatch: ${helo} ≠ ${fromDom} — Sending-Domain nicht konsistent mit From-Domain.`);
          }
        }
      }
    }

    // ── Structural / content patterns ───────────────────────────────────────
    if (bodyHtml) {
      const rawHidden      = this._extractHiddenText(bodyHtml);
      const filteredHidden = this._extractHiddenTextFiltered(bodyHtml);
      const plainText      = this._stripHtml(bodyHtml);
      const visibleText    = this._extractVisibleText(bodyHtml);

      // Display:none-rendered-via-CSS pattern
      if (rawHidden.length > 500
          && filteredHidden.length < rawHidden.length * 0.2) {
        notes.push(
          `display:none-Anteil ~${rawHidden.length} Z. via CSS Media-Query — Spamfilter sehen Inhalt als versteckt.`
        );
      }

      // Visible DOM tiny relative to total HTML payload (similar pattern)
      if (visibleText.length > 0
          && plainText.length > 1000
          && visibleText.length < plainText.length * 0.2
          && !notes.some(n => n.includes('display:none'))) {
        notes.push(
          `Sichtbarer Text (${visibleText.length} Z.) < 20% HTML-Gesamt — Dark/Light-Mode-Duplikate.`
        );
      }

      // Pervasive white text — even on coloured backgrounds (CTAs, callouts)
      // it can trigger naive filter heuristics.
      const whiteTextCount = (bodyHtml.match(/color\s*:\s*(white|#fff\b|#ffffff)/gi) || []).length;
      if (whiteTextCount >= 8) {
        notes.push(
          `${whiteTextCount}× color:white inline — klassische Filter zählen weiße Textfarbe als Spam-Signal.`
        );
      }

      // Quoted-Printable density — already scored, but if even moderate amount
      // exists in HTML, it's worth telling the sender.
      const qpMatches = (bodyHtml.match(/=[0-9A-Fa-f]{2}/g) || []).length;
      if (qpMatches > 15 && bodyHtml.length > 0
          && (qpMatches / (bodyHtml.length / 100)) > 0.5) {
        notes.push(
          `${qpMatches} QP-Sequenzen (=XX) im HTML — Spam-Pipelines verschleiern Content so; UTF-8 bevorzugen.`
        );
      }
    }

    return notes;
  }

  // Convenience wrapper that produces the comparison-text fallback used by
  // both analyze() and _analyzeBody. Picks visibleText when it's a meaningful
  // size, falls back to plainText otherwise (handles emails where the entire
  // visible content sits inside display:none containers re-shown by media
  // queries — common in dark/light-mode and responsive templates).
  _extractHiddenTextFiltered(bodyHtml) {
    const plainText   = this._stripHtml(bodyHtml || '');
    const visibleText = this._extractVisibleText(bodyHtml || '');
    // If <20% of total text is actually visible (DOM-rendered), the email
    // very likely renders content via CSS media-query overrides on default-
    // hidden blocks. In that case visibleText is unreliable as a comparison
    // basis — fall back to the full plainText so duplicates still get caught.
    const compareText = visibleText.length < plainText.length * 0.2
      ? plainText
      : visibleText;
    return this._extractHiddenText(bodyHtml || '', compareText);
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
    // bclVal is hoisted so it can gate the dest:J reduction below and be shared with _analyzeBody.
    const msAntispam = this._getHeader(headers, 'X-Microsoft-Antispam') || '';
    const bclM   = msAntispam.match(/BCL:(\d+)/);
    const bclVal = bclM ? parseInt(bclM[1], 10) : 0;
    if (bclM) {
      if (bclVal >= 8)      { score += 2;   reasons.push(`Microsoft BCL ${bclVal}: sehr hohe Beschwerderate`); }
      else if (bclVal >= 7) { score += 2.5; reasons.push(`Microsoft BCL ${bclVal}: hohe Beschwerderate (Bulk-Mail)`); }
      else if (bclVal >= 4) { score += 0.8; reasons.push(`Microsoft BCL ${bclVal}: erhöhte Beschwerderate`); }
    }

    // dest:J = Exchange delivered to Junk — the server already classified it as spam.
    // The authFullyPasses reduction only applies when BCL < 7 AND OFR is absent.
    // OFR:SpamFilter means the spam filter explicitly overrode an auth-pass decision —
    // if the server already decided it's spam despite clean auth, the ESP exemption
    // should not apply (e.g. BCL 6 + OFR = confirmed spam, not a legitimate ESP sender).
    const msDelivery = this._getHeader(headers, 'X-Microsoft-Antispam-Mailbox-Delivery') || '';
    const hasOFR     = /OFR:SpamFilter/i.test(msDelivery);
    if (/dest:J/i.test(msDelivery)) {
      if (authFullyPasses && bclVal < 7 && !hasOFR) {
        score += 0.5; reasons.push('Microsoft Exchange: Junk-Zustellung (aber vollständige Authentifizierung — evtl. ESP)');
      } else {
        score += 2; reasons.push('Microsoft Exchange: an Junk-Ordner zugestellt');
      }
    }

    // OFR:SpamFilterAuthJ = Exchange spam filter explicitly overrode an auth-based pass decision.
    // Strong signal: the server identified spam characteristics despite clean auth.
    if (/OFR:SpamFilter/i.test(msDelivery)) {
      score += 1.5;
      reasons.push('Microsoft Exchange: Spam-Filter hat Auth-Pass überstimmt (OFR:SpamFilter)');
    }

    // Combo: dest:J AND OFR together = two independent Microsoft verdicts → stronger than either alone
    if (/dest:J/i.test(msDelivery) && /OFR:SpamFilter/i.test(msDelivery)) {
      score += 0.5;
      reasons.push('Microsoft Exchange: Doppel-Signal — Junk-Zustellung UND Filter-Override');
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

      // Sender domain uses a TLD that is heavily abused for throwaway spam/phishing domains.
      // Note: .la, .pw, .cc etc. are technically valid ccTLDs but almost never used by legitimate
      // bulk senders — phishers register them precisely because they're cheap and obscure.
      const suspSenderTld = /\.(tk|cf|ga|ml|gq|xyz|top|click|download|stream|loan|win|racing|buzz|la|pw|cc|ws|nu)$/i;
      if (suspSenderTld.test(fromDomain)) {
        score += 1.5;
        reasons.push(`Verdächtige Absender-Domain-TLD (.${fromDomain.split('.').pop()})`);
      }
    }

    // Store root domain for brand-impersonation check in _analyzeBody (subject not available here)
    this._lastFromRootDomain = this._extractRootDomain(fromDomain);

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

    // Spam keywords in the From display name (e.g. "Detox Nachrichten" <alert@andressacupuncture.com>).
    // Spammers set an enticing display name that has nothing to do with the sender domain.
    // Only fires when the display name exists and is distinct from the domain name.
    const fromDisplayName = (fromHeader.match(/^"?([^"<@\n]+?)"?\s*</) || [])[1]?.trim() || '';
    if (fromDisplayName) {
      const displayLower = fromDisplayName.toLowerCase();
      const domainRoot   = this._extractRootDomain(fromDomain) || '';
      // Skip if the display name is just the company name embedded in the domain
      const domainWord   = domainRoot.split('.')[0];
      if (!displayLower.includes(domainWord) &&
          /detox|abnehm|gewicht\s*(verlier|verlor|abgenomm)|schlank|fettverbrenner|keto\b|nahrungsergänzung|supplement|casino|jackpot|gewinn(?!chein)|lotterie|crypto|bitcoin|kredit(?!karte)|darlehen|niedrigzins|pharma|viagra|glück.{0,10}spiel/i.test(fromDisplayName)) {
        score += 1.5;
        reasons.push(`Spam-Keyword im Absender-Anzeigename: "${fromDisplayName}"`);
      }
    }

    // Expose auth state and BCL to _analyzeBody via instance state (avoids parameter threading)
    this._lastAuthFullyPasses = authFullyPasses;
    this._lastBclVal          = bclVal;

    return score;
  }

  _analyzeBody(bodyHtml, subject, reasons) {
    let score = 0;

    // Read auth/BCL state set by _analyzeHeaders.
    // authFullyPasses reductions are overridden when BCL ≥ 7 (confirmed bulk complaint sender).
    const authFullyPasses = this._lastAuthFullyPasses || false;
    const bclVal          = this._lastBclVal          || 0;
    const highBcl         = bclVal >= 7;   // BCL 7–9 = mass complaint sender, no ESP exemption

    const plainText   = this._stripHtml(bodyHtml || '');
    const fullText    = (subject || '') + ' ' + plainText;
    const fullLower   = fullText.toLowerCase();

    // Spam keyword patterns (German + English)
    const patterns = [
      { re: /gewinn(en|er|t|chance)|ihre?\s+gewinnchance|lotterie|jackpot|millionen?\s*euro|preis\s*gewonnen|haben\s+(sie\s+)?gewonnen/i, w: 2, label: 'Gewinnversprechen' },
      { re: /nigeria|prince|inheritance|erbschaft|million[s]?\s*dollar/i,                  w: 2.5, label: 'Nigeria-/Vorschussbetrug' },
      { re: /viagra|cialis|levitra|pharmacy|apotheke\s*ohne\s*rezept/i,                    w: 2.5, label: 'Pharma-Spam' },
      { re: /casino|online.?wett(en|büro)|glücksspiel|freispiel(e)?|\bslots?\b|roulette|blackjack|poker\s*bonus/i, w: 1.5, label: 'Glücksspiel/Casino' },
      { re: /\d[\d.,]*\s*€\s*(zum|bei)\s+(niedrig|günstig|tief)zins|kreditangebot|sofortkredit|kredit\s+ohne\s+(schufa|bonitätsprüfung)|umschuldung|privat(kredit|darlehen)|effektiver\s+jahreszins|sollzinssatz/i, w: 1.5, label: 'Finanzangebot-Spam (Kredit/Darlehen)' },
      { re: /ihr\s+(konto|paypal|amazon|apple|microsoft).{0,30}(gesperrt|deaktiviert)/i,   w: 2,   label: 'Phishing: Konto gesperrt' },
      { re: /passwort\s*(ablaufen|bestätigen|verifizieren|erneuern|expired)/i,             w: 2,   label: 'Phishing: Passwort-Anfrage' },
      { re: /klicken\s*sie\s*hier|click\s*here|jetzt\s*klicken/i,                         w: 0.5, label: 'Generische Klick-Aufforderung' },
      { re: /dringend|urgent|sofort\s*handeln|act\s*now|limited\s*time|angebot\s*(endet|läuft)|läuft\s*(heute\s*)?ab|bald\s*nicht\s*mehr\s*verfügbar|bonus\s*(endet|läuft|expires)|angebot\s+endet\s+bald/i, w: 0.5, label: 'Künstliche Dringlichkeit' },
      { re: /100\s*%\s*(kostenlos|gratis|free)|völlig\s*kostenlos/i,                      w: 0.8, label: 'Gratis-Versprechen' },
      { re: /sie\s*wurden\s*ausgewählt|you\s*have\s*been\s*selected/i,                    w: 1.5, label: 'Pseudo-Auszeichnung' },
      { re: /\bcrypto|bitcoin|kryptowährun|invest.{0,30}(rendite|gewinne?|robot)|hohe\s*rendite|trading.{0,20}(auto|bot|signal)|warum\s+alle.{0,20}invest|fibonacci|forex\s+signal/i, w: 1.5, label: 'Crypto/Investment-Spam' },
      { re: /ihre\s*(daten|informationen)\s*(wurden\s*)?bestätigen|verify\s*your\s*info/i, w: 1.5, label: 'Datenmissbrauch-Phishing' },
      { re: /lions?\s*(mane|spray)|körper\s*reset|nahrungsergänzung|supplement\b|fettverbrenner|schlank(heits)?|kräuter.{0,25}(spray|tropfen|kapsel)|testosteron.{0,20}boost|abnehm|\bdetox\b|keto\s*(diät|plan|programm|rezept|\b)|\d+\s*kg\s*(verloren?|abgenommen)|gewicht\s*(verloren?|verlier|abgenomm)|bauchfett|taille\s*(reduzier|weg|schmaler)/i, w: 1.5, label: 'Supplement/Gewichtsabnahme-Spam' },
      { re: /wechat|微信|telegram\s*(channel|contact|group|id)|whatsapp\s*(contact|number|group)|line\s*id\s*:/i, w: 1.5, label: 'Messenger-Kontakt-Solicitation (WeChat/Telegram/WhatsApp)' },
      { re: /bundeszentralamt|finanzamt\b|bundeszoll|steuerpr[üu]fung.*krypto|amtliche?\s+(mahnung|aufforderung|mitteilung).*steuer/i, w: 2.5, label: 'Behörden-Impersonation (Finanzamt/BZSt)' },
      { re: /\b(UPS|DHL|FedEx|Hermes|DPD|GLS|Yodel|Evri)\b.{0,40}(paket|lieferung|sendung|delivery|tracking|notification|nicht\s*zugestellt)/i, w: 1.5, label: 'Kurierdienst-Erwähnung (auf Domain-Mismatch prüfen)' },
    ];

    for (const p of patterns) {
      if (p.re.test(fullLower)) { score += p.w; reasons.push(p.label); }
    }

    // Brand impersonation: subject prominently names a major brand but the sender domain
    // doesn't belong to that brand — classic phishing pattern.
    // Only fires when _lastFromRootDomain is known and doesn't match the brand's official roots.
    // False-positive guard: legitimate newsletters from a brand come from the brand's own domain.
    const fromRootForBrand = this._lastFromRootDomain || null;
    if (fromRootForBrand) {
      const brandMap = [
        { re: /\brewe\b/i,                        roots: ['rewe.de', 'rewe-group.com'] },
        { re: /\bedeka\b/i,                        roots: ['edeka.de', 'edeka-group.com'] },
        { re: /\blidl\b/i,                         roots: ['lidl.de', 'lidl.com'] },
        { re: /\baldi\b/i,                         roots: ['aldi-sued.de', 'aldi-nord.de', 'aldi.de', 'aldi.com'] },
        { re: /\bkaufland\b/i,                     roots: ['kaufland.de', 'kaufland.com'] },
        { re: /\bpenny\b/i,                        roots: ['penny.de'] },
        { re: /\bnetto\b/i,                        roots: ['netto-online.de', 'netto.de'] },
        { re: /\brossmann\b/i,                     roots: ['rossmann.de'] },
        { re: /\bdm[\s-]?(drogerie|markt)\b/i,     roots: ['dm.de'] },
        { re: /\bdeutsche\s*bahn\b|\bdb\s+bahn\b/, roots: ['deutschebahn.com', 'bahn.de', 'db.de'] },
        { re: /\bdhl\b/i,                          roots: ['dhl.de', 'dhl.com', 'dhl-group.com'] },
        { re: /\bups\b/i,                          roots: ['ups.com', 'ups.de'] },
        { re: /\bhermes\b/i,                       roots: ['myhermes.de', 'hermesworld.com', 'hlg.de'] },
        { re: /\bamazon\b/i,                       roots: ['amazon.de', 'amazon.com', 'amazon.co.uk'] },
        { re: /\bpaypal\b/i,                       roots: ['paypal.com', 'paypal.de'] },
        { re: /\bnetflix\b/i,                      roots: ['netflix.com', 'netflix.net'] },
        { re: /\bspotify\b/i,                      roots: ['spotify.com'] },
        { re: /\bapple\b/i,                        roots: ['apple.com'] },
        { re: /\bmicrosoft\b|\boutlook\.com\b|\bonedrive\b/i, roots: ['microsoft.com', 'outlook.com', 'live.com', 'hotmail.com'] },
        { re: /\bsparkasse\b/i,                    roots: ['sparkasse.de'] },
        { re: /\bvolksbank\b/i,                    roots: ['volksbank.de', 'vr.de'] },
        { re: /\bpostbank\b/i,                     roots: ['postbank.de'] },
        { re: /\bdeutsche\s*bank\b/i,              roots: ['deutsche-bank.de', 'db.com'] },
        { re: /\bcommerzbank\b/i,                  roots: ['commerzbank.de', 'commerzbank.com'] },
        { re: /\bing[\s-]?diba\b|\bing\s+bank\b/i, roots: ['ing.de', 'ing-diba.de'] },
        // Automotive / mobility
        { re: /\badac\b/i,                           roots: ['adac.de', 'adac.com'] },
        { re: /\bdekra\b/i,                          roots: ['dekra.de', 'dekra.com'] },
        // Retail / e-commerce
        { re: /\bzalando\b/i,                        roots: ['zalando.de', 'zalando.com'] },
        { re: /\bmediamarkt\b/i,                     roots: ['mediamarkt.de', 'mediamarkt.com'] },
        { re: /\bsaturn\b/i,                         roots: ['saturn.de'] },
        { re: /\bdecathlon\b/i,                      roots: ['decathlon.de', 'decathlon.com'] },
        // Telecoms
        { re: /\btelekom\b|\bdeutsche\s*telekom\b/i, roots: ['telekom.de', 'telekom.com', 'deutschetelekom.com'] },
        { re: /\bvodafone\b/i,                       roots: ['vodafone.de', 'vodafone.com'] },
      ];
      // Check subject first (high confidence, weight 2.5).
      // If the subject is clean, fall back to the first 800 chars of body text (weight 1.5)
      // to catch impersonation cases where only the email body names the brand.
      // Body-only weight is lower to tolerate legitimate newsletters that editorially
      // mention a competitor or partner brand name.
      for (const { re, roots } of brandMap) {
        if (!roots.includes(fromRootForBrand)) {
          const inSubject = re.test(subject);
          const inBody    = !inSubject && re.test(plainText.slice(0, 800));
          if (inSubject || inBody) {
            const matchedBrand = (subject.match(re) || plainText.match(re) || [''])[0];
            const w            = inSubject ? 2.5 : 1.5;
            score += w;
            reasons.push(`Marken-Impersonation: "${matchedBrand}" ${inSubject ? 'im Betreff' : 'im E-Mail-Text'}, Absender-Domain "${fromRootForBrand}"`);
            break; // one impersonation signal is enough
          }
        }
      }
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
    //
    // Only href="https://…" attributes count as visible links for density purposes.
    // A global /https?:\/\//g match on the whole HTML also hits originalsrc values,
    // img src, CSS backgrounds, etc. — inflating the count (e.g. 4 Safe-Links hrefs
    // would report 11 because each href/originalsrc pair is matched separately).
    const hrefRe   = /\bhref="(https?:\/\/[^"]+)"/gi;
    const rawLinks = [];
    let hlm;
    while ((hlm = hrefRe.exec(bodyHtml || '')) !== null) rawLinks.push(hlm[1]);

    // Separately extract Microsoft Safe Links originalsrc — the real destination URL.
    // Used only for TLD / shortener checks, not for link counting.
    const origSrcRe = /originalsrc="([^"]+)"/gi;
    const origSrcs  = [];
    let osm;
    while ((osm = origSrcRe.exec(bodyHtml || '')) !== null) origSrcs.push(osm[1]);

    // For suspicious-URL checks use unwrapped destinations first, fall back to raw hrefs.
    const links     = [...new Set([...origSrcs, ...rawLinks])];
    const linkCount = rawLinks.length;   // visible href links only

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

    // Suspicious URL structures used by spam redirect/obfuscation systems.
    // .jspx files: a Java Server Page variant almost never served in legitimate email links;
    // spammers use random-string .jspx filenames (e.g. "8O9DpCvO5e.jspx") as redirect handlers.
    if (links.some(l => /\/[A-Za-z0-9]{5,15}\.jspx(\?|$)/i.test(l))) {
      score += 1.5;
      reasons.push('Verdächtige URL-Dateiendung (.jspx) — Spam-Redirect-System');
    }

    // Exclamation marks (!) inside URL parameter values are not valid unencoded in URLs (RFC 3986
    // permits ! in paths but spam trackers use garbled strings like "ev7jtp!jhhhjhwwl1t!j!j21t5"
    // as obfuscated tracking tokens). Legitimate ESPs use proper base64/hex encoding.
    if (links.some(l => /[?&][a-z]{1,6}=[a-z0-9]{4,}![a-z0-9!]{4,}/i.test(l))) {
      score += 1;
      reasons.push('Obfuskierte URL-Parameter mit Sonderzeichen — Spam-Tracking-Token');
    }

    if (linkCount > 0) {
      const textLen = plainText.length;
      if (textLen < 80 && linkCount >= 2) {
        score += 1;
        reasons.push('Sehr kurzer Text mit mehreren Links');
      } else if (textLen > 0 && (linkCount / (textLen / 100)) > 0.4) {
        // Reduce link-density penalty for fully-authenticated, low-BCL senders only.
        // High BCL (≥7) means confirmed bulk complaint sender — no reduction.
        const raw     = Math.min(1, linkCount * 0.12);
        const penalty = (authFullyPasses && !highBcl) ? raw * 0.3 : raw;
        if (penalty >= 0.1) {
          score += penalty;
          reasons.push(`Hohe Link-Dichte (${linkCount} Links)`);
        }
      }
    }

    // Hidden / invisible text — classic spam obfuscation technique.
    //
    // Two-stage filter to avoid false positives:
    //   1. _extractHiddenText filters duplicated content (responsive variants,
    //      dark-mode alternates) by comparing word-overlap with the truly visible
    //      DOM text — not _stripHtml, which ignores display:none.
    //   2. Threshold scales with authentication quality:
    //      • Fully authenticated, low-BCL sender → tolerate 500 chars (preheader
    //        is typically 100–250 chars and is a legitimate marketing pattern).
    //      • Unauthenticated or high-BCL sender → 60-char threshold (strict).
    if (/color\s*:\s*(white|#fff\b|#ffffff)|font-size\s*:\s*[01]px|display\s*:\s*none|visibility\s*:\s*hidden/i.test(bodyHtml || '')) {
      const hiddenContent = this._extractHiddenTextFiltered(bodyHtml || '');
      const hiddenLen     = hiddenContent.length;
      const trustedSender = authFullyPasses && !highBcl;
      // Trusted senders: tolerate up to 500 chars of hidden text (preheader + variants).
      // Untrusted: 60-char threshold for the "substantial" flag.
      const substantialThreshold = trustedSender ? 500 : 60;

      if (hiddenLen > substantialThreshold) {
        score += 1.5;
        reasons.push(`Versteckter/unsichtbarer Text gefunden (substantiell, abweichend vom sichtbaren Inhalt — ${hiddenLen} Zeichen)`);
      } else if (hiddenLen > 60 && !trustedSender) {
        // Modest amount of hidden text + weak auth → tracking pixel / minor obfuscation
        score += 0.5;
        reasons.push('Versteckte Elemente gefunden (Tracking-Pixel o.ä.)');
      }
      // Trusted sender + ≤500 chars hidden → no penalty (legitimate preheader/responsive)
    }

    // Quoted-Printable obfuscation in HTML body — spam pipelines encode content to evade filters
    // Legitimate email rarely has dense QP encoding embedded in HTML markup
    const qpMatches = ((bodyHtml || '').match(/=[0-9A-Fa-f]{2}/g) || []).length;
    const htmlLen   = (bodyHtml || '').length;
    if (qpMatches > 30 && htmlLen > 0 && (qpMatches / (htmlLen / 100)) > 1.5) {
      score += 1;
      reasons.push(`Quoted-Printable-Verschlüsselung im HTML (${qpMatches} Sequenzen) — Spam-Pipeline-Merkmal`);
    }

    // Zero-width spaces / invisible Unicode characters — inserted between words to break
    // tokenization and evade keyword-based filters (U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ,
    // U+FEFF BOM, U+00AD soft hyphen). Legitimate email never contains >5 of these.
    const zwsCount = ((bodyHtml || '').match(/[​‌‍﻿­]/g) || []).length;
    if (zwsCount > 5) {
      score += 1.5;
      reasons.push(`Zero-Width-Space-Obfuskation (${zwsCount} unsichtbare Zeichen) — Spam-Filter-Umgehung`);
    }

    // Image-only body — no visible text, just image links (common for image-spam evading text filters)
    const imgCount = ((bodyHtml || '').match(/<img\b/gi) || []).length;
    if (imgCount >= 2 && plainText.length < 60) {
      score += 1.5;
      reasons.push(`Nur-Bild-E-Mail (${imgCount} Bilder, kaum Text) — umgeht Text-basierte Spamfilter`);
    }

    // Generic mass-mailing salutation — no recipient name, clearly impersonal bulk mail.
    // "Liebe Leserinnen und liebe Leser", "Sehr geehrte Damen und Herren", "Dear Customer" etc.
    if (/^(liebe[rs]?\s+leser(innen)?(\s+und\s+(liebe\s+)?leser)?|sehr\s+geehrte[rs]?\s+(damen?\s+und\s+herren?|dame|herr[,.])|dear\s+(customer|subscriber|reader|member|valued\s+customer))/im.test(plainText)) {
      score += 0.5;
      reasons.push('Generische Massen-Anrede (kein personalisierter Empfänger)');
    }

    // Unsubstituted merge tag in subject, e.g. {Name}, {Felber} — bulk mailer didn't replace placeholder
    if (/\{[A-Za-z][^}]{0,25}\}/.test(subject)) {
      score += 2;
      reasons.push('Nicht ersetzter Platzhalter im Betreff (z.B. {Name}) — Massen-E-Mail bestätigt');
    }

    // Email address embedded in subject line — phishing personalization technique.
    // Spammers include the recipient's email in the subject (e.g. "Für Sie reserviert – user@example.com")
    // to make the message appear individually targeted. Legitimate commercial senders never do this.
    if (/@[\w.-]+\.[a-z]{2,}/i.test(subject)) {
      score += 2;
      reasons.push('E-Mail-Adresse im Betreff — Phishing-Personalisierungstechnik');
    }

    // Fake product reservation / last-step urgency schemes.
    // "Für Sie zurückgelegt", "Letzter Schritt", "24-Stunden-Frist" are hallmarks of
    // fake reservation phishing: create urgency so the victim clicks without thinking.
    // False-positive guard: "Letzter Schritt" alone (e.g. onboarding flows) is excluded;
    // the pattern requires at least one additional reservation or countdown signal.
    if (/für\s+sie\s+(zurückgelegt|reserviert\b|bereitgestellt|hinterlegt)|letzter\s+schritt.{0,60}best[äa]tig|best[äa]tig.{0,60}letzter\s+schritt|24[-.\s]stunden[-.\s]?(frist|ablauf|verfall|countdown|gültig)|reservierung\s+(läuft\s+)?ab|ihr\s+platz\s+abl[äa]uft/i.test(fullText)) {
      score += 1.5;
      reasons.push('Fake-Reservierung / Letzter-Schritt-Countdown — Phishing-Köder ("für Sie zurückgelegt", "24-Stunden-Frist")');
    }

    // Cloud storage as click target — storage.googleapis.com and firebasestorage.googleapis.com
    // are routinely abused as phishing page hosts because the trusted *.googleapis.com domain
    // bypasses many URL filters. Legitimate commercial email never links to these endpoints.
    if (links.some(l => /storage\.googleapis\.com|firebasestorage\.googleapis\.com/i.test(l))) {
      score += 2.5;
      reasons.push('Phishing-Link zu Google-Cloud-Storage (storage.googleapis.com) — kein legitimes E-Mail-Ziel');
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

    // Affiliate-spam indicators: responsibility deflection or third-party consent claims.
    // "advertiser does not manage your subscription", "you registered via cooperation partner",
    // "your consent was provided through a partner network" — all classic affiliate spam patterns.
    if (/verwaltet\s+(ihr|dein)\s+abonnement\s+nicht|does\s+not\s+manage\s+your\s+subscri|kooperationspartner|cooperation\s+partner|(einwilligung|registriert|angemeldet)\s+(über|via|durch)\s+(einen?\s+)?(partner|kooperation|affiliate)/i.test(plainText)) {
      score += 0.8;
      reasons.push('Affiliate-Spam: Drittpartei-Einwilligung oder Verantwortungs-Ablehnung');
    }

    return score;
  }

  // Extract truly visible text from HTML by walking the DOM and skipping any
  // descendant of an element that is hidden via inline style. This is what the
  // recipient actually sees — _stripHtml() does NOT do this; it just removes
  // tag delimiters and returns ALL text including hidden content.
  //
  // Used as the comparison basis for the hidden-text duplicate filter so that
  // legitimate preheader / dark-mode / responsive variants are correctly
  // identified as duplicated (their words appear in visible body too).
  _extractVisibleText(html) {
    if (!html) return '';
    try {
      const tmp = document.createElement('div');
      tmp.innerHTML = html;
      const isHiddenEl = el => {
        if (!el || el.nodeType !== 1) return false;
        const st = el.style;
        if (!st) return false;
        const fs = parseFloat(st.fontSize);
        return st.visibility === 'hidden'
            || st.display    === 'none'
            || (!isNaN(fs) && fs <= 1)
            || /^transparent$/i.test(st.color);
      };
      const SKIP_TAGS = { SCRIPT: 1, STYLE: 1, NOSCRIPT: 1, HEAD: 1 };
      const walk = node => {
        if (node.nodeType === 3) return node.textContent;             // text node
        if (node.nodeType !== 1) return '';                           // not an element
        if (SKIP_TAGS[node.tagName]) return '';
        if (isHiddenEl(node)) return '';                              // hidden subtree
        let out = '';
        for (const child of node.childNodes) out += walk(child);
        return out;
      };
      return walk(tmp).replace(/\s+/g, ' ').trim();
    } catch { return ''; }
  }

  // Extract text content from genuinely-hidden elements — for the expander UI
  // and the spam-scoring decision.
  //
  // Conservative detection: only flag styles that hide content REGARDLESS of
  // surrounding context (display/visibility/font-size, plus color:transparent).
  // We deliberately do NOT flag color:white, because white text on a coloured
  // background (CTA buttons, callout panels, footer text) is extremely common
  // in legitimate marketing emails. The raw spam-scoring regex on the bodyHtml
  // still catches white-on-white obfuscation patterns separately.
  //
  // Optional visibleText filter: removes hidden snippets whose distinguishing
  // words mostly (≥70%) also appear in the visible body. These are typical
  // of responsive-design / dark-mode / accessibility duplications, NOT spam
  // stuffing — counting them inflates the "substantial hidden text" trigger
  // and floods the report with redundant entries.
  _extractHiddenText(html, visibleText) {
    if (!html) return '';
    try {
      const tmp = document.createElement('div');
      tmp.innerHTML = html;
      const texts = [];
      tmp.querySelectorAll('[style]').forEach(el => {
        const st = el.style;
        const fontSizeNum = parseFloat(st.fontSize);
        const isHidden =
          st.visibility === 'hidden' ||
          st.display    === 'none'   ||
          (!isNaN(fontSizeNum) && fontSizeNum <= 1) ||
          /^transparent$/i.test(st.color);
        if (isHidden) {
          const t = el.textContent.replace(/\s+/g, ' ').trim();
          if (t.length > 3) texts.push(t);
        }
      });

      let unique = [...new Set(texts)];

      if (visibleText) {
        // Two-stage filter to robustly remove duplicated content:
        //   1. Normalised substring: strip all non-alphanumeric chars from both
        //      texts and check whether the hidden snippet appears verbatim in
        //      the visible body. Catches phone numbers, addresses, codes, and
        //      any content that is duplicated character-for-character but with
        //      different surrounding punctuation/whitespace.
        //   2. Token overlap: split into tokens of 3+ letters OR digits and
        //      drop snippets where ≥70% of tokens appear in visible text.
        //      Catches paraphrased duplicates (e.g. dark/light variants where
        //      formatting differs).
        const norm    = s => s.toLowerCase().replace(/[^\p{L}\p{N}]/gu, '');
        const visNorm = norm(visibleText);
        const visLower = visibleText.toLowerCase();

        unique = unique.filter(t => {
          const tNorm = norm(t);
          if (tNorm.length > 0 && visNorm.includes(tNorm)) return false;

          // Tokenise on letters AND digits (3+ chars). Phone numbers,
          // ID codes, dates etc. are now properly compared.
          const tokens = t.toLowerCase().match(/[\p{L}\p{N}]{3,}/gu) || [];
          if (tokens.length === 0) return true;       // pure emoji / symbols → keep
          let matches = 0;
          for (const tok of tokens) if (visLower.includes(tok)) matches++;
          return (matches / tokens.length) < 0.7;
        });
      }

      return unique.join('\n').trim();
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

const VERSION    = '2.0.19';
const WORKER_URL = 'https://spam-scorer-ai.felber.workers.dev';

/**
 * Detect the Outlook UI language and return a two-letter BCP-47 base tag.
 * Falls back to 'de' (German) so existing behaviour is unchanged when
 * Office.context is not yet ready or the locale cannot be determined.
 */
function detectUiLang() {
  try {
    const loc = (Office.context && Office.context.displayLanguage) || 'de-DE';
    return loc.split('-')[0].toLowerCase();
  } catch { return 'de'; }
}

/** Active UI language — set once in Office.onReady */
let UI_LANG = 'de';

// ─── Report template strings (localized) ─────────────────────────────────────

const REPORT_STRINGS = {
  de: {
    htmlLang:        'de',
    reportTitle:     n => `Spam-Analyse-Bericht #${n}`,
    reportLabel:     'Bericht',
    created:         'Erstellt',
    subject:         'Betreff',
    sender:          'Absender',
    date:            'Datum',
    auth:            'Authentifizierung',
    addinSignals:    'Add-in Spam-Indikatoren',
    noSignals:       'Keine Indikatoren gefunden.',
    aiAnalysis:      'AI Analyse',
    aiSignalsNone:   'Keine.',
    hiddenTitle:     'Versteckter Text im HTML',
    hiddenInfo:      n => `${n} versteckte${n === 1 ? 'r' : ''} Textblock${n === 1 ? '' : 'e'} gefunden — Auszug (max. 100 Zeichen je Eintrag):`,
    recommendations: 'Empfehlungen für den Absender',
    noRecs:          'Keine Empfehlungen vorhanden.',
    footer:          `Generiert von Spam-Bewerter v${VERSION}`,
    filename:        n => `Spam-Report-${n}.html`,
    toast:           'Bericht wird heruntergeladen…',
    dateLocale:      'de-DE',
    verdictText:     score => score === 0 ? 'Kein Spam' : score <= 2 ? 'Wahrscheinlich kein Spam' : score <= 4 ? 'Leicht verdächtig' : score <= 6 ? 'Verdächtig' : score <= 8 ? 'Wahrscheinlich Spam' : 'Sehr wahrscheinlich Spam',
  },
  en: {
    htmlLang:        'en',
    reportTitle:     n => `Spam Analysis Report #${n}`,
    reportLabel:     'Report',
    created:         'Created',
    subject:         'Subject',
    sender:          'Sender',
    date:            'Date',
    auth:            'Authentication',
    addinSignals:    'Add-in Spam Indicators',
    noSignals:       'No indicators found.',
    aiAnalysis:      'AI Analysis',
    aiSignalsNone:   'None.',
    hiddenTitle:     'Hidden Text in HTML',
    hiddenInfo:      n => `${n} hidden text block${n === 1 ? '' : 's'} found — excerpt (max. 100 chars each):`,
    recommendations: 'Recommendations for the Sender',
    noRecs:          'No recommendations available.',
    footer:          `Generated by Spam Scorer v${VERSION}`,
    filename:        n => `Spam-Report-${n}.html`,
    toast:           'Downloading report…',
    dateLocale:      'en-US',
    verdictText:     score => score === 0 ? 'Not spam' : score <= 2 ? 'Probably not spam' : score <= 4 ? 'Slightly suspicious' : score <= 6 ? 'Suspicious' : score <= 8 ? 'Probably spam' : 'Almost certainly spam',
  },
};

/** Return the REPORT_STRINGS entry for the active UI language */
function rStr() { return REPORT_STRINGS[UI_LANG] || REPORT_STRINGS.de; }

const analyzer = new SpamAnalyzer();
let currentScore    = null;
let lastHeaders     = '';
let lastBodyHtml    = '';   // raw HTML — for originalsrc extraction sent to worker
let lastBodyText    = '';   // cleaned plain text — for copy button
let lastHiddenText  = '';   // text extracted from hidden elements
let lastAnalysis    = null; // { score, reasons, hiddenText }
let lastClaudeResult = null;
let lastAdviceResult = null;

// ─── Office init ───────────────────────────────────────────────────────────────

Office.onReady(info => {
  if (info.host !== Office.HostType.Outlook) return;

  UI_LANG = detectUiLang();

  document.getElementById('btn-retry').addEventListener('click', analyzeCurrentItem);
  document.getElementById('btn-copy-headers').addEventListener('click', () => copyToClipboard(lastHeaders, 'Header kopiert'));
  document.getElementById('btn-copy-body').addEventListener('click',    () => copyToClipboard(lastBodyText, 'Body-Text kopiert'));
  document.getElementById('btn-claude').addEventListener('click', runClaudeCheck);
  document.getElementById('btn-toggle-hidden').addEventListener('click', toggleHiddenText);
  document.getElementById('btn-advice').addEventListener('click', runAdviceCheck);
  document.getElementById('btn-delivery-report').addEventListener('click', downloadDeliverabilityReport);
  document.getElementById('btn-action-plan').addEventListener('click', () => generateArtifact('action-plan'));
  document.getElementById('btn-anschreiben').addEventListener('click', () => generateArtifact('anschreiben'));

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

// ─── AI check ──────────────────────────────────────────────────────────────────

async function runClaudeCheck() {
  const btn      = document.getElementById('btn-claude');
  const resultEl = document.getElementById('claude-result');

  if (!lastHeaders && !lastBodyText) {
    showToast('Keine E-Mail-Daten verfügbar — bitte zuerst analysieren', true);
    return;
  }

  // Reuse cached result — avoids a second API call for the same email
  if (lastClaudeResult) {
    const cachedItem    = Office.context.mailbox.item;
    const cachedSubject = cachedItem?.subject            || '';
    const cachedSender  = cachedItem?.from?.emailAddress || '';
    renderClaudeResult(lastClaudeResult, cachedSubject, cachedSender);
    return;
  }

  btn.disabled    = true;
  btn.textContent = 'AI analysiert…';
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
      body: JSON.stringify({ headers: lastHeaders, bodyText: lastBodyText, subject, senderEmail, origSrcUrls, lang: UI_LANG }),
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Worker-Fehler ${res.status}: ${errText}`);
    }

    const data = await res.json();
    if (data.error) throw new Error(data.error);

    lastClaudeResult = data;
    renderClaudeResult(data, subject, senderEmail);
  } catch (err) {
    resultEl.innerHTML = `<p class="claude-error">⚠ ${escapeHtml(err.message)}</p>`;
    resultEl.classList.remove('hidden');
  } finally {
    btn.disabled    = false;
    btn.textContent = 'Mit AI prüfen';
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
  `;
  resultEl.classList.remove('hidden');

  // LLM-Prompt below advice-result
  const promptContainer = document.getElementById('llm-prompt-container');
  if (promptContainer) {
    promptContainer.innerHTML = promptHtml;
    promptContainer.classList.remove('hidden');
    promptContainer.querySelector('#btn-copy-prompt')?.addEventListener('click', () => {
      copyToClipboard(promptText, 'Prompt kopiert');
    });
  }

  // Hide the trigger button — result is now visible
  document.getElementById('btn-claude')?.classList.add('hidden');
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
AI Score      : ${aiScore}/10 — Verdict: ${claudeData.verdict ?? '?'} (${claudeData.confidence ?? '?'}% Konfidenz)
Falltyp       : ${caseType}

## Add-in Signale (gefundene Indikatoren)
${signals}

## AI Signale
${aiSignals}

## AI Zusammenfassung
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
  const promptContainer = document.getElementById('llm-prompt-container');
  if (promptContainer) { promptContainer.innerHTML = ''; promptContainer.classList.add('hidden'); }
  document.getElementById('btn-claude')?.classList.remove('hidden');
  lastClaudeResult = null;
}

// ─── Artifact generation ───────────────────────────────────────────────────────

async function generateArtifact(mode) {
  const btnId = mode === 'action-plan' ? 'btn-action-plan' : 'btn-anschreiben';
  const btn   = document.getElementById(btnId);

  if (!lastAnalysis) {
    showToast('Bitte zuerst eine E-Mail analysieren', true);
    return;
  }

  const item        = Office.context.mailbox.item;
  const subject     = item?.subject             || '';
  const senderEmail = item?.from?.emailAddress  || '';

  const origLabel = btn.textContent;
  btn.disabled    = true;

  try {
    if (!lastClaudeResult) {
      btn.textContent = 'AI analysiert…';
      await runClaudeCheck();
    }

    if (!lastAdviceResult) {
      btn.textContent = 'Empfehlungen…';
      await runAdviceCheck();
    }

    btn.textContent = 'Generiere…';

    const res = await fetch(WORKER_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mode,
        headers:      lastHeaders,
        bodyText:     lastBodyText,
        subject,
        senderEmail,
        addinScore:   currentScore,
        addinSignals: lastAnalysis?.reasons || [],
        claudeResult: lastClaudeResult,
        adviceResult: lastAdviceResult,
      }),
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Worker-Fehler ${res.status}: ${errText}`);
    }

    const data = await res.json();
    if (data.error) throw new Error(data.error);

    const html     = data.html || '';
    const blob     = new Blob([html], { type: 'text/html;charset=utf-8' });
    const url      = URL.createObjectURL(blob);
    const date     = new Date().toISOString().slice(0, 10);
    const domain   = (senderEmail.match(/@([\w.-]+)/) || [])[1] || 'sender';
    const filename = mode === 'action-plan'
      ? `${domain}-Aktionsplan-${date}.html`
      : `${domain}-Anschreiben-${date}.html`;

    const a    = document.createElement('a');
    a.href     = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);

    showToast(`${filename} wird heruntergeladen…`, false);
  } catch (err) {
    showToast(`⚠ ${err.message}`, true);
  } finally {
    btn.disabled    = false;
    btn.textContent = origLabel;
  }
}

// ─── Reputation advice ─────────────────────────────────────────────────────────

async function runAdviceCheck() {
  const btn      = document.getElementById('btn-advice');
  const resultEl = document.getElementById('advice-result');

  // Reuse cached result — avoids a second API call for the same email.
  // Guard: evict the cache entry if it looks malformed (raw JSON leaked into summary
  // before the extractJson fix was deployed on the worker side).
  if (lastAdviceResult) {
    const s = (lastAdviceResult.summary || '').trimStart();
    const malformed = (!lastAdviceResult.recommendations?.length)
                   && (s.startsWith('{') || s.startsWith('`'));
    if (!malformed) {
      renderAdviceResult(lastAdviceResult);
      return;
    }
    // Bad cache — discard and re-fetch from worker
    lastAdviceResult = null;
  }

  if (!lastClaudeResult) {
    btn.disabled    = true;
    btn.textContent = 'AI analysiert…';
    await runClaudeCheck();
  }

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
        mode:                 'advice',
        headers:              lastHeaders,
        bodyText:             lastBodyText,
        subject,
        senderEmail,
        addinScore:           currentScore,
        addinSignals:         lastAnalysis?.reasons || [],
        deliverabilityNotes:  lastAnalysis?.deliverabilityNotes || [],
        claudeResult:         lastClaudeResult,
        lang:                 UI_LANG,
      }),
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Worker-Fehler ${res.status}: ${errText}`);
    }

    const data = await res.json();
    if (data.error) throw new Error(data.error);

    // Only cache well-formed responses (has at least one recommendation).
    // Malformed responses (raw JSON as summary, empty recommendations) must not be
    // cached so the next button press retries the worker call.
    if (data.recommendations?.length) {
      lastAdviceResult = data;
    }
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

  // Defensive recovery: worker may have fallen back to summary=rawText if
  // its own extractJson failed. Try harder client-side with the same
  // recovery ladder including truncation handling.
  if ((!data.recommendations || data.recommendations.length === 0) && data.summary) {
    const recovered = _recoverAdviceJson(data.summary);
    if (recovered && Array.isArray(recovered.recommendations) && recovered.recommendations.length > 0) {
      data = recovered;
      lastAdviceResult = data;            // upgrade cache to the recovered version
    }
  }

  // FINAL UI safety net: if data is STILL malformed (no usable recommendations
  // and summary looks like raw JSON / fenced text), show a clean error with a
  // retry button — never dump raw JSON in the user's face.
  const summaryLooksLikeJson = typeof data.summary === 'string'
    && /^\s*(?:```|[{[])/.test(data.summary.trim());
  if ((!data.recommendations || data.recommendations.length === 0) && summaryLooksLikeJson) {
    resultEl.innerHTML = `
      <div class="advice-error">
        <p>⚠ Die KI-Antwort konnte nicht vollständig geparst werden (vermutlich Antwort-Truncation bei sehr ausführlichen Empfehlungen).</p>
        <button id="btn-retry-advice" class="btn btn-secondary" style="margin-top: 10px;">🔄 Erneut versuchen</button>
      </div>`;
    resultEl.classList.remove('hidden');
    document.getElementById('btn-retry-advice')?.addEventListener('click', () => {
      lastAdviceResult = null;            // bust cache, force fresh worker call
      runAdviceCheck();
    });
    return;
  }

  const summaryHtml = data.summary
    ? `<p class="advice-summary">${escapeHtml(data.summary)}</p>`
    : '';

  const recs = data.recommendations || [];
  const recsHtml = recs.length
    ? '<ul class="advice-list">' + recs.map(r => {
        const prioClass = (r.priority || '').toLowerCase() === 'hoch'   ? 'prio-hoch'
                        : (r.priority || '').toLowerCase() === 'mittel' ? 'prio-mittel'
                        :                                                  'prio-niedrig';

        // Ist → Soll comparison row
        const istSollHtml = (r.ist || r.soll) ? `
          <div class="advice-ist-soll">
            ${r.ist  ? `<div class="advice-ist-pill ist-pill"><span class="ist-soll-label">Ist</span>${escapeHtml(r.ist)}</div>` : ''}
            ${r.ist && r.soll ? `<span class="ist-soll-arrow">→</span>` : ''}
            ${r.soll ? `<div class="advice-ist-pill soll-pill"><span class="ist-soll-label">Soll</span>${escapeHtml(r.soll)}</div>` : ''}
          </div>` : '';

        // Detail paragraphs (optional)
        const detailHtml = (r.ist_detail || r.soll_detail) ? `
          <div class="advice-details">
            ${r.ist_detail  ? `<p class="advice-detail det-ist">${escapeHtml(r.ist_detail)}</p>`  : ''}
            ${r.soll_detail ? `<p class="advice-detail det-soll">${escapeHtml(r.soll_detail)}</p>` : ''}
          </div>` : '';

        // Callout block (ok = green / diag = blue / warn = orange)
        let calloutHtml = '';
        if (r.callout) {
          const calloutClass = r.callout.type === 'ok'   ? 'callout-ok'
                             : r.callout.type === 'diag' ? 'callout-diag'
                             :                             'callout-warn';
          const calloutIcon  = r.callout.type === 'ok'   ? '✓'
                             : r.callout.type === 'diag' ? 'ℹ'
                             :                             '⚠';
          calloutHtml = `
            <div class="advice-callout ${calloutClass}">
              <strong>${calloutIcon} ${escapeHtml(r.callout.title || '')}</strong>
              <p>${escapeHtml(r.callout.text || '')}</p>
            </div>`;
        }

        return `<li class="advice-item ${prioClass}">
          <div class="advice-item-header">
            <span class="advice-category">${escapeHtml(r.category || '')}</span>
            <span class="advice-priority">${escapeHtml(r.priority || '')}</span>
          </div>
          <div class="advice-title">${escapeHtml(r.title || '')}</div>
          ${istSollHtml}
          ${detailHtml}
          <div class="advice-action">${escapeHtml(r.action || '')}</div>
          ${calloutHtml}
        </li>`;
      }).join('') + '</ul>'
    : '<p class="advice-none">Keine Empfehlungen gefunden.</p>';

  resultEl.innerHTML = summaryHtml + recsHtml;
  resultEl.classList.remove('hidden');
}

function resetAdviceResult() {
  const resultEl = document.getElementById('advice-result');
  if (resultEl) { resultEl.innerHTML = ''; resultEl.classList.add('hidden'); }
  lastAdviceResult = null;
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

/**
 * Aggressive client-side JSON recovery for advice responses. Mirrors the
 * worker's extractJson — direct parse → strip fences → brace-balanced scan
 * with truncation recovery. Returns null on total failure.
 */
function _recoverAdviceJson(text) {
  if (!text || typeof text !== 'string') return null;
  const trimmed = text.trim();

  // 1. Direct parse
  try { return JSON.parse(trimmed); } catch { /* next */ }

  // 2. Strip markdown fences then parse
  const stripped = trimmed
    .replace(/^```(?:json)?\s*/i, '')
    .replace(/\s*```\s*$/i, '')
    .trim();
  try { return JSON.parse(stripped); } catch { /* next */ }

  // 3. Brace-balanced scan from first '{', tracking string state.
  //    Records the position where each top-level recommendation closes so we
  //    can manually close the array after the last complete one if the
  //    response was truncated mid-recommendation.
  const start = text.indexOf('{');
  if (start === -1) return null;

  let depth = 0, inStr = false, escape = false;
  let lastRecEnd = -1;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (escape) { escape = false; continue; }
    if (c === '\\' && inStr) { escape = true; continue; }
    if (c === '"') { inStr = !inStr; continue; }
    if (inStr) continue;
    if (c === '{') depth++;
    else if (c === '}') {
      depth--;
      if (depth === 1) lastRecEnd = i;
      else if (depth === 0) {
        try { return JSON.parse(text.slice(start, i + 1)); }
        catch { break; }
      }
    }
  }

  // 4. Truncation recovery
  if (lastRecEnd !== -1) {
    try {
      return JSON.parse(text.slice(start, lastRecEnd + 1) + '\n  ]\n}');
    } catch { /* unrecoverable */ }
  }

  return null;
}

// ─── Deliverability HTML report ────────────────────────────────────────────────
// All functions here produce a self-contained HTML file downloaded by the user.
// No extra API call is made — data comes from the cached analysis + advice results.

/** Pure HTML-escape for report template strings (no DOM required) */
function escR(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

const REPORT_CSS = `
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: system-ui, -apple-system, 'Segoe UI', sans-serif; font-size: 14px; line-height: 1.5; background: #f1f5f9; color: #1e293b; }
.page { max-width: 820px; margin: 0 auto; padding: 24px; }

/* Header */
.rpt-header { display: flex; justify-content: space-between; align-items: flex-start; background: linear-gradient(135deg, #1e3a5f 0%, #0f4c81 100%); color: white; border-radius: 12px 12px 0 0; padding: 24px 28px; }
.rpt-header h1 { font-size: 20px; font-weight: 700; }
.rpt-meta { margin-top: 4px; font-size: 11px; opacity: .7; }
.rpt-header-badge { background: rgba(255,255,255,.15); border-radius: 20px; padding: 4px 14px; font-size: 11px; white-space: nowrap; margin-top: 4px; }

/* Subject box */
.rpt-subject-box { background: #fff; border: 1px solid #e2e8f0; border-top: none; padding: 16px 24px; margin-bottom: 16px; }
.meta-table { width: 100%; border-collapse: collapse; }
.meta-table th { text-align: left; font-weight: 600; color: #64748b; font-size: 11px; text-transform: uppercase; letter-spacing: .04em; width: 80px; padding: 3px 10px 3px 0; vertical-align: top; }
.meta-table td { padding: 3px 0; font-size: 13px; word-break: break-word; }

/* Metrics grid */
.rpt-metrics { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 16px; }
.metric-card { background: #fff; border-radius: 10px; padding: 16px 20px; border-top: 4px solid var(--accent, #94a3b8); text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,.05); }
.metric-score { font-size: 38px; font-weight: 800; color: var(--accent, #1e293b); line-height: 1; }
.metric-denom { font-size: 18px; font-weight: 400; color: #94a3b8; }
.metric-label { font-size: 10px; text-transform: uppercase; color: #64748b; margin-top: 6px; letter-spacing: .05em; }
.metric-verdict { font-size: 12px; font-weight: 600; margin-top: 4px; color: var(--accent, #1e293b); }

/* Sections */
.rpt-section { background: #fff; border-radius: 10px; padding: 20px 24px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,.05); }
.rpt-section h2 { font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: .06em; color: #1e3a5f; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; margin-bottom: 14px; }
.rpt-section ul { padding-left: 20px; }
.rpt-section li { margin-bottom: 4px; font-size: 13px; }
.none { color: #94a3b8; font-style: italic; font-size: 13px; }
.ai-summary, .advice-intro { background: #f8fafc; border-left: 3px solid #60a5fa; padding: 10px 14px; border-radius: 0 6px 6px 0; margin-bottom: 12px; color: #374151; font-size: 13px; }

/* Auth badges */
.rpt-auth-row { display: flex; flex-wrap: wrap; gap: 8px; }
.rpt-auth-badge { padding: 4px 14px; border-radius: 20px; font-size: 12px; font-weight: 700; border: 1px solid transparent; }
.auth-pass     { background: #dcfce7; color: #166534; border-color: #86efac; }
.auth-fail     { background: #fee2e2; color: #991b1b; border-color: #fca5a5; }
.auth-softfail { background: #fef9c3; color: #854d0e; border-color: #fde047; }
.auth-warn     { background: #fff7ed; color: #9a3412; border-color: #fdba74; }
.auth-none     { background: #f1f5f9; color: #64748b; border-color: #cbd5e1; }

/* Findings */
.finding { background: #fff; border-radius: 8px; padding: 16px 20px; margin-bottom: 12px; border-left: 4px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0,0,0,.04); }
.finding.prio-hoch    { border-left-color: #dc2626; }
.finding.prio-mittel  { border-left-color: #d97706; }
.finding.prio-niedrig { border-left-color: #16a34a; }
.finding-header { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.f-category { background: #eff6ff; color: #1d4ed8; border-radius: 20px; padding: 2px 10px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; }
.f-priority { border-radius: 20px; padding: 2px 10px; font-size: 10px; font-weight: 700; text-transform: uppercase; }
.prio-hoch    .f-priority { background: #fee2e2; color: #991b1b; }
.prio-mittel  .f-priority { background: #fef9c3; color: #854d0e; }
.prio-niedrig .f-priority { background: #dcfce7; color: #166534; }
.finding-title { font-weight: 700; font-size: 14px; margin-bottom: 10px; color: #0f172a; }
.finding-ist-soll { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; flex-wrap: wrap; }
.finding-ist, .finding-soll { display: inline-flex; align-items: center; gap: 6px; border-radius: 6px; padding: 4px 10px; font-size: 12px; }
.finding-ist  { background: #fee2e2; color: #991b1b; border: 1px solid #fca5a5; }
.finding-soll { background: #dcfce7; color: #166534; border: 1px solid #86efac; }
.f-label { font-size: 9px; font-weight: 800; text-transform: uppercase; letter-spacing: .05em; opacity: .7; }
.f-arrow { font-size: 16px; color: #94a3b8; }
.finding-details { margin-bottom: 8px; }
.det-ist  { font-size: 12px; color: #991b1b; margin-bottom: 3px; }
.det-soll { font-size: 12px; color: #166534; margin-bottom: 3px; }
.finding-action { font-size: 13px; color: #374151; line-height: 1.6; }
.finding-callout { border-radius: 6px; padding: 10px 14px; margin-top: 12px; }
.finding-callout strong { display: block; margin-bottom: 4px; font-size: 12px; }
.finding-callout p { font-size: 12px; line-height: 1.5; margin: 0; }
.co-ok   { background: #f0fdf4; border: 1px solid #86efac; color: #14532d; }
.co-diag { background: #eff6ff; border: 1px solid #93c5fd; color: #1e3a8a; }
.co-warn { background: #fff7ed; border: 1px solid #fdba74; color: #7c2d12; }

/* Hidden-text section */
.rpt-hidden-info { font-size: 12px; color: #64748b; margin-bottom: 12px; }
.rpt-hidden-list { list-style: none; padding: 0; margin: 0; }
.rpt-hidden-item { display: flex; gap: 10px; align-items: flex-start; background: #fef9c3; border-left: 3px solid #ca8a04; padding: 8px 12px; margin-bottom: 6px; border-radius: 0 6px 6px 0; }
.rpt-hidden-num { color: #854d0e; font-weight: 700; font-size: 12px; flex-shrink: 0; min-width: 24px; }
.rpt-hidden-code { font-family: 'Cascadia Code', 'Consolas', 'Menlo', monospace; font-size: 12px; color: #422006; word-break: break-word; white-space: pre-wrap; line-height: 1.5; }

/* Footer */
.rpt-footer { text-align: center; color: #94a3b8; font-size: 11px; padding: 20px 0 8px; }
`;

/** Extract From / Date / sending IP / PTR hostname from raw internet headers */
function parseHeaderMeta(headers) {
  const get = name => {
    const re = new RegExp(`^${name}:\\s*(.+(?:\\r?\\n[ \\t].+)*)`, 'im');
    const m  = headers ? headers.match(re) : null;
    return m ? m[1].replace(/\r?\n[ \t]+/g, ' ').trim() : '';
  };

  // Sending IP — prefer Received-SPF client-ip=, fall back to first IP in brackets in Received:
  let sendingIp   = null;
  let ptrHostname = null;
  if (headers) {
    const spfIp = headers.match(/client-ip=([\d.a-f:]+)/i);
    if (spfIp) sendingIp = spfIp[1];

    // First Received: header with "from HELO (PTR [IP])" or "from HELO ([IP])"
    const rcvd = headers.match(/^Received:.*?from\s+([\w.\-[\]:]+)(?:\s+\(([\w.\-]+)\s+)?\[([\d.a-f:]+)\]/im);
    if (rcvd) {
      if (!sendingIp) sendingIp = rcvd[3];
      // rcvd[2] is the PTR hostname if present (the resolved name in parens before the IP)
      // rcvd[1] is the HELO/EHLO name
      ptrHostname = rcvd[2] || rcvd[1] || null;
      // Clean up — ignore if it's just the IP repeated
      if (ptrHostname && ptrHostname === sendingIp) ptrHostname = null;
    }
  }

  return { from: get('From'), date: get('Date'), sendingIp, ptrHostname };
}

/** Trigger the browser file download — auto-chains AI check + advice if not yet run */
async function downloadDeliverabilityReport() {
  const btn = document.getElementById('btn-delivery-report');
  btn.disabled = true;

  try {
    if (!lastClaudeResult) {
      btn.textContent = 'AI analysiert…';
      await runClaudeCheck();
    }

    if (!lastAdviceResult) {
      btn.textContent = 'Empfehlungen…';
      await runAdviceCheck();
    }

    btn.textContent = 'Erstelle Report…';

    const item        = Office.context.mailbox.item;
    const subject     = item?.subject            || '';
    const senderEmail = item?.from?.emailAddress || '';
    const senderName  = item?.from?.displayName  || '';

    const reportNum = (parseInt(localStorage.getItem('reportCount') || '0', 10) + 1);
    localStorage.setItem('reportCount', String(reportNum));

    const html = buildDeliverabilityHtml({
      subject, senderEmail, senderName,
      addinScore:   currentScore,
      addinSignals: lastAnalysis?.reasons || [],
      claudeResult: lastClaudeResult,
      adviceResult: lastAdviceResult,
      headers:      lastHeaders,
      hiddenText:   lastHiddenText,
      reportNum,
    });

    const s    = rStr();
    const blob = new Blob([html], { type: 'text/html; charset=utf-8' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    const date   = new Date().toISOString().slice(0, 10);
    const domain = (senderEmail.match(/@([\w.-]+)/) || [])[1] || 'sender';
    a.download = `${domain}-Report-${date}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast(s.toast, false);
  } finally {
    btn.disabled    = false;
    btn.textContent = '📄 Report';
  }
}

/** Assemble the full HTML document */
function buildDeliverabilityHtml({ subject, senderEmail, senderName, addinScore, addinSignals, claudeResult, adviceResult, headers, hiddenText, reportNum }) {
  const t        = rStr();   // localized strings
  const meta     = parseHeaderMeta(headers);
  const numStr   = String(reportNum).padStart(4, '0');
  const now      = new Date().toLocaleString(t.dateLocale);
  const fromLine = senderName ? `${escR(senderName)} &lt;${escR(senderEmail)}&gt;` : escR(senderEmail);
  const dateStr  = meta.date ? escR(meta.date) : '—';
  const { sendingIp, ptrHostname } = meta;

  // Pick accent colour by score
  const scoreColor = s => s <= 2 ? '#16a34a' : s <= 5 ? '#d97706' : s <= 7 ? '#dc2626' : '#7f1d1d';
  const addinColor = addinScore !== null ? scoreColor(addinScore) : '#94a3b8';
  const aiColor    = claudeResult?.score != null ? scoreColor(claudeResult.score) : '#94a3b8';

  const signalsHtml = addinSignals.length
    ? '<ul>' + addinSignals.map(s => `<li>${escR(s)}</li>`).join('') + '</ul>'
    : `<p class="none">${t.noSignals}</p>`;

  const aiSignalsHtml = (claudeResult?.signals || []).length
    ? '<ul>' + (claudeResult.signals || []).map(s => `<li>${escR(s)}</li>`).join('') + '</ul>'
    : `<p class="none">${t.aiSignalsNone}</p>`;

  const recs     = adviceResult?.recommendations || [];
  const recsHtml = recs.length
    ? recs.map(r => rFinding(r)).join('')
    : `<p class="none">${t.noRecs}</p>`;

  return `<!DOCTYPE html>
<html lang="${t.htmlLang}">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${t.reportTitle(numStr)}</title>
  <style>${REPORT_CSS}</style>
</head>
<body>
<div class="page">

  <header class="rpt-header">
    <div>
      <h1>E-Mail Deliverability Report</h1>
      <p class="rpt-meta">${t.reportLabel} #${numStr} · ${t.created}: ${escR(now)}</p>
    </div>
    <div class="rpt-header-badge">Spam Scorer v${VERSION}</div>
  </header>

  <div class="rpt-subject-box">
    <table class="meta-table">
      <tr><th>${t.subject}</th><td>${escR(subject)}</td></tr>
      <tr><th>${t.sender}</th><td>${fromLine}</td></tr>
      <tr><th>${t.date}</th><td>${dateStr}</td></tr>
    </table>
  </div>

  ${rMetrics({ addinScore, claudeResult, addinColor, aiColor })}

  ${rInfraSection(sendingIp, ptrHostname)}

  ${rAuthSection(headers)}

  <section class="rpt-section">
    <h2>${t.addinSignals}</h2>
    ${signalsHtml}
  </section>

  ${rHiddenTextSection(hiddenText)}

  <section class="rpt-section">
    <h2>${t.aiAnalysis}</h2>
    ${claudeResult?.summary ? `<p class="ai-summary">${escR(claudeResult.summary)}</p>` : ''}
    ${aiSignalsHtml}
  </section>

  <section class="rpt-section">
    <h2>${t.recommendations}</h2>
    ${adviceResult?.summary ? `<p class="advice-intro">${escR(adviceResult.summary)}</p>` : ''}
    ${recsHtml}
  </section>

  <footer class="rpt-footer">
    ${t.footer} · ${escR(now)}
  </footer>

</div>
</body>
</html>`;
}

function rMetrics({ addinScore, claudeResult, addinColor, aiColor }) {
  const addinVerdict = addinScore !== null ? rStr().verdictText(addinScore) : '—';
  const aiScore      = claudeResult?.score    ?? null;
  const aiVerdict    = claudeResult?.verdict  || '—';
  const aiConf       = claudeResult?.confidence ?? null;

  return `<div class="rpt-metrics">
    <div class="metric-card" style="--accent: ${addinColor}">
      <div class="metric-score">${addinScore ?? '—'}<span class="metric-denom">/10</span></div>
      <div class="metric-label">Add-in Score</div>
      <div class="metric-verdict">${escR(addinVerdict)}</div>
    </div>
    <div class="metric-card" style="--accent: ${aiColor}">
      <div class="metric-score">${aiScore ?? '—'}<span class="metric-denom">/10</span></div>
      <div class="metric-label">AI Score</div>
      <div class="metric-verdict">${escR(aiVerdict)}${aiConf !== null ? ` · ${aiConf}%` : ''}</div>
    </div>
  </div>`;
}

/**
 * Render the hidden-text section: each snippet truncated to 100 chars,
 * displayed as a monospaced code-style line so the user can see exactly
 * what content was concealed in the original HTML.
 */
function rHiddenTextSection(hiddenText) {
  if (!hiddenText) return '';

  const MAX_CHARS = 100;
  const snippets = hiddenText
    .split('\n')
    .map(s => s.trim())
    .filter(s => s.length > 0)
    .map(s => s.length > MAX_CHARS ? s.slice(0, MAX_CHARS) + '…' : s);

  if (!snippets.length) return '';

  const t        = rStr();
  const itemsHtml = snippets.map((s, i) => `
    <li class="rpt-hidden-item">
      <span class="rpt-hidden-num">${i + 1}.</span>
      <code class="rpt-hidden-code">${escR(s)}</code>
    </li>`).join('');

  return `<section class="rpt-section">
    <h2>${t.hiddenTitle}</h2>
    <p class="rpt-hidden-info">${t.hiddenInfo(snippets.length)}</p>
    <ul class="rpt-hidden-list">${itemsHtml}</ul>
  </section>`;
}

function rAuthSection(headers) {
  if (!headers) return '';
  const authLine = headers.match(/^Authentication-Results:(.+(?:\r?\n[ \t].+)*)/im)
                || headers.match(/^ARC-Authentication-Results:(.+(?:\r?\n[ \t].+)*)/im);
  if (!authLine) return '';

  const str    = authLine[1];
  const checks = [
    { label: 'SPF',      re: /spf=(pass|fail|softfail|neutral|none)/i },
    { label: 'DKIM',     re: /dkim=(pass|fail|none)/i },
    { label: 'DMARC',    re: /dmarc=(pass|fail|none|bestguesspass)/i },
    { label: 'compauth', re: /compauth=(pass|fail|softpass)/i },
  ];

  const badgesHtml = checks.map(({ label, re }) => {
    const m   = str.match(re);
    const val = m ? m[1].toLowerCase() : null;
    const cls = !val          ? 'auth-none'
              : val === 'pass'     ? 'auth-pass'
              : val === 'softfail' ? 'auth-softfail'
              : val === 'fail'     ? 'auth-fail'
              :                     'auth-warn';
    return `<span class="rpt-auth-badge ${cls}">${label} ${val ? val.toUpperCase() : '—'}</span>`;
  }).join('');

  return `<section class="rpt-section">
    <h2>${rStr().auth}</h2>
    <div class="rpt-auth-row">${badgesHtml}</div>
  </section>`;
}

function rInfraSection(sendingIp, ptrHostname) {
  if (!sendingIp) return '';
  const ptrLine = ptrHostname
    ? `<tr><th>PTR / Hostname</th><td><code>${escR(ptrHostname)}</code></td></tr>`
    : `<tr><th>PTR / Hostname</th><td class="rpt-warn">nicht aufgelöst</td></tr>`;
  return `<section class="rpt-section">
    <h2>Infrastruktur</h2>
    <table class="meta-table">
      <tr><th>Sendende IP</th><td><code>${escR(sendingIp)}</code></td></tr>
      ${ptrLine}
    </table>
  </section>`;
}

/** Render a single recommendation card for the HTML report */
function rFinding(r) {
  const prioClass = (r.priority || '').toLowerCase() === 'hoch'   ? 'prio-hoch'
                  : (r.priority || '').toLowerCase() === 'mittel' ? 'prio-mittel'
                  :                                                  'prio-niedrig';

  const istSollHtml = (r.ist || r.soll) ? `
    <div class="finding-ist-soll">
      ${r.ist  ? `<div class="finding-ist"><span class="f-label">Ist</span>${escR(r.ist)}</div>` : ''}
      ${r.ist && r.soll ? `<span class="f-arrow">→</span>` : ''}
      ${r.soll ? `<div class="finding-soll"><span class="f-label">Soll</span>${escR(r.soll)}</div>` : ''}
    </div>` : '';

  const detailHtml = (r.ist_detail || r.soll_detail) ? `
    <div class="finding-details">
      ${r.ist_detail  ? `<p class="det-ist">${escR(r.ist_detail)}</p>`  : ''}
      ${r.soll_detail ? `<p class="det-soll">${escR(r.soll_detail)}</p>` : ''}
    </div>` : '';

  let calloutHtml = '';
  if (r.callout) {
    const cCls  = r.callout.type === 'ok'   ? 'co-ok'
                : r.callout.type === 'diag' ? 'co-diag'
                :                             'co-warn';
    const cIcon = r.callout.type === 'ok'   ? '✓'
                : r.callout.type === 'diag' ? 'ℹ'
                :                             '⚠';
    calloutHtml = `
      <div class="finding-callout ${cCls}">
        <strong>${cIcon} ${escR(r.callout.title || '')}</strong>
        <p>${escR(r.callout.text || '')}</p>
      </div>`;
  }

  return `<div class="finding ${prioClass}">
    <div class="finding-header">
      <span class="f-category">${escR(r.category || '')}</span>
      <span class="f-priority">${escR(r.priority || '')}</span>
    </div>
    <div class="finding-title">${escR(r.title || '')}</div>
    ${istSollHtml}
    ${detailHtml}
    <div class="finding-action">${escR(r.action || '')}</div>
    ${calloutHtml}
  </div>`;
}
