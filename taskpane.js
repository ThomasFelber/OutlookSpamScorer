'use strict';

// ─── Spam Analyzer ────────────────────────────────────────────────────────────
// Pure logic — no DOM or Office dependencies.

class SpamAnalyzer {
  analyze(headers, bodyHtml, subject, senderEmail) {
    const reasons    = [];
    const hScore     = headers ? this._analyzeHeaders(headers, reasons, subject) : 0;
    const bScore     = this._analyzeBody(bodyHtml, subject, reasons);
    const hiddenText = this._extractHiddenTextFiltered(bodyHtml || '');

    // Deliverability notes: observations the score MAY have softened (because
    // the recipient's reading experience is not affected) but which the sender
    // must address — spam filters can't execute CSS, don't grant ESP-exemptions
    // for engagement signals, and look at headers Microsoft already filled in.
    const deliverabilityNotes = this._collectDeliverabilityNotes(headers || '', bodyHtml || '');

    // Score 2: improvement potential / business opportunity (authorized account only)
    const opp = headers ? this._computeOpportunityScore(headers, bodyHtml || '') : { score: 0, reasons: [] };

    return {
      score: Math.min(10, Math.round(hScore + bScore)),
      reasons,
      hiddenText,
      deliverabilityNotes,
      opportunityScore:   opp.score,
      opportunityReasons: opp.reasons,
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

  _analyzeHeaders(headers, reasons, subject = '') {
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

    // Microsoft Exchange signals — declared here, NOT scored here.
    // SCL, BCL, dest:J and OFR reflect the *recipient* MTA's verdict, not the
    // content quality. Including them in Score 1 would make the spam verdict
    // dependent on which email system receives the test message.
    // They are used exclusively in _computeOpportunityScore (Score 2).
    const scl        = parseInt(this._getHeader(headers, 'X-MS-Exchange-Organization-SCL') || '', 10); // eslint-disable-line no-unused-vars
    const msAntispam = this._getHeader(headers, 'X-Microsoft-Antispam') || '';
    const bclM       = msAntispam.match(/BCL:(\d+)/);
    const bclVal     = bclM ? parseInt(bclM[1], 10) : 0;   // shared with _analyzeBody via this._lastBclVal
    const msDelivery = this._getHeader(headers, 'X-Microsoft-Antispam-Mailbox-Delivery') || ''; // eslint-disable-line no-unused-vars
    const hasOFR     = /OFR:SpamFilter/i.test(msDelivery); // eslint-disable-line no-unused-vars

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
        score += 1.2;
        reasons.push(`Reply-To-Domain abweichend (${replyToDomain} ≠ ${fromDomain})`);
      }

      // Reply-To-Look-alike: Reply-To-Domain enthält einen Markennamen als
      // Teilstring, ist aber NICHT die offizielle Brand-Domain. Klassisches
      // Typosquatting bei Phishing — Antworten landen beim Angreifer.
      if (replyToRoot) {
        const replyToNormalized = replyToRoot.replace(/-/g, '');
        const brandLookalikes = [
          { sub: 'rayban',    official: /^(?:ray-?ban)\.com$/i },
          { sub: 'meta',      official: /^(?:meta|facebook|fb|instagram|whatsapp)\.com$/i },
          { sub: 'facebook',  official: /^facebook\.(?:com|net)$/i },
          { sub: 'google',    official: /^(?:google\.(?:com|de|co\.uk)|googlemail\.com|gmail\.com|abc\.xyz|youtube\.com)$/i },
          { sub: 'apple',     official: /^apple\.com$/i },
          { sub: 'amazon',    official: /^amazon\.(?:com|de|co\.uk|fr|es|it|nl|pl|com\.au|co\.jp)$/i },
          { sub: 'paypal',    official: /^paypal\.(?:com|de)$/i },
          { sub: 'netflix',   official: /^netflix\.(?:com|net)$/i },
          { sub: 'spotify',   official: /^spotify\.com$/i },
          { sub: 'tesla',     official: /^tesla\.com$/i },
          { sub: 'nike',      official: /^nike\.com$/i },
          { sub: 'adidas',    official: /^adidas\.(?:com|de)$/i },
          { sub: 'microsoft', official: /^(?:microsoft|live|hotmail|outlook|msn)\.com$/i },
          { sub: 'linkedin',  official: /^linkedin\.com$/i },
          { sub: 'tiktok',    official: /^tiktok\.com$/i },
        ];
        for (const { sub, official } of brandLookalikes) {
          if (replyToNormalized.includes(sub) && !official.test(replyToRoot)) {
            score += 2.0;
            reasons.push(`Reply-To-Domain "${replyToRoot}" enthält Markennamen "${sub}" — Typosquat/Look-alike (Phishing-Indikator)`);
            break;
          }
        }
      }
    }

    // No-Code-/Low-Code-Plattformen (AppSheet, Typeform, Tally, JotForm …)
    // sind legitime Infrastruktur, werden aber überdurchschnittlich häufig
    // für Spear-Phishing missbraucht, weil sie korrekt authentifizieren.
    // Kombination mit Recruitment-Pitch im Subject = roter Punkt.
    const fromDomainNC      = this._extractDomain(fromHeader);
    const fromRootNC        = this._extractRootDomain(fromDomainNC);
    const noCodeSenderDomain = /^(?:appsheet\.com|typeform\.com|tally\.so|glide(?:apps)?\.com|airtable\.com|jotform\.com|wufoo\.com|notion\.so|softr\.io|adalo\.com|bubble\.io|smartsuite\.com|smartsheet\.com|formstack\.com|zapier\.com|make\.com|paperform\.co)$/i;
    const recruitmentSubject = /\b(?:recruit(?:ing|ment|er)?|talent\s+(?:acquisition|core|hunt)|head[\s-]?hunt|job\s+(?:offer|opportunity)|career\s+opportunity|hiring|elite\s+(?:marketing|sales|leadership)|exceptional\s+(?:opportunity|leader)|exclusive\s+(?:position|opportunity)|advisor\s+(?:position|role)|chief\s+\w+\s+officer\s+(?:opportunity|position))\b/i;
    if (fromRootNC && noCodeSenderDomain.test(fromRootNC) && recruitmentSubject.test(subject)) {
      score += 2.0;
      reasons.push(`Recruitment-Pitch via No-Code-Plattform (${fromRootNC}) — typische Spear-Phishing-Infrastruktur`);
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

    // HELO-Domain-Mismatch wird nicht mehr als Spam-Indikator gewertet — siehe
    // _calculateOpportunityScore() für die Behandlung als Verbesserungspotenzial.

    // DKIM signing domain ≠ From domain (org-domain / relaxed alignment).
    // Skip known relay services that legitimately re-sign.
    const dkimRelayWhitelist = /privaterelay\.appleid\.com|icloud\.com|groups\.google\.com/i;
    const dkimSig   = this._getHeader(headers, 'DKIM-Signature') || '';
    const dkimDomM  = dkimSig.match(/\bd=([\w.-]+)/i);
    if (dkimDomM) {
      const dkimDomain  = dkimDomM[1].toLowerCase();
      const fromDomainD = this._extractDomain(fromHeader);
      // Use relaxed (org-domain) alignment — subdomains like info.example.com align with example.com
      const dkimRoot = this._extractRootDomain(dkimDomain);
      const fromRoot = this._extractRootDomain(fromDomainD);
      if (fromDomainD && dkimRoot !== fromRoot && !dkimRelayWhitelist.test(dkimDomain)) {
        score += 1.5;
        reasons.push(`DKIM-Signatur-Domain abweichend (${dkimDomain} ≠ ${fromDomainD})`);
      }
    }

    // Multiple DKIM signatures from different domains → relaying through unrelated infrastructure.
    // Exclude known infrastructure providers (Amazon SES, SendGrid, …) that co-sign transactional
    // email on behalf of the real sender, and same-org subdomains.
    // Also skip if at least one signing domain is aligned with From — the email is properly signed.
    const allDkimSigs = headers.match(/^DKIM-Signature:.+(?:\r?\n[ \t].+)*/gim) || [];
    if (allDkimSigs.length > 1) {
      const dkimDomains = new Set(
        allDkimSigs.map(s => (s.match(/\bd=([\w.-]+)/i) || [])[1]?.toLowerCase()).filter(Boolean)
      );
      const fromDomainC     = this._extractDomain(fromHeader);
      const fromRootDomainC = this._extractRootDomain(fromDomainC);
      const dkimInfraRe = /amazonses\.com|sendgrid\.net|mailgun\.net|sparkpostmail\.com|mandrill\.com|exacttarget\.com|postmarkapp\.com|brevo\.com|mailjet\.com|elasticemail\.com|klaviyo\.com/i;
      const anyAligned  = [...dkimDomains].some(d => this._extractRootDomain(d) === fromRootDomainC);
      const foreignDoms = [...dkimDomains].filter(d =>
        this._extractRootDomain(d) !== fromRootDomainC &&
        !dkimInfraRe.test(d) &&
        !dkimRelayWhitelist.test(d)
      );
      // Only flag when no aligned signing domain exists — aligned multi-sig is legitimate ESP co-signing
      if (dkimDomains.size > 1 && foreignDoms.length > 0 && !anyAligned) {
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
      const suspSenderTld = /\.(tk|cf|ga|ml|gq|xyz|top|click|download|stream|loan|win|racing|buzz|la|pw|cc|ws|nu|store|shop|online|space|link|site|website|fit|live)$/i;
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

    // Manufactured business identity on a free-mail provider: real Content Managers,
    // Marketing Specialists, Outreach Agents etc. have company email — not gmail/yahoo.
    // Pattern: "<firstname>.<role-keyword>@<freemail>" — e.g. "adamr.contentmanager@gmail.com"
    const freeMailDomain = /^(?:gmail|googlemail|yahoo|outlook|hotmail|live|gmx|aol|icloud|protonmail|proton|tutanota|tuta|mail|zoho|fastmail|yandex)\.[a-z.]+$/i;
    const rolePart       = /(?:content|marketing|outreach|partnership|seo|business|sales|pr|growth|digital|communications?|publishing|editor(?:ial)?)[\s_.-]?(?:manager|specialist|consultant|director|lead|coordinator|officer|agent|representative|exec|head)/i;
    if (freeMailDomain.test(fromDomain || '') && rolePart.test(fromLocalPart)) {
      score += 1.5;
      reasons.push(`Fabrizierte Business-Identität auf Free-Mail-Provider: "${fromLocalPart}@${fromDomain}"`);
    }

    // "alert@" / "notify@" / "security@" local-parts are legitimate only on a
    // narrow set of trusted senders (banks, government, major SaaS). Anywhere
    // else they are a manufactured-trust pattern — typically used after a
    // small-biz mailbox is compromised or for cheap throwaway domains.
    const alertPrefix         = /^(?:alert|alerts|notify|notification|notifications|notice|security[-_]?alert|incident|warning|admin[-_]?alert)s?[-_]?\d*$/i;
    const trustedAlertSenders = /(?:^|\.)(?:gov|mil|edu|police|amazon\.com|amazonaws\.com|paypal\.com|google\.com|microsoft\.com|apple\.com|github\.com|cloudflare\.com|sparkasse\.de|commerzbank\.de|postbank\.de|volksbank\.de|ing\.de|dkb\.de|n26\.com|revolut\.com|deutsche-bank\.de|fritz\.box)$/i;
    if (alertPrefix.test(fromLocalPart) && fromDomain && !trustedAlertSenders.test(fromDomain)) {
      score += 1.5;
      reasons.push(`"${fromLocalPart}@"-Absender auf nicht-zertifizierter Domain ${fromDomain} — echte Alerts kommen von Banken/Behörden/großen SaaS-Providern`);
    }

    // Bulk-mail-infrastructure headers (X-Job-ID, X-Feedback-ID, X-Campaign-Id …)
    // are normal on legitimate ESP traffic. They are a RED FLAG when the sender
    // domain is a single-business artisan / small-shop type — those domains
    // never run mass campaigns themselves. Combination = compromised mailbox or
    // rented sending infrastructure abused for bulk.
    const bulkInfraRe    = /^X-(?:Job-ID|Feedback-ID|Campaign(?:-(?:Id|Name))?|Mailer-RecptId|Mailgun-[\w-]+|SES-[\w-]+|Sendgrid-[\w-]+|MJ-Mid|Constant-Contact-ID|Mandrill-[\w-]+|Klaviyo-[\w-]+|HS-[\w-]+|Pardot-[\w-]+|Marketo-[\w-]+|Mta-Tag):/im;
    const fromMainHdr    = (this._extractRootDomain(fromDomain || '') || '').split('.')[0] || '';
    const smallBizDomain = /(?:acupunctur|chiropract|osteopath|physio|dentist|zahnarzt|arztpraxis|hausarzt|tierarzt|kinderarzt|salon|friseur|kosmetik|massag|yoga|pilates|fitnessstudio|photograph|fotograf|wedding|hochzeit|florist|blume(?:n)?laden|plumber|installateur|elektriker|maler|schreiner|tischler|carpenter|catering|baeckerei|bakery|metzger|barber|tattoo|piercing|spamassage|nageldesign|nailbar|notariat|kanzlei|praxis|pfarr|kirche|verein\b)/i;
    const isSmallBiz     = smallBizDomain.test(fromMainHdr) && fromMainHdr.length <= 30;
    if (bulkInfraRe.test(headers) && isSmallBiz) {
      score += 2.5;
      reasons.push(`Massenmail-Infrastruktur-Header auf Kleinunternehmer-Domain "${fromDomain}" — wahrscheinlich kompromittiertes Postfach oder gemietete Sendinfrastruktur`);
    }

    // More than 3 bulk-infra / campaign-tracking X-Headers WITHOUT a List-ID
    // header (which would indicate a proper ESP newsletter list) suggest rented
    // or abused sending infrastructure with uncertain provenance.
    const xTrackingCount = (headers.match(/^X-(?:Campaign|Job|Mailer-Recpt|Feedback|Recipient|Subscriber|List(?:-Type)?|Tracking|Click|Open|Mta-Tag|MC-)[\w-]*:/gim) || []).length;
    const hasListId      = /^List-ID:/im.test(headers);
    if (xTrackingCount >= 3 && !hasListId) {
      score += 0.8;
      reasons.push(`${xTrackingCount} Tracking/Kampagnen-Header ohne List-Id — uneindeutige Versand-Herkunft`);
    }

    // Store small-biz flag for the body-side topic-domain-mismatch check below.
    this._lastSmallBizDomain = isSmallBiz ? fromMainHdr.match(smallBizDomain)?.[0] : null;

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

    // ── Random-Token-Subdomain / Random-Localpart ──────────────────────────────
    // Aussprechbare Teile haben Vokal-Anteil ≥ 0.15; Throwaway-Subdomains wie
    // "qcnkqmsos" oder Local-Parts wie "newsletters.wkdwx" fallen darunter.
    const fromHostParts2  = (fromDomain || '').split('.');
    const subdomainParts2 = fromHostParts2.slice(0, -2);
    const isGibberish = s => {
      if (!s || s.length < 6) return false;
      const vowels = (s.match(/[aeiouäöü]/gi) || []).length;
      return (vowels / s.length) < 0.15
          || /^[bcdfghjklmnpqrstvwxz]{5,}$/i.test(s);
    };
    const gibberishSubdomain = subdomainParts2.some(isGibberish);
    const fromLocalLast = (fromLocalPart || '').split('.').pop() || '';
    const gibberishLocal     = isGibberish(fromLocalLast);
    if (gibberishSubdomain) {
      score += 1.5;
      reasons.push(`Random-Token-Subdomain in "${fromDomain}" — Throwaway-Mass-Mail-Pattern`);
    }
    if (gibberishLocal && !gibberishSubdomain) {
      score += 0.8;
      reasons.push(`Vokal-arme Random-Local-Part "${fromLocalPart}" — Bot-generierte Versand-Adresse`);
    }

    // ── Affiliate-/Lead-Gen-Marketing-Domain ───────────────────────────────────
    // Domain-Namen mit "leads-marketing", "affiliate", "lead-gen", "email-
    // marketing" sind nahezu ausschließlich Drittanbieter-Bulk-Marketing-
    // Netzwerke. Auth ist korrekt, Versand ist immer ungebeten.
    const leadGenRe = /(?:^|[-_.])(?:leads?[-_]?(?:marketing|generation|gen|hub|network|finder|broker)|email[-_]?marketing|affiliate[-_]?(?:network|hub)?|cpa[-_]?network|lead[-_]?gen|cold[-_]?(?:email|mail)|direct[-_]?(?:mailing|response)|mass[-_]?mail(?:ing)?)\.[a-z]{2,}$/i;
    if (fromDomain && (leadGenRe.test(fromDomain) || leadGenRe.test(this._extractRootDomain(fromDomain) || ''))) {
      score += 2.0;
      reasons.push(`Affiliate-/Lead-Gen-Marketing-Domain "${fromDomain}" — Drittanbieter-Massenversand-Netzwerk`);
    }

    // ── Compromised West-African Institutional TLD ────────────────────────────
    // .edu.ng, .ac.ng, .gov.ng etc. pass SPF/DKIM but are widely compromised
    // for 419/advance-fee fraud — institutional accounts look trustworthy.
    const westAfricanInstitTld = /\.(?:edu|ac|gov|sch|org|net)\.(?:ng|gh|ke|ug|tz|cm|ci|sn|rw|et|zm|bw)$/i;
    if (fromDomain && westAfricanInstitTld.test(fromDomain)) {
      score += 1.0;
      reasons.push(`West-Afrikanische Institutionelle Domain "${fromDomain}" — häufig kompromittiert für Vorschuss-Betrug`);

      // Compound: Google-WS-DKIM + institutional domain + free-mail Reply-To
      const googleWsDkim = allDkimSigs.some(s => /\bd=(?:google\.com|googlemail\.com)\b/i.test(s));
      const freeMailReTld = /^(?:gmail|googlemail|yahoo|hotmail|outlook|live|gmx|aol|icloud|protonmail|proton|tutanota|tuta|mail\.com|zoho|yandex)\.[a-z]{2,}$/i;
      const replyToDomAf  = this._extractDomain(replyToHeader);
      if (googleWsDkim && replyToDomAf && freeMailReTld.test(replyToDomAf)) {
        score += 2.5;
        reasons.push(`Compound 419-Muster: Google-WS-DKIM + "${fromDomain}" + Free-Mail Reply-To "${replyToDomAf}" — klassischer Vorschussbetrug`);
      }
    }

    // Expose auth state and BCL to _analyzeBody via instance state (avoids parameter threading)
    this._lastAuthFullyPasses = authFullyPasses;
    this._lastBclVal          = bclVal;
    this._lastFromHeader      = fromHeader;
    this._lastFromDomain      = fromDomain;
    this._lastDisplayName     = fromDisplayName;

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
      { re: /\b(?:nigeria|ghana|uganda|central\s+bank\s+of|next[\s-]?of[\s-]?kin|beneficiary\s+(?:of|fund)|atm\s+(?:card|release)|inheritance\s+(?:fund|claim|transfer)|unclaimed\s+(?:fund|deposit)|diplomat(?:ic)?\s+(?:box|trunk)|anti[\s-]?terrorism\s+clearance|fund\s+(?:transfer|release)|\$\s*\d[\d.,]*\s*(?:m(?:illion)?|b(?:illion)?)\b|millions?\s+(?:usd|us\$|\$)|billions?\s+(?:usd|us\$|\$)|prince\b|erbschaft|million[s]?\s*dollar)\b/i, w: 2.5, label: 'Nigeria-419-/Vorschussbetrug' },
      { re: /\b(?:western\s+union|moneygram|ria\s+(?:money|transfer)|wire\s+(?:the\s+)?(?:transfer|fee|charge)|transaction\s+pin\b|secret\s+(?:pin|code)\s+(?:to|for)|pay\s+(?:the\s+)?(?:clearance|delivery|release|insurance|legal)\s+fee)\b/i, w: 1.5, label: 'Überweisungs-Kanal (Western Union/MoneyGram) — Vorschussbetrug-Signal' },
      { re: /\b(?:central\s+bank\s+of\s+(?:nigeria|ghana|uganda|kenya|africa)|uba\s+(?:plc|bank|nigeria)|first\s+bank\s+(?:of\s+)?nigeria|zenith\s+bank|access\s+bank\s+nigeria|union\s+bank\s+of\s+nigeria|polaris\s+bank)\b/i, w: 1.5, label: 'West-Afrikanische Bankbehörde im Text — 419-Fraud-Signal' },
      { re: /viagra|cialis|levitra|pharmacy|apotheke\s*ohne\s*rezept/i,                    w: 2.5, label: 'Pharma-Spam' },
      { re: /casino|online.?wett(en|büro)|glücksspiel|freispiel(e)?|\bslots?\b|roulette|blackjack|poker\s*bonus/i, w: 1.5, label: 'Glücksspiel/Casino' },
      { re: /\d[\d.,]*\s*€\s*(zum|bei)\s+(niedrig|günstig|tief)zins|kreditangebot|sofortkredit|kredit\s+ohne\s+(schufa|bonitätsprüfung)|umschuldung|privat(kredit|darlehen)|effektiver\s+jahreszins|sollzinssatz/i, w: 1.5, label: 'Finanzangebot-Spam (Kredit/Darlehen)' },
      { re: /ihr\s+(konto|paypal|amazon|apple|microsoft).{0,30}(gesperrt|deaktiviert)/i,   w: 2,   label: 'Phishing: Konto gesperrt' },
      { re: /passwort\s*(ablaufen|bestätigen|verifizieren|erneuern|expired)/i,             w: 2,   label: 'Phishing: Passwort-Anfrage' },
      { re: /klicken\s*sie\s*hier|click\s*here|jetzt\s*klicken/i,                         w: 0.7, label: 'Generische Klick-Aufforderung' },
      { re: /dringend|urgent|sofort\s*handeln|act\s*now|limited\s*time|angebot\s*(endet|läuft)|läuft\s*(heute\s*)?ab|bald\s*nicht\s*mehr\s*verfügbar|bonus\s*(endet|läuft|expires)|angebot\s+endet\s+bald/i, w: 0.5, label: 'Künstliche Dringlichkeit' },
      { re: /100\s*%\s*(kostenlos|gratis|free)|völlig\s*kostenlos/i,                      w: 0.8, label: 'Gratis-Versprechen' },
      { re: /sie\s*wurden\s*ausgewählt|you\s*have\s*been\s*selected/i,                    w: 1.5, label: 'Pseudo-Auszeichnung' },
      { re: /\bcrypto|bitcoin|kryptowährun|invest.{0,30}(rendite|gewinne?|robot)|hohe\s*rendite|trading.{0,20}(auto|bot|signal)|warum\s+alle.{0,20}invest|fibonacci|forex\s+signal/i, w: 1.5, label: 'Crypto/Investment-Spam' },
      { re: /ihre\s*(daten|informationen)\s*(wurden\s*)?bestätigen|verify\s*your\s*info/i, w: 1.5, label: 'Datenmissbrauch-Phishing' },
      { re: /lions?\s*(mane|spray)|körper\s*reset|nahrungsergänzung|supplement\b|fettverbrenner|schlank(heits)?|kräuter.{0,25}(spray|tropfen|kapsel)|testosteron.{0,20}boost|abnehm|\bdetox\b|keto\s*(diät|plan|programm|rezept|\b)|\d+\s*kg\s*(verloren?|abgenommen)|gewicht\s*(verloren?|verlier|abgenomm)|bauchfett|taille\s*(reduzier|weg|schmaler)/i, w: 1.5, label: 'Supplement/Gewichtsabnahme-Spam' },
      { re: /\b(?:vita[-\s]?glp|gluco[-\s]?pro|sugar[-\s]?defender|ozempic[-_]?(?:alternative|natural|generic)|GLP[-\s]?1\s+(?:natural|alternative|generic)|abnehmspritze\s+(?:ohne\s+rezept|alternative|generic))\b/i, w: 1.5, label: 'GLP-1-/Ozempic-Klon-Spam (Supplement)' },
      { re: /wechat|微信|telegram\s*(channel|contact|group|id)|whatsapp\s*(contact|number|group)|line\s*id\s*:/i, w: 1.5, label: 'Messenger-Kontakt-Solicitation (WeChat/Telegram/WhatsApp)' },
      { re: /bundeszentralamt|finanzamt\b|bundeszoll|steuerpr[üu]fung.*krypto|amtliche?\s+(mahnung|aufforderung|mitteilung).*steuer/i, w: 2.5, label: 'Behörden-Impersonation (Finanzamt/BZSt)' },
      { re: /\b(UPS|DHL|FedEx|Hermes|DPD|GLS|Yodel|Evri)\b.{0,40}(paket|lieferung|sendung|delivery|tracking|notification|nicht\s*zugestellt)/i, w: 1.5, label: 'Kurierdienst-Erwähnung (auf Domain-Mismatch prüfen)' },

      // SEO / Link-Building / Guest-Post-Outreach — eigene Spam-Klasse mit hoher Spezifität
      { re: /\b(guest[\s-]?(post|blog|article|author)|gastbeitrag|gesponsorter?\s+(beitrag|artikel|post)|sponsored\s+(post|article|content|placement)|paid\s+(post|placement|article))\b/i,
        w: 2.0, label: 'Gastbeitrag-/Sponsored-Content-Anfrage (Link-Building)' },
      { re: /\b(backlinks?|link[\s-]?building|link[\s-]?exchange|link[\s-]?placement|link[\s-]?insertion|niche[\s-]?edit|do[\s-]?follow\s+link|reciprocal\s+link)\b/i,
        w: 2.0, label: 'Backlink-/Link-Exchange-Anfrage' },
      { re: /\b(?:DR|DA|TF|CF|PA)\s*[:=]?\s*\d{2,}\+?\b|\b(?:domain\s+(?:rating|authority)|trust\s+flow|citation\s+flow|page\s+authority|ahrefs\s+(?:rank|score))\b\s*(?:of\s+|=\s*|:\s*)?\d{2,}/i,
        w: 1.8, label: 'SEO-Metrik-Versprechen (DR/DA/TF) — Link-Selling-Anbahnung' },
      { re: /\b\d+(?:[.,]\d+)?\s*(?:[KMm]|million|tausend|thousand)\+?\s*(?:monthly|monatlich(?:e)?|per\s+month|im\s+monat)\s*(?:visit|visitor|audience|reach|traffic|impression|unique|reader|leser)/i,
        w: 1.5, label: 'Reichweiten-Pitch ("2M+ monthly audience")' },
      { re: /\b(write\s+for\s+us|contribute\s+to\s+(?:our|your)|content\s+collaboration|content\s+partnership|publishing\s+opportunity|featured\s+(?:article|post)\s+(?:opportunity|placement)|editorial\s+(?:placement|opportunity))\b/i,
        w: 1.5, label: 'SEO-Outreach-Phrase ("write for us" / "content collaboration")' },

      // Cold-Pitch-Floskeln — einzeln schwach, kumulativ stark (Compound-Check unten verstärkt)
      { re: /\b(?:i\s+)?hope\s+(?:this|you|all)\s+(?:message\s+|email\s+|note\s+)?(?:finds?|are|is)\s+(?:you\s+)?(?:well|doing\s+well|good)\b/i,
        w: 0.4, label: 'Generische Cold-Pitch-Eröffnung ("hope this finds you well")' },
      { re: /\b(?:i'?m\s+|just\s+|wanted\s+to\s+|circling\s+back\s+|following\s+up\s+(?:on\s+)?)?reach(?:ing|ed)?\s+out(?:\s+to\s+(?:you|offer|propose|discuss))?\b/i,
        w: 0.4, label: 'Cold-Pitch-Opener ("reaching out")' },
      { re: /\b(?:exciting|amazing|unique|great|fantastic|incredible)\s+(?:opportunity|chance|partnership|collaboration)\b/i,
        w: 0.5, label: 'Generisches Opportunity-Pitch-Adjektiv' },

      // Recruitment-Phishing — unsolicited grand-title job offers
      { re: /\b(?:elite|exclusive|exceptional|prestigious|high[-\s]?profile|top[-\s]?tier)\s+(?:marketing|sales|recruitment|talent|leadership|advisor|consultant)\s+(?:advisor|position|opportunity|role|consultant)?/i,
        w: 1.5, label: 'Recruitment-Phishing-Phrase ("elite advisor", "exclusive position")' },
      { re: /\bsignificant\s+(?:decision|opportunity|career\s+(?:move|step))|career[-\s]?changing\s+(?:opportunity|decision)|life[-\s]?changing\s+offer/i,
        w: 0.8, label: 'High-Pressure Recruitment-Sprache' },
      { re: /\b(?:Dear|Hi|Hello)\s+[A-ZÄÖÜ][a-zäöü]{2,15}\s*[,!.]?\s*(?:\r?\n|\s){1,3}\s*(?:I\s+(?:am|wanted|hope)|We\s+(?:are|have)|My\s+name\s+is)\b/i,
        w: 0.5, label: 'Personalisierte Anrede + generischer Cold-Pitch-Opener' },
      { re: /\bresonates?\s+with\s+you\b|\bspeak(?:s)?\s+to\s+(?:you|your\s+experience)\b|\baligned?\s+with\s+your\s+(?:career|experience|background)/i,
        w: 0.5, label: 'Manipulative Resonanz-Sprache ("resonates with you")' },
    ];

    for (const p of patterns) {
      if (p.re.test(fullLower)) { score += p.w; reasons.push(p.label); }
    }

    // ── Topic-Domain-Mismatch ─────────────────────────────────────────────────
    // Sender-Domain hat eine erkennbare Business-Bedeutung (Akupunktur, Zahnarzt,
    // Floristik …), aber der Mailinhalt behandelt ein völlig unverwandtes
    // Mass-Market-Thema (Auto, Krypto, Diät …) — klassisches Zeichen für
    // gekapertes Postfach oder gemietete Sendinfrastruktur. Konservativ:
    // wir feuern nur bei deutlichen Topic-Keywords.
    if (this._lastSmallBizDomain) {
      const topicTriggers = [
        { topic: 'Automotive',      re: /\b(auto|kfz|fahrzeug|car\s|wagen|notfall.{0,10}auto|garage|reifen|werkstatt|t[üu]v|[öo]lwechsel|motor.{0,10}defekt|sicherheitsgurt|airbag)\b/i },
        { topic: 'Gewichtsabnahme', re: /\b(abnehm|di[äa]t|fettverbrenn|schlankheit(?:s)?|kalorien|keto\s|bauchfett|stoffwechsel)\b/i },
        { topic: 'Krypto/Forex',    re: /\b(bitcoin|krypto|forex|trading|investment|rendite|fibonacci|broker(?:konto)?)\b/i },
        { topic: 'Glücksspiel',     re: /\b(casino|jackpot|roulette|spielautomat|sportwetten|freispiel)\b/i },
        { topic: 'Pharma/Potenz',   re: /\b(viagra|cialis|levitra|potenzmittel|libido|erektion|generika)\b/i },
        { topic: 'Finanzkredit',    re: /\b(sofortkredit|umschuldung|privatdarlehen|kredit\s+ohne|schufa[-\s]?frei|effektiver\s+jahreszins)\b/i },
      ];
      for (const { topic, re } of topicTriggers) {
        if (re.test(fullText)) {
          score += 2.0;
          reasons.push(`Themen-Domain-Mismatch: Domain deutet auf "${this._lastSmallBizDomain}", Inhalt ist Thema "${topic}" — wahrscheinlich missbrauchter Absender`);
          break;
        }
      }
    }

    // ── Free-Mail-Provider + B2B-Outreach (Compound-Check) ─────────────────────
    // Persönliche Free-Mail-Adressen (Gmail, Yahoo, GMX …) sind legitim für
    // Privatkorrespondenz, aber NIE für seriöse B2B-Outreach — echte Unternehmen
    // nutzen ihre eigene Domain. Wir flaggen nur, wenn freemail + mindestens
    // 2 Outreach-Signale zusammenkommen, um False-Positives bei privaten Mails
    // zu vermeiden.
    const freeMailBody = /^(?:gmail\.com|googlemail\.com|yahoo\.(?:com|de|co\.uk|fr|es|it)|outlook\.com|hotmail\.com|live\.com|gmx\.(?:de|net|com|at|ch)|web\.de|t-online\.de|aol\.com|icloud\.com|me\.com|mac\.com|protonmail\.com|proton\.me|tutanota\.com|tuta\.com|mail\.com|zoho\.com|fastmail\.com|yandex\.(?:com|ru))$/i;
    const isFreeMail   = freeMailBody.test((this._lastFromDomain || '').toLowerCase());
    if (isFreeMail) {
      const outreachSignals = [
        /\b(?:guest\s+post|backlink|link\s+building|sponsored\s+post|content\s+collaboration|write\s+for\s+us)\b/i,
        /\b(?:DR|DA|TF)\s*[:=]?\s*\d{2,}\+?\b|\bdomain\s+(?:rating|authority)\b/i,
        /\b\d+[KMm]\+?\s*(?:monthly|unique|visitor|audience|reach|traffic)/i,
        /\bhope\s+(?:this|you).{0,30}(?:finds?|are)\s+(?:you\s+)?well\b/i,
        /\b(?:reaching|reached)\s+out\b/i,
        /\b(?:opportunity|partnership|collaboration)\b/i,
      ];
      const hits = outreachSignals.filter(re => re.test(fullText)).length;
      if (hits >= 2) {
        // False-Positive-Guard: echte persönliche Signatur mit Tel + Firmen-URL ≠
        // Free-Mail-Domain → Penalty halbieren. Spam-Outreach hat fast nie beides.
        const hasBusinessSignature =
          /\b(?:tel|telefon|phone|mobile|mob\.?)\s*[:.]?\s*[+\d][\d\s\-/()]{6,}/i.test(plainText)
          && /https?:\/\/(?!.*(?:gmail|googlemail|yahoo|outlook|hotmail|live\.com|gmx|web\.de|t-online|aol|icloud|protonmail|tutanota|mail\.com|zoho|fastmail|yandex))[\w.-]+\.[a-z]{2,}/i.test(bodyHtml || '');
        let w = Math.min(3, 1.0 + hits * 0.5);   // 2 Hits = 2.0, 3 = 2.5, 4+ = 3.0
        if (hasBusinessSignature) w *= 0.5;
        score += w;
        reasons.push(`Free-Mail-Provider (${this._lastFromDomain}) + ${hits} B2B-Outreach-Signale — kein seriöser Geschäftsabsender${hasBusinessSignature ? ' (Penalty halbiert wg. Business-Signatur)' : ''}`);
      }
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
        // Globale Marken (häufig im Spear-Phishing für Recruitment-Scams)
        { re: /\bray[-\s]?ban\b/i,                   roots: ['ray-ban.com', 'rayban.com'] },
        { re: /\bmeta\b(?!\s*(?:gen|tag|data|\sdescription))/i, roots: ['meta.com', 'facebook.com', 'fb.com', 'instagram.com'] },
        { re: /\bfacebook\b/i,                       roots: ['facebook.com', 'fb.com', 'meta.com'] },
        { re: /\binstagram\b/i,                      roots: ['instagram.com', 'facebook.com', 'meta.com'] },
        { re: /\bgoogle\b/i,                         roots: ['google.com', 'google.de', 'googlemail.com', 'gmail.com', 'abc.xyz', 'youtube.com'] },
        { re: /\btesla\b/i,                          roots: ['tesla.com'] },
        { re: /\bnike\b/i,                           roots: ['nike.com'] },
        { re: /\badidas\b/i,                         roots: ['adidas.com', 'adidas.de'] },
        { re: /\blinkedin\b/i,                       roots: ['linkedin.com'] },
        { re: /\btiktok\b/i,                         roots: ['tiktok.com'] },
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
            const w            = inSubject ? 2.5 : 1.7;
            score += w;
            reasons.push(`Marken-Impersonation: "${matchedBrand}" ${inSubject ? 'im Betreff' : 'im E-Mail-Text'}, Absender-Domain "${fromRootForBrand}"`);
            break; // one impersonation signal is enough
          }
        }
      }

      // ── Display-Name-Brand-Impersonation ──────────────────────────────────────
      // Anzeigename nennt eine bekannte Marke (z. B. „Max von smava"), aber
      // Sender-Domain gehört nicht zur Marke. Ergänzt den obigen Subject/Body-
      // Check um die From-Display-Name-Achse.
      const displayName = this._lastDisplayName || '';
      if (displayName) {
        const dispLower = displayName.toLowerCase();
        const domainWord = (fromRootForBrand || '').split('.')[0] || '';
        if (domainWord && !dispLower.includes(domainWord)) {
          for (const { re, roots } of brandMap) {
            if (re.test(dispLower)
                && !roots.includes(fromRootForBrand)
                && !roots.some(r => fromRootForBrand && fromRootForBrand.endsWith('.' + r))) {
              const matched = (dispLower.match(re) || [''])[0];
              score += 2.0;
              reasons.push(`Marken-Impersonation im Absender-Anzeigename: "${matched}" — Sender-Domain "${fromRootForBrand}" gehört nicht zur Marke`);
              break;
            }
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

    // ── Aktenzeichen / EU-Richtlinien-Referenz auf Nicht-Behörden-Domain ──────
    // "Az: BZSt-...", "Akt.-Z.", "Geschäftszeichen" oder konkrete EU-Richtlinien-
    // Nummern (DAC8, EU 2023/2226) deuten auf Behörden-/Authority-Kontext. Auf
    // nicht-amtlicher Domain ist das ein klares Phishing-Muster.
    const akzFormat   = /\b(?:Az\.?\s*:|Akt\.?\s*-?Z\.?\s*:|Aktenzeichen|Gesch[äa]ftszeichen)\s*[A-Z][A-Z0-9\-/]+/i;
    const euDirective = /\bDAC\s*[\-]?\s*\d+\b|EU[-\s]?(?:Verordnung|Directive|Richtlinie)\s+\d{4}\/\d{2,4}|EU[\s/]?\d{4}\/\d{4}|MiCA[-\s]?Regulation/i;
    const officialAuthorityDomain = /(?:^|\.)(?:bund\.de|bundesamt[-.\w]+|bzst\.de|bzst\.bund\.de|bmf\.bund\.de|bafin\.de|deutsche-rentenversicherung\.de|elster\.de|bayern\.de|hessen\.de|nrw\.de|berlin\.de|brandenburg\.de|saarland\.de|schleswig-holstein\.de)$|\.(gov|gov\.uk|europa\.eu)$/i;
    const fromDomLow  = (this._lastFromDomain || '').toLowerCase();
    const isAuthorityDomain = officialAuthorityDomain.test(fromDomLow);
    if ((akzFormat.test(subject || '') || akzFormat.test(plainText) || euDirective.test(plainText)) && !isAuthorityDomain) {
      score += 2.0;
      reasons.push(`Aktenzeichen-/EU-Richtlinien-Format auf nicht-amtlicher Domain "${this._lastFromDomain}" — Behörden-Phishing-Indikator`);
    }

    // ── AWS-SES-Tracking + Behörden-Pretext ───────────────────────────────────
    // awstrack.me ist legitime AWS-SES-Tracking-Infrastruktur. In Kombination
    // mit Behörden-Pretext (BZSt, Finanzamt etc.) ist sie gemietete SES-
    // Infrastruktur für Phishing-Kampagnen.
    const awsTrackUrl       = /awstrack\.me|us-(?:east|west)-\d\.awstrack/i;
    const authorityPretext  = /Bundeszentralamt|Finanzamt|BMF|BZSt|Bundesregierung|Bundesministerium|Beh[öo]rde\s+f[üu]r|Steueridentifikationsnummer/i;
    if (awsTrackUrl.test(bodyHtml || '') && authorityPretext.test(fullText)) {
      score += 1.5;
      reasons.push('AWS-SES-Tracking-URL kombiniert mit Behörden-Pretext — gemietete Phishing-Infrastruktur');
    }

    // ── CJK / Cyrillic content in non-asian email ──────────────────────────────
    // Substanzielle Mengen ostasiatischer (CJK) oder kyrillischer Zeichen im
    // Body deuten auf Sprach-Misalignment — typisch für ostasiatische/russische
    // Spam-Kampagnen, die deutsche/englische Subject-Pretexts verwenden.
    const cjkChars      = (plainText.match(/[一-鿿぀-ゟ゠-ヿ]/g) || []).length;
    const cyrillicChars = (plainText.match(/[Ѐ-ӿ]/g) || []).length;
    if (cjkChars >= 8) {
      score += 1.5;
      reasons.push(`${cjkChars} CJK-Zeichen im Body — Fremdsprache passt nicht zum Empfänger-Kontext`);
    } else if (cyrillicChars >= 8) {
      score += 1.2;
      reasons.push(`${cyrillicChars} kyrillische Zeichen im Body — Fremdsprache passt nicht zum Empfänger-Kontext`);
    }

    // ── Calendar-Invitation-Pretext ohne ICS-Payload ──────────────────────────
    // "Notification: You're invited to share this calendar" als Subject, aber
    // keine echte ICS-Payload im Mail-Body. Klassisches Spam-Pretext-Muster.
    const calendarSubject = /(?:share\s+this\s+calendar|invited\s+to\s+share|calendar\s+invitation|kalender(?:einladung|freigabe)|einladung\s+zum\s+(?:kalender|termin))/i;
    const hasIcsPayload   = /Content-Type:\s*text\/calendar|BEGIN:VCALENDAR|\.ics(?:\s|"|;)/i.test((bodyHtml || ''));
    if (calendarSubject.test(subject || '') && !hasIcsPayload) {
      score += 1.5;
      reasons.push('Kalender-Einladungs-Pretext im Subject ohne ICS-Payload — Curiosity-Spam-Pretext');
    }

    // ── ALL-CAPS subject line ──────────────────────────────────────────────────
    // "FUNDS IS LOADED INTO AN ATM CARD" — legitimate senders never shout.
    // Fires only when ≥4 words and ≥80% are all-caps (excludes normal acronyms).
    if (subject) {
      const subjWords  = subject.split(/\s+/).filter(w => w.length > 2);
      if (subjWords.length >= 4) {
        const capsWords = subjWords.filter(w => w === w.toUpperCase() && /[A-Z]/.test(w));
        if (capsWords.length / subjWords.length >= 0.8) {
          score += 1.2;
          reasons.push(`Betreff komplett in Großbuchstaben: "${subject.slice(0, 60)}" — aggressives Spam-Muster`);
        }
      }
    }

    // Exclamation mark analysis — density + subject + consecutive (not raw count)
    const subjectExcl   = (subject || '').match(/!/g)?.length ?? 0;
    const bodyExcl      = (plainText.match(/!/g) || []).length;
    const wordCount     = Math.max(1, (plainText.match(/\b\w{2,}\b/g) || []).length);
    const exclDensity   = (bodyExcl / wordCount) * 100;  // per 100 words
    const hasConsec     = /!!/.test(fullText);

    let exclScore = 0;
    const exclDetails = [];

    if (subjectExcl >= 2) {
      exclScore += subjectExcl * 0.25;
      exclDetails.push(`${subjectExcl}× Betreff`);
    }
    if (hasConsec) {
      exclScore += 0.35;
      exclDetails.push('!! Häufung');
    }
    if (exclDensity > 1.0) {
      exclScore += Math.min(0.8, (exclDensity - 1.0) * 0.5);
      exclDetails.push(`${exclDensity.toFixed(1)}/100 Wörter`);
    } else if (bodyExcl > 5 && wordCount < 200) {
      // High absolute count in a short email (B2B-like scenario)
      exclScore += 0.25;
      exclDetails.push(`${bodyExcl} bei <200 Wörtern`);
    }

    if (exclScore > 0) {
      score += exclScore;
      reasons.push(`Ausrufezeichen (${subjectExcl + bodyExcl}): ${exclDetails.join(', ')}`);
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

    // URL shorteners hide destination — always suspicious.
    // Bewusst NICHT enthalten: youtu.be (YouTube official), lnkd.in (LinkedIn),
    // fb.me (Facebook), amzn.to (Amazon) — sind legitime Plattform-Shortener.
    const shortenerRe = /\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|cutt\.ly|rb\.gy|is\.gd|short\.io|tiny\.cc|shorturl\.at|rebrand\.ly|bit\.do|s\.id|link\.tl|tr\.im|soo\.gd|qr\.ae|x\.co)\//i;
    if (links.some(l => shortenerRe.test(l))) {
      score += 1.5;
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
      score += 1.5;
      reasons.push('Obfuskierte URL-Parameter mit Sonderzeichen — Spam-Tracking-Token');
    }

    if (linkCount > 0) {
      const textLen = plainText.length;
      if (textLen < 80 && linkCount >= 2) {
        score += 1.3;
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
    let hiddenTextFlagged = false;
    if (/color\s*:\s*(white|#fff\b|#ffffff)|font-size\s*:\s*[01]px|display\s*:\s*none|visibility\s*:\s*hidden/i.test(bodyHtml || '')) {
      const hiddenContent = this._extractHiddenTextFiltered(bodyHtml || '');
      const hiddenLen     = hiddenContent.length;
      const trustedSender = authFullyPasses && !highBcl;
      // Only legitimate exception: preheader text (85–140 chars).
      // Threshold: trusted sender 150 chars, untrusted 50 chars.
      const substantialThreshold = trustedSender ? 150 : 50;

      if (hiddenLen > substantialThreshold) {
        score += 1.5;
        reasons.push(`Versteckter/unsichtbarer Text gefunden (${hiddenLen} Zeichen — über Preheader-Norm, abweichend vom sichtbaren Inhalt)`);
        hiddenTextFlagged = true;
      } else if (hiddenLen > 0 && !trustedSender) {
        score += 0.5;
        reasons.push('Versteckte Elemente gefunden (Tracking-Pixel o.ä.)');
        hiddenTextFlagged = true;
      }
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
    // U+FEFF BOM, U+00AD soft hyphen). No legitimate use in marketing email; 3+ is a signal.
    const zwsCount = ((bodyHtml || '').match(/[​‌‍﻿­]/g) || []).length;
    if (zwsCount > 2) {
      const zwsScore = zwsCount >= 50 ? 2.0 : zwsCount >= 15 ? 1.5 : 1.0;
      score += zwsScore;
      reasons.push(`Zero-Width-Space-Obfuskation (${zwsCount} unsichtbare Zeichen) — Spam-Filter-Umgehung`);
      // Combined hidden-text + ZWS pattern: enterprise filters (Proofpoint, Mimecast, Defender) treat this as high-risk
      if (hiddenTextFlagged) {
        score += 0.5;
        reasons.push('Kombination: Versteckter Text + ZWS — Enterprise-Filter stufen dies als High-Risk ein');
      }
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

  // ── Score 2: Opportunity / Improvement-Potential ─────────────────────────────
  // High score = many fixable issues = strong business opportunity.
  // Weights:  technical configuration (highest — easy money),
  //           content / markup quality (second — how-to guide territory).
  // Relies on this._lastAuthFullyPasses and this._lastBclVal set by _analyzeHeaders.
  // ── Score 2: Opportunity / Improvement-Potential ─────────────────────────────
  // Assumes the email is legitimate. Scores how much the spam classification
  // can be improved through targeted, fixable changes.
  //
  // Category caps (sum = max 10):
  //   tech    max 6  (60 %) — DNS / infrastructure / authentication config
  //   struct  max 3  (30 %) — HTML/CSS structure, markup, encoding
  //   content max 1  (10 %) — CTA wording, salutation, tone
  _computeOpportunityScore(headers, bodyHtml) {
    const oppReasons      = [];
    let tech    = 0;  // max 6
    let struct  = 0;  // max 3
    let content = 0;  // max 1

    const authFullyPasses = this._lastAuthFullyPasses || false;
    const bclVal          = this._lastBclVal          || 0;

    // ── TECHNICAL (max 6) ─────────────────────────────────────────────────────

    if (headers) {
      const msDelivery = this._getHeader(headers, 'X-Microsoft-Antispam-Mailbox-Delivery') || '';
      const hasDestJ   = /dest:J/i.test(msDelivery);
      const hasOFR     = /OFR:SpamFilter/i.test(msDelivery);
      const scl        = parseInt(this._getHeader(headers, 'X-MS-Exchange-Organization-SCL') || '', 10);
      const authLine   = this._getHeader(headers, 'Authentication-Results')
                      || this._getHeader(headers, 'ARC-Authentication-Results')
                      || '';

      // Microsoft delivery verdicts.
      // Auth-fail cases score as high as auth-pass cases: broken DMARC alignment
      // is MORE fixable than an IP reputation problem on correctly authenticated mail.
      if (hasDestJ) {
        if (hasOFR) {
          tech += 2.5;
          if (authFullyPasses) {
            oppReasons.push('dest:J + Auth-Pass + OFR — Infrastrukturproblem trotz sauberem Auth');
          } else {
            oppReasons.push('dest:J + Auth-Fehler + OFR — DMARC-Alignment, IP-Reputation und Inhalt beheben');
          }
        } else if (authFullyPasses) {
          tech += 2.0;
          oppReasons.push('dest:J trotz vollständiger Authentifizierung — IP/Reputation');
        } else {
          tech += 2.0;
          oppReasons.push('dest:J mit Auth-Fehlern — DMARC-Alignment + Infrastruktur verbessern');
        }
      }
      if (hasOFR && !hasDestJ) {
        tech += 1.0;
        oppReasons.push('OFR:SpamFilter — Filter-Override trotz Auth');
      }

      if (!isNaN(scl)) {
        if (scl >= 7 && authFullyPasses) {
          tech += 1.5;
          oppReasons.push(`SCL ${scl} trotz vollst. Auth — starkes Reputationssignal`);
        } else if (scl >= 7) {
          tech += 1.0;
          oppReasons.push(`SCL ${scl} — Spam-Klassifikation`);
        } else if (scl >= 5 && authFullyPasses) {
          tech += 1.0;
          oppReasons.push(`SCL ${scl} trotz vollst. Auth — Junk-Einstufung gezielt behebbar`);
        } else if (scl >= 5) {
          // SCL elevated AND auth broken — fixing alignment will directly reduce SCL
          tech += 0.8;
          oppReasons.push(`SCL ${scl} — Auth-Alignment-Fix wird SCL direkt senken`);
        }
      }

      if (bclVal >= 7) {
        tech += 1.5;
        oppReasons.push(`BCL ${bclVal} — hohe Beschwerderate`);
      } else if (bclVal >= 4) {
        tech += 0.8;
        oppReasons.push(`BCL ${bclVal} — erhöhte Beschwerderate`);
      }

      // DMARC enforcement level.
      // Microsoft Authentication-Results reports "action=none/quarantine/reject"
      // (what Exchange did) rather than "p=none/quarantine/reject" (the DNS record).
      // When dmarc=fail + action=none it always means p=none — check both forms.
      const dmarcSeg = (authLine.match(/dmarc=[^;]+/i) || [''])[0];
      let dPolicy = null;
      const pM = dmarcSeg.match(/\bp=(none|quarantine|reject)\b/i);
      if (pM) {
        dPolicy = pM[1].toUpperCase();
      } else if (/dmarc=fail/i.test(dmarcSeg)) {
        // action=none on a fail → p=none; action=quarantine → p=quarantine etc.
        const aM = dmarcSeg.match(/\baction=(none|quarantine|reject)\b/i);
        if (aM) dPolicy = aM[1].toUpperCase();
      }
      if (dPolicy === 'NONE') {
        tech += 1.5;
        oppReasons.push('DMARC p=NONE — keine Durchsetzung; auf REJECT anheben');
      } else if (dPolicy === 'QUARANTINE') {
        tech += 0.8;
        oppReasons.push('DMARC p=QUARANTINE — noch nicht auf REJECT gesetzt');
      }

      // Return-Path domain mismatch
      const fromHeader = this._getHeader(headers, 'From')        || '';
      const returnPath = this._getHeader(headers, 'Return-Path') || '';
      if (fromHeader && returnPath) {
        const fromRoot = this._extractRootDomain(this._extractDomain(fromHeader));
        const rpRoot   = this._extractRootDomain(this._extractDomain(returnPath));
        if (fromRoot && rpRoot && fromRoot !== rpRoot) {
          tech += 0.8;
          oppReasons.push('Return-Path-Domain abweichend — ESP-Konfiguration anpassen');
        }
      }

      // DKIM domain mismatch / missing signature
      const fromHdr2    = this._getHeader(headers, 'From') || '';
      const dkimSig     = this._getHeader(headers, 'DKIM-Signature') || '';
      const dkimDomM    = dkimSig.match(/\bd=([\w.-]+)/i);
      const dkimRelay   = /privaterelay\.appleid\.com|icloud\.com|groups\.google\.com/i;
      // Default cloud DKIM: tenant hasn't configured custom domain signing
      const dkimM365    = /\.onmicrosoft\.com$/i;
      let   dkimAligned = false;  // used for auth-fragile check below

      if (dkimDomM && fromHdr2) {
        const dkimRoot = this._extractRootDomain(dkimDomM[1].toLowerCase());
        const frRoot   = this._extractRootDomain(this._extractDomain(fromHdr2));
        dkimAligned    = !!(dkimRoot && frRoot && dkimRoot === frRoot);
        if (dkimRoot && frRoot && dkimRoot !== frRoot && !dkimRelay.test(dkimDomM[1])) {
          if (dkimM365.test(dkimDomM[1])) {
            // Microsoft 365 default signing — trivially easy fix (2 CNAME records + M365 admin toggle)
            tech += 1.5;
            oppReasons.push('DKIM: M365-Standard-Signatur (onmicrosoft.com) — eigene Domain in 2 DNS-Einträgen aktivieren');
          } else {
            tech += 0.8;
            oppReasons.push('DKIM d= abweichend — Signatur-Domain nicht mit From ausgerichtet');
          }
        }
      } else if (!dkimSig) {
        tech += 1.0;
        oppReasons.push('Keine DKIM-Signatur — E-Mail-Authentifizierung unvollständig');
      }

      // Auth fragility: DMARC passes but only via SPF alignment; DKIM alignment
      // is a second, independent factor — if the SPF record changes, DMARC fails.
      if (dkimSig && !dkimAligned && /dmarc=pass/i.test(authLine)) {
        tech += 1.0;
        oppReasons.push('DMARC-Pass nur über SPF — DKIM-Alignment als zweiten Auth-Pfad einrichten');
      }

      // HELO/EHLO domain mismatch — sending host announces a name unrelated to the
      // From domain. Not a spam signal on its own (many ESPs do this legitimately),
      // but worth surfacing as a deliverability improvement: aligned HELO improves
      // reverse-DNS / FCrDNS reputation and reduces filter friction.
      const espHelo = /\.(mailgun\.net|sendgrid\.net|amazonses\.com|sparkpostmail\.com|exacttarget\.com|salesforceemails\.com|campaignmonitor\.com|createsend\.com|mandrill\.com|postmarkapp\.com|mimecast\.com|proofpoint\.com|constantcontact\.com|hubspot\.com|marketo\.net|klaviyo\.com|brevo\.com|mailjet\.com|elasticemail\.com)$/i;
      const receivedSpf = this._getHeader(headers, 'Received-SPF') || '';
      const heloM = receivedSpf.match(/helo=([\w.-]+)/i);
      if (heloM && fromHdr2) {
        const heloDomain  = heloM[1].toLowerCase();
        const fromDomainH = this._extractDomain(fromHdr2);
        if (fromDomainH && heloDomain !== fromDomainH
            && !heloDomain.endsWith('.' + fromDomainH)
            && !fromDomainH.endsWith('.' + heloDomain)
            && !espHelo.test(heloDomain)) {
          tech += 0.5;
          oppReasons.push(`HELO-Domain abweichend (${heloDomain} ≠ ${fromDomainH}) — Sending-Host an From-Domain ausrichten (FCrDNS/Reputation)`);
        }
      }
    }

    tech = Math.min(6, tech);

    // ── STRUCTURAL (max 3) ────────────────────────────────────────────────────
    // HTML/CSS markup quality, text/image balance, encoding practices.

    if (bodyHtml) {
      const plainText   = this._stripHtml(bodyHtml).replace(/\s+/g, ' ').trim();
      const visibleText = this._extractVisibleText(bodyHtml);
      const imgCount    = (bodyHtml.match(/<img\b/gi) || []).length;
      const htmlLen     = bodyHtml.length;

      // Plain-text alternative missing or near-empty (affects all non-HTML clients)
      if (plainText.length < 100 && htmlLen > 500) {
        struct += 1.2;
        oppReasons.push('Plain-Text-Alternative fehlt — kritisch für alle E-Mail-Systeme');
      } else if (plainText.length < 300 && htmlLen > 1500) {
        struct += 0.8;
        oppReasons.push('Plain-Text-Alternative zu kurz — vollständigen Inhalt spiegeln');
      }

      // Image-heavy / image-only body
      if (imgCount >= 2 && plainText.length < 80) {
        struct += 1.0;
        oppReasons.push(`Nur-Bild-E-Mail (${imgCount} Bilder, kaum Text) — Inhalt als HTML-Text ergänzen`);
      } else if (imgCount >= 3 && plainText.length < 300) {
        struct += 0.5;
        oppReasons.push(`Bildübergewicht (${imgCount} Bilder) — Text-Bild-Verhältnis verbessern`);
      }

      // CSS Grid — fully removed by Gmail and classic Outlook; real layout breakage
      const hasGrid = /display\s*:\s*(grid|inline-grid)/i.test(bodyHtml);
      if (hasGrid) {
        struct += 0.6;
        oppReasons.push('CSS Grid — wird von Gmail und klassischem Outlook vollständig entfernt; HTML-Tabellen als primäres Layout verwenden');
      }

      // Flexbox sub-properties — Gmail keeps display:flex but strips align-items,
      // justify-content, flex-direction etc., causing broken layouts
      const hasFlex    = /display\s*:\s*(flex|inline-flex)/i.test(bodyHtml);
      const flexSubRe  = /\b(align-items|justify-content|flex-direction|flex-wrap|flex-grow|flex-shrink|flex-basis|align-self|align-content|flex-flow|order)\s*:/i;
      const hasFlexSub = hasFlex && flexSubRe.test(bodyHtml);
      if (!hasGrid && hasFlexSub) {
        struct += 0.5;
        oppReasons.push('Flexbox-Sub-Properties (align-items, justify-content …) — von Gmail gestripped während display:flex erhalten bleibt; Hybrid-Coding mit Tabellen als primäres Layout empfohlen');
      }

      // display:none — spam filters see hidden content; responsive show/hide pattern
      const displayNoneCount = (bodyHtml.match(/display\s*:\s*none/gi) || []).length;
      if (displayNoneCount >= 5) {
        struct += 0.7;
        oppReasons.push(`${displayNoneCount}× display:none — Spam-Filter sehen versteckte Inhalte`);
      } else if (displayNoneCount >= 2) {
        struct += 0.4;
        oppReasons.push(`${displayNoneCount}× display:none — versteckte Inhalte reduzieren`);
      }

      // Low visible-to-total text ratio (duplicate dark/light-mode content)
      if (visibleText.length > 0 && plainText.length > 800
          && visibleText.length < plainText.length * 0.25) {
        struct += 0.6;
        oppReasons.push('Sichtbarer Text <25% des HTML-Inhalts — responsive Duplikate reduzieren');
      }

      // Excessive inline style attributes (CSS-heavy template bloat)
      const inlineStyleCount = (bodyHtml.match(/\bstyle\s*=/gi) || []).length;
      if (inlineStyleCount > 100) {
        struct += 0.5;
        oppReasons.push(`${inlineStyleCount} inline style-Attribute — Template-Komplexität reduzieren`);
      } else if (inlineStyleCount > 50) {
        struct += 0.3;
        oppReasons.push(`${inlineStyleCount} inline style-Attribute — CSS-Ballast verringern`);
      }

      // Quoted-Printable encoding in HTML (spam filter concern)
      const qpCount = (bodyHtml.match(/=[0-9A-Fa-f]{2}/g) || []).length;
      if (qpCount > 30 && htmlLen > 0 && (qpCount / (htmlLen / 100)) > 1.0) {
        struct += 0.5;
        oppReasons.push(`${qpCount} QP-Sequenzen (=XX) im HTML — auf UTF-8 ohne QP umstellen`);
      }

      // Pervasive white text (spam filter heuristic)
      const whiteCount = (bodyHtml.match(/color\s*:\s*(white|#fff\b|#ffffff)/gi) || []).length;
      if (whiteCount >= 8) {
        struct += 0.4;
        oppReasons.push(`${whiteCount}× color:white — gezielt einsetzen, Filter reagieren darauf`);
      }
    }

    struct = Math.min(3, struct);

    // ── CONTENT (max 1) ───────────────────────────────────────────────────────
    // Word choice, CTA text, salutation — limited impact on deliverability.

    if (bodyHtml) {
      const plainText = this._stripHtml(bodyHtml).replace(/\s+/g, ' ').trim();

      if (/klicken\s*sie\s*hier|click\s*here|jetzt\s*klicken/i.test(plainText)) {
        content += 0.4;
        oppReasons.push('Generischer CTA — konkreter formulieren');
      }
      if (/^(liebe[rs]?\s+leser|sehr\s+geehrte[rs]?\s+(damen|herren)|dear\s+(customer|subscriber))/im.test(plainText)) {
        content += 0.3;
        oppReasons.push('Generische Massen-Anrede — Engagement durch Personalisierung verbessern');
      }
      const exclCount = (plainText.match(/!/g) || []).length;
      if (exclCount > 5) {
        content += 0.3;
        oppReasons.push(`${exclCount} Ausrufezeichen — Ton natürlicher gestalten`);
      }
    }

    content = Math.min(1, content);

    return {
      score:   Math.min(10, Math.round(tech + struct + content)),
      reasons: oppReasons,
    };
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

const VERSION            = '2.2.7';
const WORKER_URL         = 'https://spam-scorer-ai.felber.workers.dev';

let signalExplanations      = {};   // signal text → explanation (populated by prefetch)
let explanationBatchPromise = null; // resolves when batch fetch completes
let explanationGeneration   = 0;   // incremented on each new email to discard stale batch results
const AUTHORIZED_ACCOUNT = 'felber@live.de';
const SAVE_TOKEN = 'XWqnAysvnXKpA6VAnOt6llM3OqHSq6J4HERW-xrwtWE';

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
let isAuthorizedAccount      = false;
let currentScore             = null;
let currentOpportunityScore  = null;
let lastHeaders              = '';
let lastBodyHtml             = '';   // raw HTML — for originalsrc extraction sent to worker
let lastBodyText             = '';   // cleaned plain text — for copy button
let lastHiddenText           = '';   // text extracted from hidden elements
let lastAnalysis             = null; // { score, reasons, hiddenText, opportunityScore, … }
let lastClaudeResult         = null;
let lastAdviceResult         = null;
let lastAnschreibenHtml      = null;
let lastActionPlanHtml       = null;
let lastDnsResult            = null;

// ─── Office init ───────────────────────────────────────────────────────────────

Office.onReady(info => {
  if (info.host !== Office.HostType.Outlook) return;

  UI_LANG = detectUiLang();

  const userEmail = (Office.context.mailbox?.userProfile?.emailAddress || '').toLowerCase();
  isAuthorizedAccount = userEmail === AUTHORIZED_ACCOUNT;

  document.getElementById('btn-retry').addEventListener('click', analyzeCurrentItem);
  document.getElementById('btn-copy-headers').addEventListener('click', () => copyToClipboard(lastHeaders, 'Header kopiert'));
  document.getElementById('btn-copy-body').addEventListener('click',    () => copyToClipboard(lastBodyText, 'Body-Text kopiert'));
  document.getElementById('btn-claude').addEventListener('click', runClaudeCheck);
  document.getElementById('btn-detail').addEventListener('click', toggleDetailPanel);
  document.getElementById('btn-toggle-hidden').addEventListener('click', toggleHiddenText);
  document.getElementById('btn-advice').addEventListener('click', async () => {
    await runAdviceCheck();
    document.getElementById('advice-result')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
  document.getElementById('btn-delivery-report').addEventListener('click', downloadDeliverabilityReport);
  document.getElementById('btn-action-plan').addEventListener('click', () => generateArtifact('action-plan'));
  document.getElementById('btn-anschreiben').addEventListener('click', () => generateArtifact('anschreiben'));
  document.getElementById('btn-compliance-b2b')?.addEventListener('click', () => generateComplianceReport('b2b'));
  document.getElementById('btn-compliance-b2c')?.addEventListener('click', () => generateComplianceReport('b2c'));
  document.getElementById('btn-zip').addEventListener('click', downloadAssessmentZip);

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
  currentScore            = null;
  currentOpportunityScore = null;
  lastAnalysis            = null;
  lastHiddenText          = '';
  lastDnsResult           = null;
  lastAnschreibenHtml     = null;
  lastActionPlanHtml      = null;

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
    const result            = analyzer.analyze(headers, bodyHtml, subject, senderEmail);
    currentScore            = result.score;
    currentOpportunityScore = result.opportunityScore ?? 0;
    lastAnalysis            = result;
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
  // ── Score 1: spam verdict ────────────────────────────────────────────────
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

  // ── Score 2: improvement potential (rendered always; visibility toggled later)
  const oppNum    = document.getElementById('opp-number');
  const oppBar    = document.getElementById('opp-bar-fill');
  const oppWrap   = document.getElementById('opp-wrap');
  const oppVerdict = document.getElementById('opp-verdict');
  const oppScore  = result.opportunityScore ?? 0;

  if (oppNum && oppBar && oppWrap && oppVerdict) {
    oppNum.textContent  = oppScore;
    oppBar.style.width  = `${oppScore * 10}%`;
    const oLvl          = oppLevel(oppScore);
    // Preserve .hidden class — applyAccountVisibility() controls visibility
    const wasHidden     = oppWrap.classList.contains('hidden');
    oppWrap.className   = `opp-wrap opp-${oLvl}${wasHidden ? ' hidden' : ''}`;
    oppBar.className    = `score-bar-fill opp-${oLvl}`;
    oppVerdict.textContent = oppVerdictText(oppScore);
    oppBar.setAttribute('aria-valuenow', oppScore);
  }

  // Potenzial-Indikatoren
  const oppReasonsList = document.getElementById('opp-reasons-list');
  if (oppReasonsList) {
    oppReasonsList.innerHTML = '';
    const oppReasonsData = result.opportunityReasons ?? [];
    if (oppReasonsData.length === 0) {
      const li = document.createElement('li');
      li.className   = 'reason-ok';
      li.textContent = 'Keine Optimierungspotenziale erkannt';
      oppReasonsList.appendChild(li);
    } else {
      oppReasonsData.forEach(r => oppReasonsList.appendChild(createSignalLi(r)));
    }
  }

  const list = document.getElementById('reasons-list');
  list.innerHTML = '';
  if (result.reasons.length === 0) {
    const li = document.createElement('li');
    li.className   = 'reason-ok';
    li.textContent = 'Keine Spam-Indikatoren gefunden';
    list.appendChild(li);
  } else {
    result.reasons.forEach(r => list.appendChild(createSignalLi(r)));
  }

  // Hidden text expander — show only when content was found
  const htSection = document.getElementById('hidden-text-section');
  if (result.hiddenText) {
    document.getElementById('hidden-text-content').textContent = result.hiddenText;
    htSection.classList.remove('hidden');
  } else {
    htSection.classList.add('hidden');
  }

  renderDetailPanel(headers);

  applyAccountVisibility();

  // Prefetch all signal explanations in the background — ℹ buttons show instantly once loaded
  const allSignals = [...(result.reasons || []), ...(result.opportunityReasons || [])];
  explanationBatchPromise = prefetchExplanations(allSignals);
}

// ── Signal explain ────────────────────────────────────────────────────────────

function createSignalLi(text) {
  const li      = document.createElement('li');
  const body    = document.createElement('div');
  body.className = 'signal-body';

  const row     = document.createElement('div');
  row.className = 'signal-row';

  const span    = document.createElement('span');
  span.textContent = text;

  const btn     = document.createElement('button');
  btn.className = 'btn-explain';
  btn.title     = 'Erklärung anzeigen';
  btn.setAttribute('aria-label', 'Signal erklären');
  btn.textContent = 'i';

  const expDiv  = document.createElement('div');
  expDiv.className = 'signal-explanation hidden';

  row.appendChild(span);
  row.appendChild(btn);
  body.appendChild(row);
  body.appendChild(expDiv);
  li.appendChild(body);

  btn.addEventListener('click', () => explainSignal(text, btn, expDiv));
  return li;
}

async function explainSignal(signal, btn, expDiv) {
  // Toggle already-loaded explanation
  if (expDiv.dataset.loaded) {
    expDiv.classList.toggle('hidden');
    return;
  }

  // Cache hit — show instantly
  if (signalExplanations[signal]) {
    expDiv.className      = 'signal-explanation';
    expDiv.textContent    = signalExplanations[signal];
    expDiv.dataset.loaded = '1';
    return;
  }

  btn.setAttribute('aria-busy', 'true');
  expDiv.className  = 'signal-explanation loading';
  expDiv.textContent = 'Lade Erklärung …';

  try {
    // Wait for batch, then recheck cache
    await explanationBatchPromise;

    if (signalExplanations[signal]) {
      expDiv.className      = 'signal-explanation';
      expDiv.textContent    = signalExplanations[signal];
      expDiv.dataset.loaded = '1';
      return;
    }

    // Batch missed this signal — individual fallback call
    const res  = await fetch(WORKER_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ mode: 'explain', signal }),
    });
    const data = await res.json();
    const text = data.explanation || data.error || 'Keine Erklärung verfügbar.';
    expDiv.className      = 'signal-explanation';
    expDiv.textContent    = text;
    expDiv.dataset.loaded = '1';
    if (data.explanation) signalExplanations[signal] = text;
  } catch (err) {
    expDiv.className  = 'signal-explanation';
    expDiv.textContent = `Fehler: ${err.message}`;
  } finally {
    btn.removeAttribute('aria-busy');
  }
}

async function prefetchExplanations(signals) {
  if (!signals.length) return;
  const gen         = ++explanationGeneration;
  signalExplanations = {};
  try {
    const res  = await fetch(WORKER_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ mode: 'explain-batch', signals }),
    });
    const data = await res.json();
    // Discard result if a newer email was opened while this was in flight
    if (gen === explanationGeneration && data.explanations) {
      Object.assign(signalExplanations, data.explanations);
    }
  } catch { /* fail silently — individual fallback in explainSignal handles it */ }
}

function applyAccountVisibility() {
  document.getElementById('artifacts-section')?.classList.toggle('hidden', !isAuthorizedAccount);
  document.getElementById('export-section')?.classList.toggle('hidden',    isAuthorizedAccount);
  // Score 2 widget visible only for the authorized account
  document.getElementById('opp-wrap')?.classList.toggle('hidden',            !isAuthorizedAccount);
  document.getElementById('opp-reasons-section')?.classList.toggle('hidden', !isAuthorizedAccount);
  // Compact number font when both score boxes are shown side-by-side
  document.getElementById('scores-area')?.classList.toggle('dual',         isAuthorizedAccount);
}

function buildAuthBadges(headers) {
  const none = { html: '', allPass: false };
  if (!headers) return none;

  const authLine = headers.match(/^Authentication-Results:(.+(?:\r?\n[ \t].+)*)/im)
                || headers.match(/^ARC-Authentication-Results:(.+(?:\r?\n[ \t].+)*)/im);
  if (!authLine) return none;

  const str = authLine[1];

  // ── Header helpers (needed early for DKIM alignment) ──────────────────────
  const hdr = name => {
    const re = new RegExp(`^${name}:\\s*(.+(?:\\r?\\n[ \\t].+)*)`, 'im');
    const m  = headers.match(re);
    return m ? m[1].replace(/\r?\n[ \t]+/g, ' ').trim() : '';
  };
  const dom    = s => { const m = s.match(/@([\w.-]+)/); return m ? m[1].toLowerCase() : null; };
  const orgDom = d => { const p = d.split('.'); return p.length >= 2 ? p.slice(-2).join('.') : d; };

  const fromDomain = dom(hdr('From'));

  // ── SPF / DKIM / DMARC results ────────────────────────────────────────────
  const checks = [
    { label: 'SPF',   re: /spf=(pass|fail|softfail|neutral|none)/i },
    { label: 'DKIM',  re: /dkim=(pass|fail|none)/i },
    { label: 'DMARC', re: /dmarc=(pass|fail|none|bestguesspass)/i },
  ];
  const results = checks.map(({ label, re }) => {
    const m = str.match(re);
    return { label, val: m ? m[1].toLowerCase() : null };
  });

  // ── DKIM alignment: signing domain (from auth-results) vs From domain ─────
  // Relaxed alignment: same organisational domain (last 2 labels).
  // If ANY dkim=pass segment aligns → aligned. Flag only when all signing
  // domains are foreign to the From domain.
  const dkimPassed = results.find(r => r.label === 'DKIM')?.val === 'pass';
  let dkimAligned       = true;  // default: no issue if undetermined
  let dkimMismatchDomain = null; // first misaligned signing domain for the badge

  if (dkimPassed && fromDomain) {
    const signingDomains = [];
    const segRe = /dkim=pass[^;]*/gi;
    let seg;
    while ((seg = segRe.exec(str)) !== null) {
      const dm = seg[0].match(/header\.d=([\w.-]+)/i)
              || seg[0].match(/header\.i=(?:[^@;\s]*@)?([\w.-]+)/i);
      if (dm) signingDomains.push(dm[1].toLowerCase());
    }
    if (signingDomains.length > 0) {
      dkimAligned = signingDomains.some(d => orgDom(d) === orgDom(fromDomain));
      if (!dkimAligned) dkimMismatchDomain = signingDomains[0];
    }
  }

  // ── Build badge row ────────────────────────────────────────────────────────
  // DKIM alignment is merged into the DKIM badge itself — no separate badge.
  const badgesHtml = results.map(({ label, val }) => {
    if (!val) return `<span class="auth-badge auth-none">${label} —</span>`;
    let cls = val === 'pass'     ? 'auth-pass'
            : val === 'softfail' ? 'auth-softfail'
            : val === 'fail'     ? 'auth-fail'
            :                     'auth-warn';
    let displayLabel = `${label} ${val.toUpperCase()}`;
    // When DKIM passes but signing domain doesn't align to From domain, downgrade badge
    if (label === 'DKIM' && dkimPassed && fromDomain && !dkimAligned) {
      cls = 'auth-softfail';
      displayLabel = `DKIM PASS ⚠ (${escapeHtml(dkimMismatchDomain || '?')})`;
    }
    return `<span class="auth-badge ${cls}">${displayLabel}</span>`;
  }).join('');

  // allPass: SPF + DKIM + DKIM-Align + DMARC all pass
  const allPass = results.every(r => r.val === 'pass') && dkimAligned;

  // ── Domain-path alignment table (only when there are mismatches worth showing) ──
  const returnPathDomain = dom(hdr('Return-Path'));
  const replyToDomain    = dom(hdr('Reply-To'));
  const dkimSigDomain    = (hdr('DKIM-Signature').match(/\bd=([\w.-]+)/i) || [])[1]?.toLowerCase() ?? null;

  const rows = [
    { label: 'Von (From)',  domain: fromDomain,       ref: true  },
    { label: 'Return-Path', domain: returnPathDomain, ref: false },
    { label: 'DKIM d=',     domain: dkimSigDomain,    ref: false },
    { label: 'Reply-To',    domain: replyToDomain,    ref: false },
  ].filter(r => r.domain);

  let alignHtml = '';
  const hasMismatch = rows.some(r => !r.ref && r.domain !== fromDomain);
  if (rows.length > 1 && hasMismatch) {
    const rowsHtml = rows.map(r => {
      if (r.ref) return `<tr><td class="ap-label">Von (From)</td><td class="ap-domain">${escapeHtml(r.domain)}</td><td class="ap-icon ap-ref">—</td></tr>`;
      const ok = r.domain === fromDomain;
      return `<tr class="${ok ? 'ap-ok' : 'ap-warn'}">
        <td class="ap-label">${r.label}</td>
        <td class="ap-domain">${escapeHtml(r.domain)}</td>
        <td class="ap-icon">${ok ? '✓' : '⚠'}</td>
      </tr>`;
    }).join('');
    alignHtml = `<table class="auth-paths">${rowsHtml}</table>`;
  }

  return { html: badgesHtml + alignHtml, allPass };
}

// ─── Header-Details panel ─────────────────────────────────────────────────────

const DETAIL_LS_KEY = 'spam-scorer:detail-open';

function renderDetailPanel(headers) {
  const hdr = name => {
    if (!headers) return null;
    const m = headers.match(new RegExp(`^${name}:\\s*(.+(?:\\r?\\n[ \\t].+)*)`, 'im'));
    return m ? m[1].replace(/\r?\n[ \t]+/g, ' ').trim() : null;
  };

  // ── Auth ──────────────────────────────────────────────────────────────────
  const auth = buildAuthBadges(headers);

  // ── MS spam indicators ────────────────────────────────────────────────────
  const sclRaw  = hdr('X-MS-Exchange-Organization-SCL');
  const scl     = sclRaw !== null ? parseInt(sclRaw, 10) : null;
  const antispam = hdr('X-Microsoft-Antispam') || '';
  const bclM    = antispam.match(/BCL:(\d+)/i);
  const bcl     = bclM ? parseInt(bclM[1], 10) : null;
  const delivery = hdr('X-Microsoft-Antispam-Mailbox-Delivery') || '';
  const destM   = delivery.match(/dest:([A-Z]+)/i);
  const dest    = destM ? destM[1].toUpperCase() : null;
  const forefront = hdr('X-Forefront-Antispam-Report') || '';
  const ff = k => { const m = forefront.match(new RegExp(`(?:^|;)\\s*${k}:([^;]+)`, 'i')); return m ? m[1].trim() : null; };
  const sfv = ff('SFV');
  const cat = ff('CAT');

  const hasMsData = scl !== null || bcl !== null || dest || sfv;

  // ── Build peek summary (shown in closed state) ────────────────────────────
  const peekParts = [];

  // Auth peek — derive icons from auth.allPass + DKIM align
  if (headers) {
    const authLine = headers.match(/^Authentication-Results:(.+(?:\r?\n[ \t].+)*)/im)
                  || headers.match(/^ARC-Authentication-Results:(.+(?:\r?\n[ \t].+)*)/im);
    if (authLine) {
      const str = authLine[1];
      [
        { label: 'SPF',   re: /spf=(pass|fail|softfail|neutral|none)/i },
        { label: 'DKIM',  re: /dkim=(pass|fail|none)/i },
        { label: 'DMARC', re: /dmarc=(pass|fail|none|bestguesspass)/i },
      ].forEach(({ label, re }) => {
        const m   = str.match(re);
        const val = m ? m[1].toLowerCase() : null;
        const icon = !val ? '?' : val === 'pass' ? '✓' : '✗';
        peekParts.push(`${label} ${icon}`);
      });
      // Alignment is merged into the DKIM badge — no separate Align entry in peek
    }
  }

  // MS peek
  if (scl !== null) peekParts.push(`SCL ${scl}`);
  if (bcl !== null && bcl > 0) peekParts.push(`BCL ${bcl}`);
  if (dest) peekParts.push(dest === 'I' ? 'Inbox' : dest === 'J' ? '⚠ Junk' : dest);
  if (sfv && sfv !== 'NSPM') peekParts.push(`SFV:${sfv}`);

  document.getElementById('det-peek').textContent = peekParts.length
    ? peekParts.join('  ·  ')
    : 'Header-Details';

  // ── Auth group ────────────────────────────────────────────────────────────
  const detAuth = document.getElementById('det-auth');
  detAuth.innerHTML = auth.html
    ? `<div class="det-group-label">Authentifizierung</div>
       <div class="det-auth-row auth-summary">${auth.html}</div>`
    : '';

  // ── MS spam group ─────────────────────────────────────────────────────────
  const detMs = document.getElementById('det-ms');
  if (!hasMsData) {
    detMs.innerHTML = '';
  } else {
    // ms(key, label, cls, shortTip, longTip?)
    // longTip triggers an i-button; shortTip goes on the badge title
    const ms = (key, label, cls, shortTip, longTip) => {
      const infoBtn = longTip
        ? `<button class="det-ms-info" data-tip="${escapeHtml(longTip)}" aria-label="${key} erklären">i</button><span class="det-ms-tip hidden"></span>`
        : '';
      return `<div class="det-ms-row">
        <span class="det-ms-key">${key}</span>
        <div class="det-ms-val-row">
          <span class="det-ms-val det-ms-${cls}" title="${escapeHtml(shortTip)}">${escapeHtml(label)}</span>
          ${infoBtn}
        </div>
      </div>`;
    };

    const sclCls   = scl === null ? 'none' : scl <= 1 ? 'ok' : scl <= 4 ? 'warn' : 'bad';
    const sclLabel = scl === null ? '–' : scl === -1 ? '–1 Intern' : scl <= 1 ? `${scl} Kein Spam` : scl <= 4 ? `${scl} Gering` : scl <= 6 ? `${scl} Junk` : `${scl} Hohe Konfidenz`;
    const sclShort = scl === null ? '' : scl <= 1 ? 'Microsoft hält E-Mail für legitim' : scl <= 4 ? 'Leicht erhöhter Verdacht' : scl <= 6 ? '→ Junk-Ordner' : 'Hohe Spam-Konfidenz';
    const sclLong  = 'Spam Confidence Level (0–9): Microsofts eigene Spam-Bewertung beim Empfang. −1 = interne/vertrauenswürdige Quelle. 0–1 = kein Spam. 2–4 = leicht erhöht, trotzdem Posteingang. 5–6 = Junk-Ordner. 7–9 = hohe Konfidenz, kann direkt gelöscht werden.';

    const bclCls   = bcl === null ? 'none' : bcl === 0 ? 'ok' : bcl <= 3 ? 'warn' : 'bad';
    const bclLabel = bcl === null ? '–' : bcl === 0 ? '0 Kein Bulk' : bcl <= 3 ? `${bcl} Gering` : bcl <= 6 ? `${bcl} Mittel` : `${bcl} Hoch`;
    const bclShort = bcl === null ? '' : bcl === 0 ? 'Keine Bulk-Beschwerden' : bcl <= 3 ? 'Wenige Beschwerden' : bcl <= 6 ? 'Erhöhte Beschwerderate' : 'Hohe Beschwerderate';
    const bclLong  = 'Bulk Complaint Level (0–9): Wie viele Empfänger ähnliche E-Mails dieses Absenders als Spam markiert haben. 0 = keine bekannten Beschwerden. 1–3 = wenige Beschwerden, meist unkritisch. 4–7 = erhöhte Beschwerderate, Junk-Risiko steigt spürbar. 8–9 = hohe Beschwerderate, starker Reputationsnachteil.';

    const destCls   = !dest ? 'none' : dest === 'I' ? 'ok' : dest === 'J' ? 'bad' : 'warn';
    const destLabel = !dest ? '–' : dest === 'I' ? 'I Posteingang' : dest === 'J' ? 'J Junk' : dest === 'D' ? 'D Gelöscht' : dest;
    const destShort = !dest ? '' : dest === 'I' ? 'Exchange → Posteingang' : dest === 'J' ? 'Exchange → Junk-Ordner' : dest === 'D' ? 'Exchange → Gelöscht' : '';

    const sfvMap = { NSPM:'Kein Spam', SPM:'Spam', SKN:'Safe Sender', SFE:'Allowlist', BLK:'Blockiert', SKS:'Geblockt', SKB:'Blockierter Abs.' };
    const sfvCls = !sfv ? 'none' : /^NSPM|SKN|SFE/i.test(sfv) ? 'ok' : /^SPM|SKS|BLK|SKB/i.test(sfv) ? 'bad' : 'warn';
    const sfvLabel = !sfv ? '–' : (sfvMap[sfv.toUpperCase()] || sfv);
    const sfvShort = !sfv ? '' : `Spamfilter-Urteil: ${sfv}`;

    const catMap = { NSPM:'Kein Spam', SPAM:'Spam', PHSH:'Phishing', MALW:'Malware', BULK:'Bulk', HPHSH:'Phishing' };
    const catCls = !cat ? 'none' : /NSPM/i.test(cat) ? 'ok' : /SPAM|PHSH|MALW/i.test(cat) ? 'bad' : 'warn';
    const catLabel = cat ? (catMap[cat.toUpperCase()] || cat) : null;

    const rows = [
      scl !== null && ms('SCL', sclLabel, sclCls, sclShort, sclLong),
      bcl !== null && ms('BCL', bclLabel, bclCls, bclShort, bclLong),
      dest          && ms('Zustellung', destLabel, destCls, destShort, null),
      sfv           && ms('SFV', sfvLabel, sfvCls, sfvShort, null),
      catLabel      && ms('Kategorie', catLabel, catCls, `Exchange-Kategorie: ${catLabel}`, null),
    ].filter(Boolean).join('');

    detMs.innerHTML = `<div class="det-group-label">Microsoft Spamfilter</div>
      <div class="det-ms-grid">${rows}</div>`;

    // Wire up i-buttons (event delegation avoids inline onclick — CSP safe)
    detMs.querySelectorAll('.det-ms-info').forEach(btn => {
      btn.addEventListener('click', () => {
        const tip = btn.nextElementSibling;
        if (!tip) return;
        const isOpen = !tip.classList.contains('hidden');
        tip.textContent = btn.dataset.tip;
        tip.classList.toggle('hidden', isOpen);
      });
    });
  }

  // ── Restore expander state from localStorage ──────────────────────────────
  const savedOpen = localStorage.getItem(DETAIL_LS_KEY) === 'true';
  const btn   = document.getElementById('btn-detail');
  const panel = document.getElementById('detail-panel');
  btn.setAttribute('aria-expanded', String(savedOpen));
  panel.classList.toggle('hidden', !savedOpen);
}

function toggleDetailPanel() {
  const btn   = document.getElementById('btn-detail');
  const panel = document.getElementById('detail-panel');
  const open  = btn.getAttribute('aria-expanded') !== 'true';
  btn.setAttribute('aria-expanded', String(open));
  panel.classList.toggle('hidden', !open);
  localStorage.setItem(DETAIL_LS_KEY, String(open));
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

// Score 2 helpers
function oppLevel(score) {
  if (score <= 2) return 'minimal';
  if (score <= 5) return 'moderate';
  if (score <= 7) return 'good';
  return 'excellent';
}

function oppVerdictText(score) {
  if (score <= 1)  return 'Kein Potenzial';
  if (score <= 2)  return 'Geringes Potenzial';
  if (score <= 4)  return 'Moderates Potenzial';
  if (score <= 6)  return 'Gutes Potenzial';
  if (score <= 8)  return 'Hohes Potenzial';
  return 'Sehr hohes Potenzial';
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

  // LLM-Prompt below advice-result (authorized account only)
  const promptContainer = document.getElementById('llm-prompt-container');
  if (promptContainer && isAuthorizedAccount) {
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

  // Serve from cache — avoids a second Sonnet call for the same email
  const cached = mode === 'action-plan' ? lastActionPlanHtml : lastAnschreibenHtml;
  if (cached) {
    const date     = new Date().toISOString().slice(0, 10);
    const domain   = (senderEmail.match(/@([\w.-]+)/) || [])[1] || 'sender';
    const filename = mode === 'action-plan'
      ? `${domain}-Aktionsplan-${date}.html`
      : `${domain}-Anschreiben-${date}.html`;
    const blob = new Blob([cached], { type: 'text/html;charset=utf-8' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
    showToast(`${filename} wird heruntergeladen…`, false);
    return;
  }

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

    const html = data.html || '';
    if (!html || !html.includes('<')) throw new Error('Generierung fehlgeschlagen — leere Antwort vom Modell. Bitte erneut versuchen.');
    if (mode === 'action-plan') lastActionPlanHtml = html; else lastAnschreibenHtml = html;
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

    saveReportToDb({
      domain,
      sender:     senderEmail,
      subject,
      emailDate:  date,
      addinScore: currentScore,
      aiScore:    lastClaudeResult?.score ?? null,
      esp:        lastClaudeResult?.esp   ?? null,
      type:       mode === 'action-plan' ? 'aktionsplan' : 'anschreiben',
      html,
    });
  } catch (err) {
    showToast(`⚠ ${err.message}`, true);
  } finally {
    btn.disabled    = false;
    btn.textContent = origLabel;
  }
}

// ─── Assessment ZIP export ─────────────────────────────────────────────────────

async function downloadAssessmentZip() {
  const btn       = document.getElementById('btn-zip');
  const origLabel = btn.textContent;
  btn.disabled    = true;
  btn.textContent = 'Erstelle ZIP…';

  try {
    const item        = Office.context.mailbox.item;
    const senderEmail = item?.from?.emailAddress || 'sender';
    const subject     = item?.subject || '';
    const date        = new Date().toISOString().slice(0, 10);
    const domain      = (senderEmail.match(/@([\w.-]+)/) || [])[1] || 'sender';

    const zip = new JSZip(); // eslint-disable-line no-undef

    // 1. Raw source: headers + body
    const sourceText = lastHeaders
      + '\n\n=== BODY ===\n\n'
      + lastBodyText;
    zip.file(`${domain}-source-${date}.txt`, sourceText);

    // 2. Add-in assessment
    const addinLines = [
      `Spam Scorer v${VERSION} — Add-in Assessment`,
      `Datum   : ${new Date().toLocaleString('de-DE')}`,
      `Betreff : ${subject}`,
      `Absender: ${senderEmail}`,
      '',
      `Score  : ${currentScore}/10 — ${verdictText(currentScore)}`,
      '',
      '=== Spam-Indikatoren ===',
      ...(lastAnalysis?.reasons?.length
        ? lastAnalysis.reasons.map(r => `  • ${r}`)
        : ['  (keine)']),
      '',
      '=== Zustellbarkeits-Hinweise ===',
      ...(lastAnalysis?.deliverabilityNotes?.length
        ? lastAnalysis.deliverabilityNotes.map(r => `  • ${r}`)
        : ['  (keine)']),
    ];
    zip.file(`${domain}-addin-assessment-${date}.txt`, addinLines.join('\n'));

    // 3. AI assessment (only if Claude was already run)
    if (lastClaudeResult) {
      const aiLines = [
        `Spam Scorer v${VERSION} — AI Assessment`,
        `Datum   : ${new Date().toLocaleString('de-DE')}`,
        '',
        `Verdict   : ${lastClaudeResult.verdict || '?'}`,
        `Konfidenz : ${lastClaudeResult.confidence ?? '—'}%`,
        `Score     : ${lastClaudeResult.score ?? '—'}/10`,
        '',
        '=== Signale ===',
        ...(lastClaudeResult.signals?.length
          ? lastClaudeResult.signals.map(s => `  • ${s}`)
          : ['  (keine)']),
        '',
        '=== Zusammenfassung ===',
        lastClaudeResult.summary || '(keine)',
      ];
      zip.file(`${domain}-ai-assessment-${date}.txt`, aiLines.join('\n'));
    }

    const blob     = await zip.generateAsync({ type: 'blob', compression: 'DEFLATE' });
    const url      = URL.createObjectURL(blob);
    const filename = `${domain}-Assessment-${date}.zip`;
    const a        = document.createElement('a');
    a.href         = url;
    a.download     = filename;
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

/* Microsoft spam indicators */
.ms-spam-table td.ms-explain { color: #64748b; font-size: 12px; padding-left: 12px; }
.ms-val { display: inline-block; padding: 2px 10px; border-radius: 20px; font-size: 12px; font-weight: 600; border: 1px solid transparent; }
.ms-ok         { background: #dcfce7; color: #166534; border-color: #86efac; }
.ms-warn-light { background: #fef9c3; color: #854d0e; border-color: #fde047; }
.ms-warn       { background: #fff7ed; color: #9a3412; border-color: #fdba74; }
.ms-bad        { background: #fee2e2; color: #991b1b; border-color: #fca5a5; }
.ms-neutral    { background: #f1f5f9; color: #475569; border-color: #cbd5e1; }

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

/* DNS table */
.rpt-warn { color: #dc2626; font-size: 13px; }
.rpt-dns-type { display: inline-block; font-size: 10px; font-weight: 700; background: #e0e7ff; color: #3730a3; border-radius: 3px; padding: 1px 5px; margin-right: 5px; vertical-align: middle; }
.meta-table code { font-family: 'Cascadia Code','Consolas','Menlo',monospace; font-size: 12px; word-break: break-all; }

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

/** Fetch SPF / DMARC / DKIM via the worker DNS mode (cached per email) */
async function fetchDnsData(senderEmail, headers) {
  if (lastDnsResult) return lastDnsResult;
  const domain = (senderEmail.match(/@([\w.-]+)/) || [])[1];
  if (!domain) return null;

  // Extract DKIM selector(s) from DKIM-Signature headers
  const dkimSelectors = [];
  const selRe = /^DKIM-Signature:.*?(?:\r?\n[ \t].+)*\bs=([^;\s]+)/gim;
  let m;
  while ((m = selRe.exec(headers)) !== null) dkimSelectors.push(m[1]);

  try {
    const res = await fetch(WORKER_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ mode: 'dns', domain, dkimSelectors }),
    });
    if (!res.ok) return null;
    const data = await res.json();
    lastDnsResult = data;
    return data;
  } catch { return null; }
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

    btn.textContent = 'DNS lookup…';

    const item        = Office.context.mailbox.item;
    const subject     = item?.subject            || '';
    const senderEmail = item?.from?.emailAddress || '';
    const senderName  = item?.from?.displayName  || '';

    const dnsResult = await fetchDnsData(senderEmail, lastHeaders);

    btn.textContent = 'Erstelle Report…';

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
      dnsResult,
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

    // Auto-save to D1 (fire-and-forget; failure is silent)
    saveReportToDb({
      domain,
      sender:     senderEmail,
      subject,
      emailDate:  new Date().toISOString().slice(0, 10),
      addinScore: currentScore,
      aiScore:    lastClaudeResult?.score ?? null,
      esp:        lastClaudeResult?.esp   ?? null,
      type:       'report',
      html,
    });
  } finally {
    btn.disabled    = false;
    btn.textContent = '📄 Report';
  }
}

async function saveReportToDb({ domain, sender, subject, emailDate, addinScore, aiScore, esp, type, html }) {
  try {
    const res = await fetch(WORKER_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'save', saveToken: SAVE_TOKEN, domain, sender, subject, emailDate, addinScore, aiScore, esp, type, html }),
    });
    const data = await res.json();
    if (data.ok) showToast('In Datenbank gespeichert ✓', false);
  } catch {
    // silent — download already succeeded
  }
}

// ─── Compliance assessment (B2B / B2C) ─────────────────────────────────────────

async function generateComplianceReport(audience) {
  const btn       = document.getElementById(`btn-compliance-${audience}`);
  const origLabel = btn?.textContent || '';
  if (!btn) return;

  const senderEmail = Office.context.mailbox.item?.from?.emailAddress || '';
  const domain      = (senderEmail.match(/@([\w.-]+)/) || [])[1];
  if (!domain) {
    showToast('⚠ Keine Absender-Domain erkannt', true);
    return;
  }

  btn.disabled    = true;
  btn.textContent = 'Prüfe…';

  try {
    const res = await fetch(WORKER_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ mode: 'compliance', audience, domain }),
    });
    if (!res.ok) throw new Error(`Worker-Fehler ${res.status}`);
    const data = await res.json();
    const html = data.html || '';
    if (!html) throw new Error('Leere Antwort vom Worker');

    const date     = new Date().toISOString().slice(0, 10);
    const filename = `${domain}-Compliance-${audience.toUpperCase()}-${date}.html`;
    const blob     = new Blob([html], { type: 'text/html;charset=utf-8' });
    const url      = URL.createObjectURL(blob);
    const a        = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
    showToast(`${filename} wird heruntergeladen…`, false);

    saveReportToDb({
      domain,
      sender:    senderEmail,
      subject:   `Compliance-Assessment ${audience.toUpperCase()}`,
      emailDate: date,
      type:      `compliance-${audience}`,
      html,
    });
  } catch (err) {
    showToast(`⚠ ${err.message}`, true);
  } finally {
    btn.disabled    = false;
    btn.textContent = origLabel;
  }
}

/** Assemble the full HTML document */
function buildDeliverabilityHtml({ subject, senderEmail, senderName, addinScore, addinSignals, claudeResult, adviceResult, headers, hiddenText, dnsResult, reportNum }) {
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

  ${rMsSpamSection(headers)}

  ${rDnsSection(dnsResult)}

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

function rDnsSection(dns) {
  if (!dns) return '';

  const trunc = (s, n = 120) => s && s.length > n ? escR(s.slice(0, n)) + '<span style="color:#94a3b8">…</span>' : escR(s || '');

  const spfRow = dns.spf?.found
    ? `<tr><th>SPF</th><td><code>${trunc(dns.spf.record)}</code></td></tr>`
    : `<tr><th>SPF</th><td class="rpt-warn">kein Eintrag gefunden</td></tr>`;

  const dmarcRow = dns.dmarc?.found
    ? `<tr><th>DMARC</th><td><code>${trunc(dns.dmarc.record)}</code></td></tr>`
    : `<tr><th>DMARC</th><td class="rpt-warn">kein Eintrag gefunden</td></tr>`;

  const dkimRows = (dns.dkim || []).length
    ? (dns.dkim || []).map(d =>
        `<tr><th>DKIM <span style="font-weight:400;color:#64748b">${escR(d.selector)}</span></th>` +
        `<td><span class="rpt-dns-type">${escR(d.type)}</span> <code>${trunc(d.record, 100)}</code></td></tr>`
      ).join('')
    : `<tr><th>DKIM</th><td class="rpt-warn">keine bekannten Selektoren gefunden</td></tr>`;

  return `<section class="rpt-section">
    <h2>DNS-Konfiguration</h2>
    <table class="meta-table">
      ${spfRow}
      ${dmarcRow}
      ${dkimRows}
    </table>
  </section>`;
}

function rAuthSection(headers) {
  if (!headers) return '';
  const authLine = headers.match(/^Authentication-Results:(.+(?:\r?\n[ \t].+)*)/im)
                || headers.match(/^ARC-Authentication-Results:(.+(?:\r?\n[ \t].+)*)/im);
  if (!authLine) return '';

  const str = authLine[1];

  // DKIM alignment
  const hdr = name => {
    const re = new RegExp(`^${name}:\\s*(.+(?:\\r?\\n[ \\t].+)*)`, 'im');
    const m  = headers.match(re);
    return m ? m[1].replace(/\r?\n[ \t]+/g, ' ').trim() : '';
  };
  const dom    = s => { const m = s.match(/@([\w.-]+)/); return m ? m[1].toLowerCase() : null; };
  const orgDom = d => { const p = d.split('.'); return p.length >= 2 ? p.slice(-2).join('.') : d; };
  const fromDomain = dom(hdr('From'));

  let dkimAligned        = true;
  let dkimMismatchDomain = null;
  if (/dkim=pass/i.test(str) && fromDomain) {
    const signingDomains = [];
    const segRe = /dkim=pass[^;]*/gi;
    let seg;
    while ((seg = segRe.exec(str)) !== null) {
      const dm = seg[0].match(/header\.d=([\w.-]+)/i)
              || seg[0].match(/header\.i=(?:[^@;\s]*@)?([\w.-]+)/i);
      if (dm) signingDomains.push(dm[1].toLowerCase());
    }
    if (signingDomains.length > 0) {
      dkimAligned = signingDomains.some(d => orgDom(d) === orgDom(fromDomain));
      if (!dkimAligned) dkimMismatchDomain = signingDomains[0];
    }
  }

  const checks = [
    { label: 'SPF',      re: /spf=(pass|fail|softfail|neutral|none)/i },
    { label: 'DKIM',     re: /dkim=(pass|fail|none)/i },
    { label: 'DMARC',    re: /dmarc=(pass|fail|none|bestguesspass)/i },
    { label: 'compauth', re: /compauth=(pass|fail|softpass)/i },
  ];

  const badgesHtml = checks.map(({ label, re }) => {
    const m   = str.match(re);
    const val = m ? m[1].toLowerCase() : null;
    const cls = !val               ? 'auth-none'
              : val === 'pass'     ? 'auth-pass'
              : val === 'softfail' ? 'auth-softfail'
              : val === 'fail'     ? 'auth-fail'
              :                     'auth-warn';
    let badgeCls   = cls;
    let badgeLabel = `${label} ${val ? val.toUpperCase() : '—'}`;
    if (label === 'DKIM' && val === 'pass' && !dkimAligned && dkimMismatchDomain) {
      badgeCls   = 'auth-warn';
      badgeLabel = `DKIM PASS ⚠ (${escR(dkimMismatchDomain)})`;
    }
    return `<span class="rpt-auth-badge ${badgeCls}">${badgeLabel}</span>`;
  }).join('');

  return `<section class="rpt-section">
    <h2>${rStr().auth}</h2>
    <div class="rpt-auth-row">${badgesHtml}</div>
  </section>`;
}

function rMsSpamSection(headers) {
  if (!headers) return '';

  const hdr = name => {
    const m = headers.match(new RegExp(`^${name}:\\s*(.+(?:\\r?\\n[ \\t].+)*)`, 'im'));
    return m ? m[1].replace(/\r?\n[ \t]+/g, ' ').trim() : null;
  };

  // SCL
  const sclRaw = hdr('X-MS-Exchange-Organization-SCL');
  const scl    = sclRaw !== null ? parseInt(sclRaw, 10) : null;

  // BCL
  const antispam = hdr('X-Microsoft-Antispam') || '';
  const bclM     = antispam.match(/BCL:(\d+)/i);
  const bcl      = bclM ? parseInt(bclM[1], 10) : null;

  // Mailbox delivery
  const delivery = hdr('X-Microsoft-Antispam-Mailbox-Delivery') || '';
  const destM    = delivery.match(/dest:([A-Z]+)/i);
  const dest     = destM ? destM[1].toUpperCase() : null;

  // Forefront report
  const forefront = hdr('X-Forefront-Antispam-Report') || '';
  const ff = k => { const m = forefront.match(new RegExp(`(?:^|;)\\s*${k}:([^;]+)`, 'i')); return m ? m[1].trim() : null; };
  const sfv = ff('SFV');
  const cat = ff('CAT');
  const ipv = ff('IPV');

  // Nothing to show
  if (scl === null && bcl === null && !dest && !sfv && !cat) return '';

  const pill = (label, value, cls, explain) =>
    `<tr>
      <th style="width:110px">${label}</th>
      <td><span class="ms-val ms-${cls}">${escR(String(value))}</span></td>
      <td class="ms-explain">${escR(explain)}</td>
    </tr>`;

  const sclCls = scl === null ? '' : scl <= 1 ? 'ok' : scl <= 4 ? 'warn' : 'bad';
  const sclLabel = scl === null ? '–'
    : scl === -1 ? 'Vertrauenswürdig (–1)'
    : scl <= 1   ? `Kein Spam (${scl})`
    : scl <= 4   ? `Gering verdächtig (${scl})`
    : scl <= 6   ? `Spam → Junk (${scl})`
    :              `Hohe Spam-Konfidenz (${scl})`;
  const sclExplain = scl === null ? 'Kein SCL-Header gefunden'
    : scl === -1 ? 'Interne/vertrauenswürdige Quelle – Spamfilter übersprungen'
    : scl <= 1   ? 'Microsoft hält E-Mail für legitim'
    : scl <= 4   ? 'Leicht erhöhter Verdacht – trotzdem Posteingang'
    : scl <= 6   ? 'Microsoft hat E-Mail als Spam klassifiziert → Junk-Ordner'
    :              'Hohe Spam-Konfidenz – kann direkt gelöscht oder abgelehnt werden';

  const bclCls = bcl === null ? '' : bcl === 0 ? 'ok' : bcl <= 3 ? 'warn-light' : bcl <= 6 ? 'warn' : 'bad';
  const bclLabel = bcl === null ? '–'
    : bcl === 0  ? `Kein Bulk (${bcl})`
    : bcl <= 3   ? `Geringes Bulk-Niveau (${bcl})`
    : bcl <= 6   ? `Mittleres Bulk-Niveau (${bcl})`
    :              `Hohes Bulk-Niveau (${bcl})`;
  const bclExplain = bcl === null ? 'Kein BCL gefunden'
    : bcl === 0  ? 'Keine Beschwerden bei Microsoft bekannt'
    : bcl <= 3   ? 'Wenige Nutzer haben ähnliche Mails als Spam markiert'
    : bcl <= 6   ? 'Erhöhte Beschwerderate – höheres Junk-Risiko'
    :              'Hohe Beschwerderate – starker Reputationsnachteil';

  const destCls = !dest ? '' : dest === 'I' ? 'ok' : dest === 'J' ? 'bad' : 'warn';
  const destLabel = !dest ? '–'
    : dest === 'I' ? 'Posteingang (I)'
    : dest === 'J' ? 'Junk-Ordner (J)'
    : dest === 'D' ? 'Gelöscht (D)'
    : dest === 'S' ? 'Gesendet (S)'
    : `Unbekannt (${dest})`;
  const destExplain = !dest ? 'Kein Delivery-Header'
    : dest === 'I' ? 'Exchange hat E-Mail in den Posteingang zugestellt'
    : dest === 'J' ? 'Exchange hat E-Mail direkt in Junk verschoben'
    : dest === 'D' ? 'Exchange hat E-Mail gelöscht'
    : 'Unbekannter Zustellungspfad';

  const sfvCls = !sfv ? '' : /^NSPM|SKN|SFE/i.test(sfv) ? 'ok' : /^SPM|SKS|BLK/i.test(sfv) ? 'bad' : 'warn';
  const sfvMap = { NSPM:'Kein Spam (NSPM)', SPM:'Spam (SPM)', SKN:'Safe Sender (SKN)', SFE:'Erlaubt (SFE)', BLK:'Blockiert (BLK)', SKS:'Spam – geblockt (SKS)', SKB:'Blockierter Absender (SKB)' };
  const sfvLabel = sfv ? (sfvMap[sfv.toUpperCase()] || sfv) : '–';
  const sfvExplain = !sfv ? 'Kein SFV-Wert gefunden'
    : /NSPM/i.test(sfv) ? 'Spamfilter hat E-Mail als legitim bewertet'
    : /SPM/i.test(sfv)  ? 'Spamfilter hat E-Mail als Spam eingestuft'
    : /SKN/i.test(sfv)  ? 'Absender steht auf der Safe-Sender-Liste'
    : /SFE/i.test(sfv)  ? 'Spamfilterung übersprungen (Allowlist)'
    : /SKS|BLK|SKB/i.test(sfv) ? 'Absender oder IP ist blockiert'
    : `Spamfilter-Urteil: ${sfv}`;

  const catCls = !cat ? '' : /NSPM/i.test(cat) ? 'ok' : /SPAM|PHSH|MALW/i.test(cat) ? 'bad' : 'warn';
  const catMap = { NSPM:'Kein Spam', SPAM:'Spam', PHSH:'Phishing', MALW:'Malware', BULK:'Bulk-Mail', HPHSH:'Sicheres Phishing', GIMP:'Interner Absender' };
  const catLabel = cat ? (catMap[cat.toUpperCase()] || cat) : null;

  const ipvCls = !ipv ? '' : /^CAL/i.test(ipv) ? 'ok' : /^CDL|CBI/i.test(ipv) ? 'bad' : 'neutral';
  const ipvMap = { NLI:'Unbekannt (NLI)', CAL:'Allowlist (CAL)', CDL:'Denyliste (CDL)', CBI:'Kompromittierte IP (CBI)' };
  const ipvLabel = ipv ? (ipvMap[ipv.toUpperCase()] || ipv) : null;

  const rows = [
    scl !== null && pill('SCL', sclLabel, sclCls, sclExplain),
    bcl !== null && pill('BCL', bclLabel, bclCls, bclExplain),
    dest          && pill('Zustellung', destLabel, destCls, destExplain),
    sfv           && pill('SFV', sfvLabel, sfvCls, sfvExplain),
    catLabel      && pill('Kategorie', catLabel, catCls, catMap[cat?.toUpperCase()] ? `Exchange-Kategorie: ${catLabel}` : cat),
    ipvLabel      && pill('IP-Status', ipvLabel, ipvCls, ipvMap[ipv?.toUpperCase()] ? `IP-Einstufung durch Microsoft: ${ipvLabel}` : ipv),
  ].filter(Boolean).join('');

  if (!rows) return '';

  return `<section class="rpt-section">
    <h2>Microsoft-Spamfilter</h2>
    <table class="meta-table ms-spam-table">${rows}</table>
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
