'use strict';

// ─── Spam Analyzer ────────────────────────────────────────────────────────────
// Pure logic — no DOM or Office dependencies.

class SpamAnalyzer {
  analyze(headers, bodyHtml, subject, senderEmail) {
    const reasons = [];
    const hScore = headers ? this._analyzeHeaders(headers, reasons) : 0;
    const bScore = this._analyzeBody(bodyHtml, subject, reasons);
    return {
      score: Math.min(10, Math.round(hScore + bScore)),
      reasons,
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
    }

    // Server-side spam verdicts from common MTA headers
    const xSpamStatus = this._getHeader(headers, 'X-Spam-Status') || '';
    const xSpamFlag   = this._getHeader(headers, 'X-Spam-Flag')   || '';
    if (/^\s*yes/i.test(xSpamStatus)) { score += 2; reasons.push('Server: als Spam markiert (X-Spam-Status)'); }
    if (/yes/i.test(xSpamFlag))       { score += 1; reasons.push('Server: X-Spam-Flag gesetzt'); }

    // Reply-To domain differs from From domain — classic phishing pattern
    const fromHeader    = this._getHeader(headers, 'From')     || '';
    const replyToHeader = this._getHeader(headers, 'Reply-To') || '';
    if (fromHeader && replyToHeader) {
      const fromDomain    = this._extractDomain(fromHeader);
      const replyToDomain = this._extractDomain(replyToHeader);
      if (fromDomain && replyToDomain && fromDomain !== replyToDomain) {
        score += 1;
        reasons.push(`Reply-To-Domain abweichend (${replyToDomain} ≠ ${fromDomain})`);
      }
    }

    // Return-Path domain mismatch
    const returnPath = this._getHeader(headers, 'Return-Path') || '';
    if (fromHeader && returnPath) {
      const fromDomain       = this._extractDomain(fromHeader);
      const returnPathDomain = this._extractDomain(returnPath);
      if (fromDomain && returnPathDomain && fromDomain !== returnPathDomain) {
        score += 0.5;
        reasons.push(`Return-Path-Domain abweichend (${returnPathDomain})`);
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

    // Excessive mail hops — overly forwarded / obfuscated routing
    const hopCount = (headers.match(/^Received:/gim) || []).length;
    if (hopCount > 8) { score += 0.5; reasons.push(`Viele Mail-Hops (${hopCount} Received-Zeilen)`); }

    return score;
  }

  _analyzeBody(bodyHtml, subject, reasons) {
    let score = 0;

    const plainText   = this._stripHtml(bodyHtml || '');
    const fullText    = (subject || '') + ' ' + plainText;
    const fullLower   = fullText.toLowerCase();

    // Spam keyword patterns (German + English)
    const patterns = [
      { re: /gewinn(en|er|t)|lotterie|jackpot|millionen?\s*euro|preis\s*gewonnen/i,        w: 2,   label: 'Gewinnversprechen' },
      { re: /nigeria|prince|inheritance|erbschaft|million[s]?\s*dollar/i,                  w: 2.5, label: 'Nigeria-/Vorschussbetrug' },
      { re: /viagra|cialis|levitra|pharmacy|apotheke\s*ohne\s*rezept/i,                    w: 2.5, label: 'Pharma-Spam' },
      { re: /casino|online.?wett(en|büro)|glücksspiel/i,                                   w: 1.5, label: 'Glücksspiel' },
      { re: /ihr\s+(konto|paypal|amazon|apple|microsoft).{0,30}(gesperrt|deaktiviert)/i,   w: 2,   label: 'Phishing: Konto gesperrt' },
      { re: /passwort\s*(ablaufen|bestätigen|verifizieren|erneuern|expired)/i,             w: 2,   label: 'Phishing: Passwort-Anfrage' },
      { re: /klicken\s*sie\s*hier|click\s*here|jetzt\s*klicken/i,                         w: 0.5, label: 'Generische Klick-Aufforderung' },
      { re: /dringend|urgent|sofort\s*handeln|act\s*now|limited\s*time|angebot\s*endet/i, w: 0.5, label: 'Künstliche Dringlichkeit' },
      { re: /100\s*%\s*(kostenlos|gratis|free)|völlig\s*kostenlos/i,                      w: 0.8, label: 'Gratis-Versprechen' },
      { re: /sie\s*wurden\s*ausgewählt|you\s*have\s*been\s*selected/i,                    w: 1.5, label: 'Pseudo-Auszeichnung' },
      { re: /\bcrypto|bitcoin|kryptowährun|invest.{0,30}rendite|hohe\s*rendite/i,         w: 1,   label: 'Crypto/Investment-Spam' },
      { re: /ihre\s*(daten|informationen)\s*(wurden\s*)?bestätigen|verify\s*your\s*info/i, w: 1.5, label: 'Datenmissbrauch-Phishing' },
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

    // Link analysis — inspect URLs textually, never follow them
    const links = (bodyHtml || '').match(/https?:\/\/[^\s"'<>)]+/gi) || [];
    const linkCount = links.length;

    // URL shorteners hide destination — always suspicious
    const shortenerRe = /bit\.ly\/|tinyurl\.com\/|t\.co\/|goo\.gl\/|ow\.ly\/|cutt\.ly\/|rb\.gy\//i;
    if (links.some(l => shortenerRe.test(l))) {
      score += 1;
      reasons.push('URL-Verkürzer gefunden (versteckt Ziel-URL)');
    }

    // Suspicious free/throwaway TLDs commonly used for spam campaigns
    const suspiciousTLD = /\.(tk|cf|ga|ml|gq|xyz|top|click|download|stream|loan|win|racing|buzz)\//i;
    if (links.some(l => suspiciousTLD.test(l))) {
      score += 1;
      reasons.push('Verdächtige Link-TLD (.tk, .xyz, .top …)');
    }

    if (linkCount > 0) {
      const textLen = plainText.length;
      if (textLen < 80 && linkCount >= 2) {
        score += 1;
        reasons.push('Sehr kurzer Text mit mehreren Links');
      } else if (textLen > 0 && (linkCount / (textLen / 100)) > 0.4) {
        score += Math.min(1, linkCount * 0.12);
        reasons.push(`Hohe Link-Dichte (${linkCount} Links)`);
      }
    }

    // Hidden / invisible text — classic spam obfuscation technique
    if (/color\s*:\s*(white|#fff\b|#ffffff)|font-size\s*:\s*[01]px|display\s*:\s*none/i.test(bodyHtml || '')) {
      score += 1.5;
      reasons.push('Versteckter/unsichtbarer Text gefunden');
    }

    return score;
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

const VERSION = '1.3.0';

const analyzer = new SpamAnalyzer();
let currentScore   = null;
let lastHeaders    = '';
let lastBodyText   = '';

// ─── Office init ───────────────────────────────────────────────────────────────

Office.onReady(info => {
  if (info.host !== Office.HostType.Outlook) return;

  document.getElementById('btn-apply').addEventListener('click', applyCategory);
  document.getElementById('btn-retry').addEventListener('click', analyzeCurrentItem);
  document.getElementById('btn-scan').addEventListener('click', scanJunkFolder);
  document.getElementById('btn-copy-headers').addEventListener('click', () => copyToClipboard(lastHeaders, 'Header kopiert'));
  document.getElementById('btn-copy-body').addEventListener('click',    () => copyToClipboard(lastBodyText, 'Body-Text kopiert'));

  initPinHint();
  document.getElementById('version-label').textContent = 'v' + VERSION;

  // Stay open automatically for every email from now on
  if (Office.addin?.setStartupBehavior) {
    Office.addin.setStartupBehavior(Office.StartupBehavior.load).catch(() => {});
  }

  // Re-analyze when user navigates to a different email (pinned pane)
  // Also hides the pin hint — ItemChanged only fires when the pane IS pinned
  Office.context.mailbox.addHandlerAsync(Office.EventType.ItemChanged, () => {
    hidePinHint();
    analyzeCurrentItem();
  });

  analyzeCurrentItem();
});

// ─── Analyze current item ──────────────────────────────────────────────────────

function analyzeCurrentItem() {
  showState('loading');
  currentScore = null;

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
    lastHeaders  = headers;
    lastBodyText = analyzer._stripHtml(bodyHtml);
    const result = analyzer.analyze(headers, bodyHtml, subject, senderEmail);
    currentScore = result.score;
    renderResult(result, headers, subject, senderName || senderEmail);
    showState('result');
  }).catch(err => {
    document.getElementById('error-message').textContent = 'Fehler: ' + err.message;
    showState('error');
  });
}

// ─── Apply category ────────────────────────────────────────────────────────────

function applyCategory() {
  if (currentScore === null) return;

  const btn          = document.getElementById('btn-apply');
  const newCategory  = `Spam: ${currentScore}`;
  const item         = Office.context.mailbox.item;

  btn.disabled    = true;
  btn.textContent = 'Speichern…';

  item.categories.getAsync(getResult => {
    const oldSpam = getResult.status === Office.AsyncResultStatus.Succeeded
      ? getResult.value.filter(c => /^Spam: \d+$/.test(c.displayName)).map(c => c.displayName)
      : [];

    const doAdd = () => {
      item.categories.addAsync([newCategory], addResult => {
        if (addResult.status === Office.AsyncResultStatus.Succeeded) {
          showToast(`Kategorie "${newCategory}" gesetzt`, false);
        } else {
          showToast('Fehler: ' + (addResult.error?.message || 'Unbekannt'), true);
        }
        btn.disabled    = false;
        btn.textContent = 'Als Kategorie speichern';
      });
    };

    if (oldSpam.length > 0) {
      item.categories.removeAsync(oldSpam, doAdd);
    } else {
      doAdd();
    }
  });
}

// ─── Junk folder scan ──────────────────────────────────────────────────────────

function scanJunkFolder() {
  if (typeof Office.context.mailbox.makeEwsRequestAsync !== 'function') {
    setScanProgress('EWS wird nicht unterstützt (nur Exchange / Microsoft 365).', true);
    document.getElementById('scan-section').classList.remove('hidden');
    return;
  }

  const btn = document.getElementById('btn-scan');
  btn.disabled = true;
  document.getElementById('scan-section').classList.remove('hidden');
  document.getElementById('scan-results').innerHTML = '';
  setScanProgress('Lade Junk-Ordner…');

  const findXml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
  xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:FindItem Traversal="Shallow">
      <m:ItemShape>
        <t:BaseShape>IdOnly</t:BaseShape>
        <t:AdditionalProperties>
          <t:FieldURI FieldURI="item:Subject"/>
          <t:FieldURI FieldURI="message:From"/>
        </t:AdditionalProperties>
      </m:ItemShape>
      <m:IndexedPageItemView MaxEntriesReturned="50" Offset="0" BasePoint="Beginning"/>
      <m:ParentFolderIds>
        <t:DistinguishedFolderId Id="junkemail"/>
      </m:ParentFolderIds>
    </m:FindItem>
  </soap:Body>
</soap:Envelope>`;

  Office.context.mailbox.makeEwsRequestAsync(findXml, findResult => {
    if (findResult.status !== Office.AsyncResultStatus.Succeeded) {
      setScanProgress('EWS-Fehler: ' + findResult.error.message, true);
      btn.disabled = false;
      return;
    }

    const xmlDoc   = new DOMParser().parseFromString(findResult.value, 'text/xml');
    const msgNodes = xmlDoc.querySelectorAll('Message');

    if (msgNodes.length === 0) {
      setScanProgress('Junk-Ordner ist leer.');
      btn.disabled = false;
      return;
    }

    setScanProgress(`${msgNodes.length} E-Mails gefunden. Analysiere…`);

    const items = Array.from(msgNodes).map(n => ({
      id:       n.querySelector('ItemId')?.getAttribute('Id') || '',
      subject:  n.querySelector('Subject')?.textContent || '(kein Betreff)',
      from:     n.querySelector('EmailAddress')?.textContent || '',
      fromName: n.querySelector('Name')?.textContent || '',
    })).filter(i => i.id);

    processEwsItems(items, 0, [], btn);
  });
}

function processEwsItems(items, index, results, btn) {
  if (index >= items.length) {
    renderScanResults(results);
    setScanProgress(`Fertig — ${results.length} E-Mails analysiert.`);
    btn.disabled = false;
    return;
  }

  const cur = items[index];
  setScanProgress(`Analysiere ${index + 1} / ${items.length}: ${cur.subject.slice(0, 40)}…`);

  // PR_TRANSPORT_MESSAGE_HEADERS (0x007D) delivers raw internet headers without body download
  const getXml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
  xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Body>
    <m:GetItem>
      <m:ItemShape>
        <t:BaseShape>IdOnly</t:BaseShape>
        <t:BodyType>HTML</t:BodyType>
        <t:AdditionalProperties>
          <t:FieldURI FieldURI="item:Body"/>
          <t:ExtendedFieldURI PropertyTag="0x007D" PropertyType="String"/>
        </t:AdditionalProperties>
      </m:ItemShape>
      <m:ItemIds>
        <t:ItemId Id="${escapeXml(cur.id)}"/>
      </m:ItemIds>
    </m:GetItem>
  </soap:Body>
</soap:Envelope>`;

  Office.context.mailbox.makeEwsRequestAsync(getXml, getResult => {
    let headers  = '';
    let bodyHtml = '';

    if (getResult.status === Office.AsyncResultStatus.Succeeded) {
      const doc   = new DOMParser().parseFromString(getResult.value, 'text/xml');
      bodyHtml    = doc.querySelector('Body')?.textContent  || '';
      // Extended property value contains the raw transport headers
      headers     = doc.querySelector('Value')?.textContent || '';
    }

    const analysis = analyzer.analyze(headers, bodyHtml, cur.subject, cur.from);
    results.push({ ...cur, ...analysis });

    // Small delay to avoid overwhelming Exchange
    setTimeout(() => processEwsItems(items, index + 1, results, btn), 120);
  });
}

// ─── Rendering ─────────────────────────────────────────────────────────────────

function renderResult(result, headers, subject, senderDisplay) {
  document.getElementById('meta-subject').textContent = subject;
  document.getElementById('meta-subject').title       = subject;
  document.getElementById('meta-from').textContent    = senderDisplay;

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

  document.getElementById('auth-summary').innerHTML = buildAuthBadges(headers);
}

function renderScanResults(results) {
  results.sort((a, b) => b.score - a.score);
  const container = document.getElementById('scan-results');

  if (results.length === 0) {
    container.innerHTML = '<p class="scan-empty">Keine Ergebnisse.</p>';
    return;
  }

  container.innerHTML = results.map(r => {
    const lvl = scoreLevel(r.score);
    return `<div class="scan-item lvl-${lvl}">
      <span class="scan-score lvl-${lvl}">${r.score}</span>
      <div class="scan-info">
        <div class="scan-subject" title="${escapeHtml(r.subject)}">${escapeHtml(r.subject.slice(0, 55))}</div>
        <div class="scan-from">${escapeHtml(r.from)}</div>
      </div>
    </div>`;
  }).join('');
}

function buildAuthBadges(headers) {
  if (!headers) return '<span class="auth-badge auth-none">Keine Headers</span>';

  const authLine = headers.match(/^Authentication-Results:(.+(?:\r?\n[ \t].+)*)/im)
                || headers.match(/^ARC-Authentication-Results:(.+(?:\r?\n[ \t].+)*)/im);

  if (!authLine) return '<span class="auth-badge auth-none">Keine Authentication-Results</span>';

  const str    = authLine[1];
  const checks = [
    { label: 'SPF',   re: /spf=(pass|fail|softfail|neutral|none)/i },
    { label: 'DKIM',  re: /dkim=(pass|fail|none)/i },
    { label: 'DMARC', re: /dmarc=(pass|fail|none|bestguesspass)/i },
  ];

  return checks.map(({ label, re }) => {
    const m   = str.match(re);
    if (!m) return `<span class="auth-badge auth-none">${label} —</span>`;
    const val = m[1].toLowerCase();
    const cls = val === 'pass'     ? 'auth-pass'
              : val === 'softfail' ? 'auth-softfail'
              : val === 'fail'     ? 'auth-fail'
              :                     'auth-warn';
    return `<span class="auth-badge ${cls}">${label} ${val.toUpperCase()}</span>`;
  }).join('');
}

// ─── UI helpers ────────────────────────────────────────────────────────────────

function showState(state) {
  document.getElementById('state-loading').classList.toggle('hidden', state !== 'loading');
  document.getElementById('state-no-item').classList.toggle('hidden', state !== 'no-item');
  document.getElementById('state-error').classList.toggle('hidden',   state !== 'error');
  document.getElementById('state-result').classList.toggle('hidden',  state !== 'result');
}

function setScanProgress(msg, isError = false) {
  const el = document.getElementById('scan-progress');
  el.textContent = msg;
  el.className   = 'scan-progress' + (isError ? ' is-error' : '');
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

function escapeXml(str) {
  return String(str)
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&apos;');
}
