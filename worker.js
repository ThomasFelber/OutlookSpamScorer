/**
 * Cloudflare Worker — Claude AI spam analysis proxy
 *
 * Receives email data from the Outlook task pane, calls the Claude API,
 * and returns a structured spam verdict. The API key is stored as a
 * Worker secret (ANTHROPIC_API_KEY) and is never exposed to the client.
 *
 * Modes:
 *   (default)           — spam analysis via claude-haiku-4-5
 *   mode="advice"       — sender reputation advice via claude-sonnet-4-5
 *   mode="action-plan"  — technical deliverability action plan HTML via claude-sonnet-4-6
 *   mode="anschreiben"  — personalised German outreach letter HTML via claude-haiku-4-5
 *   mode="dns"          — SPF / DMARC / DKIM DNS lookups via Cloudflare DoH (no AI)
 */

const ALLOWED_ORIGIN        = 'https://outlook-spam-scorer.pages.dev';
const MODEL_ANALYSIS        = 'claude-haiku-4-5';
const MODEL_ADVICE          = 'claude-sonnet-4-5';
const MODEL_ACTION_PLAN     = 'claude-sonnet-4-6';
const MODEL_ANSCHREIBEN     = 'claude-haiku-4-5';
const MAX_TOKENS            = 1024;
const MAX_TOKENS_ADVICE     = 2048;
const MAX_TOKENS_ACTION_PLAN = 7500;
const MAX_TOKENS_ANSCHREIBEN = 2000;

const CORS_HEADERS = {
  'Access-Control-Allow-Origin':  ALLOWED_ORIGIN,
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export default {
  async fetch(request, env) {
    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    if (request.method !== 'POST') {
      return json({ error: 'Method not allowed' }, 405);
    }

    let payload;
    try {
      payload = await request.json();
    } catch {
      return json({ error: 'Invalid JSON body' }, 400);
    }

    // Route by mode
    if (payload.mode === 'advice')       return handleAdvice(payload, env);
    if (payload.mode === 'action-plan')  return handleActionPlan(payload, env);
    if (payload.mode === 'anschreiben')  return handleAnschreiben(payload, env);
    if (payload.mode === 'dns')          return handleDnsLookup(payload);
    return handleAnalysis(payload, env);
  },
};

// ── Spam analysis (default mode) ──────────────────────────────────────────────

async function handleAnalysis(payload, env) {
  const { headers = '', bodyText = '', subject = '', senderEmail = '', origSrcUrls = [] } = payload;

  if (!headers && !bodyText) {
    return json({ error: 'No email data provided' }, 400);
  }

  const trimmedHeaders  = headers.slice(0, 4000);
  const trimmedBodyText = bodyText.slice(0, 3000);

  const userPrompt = buildAnalysisPrompt(trimmedHeaders, trimmedBodyText, subject, senderEmail, origSrcUrls);

  let claudeResponse;
  try {
    const apiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model:      MODEL_ANALYSIS,
        max_tokens: MAX_TOKENS,
        system: [
          {
            type: 'text',
            text: `You are an expert email security analyst specialising in spam and phishing detection.
Analyse the provided email data carefully and respond with a single JSON object — no prose, no markdown fences.

JSON shape:
{
  "verdict":    "spam" | "ham" | "uncertain",
  "confidence": <integer 0–100, certainty in the verdict>,
  "score":      <integer 0–10, SPAM score: 0 = definitely legitimate, 10 = definitely spam>,
  "signals":    ["<specific finding>", ...],
  "summary":    "<1–2 sentences in German explaining the verdict>"
}

Score and verdict must be consistent: spam → score 7–10, uncertain → score 4–6, ham → score 0–3.`,
            cache_control: { type: 'ephemeral' },
          },
        ],
        messages: [{ role: 'user', content: userPrompt }],
      }),
    });

    if (!apiRes.ok) {
      const errText = await apiRes.text();
      return json({ error: `Claude API error ${apiRes.status}: ${errText}` }, 502);
    }

    claudeResponse = await apiRes.json();
  } catch (err) {
    return json({ error: `Fetch failed: ${err.message}` }, 502);
  }

  const rawText = claudeResponse.content?.[0]?.text ?? '';

  let analysis;
  try {
    const cleaned = rawText.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '').trim();
    analysis = JSON.parse(cleaned);
  } catch {
    analysis = { verdict: 'uncertain', confidence: 0, score: null, signals: [], summary: rawText };
  }

  return json(analysis);
}

// ── Reputation advice mode ────────────────────────────────────────────────────

async function handleAdvice(payload, env) {
  const {
    headers      = '',
    bodyText     = '',
    subject      = '',
    senderEmail  = '',
    addinScore   = null,
    addinSignals = [],
    claudeResult = null,
  } = payload;

  // Extract sending IP + PTR hostname from headers
  const spfIpM    = headers.match(/client-ip=([\d.a-f:]+)/i);
  let   sendingIp = spfIpM?.[1] ?? null;
  let   ptrHost   = null;
  const rcvdM     = headers.match(/^Received:.*?from\s+([\w.\-[\]:]+)(?:\s+\(([\w.\-]+)\s+)?\[([\d.a-f:]+)\]/im);
  if (rcvdM) {
    if (!sendingIp) sendingIp = rcvdM[3];
    const candidate = rcvdM[2] || rcvdM[1] || null;
    if (candidate && candidate !== sendingIp) ptrHost = candidate;
  }

  const userPrompt = buildAdvicePrompt(
    headers.slice(0, 3000),
    bodyText.slice(0, 2000),
    subject,
    senderEmail,
    addinScore,
    addinSignals,
    claudeResult,
    sendingIp,
    ptrHost,
  );

  let claudeResponse;
  try {
    const apiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model:      MODEL_ADVICE,
        max_tokens: MAX_TOKENS_ADVICE,
        system: [
          {
            type: 'text',
            text: `You are a senior email deliverability consultant.
Given a spam analysis report for an email, produce concrete, prioritised recommendations the SENDER can implement to improve their email reputation and reduce spam classification.
Focus on: authentication (SPF/DKIM/DMARC), content quality, sending infrastructure, list hygiene, and subscriber engagement.
Respond ONLY with a JSON object — no prose, no markdown fences.

JSON shape:
{
  "summary": "<2–3 sentences in German summarising the main deliverability issues>",
  "recommendations": [
    {
      "category": "<Authentifizierung | Inhalt | Infrastruktur | Listen-Hygiene | Engagement>",
      "priority": "<hoch | mittel | niedrig>",
      "title":    "<short title in German>",
      "action":   "<concrete actionable step in German>"
    }
  ]
}`,
            cache_control: { type: 'ephemeral' },
          },
        ],
        messages: [{ role: 'user', content: userPrompt }],
      }),
    });

    if (!apiRes.ok) {
      const errText = await apiRes.text();
      return json({ error: `Claude API error ${apiRes.status}: ${errText}` }, 502);
    }

    claudeResponse = await apiRes.json();
  } catch (err) {
    return json({ error: `Fetch failed: ${err.message}` }, 502);
  }

  const rawText = claudeResponse.content?.[0]?.text ?? '';

  let advice;
  try {
    const cleaned = rawText.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '').trim();
    advice = JSON.parse(cleaned);
  } catch {
    advice = { summary: rawText, recommendations: [] };
  }

  return json(advice);
}

// ── Technical action plan (HTML artifact) ─────────────────────────────────────

async function handleActionPlan(payload, env) {
  const {
    headers      = '',
    bodyText     = '',
    subject      = '',
    senderEmail  = '',
    addinScore   = null,
    addinSignals = [],
    claudeResult = null,
    adviceResult = null,
  } = payload;

  const signalList = (addinSignals || []).map(s => `  - ${s}`).join('\n') || '  (none)';
  const aiSummary  = claudeResult?.summary  || '(not available)';
  const aiScore    = claudeResult?.score    ?? '?';
  const aiVerdict  = claudeResult?.verdict  || '?';
  const aiSignals  = (claudeResult?.signals || []).map(s => `  - ${s}`).join('\n') || '  (none)';

  // Keep advice concise — top 6 recs, essential fields only
  const adviceSection = adviceResult?.recommendations?.length
    ? `\n=== REPUTATION RECOMMENDATIONS (already generated) ===\nSummary: ${(adviceResult.summary || '').slice(0, 300)}\n${
        adviceResult.recommendations.slice(0, 6).map(r =>
          `[${r.priority?.toUpperCase() || '?'}] ${r.category} — ${r.title}: ${(r.action || '').slice(0, 150)}`
        ).join('\n')
      }`
    : '';

  const userPrompt = `You are a senior email deliverability and infrastructure specialist.
Produce a comprehensive, senior-level technical deliverability action plan for the sender below.
Output ONLY a complete, self-contained HTML document (<!DOCTYPE html> … </html>) — no JSON, no markdown fences.
The HTML must be readable standalone in a browser. Use clean CSS embedded in <style>. German language throughout.
Keep CSS minimal and prose concise — priority is completeness of all sections over verbosity.

=== EMAIL BEING ANALYSED ===
Subject     : ${subject || '(unknown)'}
Sender      : ${senderEmail || '(unknown)'}
Add-in Score: ${addinScore ?? '?'}/10
AI Score    : ${aiScore}/10 — Verdict: ${aiVerdict}

=== ADD-IN SIGNALS ===
${signalList}

=== AI SIGNALS ===
${aiSignals}

=== AI SUMMARY ===
${aiSummary}
${adviceSection}
=== KEY HEADERS (truncated) ===
${headers.slice(0, 3000)}

=== BODY TEXT (truncated) ===
${bodyText.slice(0, 1500)}

---

Structure the HTML report with these sections:
1. Executive Summary (2–3 sentences)
2. Critical Findings (bullet list)
3. Authentication Analysis — SPF, DKIM, DMARC, ARC, compauth, alignment, Return-Path vs envelope sender
4. Header Analysis — Microsoft SCL/BCL/dest:J, X-Spam-Status, HELO/PTR, Received chain
5. HTML & Content Technical Analysis — MIME, encoding, hidden text, URL patterns, template quality
6. DNS & Infrastructure Improvements
7. Microsoft-Specific Remediation (Junk Mail Reporting Program, SNDS, Smart Network Data Services)
8. Gmail-Specific Remediation (Postmaster Tools, FBL, DMARC reporting)
9. Prioritised Technical Action Plan — an HTML table with columns: Priorität | Maßnahme | Warum | Geschätzter Impact | Risiko | Komplexität
10. Final Assessment

Target audience: senior infrastructure engineers and deliverability specialists.`;

  let claudeResponse;
  try {
    const apiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model:      MODEL_ACTION_PLAN,
        max_tokens: MAX_TOKENS_ACTION_PLAN,
        system: [
          {
            type: 'text',
            text: 'You are a senior email deliverability specialist. Output only complete standalone HTML documents when asked. No markdown, no JSON, no fences — raw HTML starting with <!DOCTYPE html>.',
            cache_control: { type: 'ephemeral' },
          },
        ],
        messages: [{ role: 'user', content: userPrompt }],
      }),
    });

    if (!apiRes.ok) {
      const errText = await apiRes.text();
      return json({ error: `Claude API error ${apiRes.status}: ${errText}` }, 502);
    }
    claudeResponse = await apiRes.json();
  } catch (err) {
    return json({ error: `Fetch failed: ${err.message}` }, 502);
  }

  const html = (claudeResponse.content?.[0]?.text ?? '')
    .replace(/^```(?:html)?\s*/i, '').replace(/\s*```$/, '').trim();
  return jsonHtml(html);
}

// ── Anschreiben generator (HTML artifact) ─────────────────────────────────────

async function handleAnschreiben(payload, env) {
  const {
    subject      = '',
    senderEmail  = '',
    addinScore   = null,
    addinSignals = [],
    claudeResult = null,
    adviceResult = null,
  } = payload;

  const topSignals = (addinSignals || []).slice(0, 5).map(s => `  - ${s}`).join('\n') || '  (keine)';
  const aiSummary  = claudeResult?.summary || '(nicht verfügbar)';
  const aiScore    = claudeResult?.score   ?? '?';
  const adviceSummary = adviceResult?.summary
    ? `\n=== BERATUNGS-ZUSAMMENFASSUNG (bereits generiert) ===\n${adviceResult.summary}`
    : '';

  const userPrompt = `Du bist ein professioneller E-Mail-Deliverability-Spezialist.
Erstelle ein professionelles deutsches Anschreiben an den Absender der analysierten E-Mail.
Erkläre nicht-technisch, dass ihre E-Mails wahrscheinlich im Spam landen, und biete Hilfe an.
Output: ONLY ein vollständiges, standalone HTML-Dokument (<!DOCTYPE html> … </html>) auf Deutsch.
Kein JSON, keine Markdown-Fences, kein Kommentar — nur reines HTML.

=== ANALYSIERTE E-MAIL ===
Absender : ${senderEmail || '(unbekannt)'}
Betreff  : ${subject || '(unbekannt)'}
Score    : Add-in ${addinScore ?? '?'}/10 · KI ${aiScore}/10

=== ERKANNTE PROBLEME (Auszug) ===
${topSignals}

=== KI-ZUSAMMENFASSUNG ===
${aiSummary}
${adviceSummary}
---

AUFBAU DES BRIEFES:
Ganz oben im Brief (vor der Anrede) die E-Mail-Adresse des Empfängers als klickbaren mailto-Link anzeigen:
<a href="mailto:${senderEmail || ''}">${senderEmail || ''}</a>

STIL:
Freundlich, kooperativ, auf Augenhöhe — nicht anmaßend, nicht überheblich, nicht belehrend.
Schreibe IMMER in der Ich-Form (Perspektive: Thomas Felber als Absender).
Stadtangabe im Datum: München.

KONTAKT DES ABSENDERS (Thomas Felber) — IMMER am Ende angeben, beide Angaben klickbar:
E-Mail : <a href="mailto:felber@live.de?subject=Newsletter-Zustellbarkeit">felber@live.de</a>
Telefon: <a href="tel:+491709064924">+49 170 9064924</a>  (wichtig für mobile Lesbarkeit — tel:-Link)

DAS ANGEBOT — IMMER beide Optionen konkret nennen:
(A) Erfolgsbasiert: Konkret einen Preis in EUR nennen, der sich an der Branche und den Margen orientiert.
    Mindestpreis: € 400,–. Nach oben anpassen je nach Branche:
    - Makler, Immobilien, Finanzdienstleister: € 700–900
    - Rechtsanwälte, Steuerberater, Unternehmensberater: € 800–1.200
    - Bauunternehmen, Handwerk mit hohen Umsätzen: € 600–900
    - Standardbetriebe / KMU: € 400–600
    Der Preis ist erst nach nachgewiesener Verbesserung fällig (Erfolgsmodell).
(B) Auf kollegialer Basis ohne Rechnung — kurz und natürlich formuliert.

PROBLEMBESCHREIBUNG:
Auf hohem Abstraktionsniveau — der Empfänger versteht, dass es ein strukturelles Problem gibt,
aber erhält NICHT genug Details um es selbst zu lösen.
Keine technischen Begriffe (kein DMARC, SPF, Return-Path, DKIM o.ä.).
Ziel: Der Empfänger soll Thomas Felber beauftragen.

Verwende sauberes eingebettetes CSS im <style>-Tag. Brief ist IMMER von Thomas Felber.`;

  let claudeResponse;
  try {
    const apiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model:      MODEL_ANSCHREIBEN,
        max_tokens: MAX_TOKENS_ANSCHREIBEN,
        system: [
          {
            type: 'text',
            text: 'Du bist ein professioneller Berater. Gib ausschließlich vollständige HTML-Dokumente aus, wenn danach gefragt wird. Kein Markdown, kein JSON, keine Fences — reines HTML ab <!DOCTYPE html>.',
            cache_control: { type: 'ephemeral' },
          },
        ],
        messages: [{ role: 'user', content: userPrompt }],
      }),
    });

    if (!apiRes.ok) {
      const errText = await apiRes.text();
      return json({ error: `Claude API error ${apiRes.status}: ${errText}` }, 502);
    }
    claudeResponse = await apiRes.json();
  } catch (err) {
    return json({ error: `Fetch failed: ${err.message}` }, 502);
  }

  const html = (claudeResponse.content?.[0]?.text ?? '')
    .replace(/^```(?:html)?\s*/i, '').replace(/\s*```$/, '').trim();
  return jsonHtml(html);
}

// ── DNS lookup (no AI, pure DoH) ─────────────────────────────────────────────

const DKIM_SELECTORS = [
  'default', 'google', 'mail', 'dkim', 's1', 's2', 'k1', 'k2',
  'selector1', 'selector2',   // Microsoft 365
  'mandrill', 'mailjet', 'smtp', 'em', 'mailo',
];

async function handleDnsLookup(payload) {
  const { domain, dkimSelectors = [] } = payload;
  if (!domain) return json({ error: 'domain required' }, 400);

  // Deduplicate: email-extracted selectors first, then common ones
  const allSelectors = [...new Set([...dkimSelectors, ...DKIM_SELECTORS])];

  const [spfTxt, dmarcTxt, ...dkimResults] = await Promise.all([
    dohTxt(domain),
    dohTxt(`_dmarc.${domain}`),
    ...allSelectors.map(sel => dkimLookup(sel, domain)),
  ]);

  const spfRecord   = spfTxt.find(r => r.startsWith('v=spf1')) ?? null;
  const dmarcRecord = dmarcTxt.find(r => r.startsWith('v=DMARC1')) ?? null;

  return json({
    spf:   { record: spfRecord,   found: !!spfRecord },
    dmarc: { record: dmarcRecord, found: !!dmarcRecord },
    dkim:  dkimResults.filter(r => r.found),
  });
}

/** Fetch all TXT records for a name via Cloudflare DoH */
async function dohTxt(name) {
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TXT`,
      { headers: { Accept: 'application/dns-json' } },
    );
    if (!res.ok) return [];
    const data = await res.json();
    return (data.Answer || []).map(a =>
      (a.data || '').replace(/^"|"$/g, '').replace(/" "/g, ''),
    );
  } catch { return []; }
}

/** Try TXT then CNAME for a DKIM selector */
async function dkimLookup(selector, domain) {
  const fqdn = `${selector}._domainkey.${domain}`;
  const txt  = await dohTxt(fqdn);
  const dkimTxt = txt.find(r => /v=DKIM1|k=rsa|k=ed25519|p=/i.test(r));
  if (dkimTxt) return { selector, type: 'TXT', record: dkimTxt, found: true };

  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(fqdn)}&type=CNAME`,
      { headers: { Accept: 'application/dns-json' } },
    );
    if (res.ok) {
      const data = await res.json();
      const cname = (data.Answer || []).find(a => a.type === 5);
      if (cname?.data) return { selector, type: 'CNAME', record: cname.data, found: true };
    }
  } catch { /* ignore */ }

  return { selector, found: false };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function jsonHtml(html) {
  return new Response(JSON.stringify({ html }), {
    status: 200,
    headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
  });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
  });
}

function getHdr(headers, name) {
  const re = new RegExp(`^${name}:\\s*(.+(?:\\r?\\n[ \\t].+)*)`, 'im');
  const m  = headers.match(re);
  return m ? m[1].replace(/\r?\n[ \t]+/g, ' ').trim() : null;
}

function extractDomain(str) {
  if (!str) return null;
  const m = str.match(/@([\w.-]+)/);
  return m ? m[1].toLowerCase() : null;
}

// ── Analysis prompt builder ───────────────────────────────────────────────────

function buildAnalysisPrompt(headers, bodyText, subject, senderEmail, origSrcUrls = []) {
  const fromHeader       = getHdr(headers, 'From')        || '';
  const returnPath       = getHdr(headers, 'Return-Path') || '';
  const replyTo          = getHdr(headers, 'Reply-To')    || '';
  const dkimSig          = getHdr(headers, 'DKIM-Signature') || '';
  const authResults      = getHdr(headers, 'Authentication-Results')
                        || getHdr(headers, 'ARC-Authentication-Results') || '';
  const receivedSpf      = getHdr(headers, 'Received-SPF') || '';
  const xSpamStatus      = getHdr(headers, 'X-Spam-Status') || '';

  const fromDomain       = extractDomain(fromHeader);
  const returnPathDomain = extractDomain(returnPath);
  const replyToDomain    = extractDomain(replyTo);
  const dkimDomain       = (dkimSig.match(/\bd=([\w.-]+)/i) || [])[1]?.toLowerCase() ?? null;

  const scl        = getHdr(headers, 'X-MS-Exchange-Organization-SCL');
  const antispam   = getHdr(headers, 'X-Microsoft-Antispam') || '';
  const bcl        = (antispam.match(/BCL:(\d+)/) || [])[1] ?? null;
  const delivery   = getHdr(headers, 'X-Microsoft-Antispam-Mailbox-Delivery') || '';
  const destJunk   = /dest:J/i.test(delivery);
  const ofrJunk    = /OFR:SpamFilter/i.test(delivery);

  const mergeTag       = /\{[A-Za-z][^}]{0,25}\}/.test(subject);
  const brokenEncoding = /Ã¶|Ã¼|Ã¤|Ã–/.test(bodyText + subject);
  const hasShortener   = /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly/i.test(bodyText);
  const canSpamBox     = /\bSte\.?\s+\d+\s*#\s*\d+|\bPMB\s*\d+/i.test(bodyText);
  const affiliateDiscl = /verwaltet\s+ihr\s+abonnement\s+nicht|does not manage your subscri/i.test(bodyText);

  const align = (domain, label) => {
    if (!domain) return null;
    const match = domain === fromDomain;
    return `${label.padEnd(16)} ${domain.padEnd(40)} ${match ? '✓ aligned' : '⚠ MISMATCH'}`;
  };

  const alignLines = [
    fromDomain ? `${'Von (From)'.padEnd(16)} ${fromDomain.padEnd(40)} (reference)` : null,
    align(returnPathDomain, 'Return-Path'),
    align(dkimDomain,       'DKIM d='),
    align(replyToDomain,    'Reply-To'),
  ].filter(Boolean).join('\n');

  const sclN    = scl ? parseInt(scl, 10) : null;
  const sclDesc = sclN == null       ? 'not present'
                : sclN <= 4          ? `${sclN} (clean)`
                : sclN <= 6          ? `${sclN} → JUNK (threshold 5–6)`
                :                     `${sclN} → SPAM (threshold 7–9)`;

  const heloM2       = receivedSpf.match(/helo=([\w.-]+)/i);
  const heloDomain   = heloM2?.[1]?.toLowerCase() ?? null;
  const heloMismatch = heloDomain && fromDomain
    && heloDomain !== fromDomain
    && !heloDomain.endsWith('.' + fromDomain)
    && !fromDomain.endsWith('.' + heloDomain);

  const origSrcSection = origSrcUrls.length > 0
    ? `\n=== REAL LINK DESTINATIONS (unwrapped from Safe Links) ===\n${origSrcUrls.slice(0, 10).join('\n')}`
    : '';

  const alignLinesExt = [
    ...alignLines.split('\n').filter(Boolean),
    heloDomain ? `${'HELO'.padEnd(16)} ${heloDomain.padEnd(40)} ${heloMismatch ? '⚠ MISMATCH' : '✓ aligned'}` : null,
  ].filter(Boolean).join('\n');

  return `Analyse this email for spam. Return ONLY a JSON object:
{ "verdict": "spam"|"ham"|"uncertain", "confidence": 0-100, "score": 0-10, "signals": ["..."], "summary": "1-2 sentences in German" }

=== SENDER DOMAIN ALIGNMENT ===
${alignLinesExt || '(no domain data)'}

=== SERVER VERDICTS ===
Microsoft SCL:          ${sclDesc}
Microsoft BCL:          ${bcl != null ? `${bcl} (4+=bulk, 7+=high complaints)` : 'not present'}
Exchange junk delivery: ${destJunk ? `YES — dest:J${ofrJunk ? ', OFR:SpamFilterAuthJ' : ''}` : 'no'}
X-Spam-Status:          ${xSpamStatus || 'not present'}

=== AUTHENTICATION RESULTS ===
${authResults || '(not present)'}
${receivedSpf ? `Received-SPF: ${receivedSpf}` : ''}

=== DETECTED PATTERNS ===
Unsubstituted merge tag in subject : ${mergeTag       ? `YES → "${subject}"` : 'no'}
Broken UTF-8 encoding (Ã¶/Ã¼)     : ${brokenEncoding ? 'YES — spam pipeline indicator' : 'no'}
HELO domain mismatch               : ${heloMismatch   ? `YES — HELO=${heloDomain}, From=${fromDomain}` : 'no'}
URL shortener in body              : ${hasShortener   ? 'YES' : 'no'}
CAN-SPAM virtual mailbox address   : ${canSpamBox     ? 'YES' : 'no'}
Affiliate disclaimer               : ${affiliateDiscl ? 'YES' : 'no'}
${origSrcSection}

=== SUBJECT ===
${subject}

=== FROM / SENDER ===
${fromHeader || senderEmail}
${returnPath ? `Return-Path: ${returnPath}` : ''}
${replyTo    ? `Reply-To:    ${replyTo}`    : ''}
${dkimSig    ? `DKIM-Signature (d=): ${dkimDomain}` : ''}

=== KEY HEADERS (truncated to 3000 chars) ===
${headers.slice(0, 3000)}

=== BODY TEXT (truncated to 2000 chars) ===
${bodyText.slice(0, 2000)}`;
}

// ── Advice prompt builder ─────────────────────────────────────────────────────

function buildAdvicePrompt(headers, bodyText, subject, senderEmail, addinScore, addinSignals, claudeResult, sendingIp, ptrHost) {
  const signalList = (addinSignals || []).map(s => `  - ${s}`).join('\n') || '  (keine)';
  const aiSummary  = claudeResult?.summary  || '(nicht verfügbar)';
  const aiScore    = claudeResult?.score    ?? '(nicht verfügbar)';
  const aiVerdict  = claudeResult?.verdict  || '(nicht verfügbar)';
  const aiSignals  = (claudeResult?.signals || []).map(s => `  - ${s}`).join('\n') || '  (keine)';

  const ipSection = sendingIp
    ? `\n=== SENDENDE IP ===\nIP       : ${sendingIp}\nHostname : ${ptrHost || '(nicht aufgelöst — kein PTR-Eintrag)'}\n`
    : '';

  const ipNote = sendingIp
    ? `WICHTIG zur IP: Die sendende IP ist ${sendingIp}${ptrHost ? ` (PTR: ${ptrHost})` : ' (kein PTR-Eintrag)'}. ` +
      `Falls diese IP bereits eine dedizierte Versand-IP ist (erkennbar am Hostname oder typischen ESP-Mustern), ` +
      `empfehle NICHT "eine dedizierte IP beschaffen" — das wäre redundant. ` +
      `Fokussiere stattdessen auf IP-Reputationsverbesserung (Warmup-Strategie, Beschwerderate senken, Engagement verbessern).`
    : '';

  return `Analysiere diesen Spam-Bericht und erstelle priorisierte Empfehlungen für den ABSENDER.
${ipNote ? '\n' + ipNote + '\n' : ''}
=== ANALYSE-ERGEBNIS ===
Add-in Score : ${addinScore ?? '?'}/10
Claude Score : ${aiScore}/10 — Verdict: ${aiVerdict}
Absender     : ${senderEmail || '(unbekannt)'}
Betreff      : ${subject || '(unbekannt)'}
${ipSection}
=== ERKANNTE PROBLEME (Add-in) ===
${signalList}

=== ERKANNTE PROBLEME (Claude KI) ===
${aiSignals}

=== CLAUDE ZUSAMMENFASSUNG ===
${aiSummary}

=== SCHLÜSSEL-HEADER ===
${headers.slice(0, 1500)}

=== BODY-TEXT (Auszug) ===
${bodyText.slice(0, 800)}`;
}
