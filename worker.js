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
 *   mode="save"         — persist report/anschreiben/aktionsplan HTML to D1 (requires SAVE_TOKEN)
 *   mode="list"         — return JSON list of saved reports from D1
 *   mode="get"          — return raw HTML of a single saved report by id
 */

const ALLOWED_ORIGIN        = 'https://outlook-spam-scorer.pages.dev';
const MODEL_ANALYSIS        = 'claude-haiku-4-5';
const MODEL_ADVICE          = 'claude-sonnet-4-5';
const MODEL_ACTION_PLAN     = 'claude-sonnet-4-6';
const MODEL_ANSCHREIBEN     = 'claude-sonnet-4-5';
const MAX_TOKENS            = 1024;
const MAX_TOKENS_ADVICE     = 4000;
const MAX_TOKENS_ACTION_PLAN = 7500;
const MAX_TOKENS_ANSCHREIBEN = 3500;

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
    if (payload.mode === 'explain')       return handleExplain(payload, env);
    if (payload.mode === 'explain-batch') return handleExplainBatch(payload, env);
    if (payload.mode === 'dns')          return handleDnsLookup(payload);
    if (payload.mode === 'compliance')   return handleCompliance(payload, env);
    if (payload.mode === 'save')         return handleSave(payload, env);
    if (payload.mode === 'list')         return handleList(payload, env);
    if (payload.mode === 'get')          return handleGet(payload, env);
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

  // Standard RFC format: from hostname (hostname [IP])
  const rcvdM = headers.match(/^Received:.*?from\s+([\w.\-[\]:]+)\s+\(([\w.\-]+)\s+\[([\d.a-f:]+)\]\)/im);
  if (rcvdM) {
    if (!sendingIp) sendingIp = rcvdM[3];
    const candidate = rcvdM[2];
    if (candidate && candidate !== sendingIp) ptrHost = candidate;
  }

  // Fallback: from hostname (IP) — round parens only, no brackets (e.g. Brevo/Sendinblue)
  if (!ptrHost && sendingIp) {
    const esc  = sendingIp.replace(/\./g, '\\.');
    const ptrM = headers.match(new RegExp(`from\\s+([\\w.\\-]+)\\s+\\(${esc}\\)`, 'i'));
    if (ptrM?.[1] && ptrM[1] !== sendingIp) ptrHost = ptrM[1];
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
    headers      = '',
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

  // Detect ESP for contextualised outreach
  const feedbackId = (headers.match(/^Feedback-ID:\s*(.+)/im) || [])[1] || '';
  const receivedHdr = (headers.match(/^Received:.*$/im) || [])[0] || '';
  const espName    = /sendinblue|brevo/i.test(feedbackId + receivedHdr) ? 'Sendinblue/Brevo'
                   : /mailchimp|mandrill/i.test(feedbackId + receivedHdr) ? 'Mailchimp/Mandrill'
                   : /mailjet/i.test(feedbackId + receivedHdr) ? 'Mailjet'
                   : /cleverreach/i.test(feedbackId + receivedHdr) ? 'CleverReach'
                   : /emarsys/i.test(feedbackId + receivedHdr) ? 'Emarsys'
                   : /hubspot/i.test(feedbackId + receivedHdr) ? 'HubSpot'
                   : /klaviyo/i.test(feedbackId + receivedHdr) ? 'Klaviyo'
                   : /activecampaign/i.test(feedbackId + receivedHdr) ? 'ActiveCampaign'
                   : null;

  // Extract misconfigurations that are specific to the detected ESP
  const espMisconfigs = espName
    ? (addinSignals || []).filter(s =>
        /return-path|dkim|align|link-dicht|versteckt|auth|SPF|DMARC/i.test(s)
      ).slice(0, 4)
    : [];

  const espContext = espName
    ? `\n=== ESP / VERSANDPLATTFORM ===
Erkannte Plattform: ${espName}
Spezifische Konfigurationsprobleme bei dieser Plattform:
${espMisconfigs.length ? espMisconfigs.map(s => `  - ${s}`).join('\n') : '  (keine spezifischen aus der Analyse extrahiert)'}

WICHTIG: Zeige im Brief implizit, dass du das konkrete Setup des Kunden kennst.
Formuliere so: "Ich habe gesehen, dass Sie [${espName}] einsetzen — und die Konfiguration weist einige typische Punkte auf, die ich häufig bei dieser Plattform antreffe."
Keine tiefen technischen Details — der Empfänger soll Thomas Felber beauftragen, nicht es selbst lösen.
`
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
${espContext}
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

DAS ANGEBOT — IMMER alle drei Optionen nennen:
(A) Festpreis: Konkret einen Preis in EUR nennen, der sich an der Branche und Margen orientiert.
    Mindestpreis: € 400,–. Nach oben anpassen je nach Branche:
    - Makler, Immobilien, Finanzdienstleister: € 700–900
    - Rechtsanwälte, Steuerberater, Unternehmensberater: € 800–1.200
    - Bauunternehmen, Handwerk mit hohen Umsätzen: € 600–900
    - Standardbetriebe / KMU: € 400–600
    Preis fällig bei Abschluss der Arbeiten. IMMER anmerken: "Sie gehen kein Risiko ein."
(B) Erstanalyse: Vollständiger Analyse-Report mit identifizierten Problemen und priorisierten
    Handlungsempfehlungen. Umsetzung liegt beim Kunden. Honorar: € 200,– (einmalig, fällig bei Übergabe).
(C) Kollegial: Kurz und natürlich formuliert — offen für ein Gespräch ohne formales Mandat.
    Was daraus entsteht, entscheiden wir gemeinsam.

ABSCHLUSS DES BRIEFES (Closing):
IMMER verwenden: "Für jedwede Rückfragen stehe ich gerne zur Verfügung."

PROBLEMBESCHREIBUNG:
Die Problembereiche dürfen explizit benannt werden: "technische Konfiguration" und "Inhalt / E-Mail-Aufbau".
Der Empfänger erhält aber NICHT genug Details um das Problem selbst zu lösen.
Keine tiefen Fachbegriffe (kein DMARC, SPF, Return-Path, DKIM, SCL o.ä.).
Ziel: Der Empfänger soll Thomas Felber beauftragen.

VERBOTENE FORMULIERUNGEN — diese Phrasen NIEMALS verwenden:
- "Was mich daran besonders beschäftigt"
- "Das macht es schwieriger zu erkennen — und umso wichtiger, es zu verstehen"
- "Was mich dabei überrascht"
- Jede Variation dieser übermäßig dramatisierenden Einstiegsformulierungen

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

// ── Signal explanation (single indicator → plain-German explanation) ──────────

async function handleExplain(payload, env) {
  const { signal = '' } = payload;
  if (!signal.trim()) return json({ error: 'signal required' }, 400);

  let apiRes;
  try {
    apiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model:      MODEL_ADVICE,   // sonnet — needs domain expertise for accurate explanations
        max_tokens: 300,
        system: [
          {
            type: 'text',
            text: `Du bist ein erfahrener E-Mail-Deliverability-Spezialist.
Erkläre technische Signale aus E-Mail-Headern und Spam-Filtern auf Deutsch.
Zielgruppe: Absender ohne tiefes technisches Vorwissen.
Jede Erklärung besteht aus genau zwei Teilen:
1. Was bedeutet dieses Signal konkret (1–2 Sätze, kein Jargon).
2. Warum hat es Optimierungspotenzial — was verbessert sich konkret, wenn es behoben wird (1–2 Sätze).
Kein JSON, kein Markdown, keine Aufzählung, keine Überschriften — nur Fließtext.`,
            cache_control: { type: 'ephemeral' },
          },
        ],
        messages: [{ role: 'user', content: `Erkläre dieses Deliverability-Signal: "${signal}"` }],
      }),
    });
  } catch (err) {
    return json({ error: `Fetch failed: ${err.message}` }, 502);
  }

  if (!apiRes.ok) {
    const errText = await apiRes.text();
    return json({ error: `Claude API error ${apiRes.status}: ${errText}` }, 502);
  }

  const data        = await apiRes.json();
  const explanation = (data.content?.[0]?.text ?? '').trim();
  return json({ explanation });
}

// ── Batch signal explanation ──────────────────────────────────────────────────

async function handleExplainBatch(payload, env) {
  const signals = (payload.signals || []).slice(0, 30);
  if (signals.length === 0) return json({ explanations: {} });

  const numbered = signals.map((s, i) => `${i + 1}. ${s}`).join('\n');

  let apiRes;
  try {
    apiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model:      MODEL_ADVICE,
        max_tokens: 2500,
        system: [
          {
            type: 'text',
            text: `Du bist ein erfahrener E-Mail-Deliverability-Spezialist.
Erkläre jedes nummerierte Signal auf Deutsch in 2–3 Sätzen Fließtext (kein Jargon, keine Aufzählung).
Für jedes Signal: (1) was es bedeutet, (2) warum es Optimierungspotenzial hat und was sich konkret verbessert wenn man es behebt.
Antworte NUR mit einem JSON-Objekt: {"1": "Erklärung...", "2": "Erklärung...", ...}`,
            cache_control: { type: 'ephemeral' },
          },
        ],
        messages: [{ role: 'user', content: `Erkläre diese Deliverability-Signale:\n\n${numbered}` }],
      }),
    });
  } catch (err) {
    return json({ explanations: {} });
  }

  if (!apiRes.ok) return json({ explanations: {} });

  const data = await apiRes.json();
  const raw  = (data.content?.[0]?.text ?? '{}').replace(/^```json?\s*/i, '').replace(/\s*```$/, '').trim();

  let indices = {};
  try { indices = JSON.parse(raw); } catch { return json({ explanations: {} }); }

  const explanations = {};
  signals.forEach((s, i) => {
    const expl = indices[String(i + 1)];
    if (expl) explanations[s] = expl;
  });
  return json({ explanations });
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

// ── Compliance assessment ────────────────────────────────────────────────────
//
// Heuristic check of a sender domain's legal pages (Impressum, Datenschutz,
// optionally AGB + Widerruf for B2C). Fetches the homepage to discover footer
// links, falls back to canonical paths. Applies regex-based pattern checks for
// each statutory disclosure. Builds an HTML report; the numeric score is stored
// only as data-* attributes (not shown in the add-in UI).
//
// Disclaimer is prominent in the report: this is NOT a legal opinion.

const COMPLIANCE_UA = 'Mozilla/5.0 (compatible; ComplianceBot/1.0; +https://outlook-spam-scorer.pages.dev)';

async function handleCompliance(payload, env) {
  const audience = payload.audience === 'b2c' ? 'b2c' : 'b2b';
  let   domain   = (payload.domain || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (!domain) return json({ error: 'domain required' }, 400);

  // Strip mail-sub-domains like info.example.com → example.com when they look
  // like sending sub-domains. We try the full domain first, then the root.
  const candidates = [];
  candidates.push(domain);
  const parts = domain.split('.');
  if (parts.length > 2) candidates.push(parts.slice(-2).join('.'));

  // Resolve homepage (https first, then http, with and without www).
  let homepageHtml = null;
  let homepageUrl  = null;
  for (const d of candidates) {
    for (const variant of [`https://${d}`, `https://www.${d}`, `http://${d}`, `http://www.${d}`]) {
      const html = await safeFetch(variant);
      if (html) { homepageHtml = html; homepageUrl = variant; break; }
    }
    if (homepageHtml) { domain = d; break; }
  }

  if (!homepageHtml) {
    return json({
      error:     'homepage_unreachable',
      domain,
      audience,
      html:      buildComplianceHtmlUnreachable(domain, audience),
    });
  }

  const baseUrl = homepageUrl.replace(/\/+$/, '');

  // Discover legal-doc URLs from homepage anchors.
  const footerLinks = extractFooterLinks(homepageHtml, baseUrl);

  // Canonical fallback paths per doc type (DE + EN variants).
  const canonical = {
    impressum:    ['/impressum', '/imprint', '/de/impressum', '/legal-notice', '/legal/impressum', '/impressum/'],
    datenschutz:  ['/datenschutz', '/datenschutzerklaerung', '/datenschutzerklärung', '/privacy', '/privacy-policy', '/de/datenschutz', '/legal/datenschutz'],
    agb:          ['/agb', '/terms', '/terms-of-service', '/terms-and-conditions', '/de/agb', '/legal/agb'],
    widerruf:     ['/widerruf', '/widerrufsrecht', '/widerrufsbelehrung', '/cancellation', '/right-of-withdrawal'],
  };

  // Fetch documents (B2B: 2 docs, B2C: 4 docs).
  const docTypes = audience === 'b2c'
    ? ['impressum', 'datenschutz', 'agb', 'widerruf']
    : ['impressum', 'datenschutz'];

  const docs = {};
  for (const type of docTypes) {
    docs[type] = await findDocument(type, baseUrl, footerLinks[type], canonical[type]);
  }

  // Per-category checks.
  const results = {};
  results.impressum    = checkImpressum(docs.impressum);
  results.datenschutz  = checkDatenschutz(docs.datenschutz);
  if (audience === 'b2c') {
    results.agb        = checkAgb(docs.agb);
    results.widerruf   = checkWiderruf(docs.widerruf);
  }
  results.cookies      = checkCookies(homepageHtml);
  results.ssl          = checkSsl(homepageUrl);

  // Weighted overall score (0-100).
  const weights = audience === 'b2c'
    ? { impressum: 22, datenschutz: 28, agb: 16, widerruf: 18, cookies: 10, ssl: 6 }
    : { impressum: 30, datenschutz: 40, cookies: 18, ssl: 12 };
  let total = 0;
  for (const [k, w] of Object.entries(weights)) {
    total += (results[k].score / results[k].max) * w;
  }
  const overall = Math.round(total);

  const html = buildComplianceHtml({
    domain, audience, baseUrl,
    results, overall, weights,
    docs,
  });

  return jsonHtml(html);
}

// ── Fetch helpers ────────────────────────────────────────────────────────────

async function safeFetch(url, timeoutMs = 8000) {
  try {
    const ctrl = new AbortController();
    const t    = setTimeout(() => ctrl.abort(), timeoutMs);
    const res  = await fetch(url, {
      signal:   ctrl.signal,
      redirect: 'follow',
      headers: {
        'User-Agent':      COMPLIANCE_UA,
        'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'de-DE,de;q=0.9,en;q=0.7',
      },
    });
    clearTimeout(t);
    if (!res.ok) return null;
    const ct = res.headers.get('content-type') || '';
    if (!/text\/html|xhtml|application\/xml/i.test(ct)) return null;
    const text = await res.text();
    return text.length > 600_000 ? text.slice(0, 600_000) : text;
  } catch {
    return null;
  }
}

function extractFooterLinks(html, baseUrl) {
  const patterns = {
    impressum:   /(?:^|\s|>)(?:impressum|imprint|legal[\s-]?notice|mentions[\s-]?l[ée]gales)(?:\s|<|$)/i,
    datenschutz: /(?:^|\s|>)(?:datenschutz(?:erkl[äa]rung)?|privacy(?:[\s-]?policy)?|politique[\s-]?de[\s-]?confidentialit)(?:\s|<|$)/i,
    agb:         /(?:^|\s|>)(?:agb|allgemeine[\s-]gesch[äa]ftsbedingungen|terms(?:[\s-]of[\s-](?:use|service))?|conditions[\s-]g[ée]n[ée]rales)(?:\s|<|$)/i,
    widerruf:    /(?:^|\s|>)(?:widerruf(?:srecht|sbelehrung)?|right[\s-]of[\s-]withdrawal|cancellation[\s-]policy)(?:\s|<|$)/i,
  };
  const hrefPatterns = {
    impressum:   /\b(impressum|imprint|legal[-_]?notice)\b/i,
    datenschutz: /\b(datenschutz|privacy)\b/i,
    agb:         /\b(agb|terms)\b/i,
    widerruf:    /\b(widerruf|cancellation|withdrawal)\b/i,
  };

  const found = {};
  const anchorRe = /<a\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let m;
  while ((m = anchorRe.exec(html)) !== null) {
    const href = m[1].trim();
    const txt  = m[2].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
    for (const type of Object.keys(patterns)) {
      if (found[type]) continue;
      if (patterns[type].test(txt) || hrefPatterns[type].test(href)) {
        found[type] = resolveUrl(href, baseUrl);
      }
    }
  }
  return found;
}

function resolveUrl(href, baseUrl) {
  href = href.split('#')[0].trim();
  if (!href) return null;
  if (/^https?:\/\//i.test(href)) return href;
  if (href.startsWith('//')) return 'https:' + href;
  if (href.startsWith('/'))  return baseUrl.replace(/\/$/, '') + href;
  return baseUrl.replace(/\/$/, '') + '/' + href;
}

async function findDocument(type, baseUrl, footerUrl, canonicalPaths) {
  // 1. Try the URL we found via footer link first.
  if (footerUrl) {
    const html = await safeFetch(footerUrl);
    if (html && html.length > 500) {
      return { url: footerUrl, source: 'footer', text: htmlToText(html), html };
    }
  }
  // 2. Try canonical paths.
  for (const path of canonicalPaths) {
    const url  = baseUrl + path;
    const html = await safeFetch(url);
    if (html && html.length > 500) {
      return { url, source: 'canonical', text: htmlToText(html), html };
    }
  }
  return null;
}

function htmlToText(html) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|h\d|li|tr)>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;|&#160;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;|&#34;/gi, '"')
    .replace(/&#39;|&#x27;/gi, "'")
    .replace(/&auml;/gi, 'ä').replace(/&ouml;/gi, 'ö').replace(/&uuml;/gi, 'ü')
    .replace(/&Auml;/gi, 'Ä').replace(/&Ouml;/gi, 'Ö').replace(/&Uuml;/gi, 'Ü')
    .replace(/&szlig;/gi, 'ß')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n[ \t]+/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

// ── Heuristic compliance checks ──────────────────────────────────────────────
// Each returns { score, max, status: 'ok'|'partial'|'missing'|'fail', checks: [...], url, source }
// `checks` items: { label, weight, found: bool, evidence?: string, note?: string }

function mkResult(checks, doc, statusMissing = 'missing') {
  const max   = checks.reduce((s, c) => s + c.weight, 0);
  const score = checks.reduce((s, c) => s + (c.found ? c.weight : 0), 0);
  const ratio = max > 0 ? score / max : 0;
  const status = !doc            ? statusMissing
              :  ratio >= 0.85   ? 'ok'
              :  ratio >= 0.5    ? 'partial'
              :                    'weak';
  return { score, max, status, checks, url: doc?.url || null, source: doc?.source || null };
}

function checkImpressum(doc) {
  const text = doc?.text || '';
  const checks = [
    { label: 'Anbieter-Anschrift (Straße + PLZ + Ort)', weight: 2,
      found: /\b[A-ZÄÖÜ][a-zäöüß-]+(?:str(?:aße|\.)|gasse|allee|weg|platz|ring|damm)\s*\d+/i.test(text)
          && /\b\d{5}\s+[A-ZÄÖÜ][\wäöüß-]+/i.test(text),
      desc: 'Pflichtangabe nach § 5 Abs. 1 Nr. 1 TMG: vollständige ladungsfähige Anschrift mit Straße, Hausnummer, PLZ und Ort. Ein Postfach genügt nicht. Bei Verstoß drohen Abmahnungen nach UWG (Streitwerte typischerweise 5.000–15.000 €) sowie Bußgelder bis 50.000 € nach § 16 TMG. Lösung: vollständige Anschrift einfügen, an der die Gesellschaft tatsächlich erreichbar ist.' },
    { label: 'E-Mail-Kontakt', weight: 1.5,
      found: /[\w.+-]+@[\w-]+\.[a-z]{2,}/i.test(text),
      desc: 'Pflichtangabe nach § 5 Abs. 1 Nr. 2 TMG für schnelle elektronische Kontaktaufnahme. Mindestens eine funktionierende E-Mail-Adresse als Klartext oder mailto-Link. EuGH (Rs. C-298/07) verlangt zusätzlich einen zweiten unmittelbaren Kommunikationsweg (Telefon oder gleichwertig). Lösung: erreichbare E-Mail-Adresse + Telefon oder Online-Formular ergänzen.' },
    { label: 'Telefon', weight: 1,
      found: /(?:Tel(?:efon)?|Phone|Fon)\.?\s*[:.]?\s*[+\d][\d\s\-/()]{6,}/i.test(text)
          || /\+49[\s\d\-/()]{6,}/.test(text),
      desc: 'Nicht strikt im TMG vorgeschrieben, aber nach EuGH (Rs. C-298/07, „Bundesverband der Verbraucherzentralen") als zweiter unmittelbarer Kommunikationsweg neben E-Mail erforderlich. Im B2C darf eine Kunden-Hotline nicht teurer als ein normales Telefongespräch sein (§ 312a Abs. 5 BGB). Alternativ: Live-Chat oder Rückrufformular.' },
    { label: 'Handelsregister + Registernummer', weight: 1.5,
      found: /(?:Handelsregister|Amtsgericht).{0,80}\bHR[AB]\s*\d+/is.test(text)
          || /\bHR[AB]\s*\d{2,}/i.test(text),
      desc: 'Pflichtangabe nach § 5 Abs. 1 Nr. 4 TMG für alle im Handelsregister eingetragenen Unternehmen (GmbH, UG, AG, KG, OHG): zuständiges Registergericht + Registernummer, z. B. „Amtsgericht München, HRB 12345". Reguläre Abmahnungsfalle bei Online-Händlern. Einzelunternehmer und nicht eingetragene GbR sind von dieser Pflicht ausgenommen.' },
    { label: 'USt-IdNr. (§ 27a UStG) oder Wirtschafts-IdNr.', weight: 1.5,
      found: /\bDE\s?\d{9}\b/i.test(text) || /Umsatzsteuer[-\s]?(?:Ident|IdNr|ID)/i.test(text),
      desc: 'Pflichtangabe nach § 5 Abs. 1 Nr. 6 TMG, soweit vorhanden. Wer eine USt-IdNr. nach § 27a UStG zugeteilt bekommen hat (üblich bei innergemeinschaftlichem Handel), muss sie nennen. Keine Pflicht zur Beantragung — aber Verschweigen einer vorhandenen Nr. wird regelmäßig abgemahnt. Format: „DE" + 9 Ziffern.' },
    { label: 'Vertretungsberechtigte/r (Geschäftsführer, Vorstand, Inhaber)', weight: 1.5,
      found: /(?:Gesch[äa]ftsf[üu]hrer(?:in)?|Vorstand|Inhaber(?:in)?|vertretungsberechtigt)/i.test(text),
      desc: 'Pflichtangabe nach § 5 Abs. 1 Nr. 1 TMG. Bei juristischen Personen (GmbH, AG, eG, Verein) müssen alle vertretungsberechtigten Personen mit vollem Vor- und Nachnamen genannt werden. GmbH: alle Geschäftsführer. AG: Vorstand + Aufsichtsratsvorsitzender. Einzelfirma: Inhaber/-in.' },
    { label: 'Verantwortlich i. S. d. § 18 MStV (für journalistisch-redaktionelle Inhalte)', weight: 1,
      found: /(?:Verantwortlich(?:e[rs]?)?\s+(?:i\.\s*S\.\s*d\.\s*)?(?:§\s*18\s*MStV|MStV|RStV|Pressegesetz))/i.test(text)
          || /Verantwortlich.{0,30}(?:für\s+den\s+Inhalt|Inhalte)/i.test(text),
      desc: 'Zusätzliche Pflicht nach § 18 Abs. 2 MStV (Medienstaatsvertrag) bei journalistisch-redaktionellen Inhalten (Blog, News-Bereich, Magazinartikel mit Meinungsäußerung). Anzugeben: Verantwortliche/r mit Vor-/Nachname und ladungsfähiger Anschrift im EU-Raum. Bei reinen Produkt- oder Unternehmens-Sites ohne redaktionellen Anteil entfällt die Pflicht.' },
  ];
  return mkResult(checks, doc);
}

function checkDatenschutz(doc) {
  const text = doc?.text || '';
  const lower = text.toLowerCase();
  const checks = [
    { label: 'Verantwortlicher (Name + Kontakt)', weight: 1.5,
      found: /Verantwortlich(?:e[rs]?|en?)\s+(?:Stelle|i\.\s*S\.\s*d\.|für|im\s+Sinne)/i.test(text),
      desc: 'Pflichtangabe nach Art. 13 Abs. 1 lit. a DSGVO. Name, Anschrift und Kontaktdaten des Verantwortlichen müssen direkt zu Beginn der Datenschutzerklärung stehen, eindeutig zugeordnet (nicht nur Verweis ins Impressum). Bußgeldrisiko nach Art. 83 Abs. 5 DSGVO: bis 20 Mio. € oder 4 % des weltweiten Jahresumsatzes.' },
    { label: 'Datenschutzbeauftragte/r oder begründete Abweichung', weight: 1,
      found: /Datenschutzbeauftragt[er]?/i.test(text),
      desc: 'Bestellungspflicht nach Art. 37 DSGVO i. V. m. § 38 BDSG: in der Regel ab 20 mit automatisierter Datenverarbeitung beschäftigten Personen oder bei umfangreicher Verarbeitung besonderer Datenkategorien (Gesundheit, biometrische Daten etc.). Kontaktdaten des/der DSB sind nach Art. 13 Abs. 1 lit. b DSGVO mitzuteilen. Bei Nichterforderlichkeit: kurzer Hinweis empfehlenswert.' },
    { label: 'Rechtsgrundlagen (Art. 6 DSGVO)', weight: 1.5,
      found: /Art(?:ikel)?\.?\s*6\s+(?:Abs\.?\s*\d+\s+)?(?:lit\.?\s*[a-f]\s+)?DSGVO/i.test(text)
          || /Rechtsgrundlage/i.test(text),
      desc: 'Pflichtangabe nach Art. 13 Abs. 1 lit. c DSGVO. Pro Verarbeitungszweck ist die spezifische Rechtsgrundlage zu nennen — Einwilligung (Art. 6 Abs. 1 lit. a), Vertragserfüllung (lit. b), rechtliche Verpflichtung (lit. c), lebenswichtige Interessen (lit. d), öffentliche Aufgabe (lit. e), berechtigtes Interesse (lit. f). Eine pauschale Nennung „auf Basis Art. 6 DSGVO" reicht nicht.' },
    { label: 'Betroffenenrechte (Auskunft, Berichtigung, Löschung)', weight: 1.5,
      found: lower.includes('auskunft') && lower.includes('berichtigung') && /(?:l[öo]schung|recht\s+auf\s+vergessen)/i.test(text),
      desc: 'Pflichtinformation nach Art. 13 Abs. 2 lit. b DSGVO über die Rechte aus Art. 15–22 DSGVO. Vollständige Aufzählung mit kurzer Erläuterung: Auskunft (Art. 15), Berichtigung (Art. 16), Löschung / „Recht auf Vergessen" (Art. 17), Einschränkung (Art. 18), Datenübertragbarkeit (Art. 20), Widerspruch (Art. 21), Widerruf einer Einwilligung (Art. 7 Abs. 3).' },
    { label: 'Datenübertragbarkeit / Widerspruch', weight: 1,
      found: /Daten[üu]bertragbarkeit/i.test(text) && /Widerspruch/i.test(text),
      desc: 'Art. 20 DSGVO (Daten in strukturiertem, maschinenlesbarem Format) und Art. 21 DSGVO (Widerspruch gegen Verarbeitung auf Basis berechtigten Interesses oder Direktmarketing) sind ausdrücklich zu benennen. Der Widerspruchshinweis im Direktmarketing-Kontext ist optisch hervorzuheben (Art. 21 Abs. 4 DSGVO).' },
    { label: 'Beschwerderecht bei Aufsichtsbehörde', weight: 1,
      found: /Aufsichtsbeh[öo]rde/i.test(text) && /Beschwerde/i.test(text),
      desc: 'Pflichtangabe nach Art. 13 Abs. 2 lit. d DSGVO: Hinweis auf das Beschwerderecht bei einer Aufsichtsbehörde. In Deutschland: zuständige Landesdatenschutzbeauftragte (am Sitz des Verantwortlichen) oder BfDI bei Bundesbehörden und TK-Anbietern. Empfehlung: konkrete Behörde mit Anschrift nennen.' },
    { label: 'Speicherdauer / Löschkonzept', weight: 1,
      found: /Speicherdauer|Aufbewahrungsfrist|gespeichert(?:e?\s+wir)?d?/i.test(text)
          && /(?:gel[öo]scht|Lo+sch)/i.test(text),
      desc: 'Pflichtangabe nach Art. 13 Abs. 2 lit. a DSGVO: konkrete Speicherdauer oder mindestens die Kriterien für deren Festlegung. Übliche Bezüge: § 257 HGB (6 Jahre für Handelsbriefe), § 147 AO (10 Jahre für Buchungsbelege), § 14b UStG (10 Jahre für Rechnungen). Pauschale Formulierung „solange erforderlich" genügt nicht.' },
    { label: 'Cookies / Tracking-Tools', weight: 1,
      found: /Cookies?/i.test(text),
      desc: 'Pflichtangabe der eingesetzten Cookies und Tracking-Tools mit Zweck, Anbieter, Speicherdauer (Empfehlung: Übersichtstabelle pro Tool). Rechtsgrundlage über § 25 TTDSG (nachweisbare Einwilligung für nicht-essentielle Cookies) bzw. Art. 6 Abs. 1 lit. f DSGVO (berechtigtes Interesse) — letzteres nur für unbedingt erforderliche technische Cookies.' },
    { label: 'Drittlandsübermittlung (Art. 44 ff. DSGVO)', weight: 1,
      found: /Drittland|Drittstaat|außerhalb\s+der\s+EU|USA|Standardvertragsklausel|adequacy/i.test(text),
      desc: 'Pflichtangabe nach Art. 13 Abs. 1 lit. f DSGVO bei Übermittlungen in Drittländer (USA, UK seit Brexit, Indien etc.). Erforderlich: Empfänger nennen, Garantien benennen (Standardvertragsklauseln nach Art. 46 Abs. 2 lit. c, Angemessenheitsbeschluss z. B. EU-US Data Privacy Framework seit Juli 2023), Hinweis auf Erhalt einer Kopie der Garantien. Praktisch betroffen: Google, Meta, AWS, Microsoft, jedes US-SaaS.' },
    { label: 'Empfänger / Auftragsverarbeiter', weight: 0.5,
      found: /Auftragsverarbeit|Empf[äa]nger|Drittanbieter|Dienstleister/i.test(text),
      desc: 'Empfehlung nach Art. 13 Abs. 1 lit. e + Art. 28 DSGVO: Eingesetzte Auftragsverarbeiter (Hosting, Newsletter-Versand, Analytics, CDN, Payment-Provider, CRM) sollten zumindest als Kategorien, idealerweise namentlich benannt werden. Ein AV-Vertrag nach Art. 28 muss in jedem Fall vorliegen.' },
  ];
  return mkResult(checks, doc);
}

function checkAgb(doc) {
  const text = doc?.text || '';
  const checks = [
    { label: 'Vertragsschluss / Angebot + Annahme', weight: 1.5,
      found: /(?:Vertragsschluss|Vertragsabschluss|Zustandekommen\s+des\s+Vertrag|Angebot\s+und\s+Annahme)/i.test(text),
      desc: 'Pflichtinformation nach § 312i Abs. 1 BGB: Im Fernabsatz muss der Verbraucher VOR Abgabe der Bestellung über alle wesentlichen Vertragsbedingungen, den Ablauf des Bestellprozesses, die Korrekturmöglichkeit, die Sprache(n) und die Speicherbarkeit informiert werden. Zusätzlich verlangt § 312j Abs. 3 BGB die „Button-Lösung" mit eindeutiger Beschriftung („Zahlungspflichtig bestellen" o. ä.) — fehlt sie, kommt KEIN wirksamer Vertrag zustande.' },
    { label: 'Preise (Endpreise inkl. MwSt.)', weight: 1.5,
      found: /(?:inkl\.\s*MwSt|inklusive\s+(?:der\s+)?(?:gesetzlichen\s+)?(?:Mehrwert|Umsatz)steuer|Endpreis|Bruttopreis)/i.test(text),
      desc: 'Pflichtangabe nach § 1 Abs. 1 PAngV (Preisangabenverordnung): Im B2C sind Endpreise inkl. Mehrwertsteuer und aller sonstigen Preisbestandteile klar erkennbar auszuweisen. Verstoß: wettbewerbsrechtliche Abmahnung nach § 3a UWG (Streitwerte 3.000–10.000 €) und Bußgeld nach § 9 PAngV bis 25.000 €. Bei rein B2B-AGB nicht zwingend, aber empfehlenswert.' },
    { label: 'Zahlungsmodalitäten', weight: 1,
      found: /(?:Zahlung(?:smodalit|sbedingung|sart|sweise)|Zahlungsmittel)/i.test(text),
      desc: 'Pflichtinformation nach Art. 246a § 1 Abs. 1 Nr. 7 EGBGB: akzeptierte Zahlungsmittel, Liefer- und Leistungsbeschränkungen. § 270a BGB verbietet zusätzliche Entgelte für SEPA-Lastschrift, SEPA-Überweisung sowie gängige Kreditkartenzahlungen (Visa, Mastercard, Maestro). Erlaubte Aufpreise nur für tatsächlich teurere Bezahlmethoden (z. B. American Express, PayPal — letzteres umstritten).' },
    { label: 'Lieferung / Versandkosten', weight: 1.5,
      found: /(?:Lieferung|Versand(?:kosten|bedingung)|Lieferzeit)/i.test(text),
      desc: 'Pflichtinformation nach Art. 246a § 1 Abs. 1 Nr. 4 EGBGB + § 1 Abs. 2 PAngV: Konkrete Lieferzeit (kein „in der Regel sofort") und Versandkosten klar und separat ausgewiesen — Versandkosten dürfen nicht im Endpreis versteckt sein. Bei Ware aus dem Ausland: Hinweis auf Einfuhrabgaben.' },
    { label: 'Mängelhaftung / Gewährleistung', weight: 1.5,
      found: /(?:M[äa]ngelhaftung|Gew[äa]hrleistung|Sachmangel)/i.test(text),
      desc: 'Hinweis auf gesetzliche Mängelhaftung nach §§ 434 ff. BGB ist Pflicht. Im B2C: Verjährungsfrist mindestens 2 Jahre ab Übergabe (§ 438 Abs. 1 Nr. 3 BGB) — kürzere AGB-Klauseln sind nach § 309 Nr. 8b BGB unwirksam und gleichzeitig wettbewerbswidrig. Im B2B kann die Verjährung auf 1 Jahr verkürzt werden. Ausschluss der Mängelhaftung im B2C ist NIE wirksam.' },
    { label: 'Streitschlichtung (OS-Plattform / VSBG)', weight: 1,
      found: /(?:Streitschlichtung|Verbraucherschlichtung|Online[-\s]?Streitbeilegung|ec\.europa\.eu\/consumers\/odr|VSBG)/i.test(text),
      desc: 'Pflichthinweis nach Art. 14 Abs. 1 ODR-VO: Online-Händler müssen auf die EU-Plattform unter https://ec.europa.eu/consumers/odr verlinken (klickbarer Link). § 36 VSBG verlangt zusätzlich den Hinweis, ob das Unternehmen an Verbraucher-Streitbeilegung teilnimmt — auch ein klares „nein" ist zulässig, muss aber explizit erklärt werden. Häufigster Abmahngrund nach DSGVO-Verstößen.' },
    { label: 'Vertragstext / Speicherung', weight: 1,
      found: /(?:Vertragstext|Vertragssprache|Speicherung\s+des\s+Vertrag)/i.test(text),
      desc: 'Pflichtinformation nach § 312i Abs. 1 Nr. 4 BGB: Der Verbraucher muss den Vertragstext speichern und reproduzieren können. Praktisch: Bestellbestätigung als PDF per E-Mail, Login-Bereich mit Auftragsarchiv, oder Hinweis auf Speicherung der AGB. Bei längeren AGB ist Verlinkung statt Inline-Anzeige zulässig.' },
    { label: 'Salvatorische Klausel / anwendbares Recht', weight: 1,
      found: /(?:salvatorisch|anwendbares\s+Recht|Gerichtsstand|deutsches?\s+Recht)/i.test(text),
      desc: 'Bei B2C-Verträgen mit EU-Verbrauchern: Art. 6 Rom-I-VO bestimmt, dass zwingend das Verbraucherschutzrecht des Wohnsitzstaates anwendbar bleibt. Pauschale Rechtswahlklauseln „Es gilt deutsches Recht" sind nach BGH I ZR 88/16 (für österr./schweiz. Verbraucher) intransparent + wettbewerbswidrig. Im B2B ist die Rechtswahl weitestgehend frei.' },
  ];
  return mkResult(checks, doc);
}

function checkWiderruf(doc) {
  const text = doc?.text || '';
  const checks = [
    { label: '14-Tage-Frist', weight: 2,
      found: /14\s*Tag(?:e|en)/i.test(text) || /vierzehn\s+Tag/i.test(text),
      desc: 'Pflichtinformation nach § 355 Abs. 2 BGB + Art. 246a § 1 Abs. 2 Nr. 1 EGBGB: Widerrufsfrist beträgt 14 Tage. Bei nicht oder fehlerhaft erteilter Belehrung verlängert sich die Frist nach § 356 Abs. 3 BGB auf 12 Monate + 14 Tage. Erhebliches wirtschaftliches Risiko bei Verstoß — Verbraucher kann monatelang Ware zurückgeben.' },
    { label: 'Muster-Widerrufsformular', weight: 2,
      found: /Muster[-\s]?Widerrufs(?:formular|erkl)/i.test(text)
          || /(?:An:|Hiermit\s+widerrufe\s+ich)/i.test(text),
      desc: 'Pflicht nach Art. 246a § 1 Abs. 2 Nr. 1 EGBGB i. V. m. Anlage 2 zum EGBGB: Das amtliche Muster-Widerrufsformular muss zur Verfügung gestellt werden — wortgleich, vollständig, mit den eigenen Kontaktdaten ausgefüllt. Eigene Formularvarianten sind zusätzlich, nicht ersetzend zulässig. Klassische Abmahnfalle.' },
    { label: 'Rücksendekosten-Regelung', weight: 1.5,
      found: /(?:R[üu]cksendekosten|Kosten\s+der\s+R[üu]cksendung|trag(?:en|t)\s+(?:Sie|der\s+Verbraucher)\s+die\s+Kosten)/i.test(text),
      desc: 'Pflichtinformation nach Art. 246a § 1 Abs. 2 Nr. 2 EGBGB: Verbraucher trägt die Rücksendekosten NUR dann, wenn er vorher klar darauf hingewiesen wurde. Fehlt der Hinweis, gehen die Kosten zu Lasten des Unternehmers — auch bei sperrigen Gütern (Möbel, große Geräte). Bei sperriger Ware zusätzlich Schätzung der Kosten erforderlich, soweit nicht per Standardpost versendbar.' },
    { label: 'Widerrufsanschrift (Adresse / E-Mail / Fax)', weight: 1.5,
      found: /(?:An\s+wen|Widerruf.{0,30}richten|Anschrift\s+des\s+Unternehmer)/i.test(text)
          || /An:\s*[^,]{3,80}(?:\d{5}|@)/i.test(text),
      desc: 'Pflichtangabe nach Art. 246a § 1 Abs. 2 Nr. 1 EGBGB: Anschrift, Telefonnummer und E-Mail-Adresse, an die der Widerruf gerichtet werden kann. Alle drei Kanäle soweit vorhanden anzugeben — reine Postanschrift oder nur E-Mail genügt seit BGH-Rechtsprechung (I ZR 7/16) nicht. Faxnummer optional, sofern vorhanden.' },
    { label: 'Folgen des Widerrufs (Rückzahlung / Wertersatz)', weight: 1.5,
      found: /(?:Folgen\s+des\s+Widerruf|R[üu]ckzahlung|Werters(?:atz|atz))/i.test(text),
      desc: 'Pflichtinformation nach § 357 BGB i. V. m. Anlage 1 zum EGBGB: 14-Tage-Rückzahlungsfrist ab Widerrufserklärung — Rückzahlung über dasselbe Zahlungsmittel; Wertersatz nur bei wertmindernder Behandlung über das zur Prüfung der Beschaffenheit Erforderliche hinaus. Achtung: Bei fehlender oder fehlerhafter Belehrung entfällt der Wertersatzanspruch komplett (§ 357 Abs. 7 Nr. 2 BGB).' },
    { label: 'Fristbeginn (Erhalt der Ware / Vertragsschluss)', weight: 1.5,
      found: /(?:Frist\s+(?:beginnt|läuft)|ab\s+(?:dem\s+)?(?:Tag|Erhalt))/i.test(text),
      desc: 'Pflichtinformation nach § 356 Abs. 2 BGB: Bei Warenkäufen beginnt die Frist mit Erhalt der Ware (bei Teillieferungen mit der letzten Teillieferung; bei Sukzessivlieferungen mit Erhalt der ersten Ware). Bei Dienstleistungen: Vertragsschluss. Falsche Angabe = unwirksame Belehrung → Frist verlängert sich automatisch auf 12 Monate + 14 Tage.' },
  ];
  return mkResult(checks, doc);
}

function checkCookies(homepageHtml) {
  // Heuristic only — HTML-static check, no JS execution. We mark this clearly
  // in the report as indikatorisch.
  const cmpSignals = [
    { label: 'Cookiebot',     re: /cookiebot\.com|consent\.cookiebot/i },
    { label: 'Usercentrics',  re: /usercentrics\.eu|consent\.usercentrics/i },
    { label: 'OneTrust',      re: /cookielaw\.org|onetrust/i },
    { label: 'Borlabs',       re: /borlabs[-_]?cookie/i },
    { label: 'Klaro',         re: /klaro[-_]?config|kiprotect/i },
    { label: 'Termly',        re: /termly\.io/i },
    { label: 'CookieYes',     re: /cookieyes/i },
    { label: 'Iubenda',       re: /iubenda/i },
    { label: 'Complianz',     re: /complianz/i },
  ];
  const detected = cmpSignals.find(s => s.re.test(homepageHtml));
  const hasCookieMention   = /cookie/i.test(homepageHtml);
  const hasConsentLanguage = /(?:einverstanden|zustimm|akzeptier|consent|accept|reject|ablehn)/i.test(homepageHtml);

  const checks = [
    { label: detected ? `Consent-Management-Plattform erkannt (${detected.label})` : 'Consent-Management-Plattform (CMP)',
      weight: 2, found: !!detected,
      note: detected ? null : 'kein bekanntes CMP-Skript im HTML — möglich, dass eigene Lösung verwendet wird',
      desc: 'TTDSG § 25 Abs. 1 (in Kraft seit 1.12.2021): Speicherung oder Auslesen von Informationen im Endgerät (Cookies, LocalStorage, Fingerprinting) ist nur mit nachweisbarer Einwilligung zulässig. Ausnahme: unbedingt erforderliche technische Cookies (Warenkorb, Login-Session, Spracheinstellung — § 25 Abs. 2 TTDSG). Eine zertifizierte CMP (Cookiebot, Usercentrics, OneTrust, Borlabs, Klaro u. a.) ist der Standardweg zur Compliance + revisionssicherer Nachweis der Einwilligung.' },
    { label: 'Cookie-Banner-Hinweis im HTML', weight: 1, found: hasCookieMention,
      desc: 'Cookie-Banner muss erscheinen BEVOR nicht-essentielle Cookies gesetzt werden (Pre-Consent-Tracking ist nach BGH I ZR 7/16 „Planet49" und EuGH C-673/17 unzulässig). Reine Information „Wir verwenden Cookies" ohne Aktionsmöglichkeit reicht nicht — der Nutzer muss aktiv einwilligen können.' },
    { label: 'Consent-Sprache (akzeptieren / ablehnen)', weight: 1, found: hasConsentLanguage,
      note: 'Heuristisch über HTML — echte Opt-in/Reject-Gleichwertigkeit erfordert Live-Test im Browser',
      desc: 'EDSA-Leitlinien 03/2022 + DSK-Beschluss vom März 2022: „Akzeptieren" und „Ablehnen" müssen auf der gleichen Ebene mit gleicher visueller Hervorhebung verfügbar sein. „Dark Patterns" wie farblich hervorgehobener Akzeptieren-Button bei verstecktem „Nur erforderliche" oder mehrfacher Klicktiefe zum Ablehnen sind nach OLG Köln (6 U 80/22) wettbewerbswidrig und bußgeldbewehrt (CNIL-Bußgeld Google 150 Mio. €, Facebook 60 Mio. € für ähnliches Muster).' },
  ];
  return mkResult(checks, { url: '(Homepage)', source: 'homepage', text: homepageHtml });
}

function checkSsl(homepageUrl) {
  const isHttps = /^https:/i.test(homepageUrl);
  const checks = [
    { label: 'Homepage über HTTPS erreichbar', weight: 1, found: isHttps,
      note: isHttps ? null : 'Pflicht nach DSGVO Art. 32 (Datenintegrität bei Übertragung)',
      desc: 'DSGVO Art. 32 verlangt geeignete technische und organisatorische Maßnahmen zur Sicherheit der Verarbeitung. TLS-Verschlüsselung gilt als anerkannter Stand der Technik bei der Übertragung personenbezogener Daten (Kontaktformular, Newsletter, Login, Bestellprozess). Bei Verstoß: Bußgeldrisiko nach Art. 83 Abs. 4 DSGVO bis 10 Mio. € oder 2 % des weltweiten Jahresumsatzes. Let\'s Encrypt bietet kostenfreie Zertifikate mit automatischer Erneuerung.' },
  ];
  return mkResult(checks, { url: homepageUrl, source: 'homepage', text: '' });
}

// ── Report HTML builder ──────────────────────────────────────────────────────

function buildComplianceHtml({ domain, audience, baseUrl, results, overall, weights, docs }) {
  const date     = new Date().toISOString().slice(0, 10);
  const title    = audience === 'b2c' ? 'B2C-Compliance-Report' : 'B2B-Compliance-Report';
  const statusBadge = s =>
    s === 'ok'      ? '<span class="status status-ok">erfüllt</span>'
   : s === 'partial' ? '<span class="status status-partial">Lücken</span>'
   : s === 'weak'    ? '<span class="status status-weak">unzureichend</span>'
   :                   '<span class="status status-missing">nicht gefunden</span>';

  const categoryLabels = {
    impressum:   'Impressum (§ 5 TMG / § 18 MStV)',
    datenschutz: 'Datenschutzerklärung (DSGVO Art. 13/14)',
    agb:         'Allgemeine Geschäftsbedingungen',
    widerruf:    'Widerrufsbelehrung (§ 312g BGB)',
    cookies:     'Cookies & Tracking (TTDSG § 25 – indikatorisch)',
    ssl:         'Transportverschlüsselung (HTTPS)',
  };

  const summaryRows = Object.entries(results).map(([key, r]) => `
    <tr>
      <td class="cat">${escR(categoryLabels[key])}</td>
      <td class="status-cell">${statusBadge(r.status)}</td>
      <td class="ratio">${r.score.toFixed(1)} / ${r.max} Pflichtangaben</td>
      <td class="weight">Gewicht: ${weights[key]}%</td>
    </tr>`).join('');

  const docSections = Object.entries(results).filter(([k]) => !['cookies', 'ssl'].includes(k)).map(([key, r]) => `
    <section class="doc-section" id="sec-${key}">
      <h2>${escR(categoryLabels[key])} ${statusBadge(r.status)}</h2>
      ${r.url
        ? `<p class="src">Geprüfte URL: <a href="${escR(r.url)}" target="_blank" rel="noopener">${escR(r.url)}</a>
             <span class="src-mode">(${r.source === 'footer' ? 'über Footer-Link' : 'kanonischer Pfad'})</span></p>`
        : `<p class="src src-missing">Keine Seite gefunden — weder über Footer-Links noch unter kanonischen Pfaden erreichbar.</p>`}
      <table class="checks">
        <thead><tr><th></th><th>Prüfpunkt</th><th>Gewicht</th><th>Nachweis</th></tr></thead>
        <tbody>
          ${r.checks.map(c => renderCheckRow(c, 4)).join('')}
        </tbody>
      </table>
    </section>`).join('');

  const cookiesSection = `
    <section class="doc-section" id="sec-cookies">
      <h2>${escR(categoryLabels.cookies)} ${statusBadge(results.cookies.status)}</h2>
      <p class="indikator">⚙ Diese Kategorie ist <strong>indikatorisch</strong>. Eine belastbare Cookie-Prüfung (Opt-in / Reject-Gleichwertigkeit, Pre-Consent-Tracking) erfordert einen Live-Test im Browser mit gestopptem JavaScript-Renderer; HTML-Statik zeigt nur, ob ein CMP eingebunden ist.</p>
      <table class="checks">
        <thead><tr><th></th><th>Prüfpunkt</th><th>Gewicht</th><th>Hinweis</th></tr></thead>
        <tbody>
          ${results.cookies.checks.map(c => renderCheckRow(c, 4)).join('')}
        </tbody>
      </table>
    </section>`;

  const sslSection = `
    <section class="doc-section" id="sec-ssl">
      <h2>${escR(categoryLabels.ssl)} ${statusBadge(results.ssl.status)}</h2>
      <table class="checks">
        <tbody>
          ${results.ssl.checks.map(c => renderCheckRow(c, 2)).join('')}
        </tbody>
      </table>
    </section>`;

  const recs = buildRecommendations(results, audience);
  const recsBlock = recs.length ? `
    <section class="recs">
      <h2>Empfehlungen</h2>
      <ol>${recs.map(r => `<li>${escR(r)}</li>`).join('')}</ol>
    </section>` : '';

  // Hidden score data — not rendered, only readable via data attributes.
  const scoreData = Object.entries(results).map(([k, r]) =>
    `data-score-${k}="${(r.score / r.max * 100).toFixed(1)}"`).join(' ');

  return `<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<title>${escR(title)} — ${escR(domain)} (${date})</title>
<style>
${COMPLIANCE_CSS}
</style>
</head>
<body data-audience="${audience}" data-domain="${escR(domain)}" data-overall-score="${overall}" ${scoreData}>
<header class="report-head">
  <div class="head-row">
    <div><h1>${escR(title)}</h1>
    <p class="meta">Domain: <strong>${escR(domain)}</strong> · Homepage: <a href="${escR(baseUrl)}" target="_blank" rel="noopener">${escR(baseUrl)}</a> · Geprüft: ${date}</p></div>
    <div class="logo-block">Thomas Felber<br><a href="mailto:felber@live.de" class="logo-sub">felber@live.de</a><br><span class="logo-tag">Compliance-Assessment</span></div>
  </div>
  <div class="disclaimer">
    <strong>⚠ Wichtiger Hinweis:</strong> Dieser Report wurde <em>automatisiert</em> auf Basis öffentlich abrufbarer Inhalte erstellt. Er ist eine <strong>technische Indikation</strong>, ersetzt <strong>keine Rechtsberatung</strong> und keine anwaltliche Einzelfallprüfung. Eine fehlende Übereinstimmung bedeutet nicht zwangsläufig einen Rechtsverstoß; eine erkannte Übereinstimmung kein vollständiger Rechtskonformitätsnachweis.
  </div>
</header>

<section class="summary">
  <h2>Übersicht</h2>
  <table class="overview">
    <thead><tr><th>Kategorie</th><th>Status</th><th>Pflichtangaben</th><th></th></tr></thead>
    <tbody>${summaryRows}</tbody>
  </table>
</section>

${docSections}
${cookiesSection}
${sslSection}
${recsBlock}

<footer class="report-foot">
  <p>Erstellt durch automatisiertes Compliance-Assessment · ${date} · Methodik: HTML-Parsing &amp; Regex-Heuristik (kein Headless-Browser, keine Rechtsberatung).</p>
</footer>
</body>
</html>`;
}

// Render a single check row + an inline detail row (only when the check failed
// AND we have a `desc` for it). The detail row spans all but the icon column
// to align the legal explanation visually under the check label.
function renderCheckRow(c, totalCols) {
  const ssCols = totalCols - 1; // spanned columns under the icon
  const main = `
    <tr class="${c.found ? 'check-found' : 'check-missing'}">
      <td class="icon">${c.found ? '✓' : '✗'}</td>
      <td>${escR(c.label)}${c.note ? `<div class="check-note">${escR(c.note)}</div>` : ''}</td>
      ${totalCols >= 3 ? `<td class="w">${c.weight ?? ''}</td>` : ''}
      ${totalCols >= 4 ? `<td class="ev">${c.found ? 'gefunden' : '—'}</td>` : ''}
    </tr>`;
  if (c.found || !c.desc) return main;
  return main + `
    <tr class="check-detail-row">
      <td></td>
      <td colspan="${ssCols}" class="check-detail">
        <span class="check-detail-tag">Detail</span>
        ${escR(c.desc)}
      </td>
    </tr>`;
}

function buildRecommendations(results, audience) {
  const recs = [];
  for (const [key, r] of Object.entries(results)) {
    if (!r) continue;
    if (r.status === 'missing') {
      const label = key === 'impressum'   ? 'Impressum'
                  : key === 'datenschutz' ? 'Datenschutzerklärung'
                  : key === 'agb'         ? 'AGB'
                  : key === 'widerruf'    ? 'Widerrufsbelehrung'
                  : key;
      recs.push(`${label}: keine Seite auffindbar — Pflichtdokument anlegen und im Footer prominent verlinken (Direktzugriff per Klick ohne weitere Navigation gefordert nach § 5 TMG bzw. DSGVO Art. 13).`);
      continue;
    }
    const missing = (r.checks || []).filter(c => !c.found);
    if (missing.length === 0) continue;
    const top = missing.slice(0, 3).map(c => c.label).join('; ');
    if (key === 'impressum')   recs.push(`Impressum ergänzen: ${top}.`);
    if (key === 'datenschutz') recs.push(`Datenschutzerklärung ergänzen: ${top}.`);
    if (key === 'agb')         recs.push(`AGB ergänzen: ${top}.`);
    if (key === 'widerruf')    recs.push(`Widerrufsbelehrung ergänzen: ${top}.`);
    if (key === 'cookies' && audience !== 'b2b-only')
      recs.push(`Cookie-Compliance: ${top}. Empfehlung: ein zertifiziertes CMP (Cookiebot, Usercentrics, Borlabs) mit gleichwertigem Reject-Button einsetzen.`);
    if (key === 'ssl' && r.status !== 'ok')
      recs.push('HTTPS aktivieren (Let\'s Encrypt-Zertifikat ist kostenfrei) — Datenübertragung muss nach DSGVO Art. 32 verschlüsselt erfolgen.');
  }
  return recs;
}

function buildComplianceHtmlUnreachable(domain, audience) {
  const date = new Date().toISOString().slice(0, 10);
  return `<!DOCTYPE html>
<html lang="de"><head><meta charset="utf-8"><title>Compliance-Report — ${escR(domain)}</title>
<style>${COMPLIANCE_CSS}</style></head>
<body data-audience="${audience}" data-domain="${escR(domain)}" data-overall-score="0" data-status="unreachable">
<header class="report-head"><h1>Compliance-Assessment fehlgeschlagen</h1>
<p class="meta">Domain: <strong>${escR(domain)}</strong> · ${date}</p></header>
<section class="summary">
<p class="src-missing">Die Homepage unter <code>https://${escR(domain)}</code> war nicht erreichbar (auch <code>www.${escR(domain)}</code> und HTTP-Varianten geprüft).</p>
<p>Mögliche Ursachen: Domain existiert nicht, Server nicht erreichbar, Bot-Block (Cloudflare/Akamai), JavaScript-Pflicht für Initial-Response. Ein automatisierter Compliance-Check ist auf erreichbares HTML angewiesen.</p>
</section></body></html>`;
}

const COMPLIANCE_CSS = `
* { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 1100px; margin: 0 auto; padding: 32px 24px; color: #1a1a1a; line-height: 1.55; }
h1 { font-size: 26px; margin: 0 0 6px; }
h2 { font-size: 18px; margin: 32px 0 12px; padding-bottom: 8px; border-bottom: 2px solid #e5e7eb; display: flex; align-items: center; gap: 12px; }
.report-head { padding-bottom: 18px; border-bottom: 2px solid #1a1a1a; margin-bottom: 8px; }
.head-row { display: flex; justify-content: space-between; align-items: flex-start; gap: 24px; }
.logo-block { text-align: right; font-weight: 600; font-size: 13px; color: #444; }
.logo-sub { font-weight: 400; font-size: 11px; color: #888; text-decoration: none; }
.logo-sub:hover { text-decoration: underline; }
.logo-tag { font-weight: 400; font-size: 11px; color: #888; }
.meta { color: #666; font-size: 13px; margin: 0; }
.disclaimer { background: #fff7ed; border-left: 4px solid #ea580c; padding: 12px 16px; margin-top: 18px; font-size: 13px; border-radius: 4px; }
table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 13px; }
table.overview th, table.overview td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }
table.overview th { background: #f9fafb; font-weight: 600; }
table.checks th, table.checks td { padding: 8px 10px; text-align: left; border-bottom: 1px solid #f3f4f6; vertical-align: top; }
table.checks th { background: #f9fafb; font-weight: 600; font-size: 12px; color: #555; }
table.checks .icon { width: 28px; font-weight: 700; font-size: 16px; }
table.checks .w { width: 60px; color: #888; }
table.checks .ev { width: 30%; color: #555; }
.check-found .icon { color: #16a34a; }
.check-missing .icon { color: #dc2626; }
.check-missing td { color: #555; }
.check-note { font-size: 11px; color: #888; margin-top: 4px; }
.check-detail-row td { border-bottom: 1px solid #f3f4f6; background: #fef2f2; padding: 0; }
.check-detail { padding: 10px 14px 12px !important; font-size: 12px; line-height: 1.55; color: #555; }
.check-detail-tag { display: inline-block; font-size: 10px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase; color: #b91c1c; background: #fee2e2; padding: 2px 7px; border-radius: 3px; margin-right: 8px; vertical-align: middle; }
.status { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px; }
.status-ok      { background: #dcfce7; color: #15803d; }
.status-partial { background: #fef3c7; color: #92400e; }
.status-weak    { background: #fee2e2; color: #b91c1c; }
.status-missing { background: #f3f4f6; color: #525252; }
.doc-section { margin-top: 24px; }
.src { font-size: 12px; color: #555; margin: 4px 0 12px; }
.src a { color: #1e40af; text-decoration: none; }
.src a:hover { text-decoration: underline; }
.src-mode { color: #888; }
.src-missing { color: #b91c1c; }
.indikator { background: #f3f4f6; padding: 10px 14px; border-radius: 4px; font-size: 12px; color: #444; margin: 8px 0 12px; }
.recs { margin-top: 32px; padding: 16px 20px; background: #f0f9ff; border-left: 4px solid #0284c7; border-radius: 4px; }
.recs h2 { border: none; margin-top: 0; padding: 0; }
.recs ol { margin: 8px 0 0 18px; padding: 0; }
.recs li { margin-bottom: 8px; font-size: 13px; }
.report-foot { margin-top: 48px; padding-top: 16px; border-top: 1px solid #e5e7eb; font-size: 11px; color: #888; }
.cat { font-weight: 500; }
.ratio, .weight { color: #666; font-size: 12px; }
`;

function escR(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}

// ── D1 persistence ───────────────────────────────────────────────────────────

async function handleSave(payload, env) {
  if (!env.DB)                              return json({ error: 'D1 not configured' }, 503);
  if (payload.saveToken !== env.SAVE_TOKEN) return json({ error: 'Unauthorized' }, 401);

  const { domain, sender, subject, emailDate, addinScore, aiScore, esp, type = 'report', html, notes } = payload;

  if (!domain || !html) return json({ error: 'domain and html required' }, 400);

  // Idempotent save: same (sender, subject, type) overwrites prior row.
  // User-requested behaviour — only the latest assessment per email is kept,
  // no historical revisions. `IS` handles NULL-safe equality (SQLite-specific).
  const existing = await env.DB.prepare(
    `SELECT id FROM reports
     WHERE sender IS ? AND subject IS ? AND type IS ?
     ORDER BY id DESC LIMIT 1`
  ).bind(sender || null, subject || null, type).first();

  if (existing) {
    await env.DB.prepare(
      `UPDATE reports
       SET domain      = ?,
           email_date  = ?,
           addin_score = ?,
           ai_score    = ?,
           esp         = ?,
           html        = ?,
           notes       = ?,
           created_at  = CURRENT_TIMESTAMP
       WHERE id = ?`
    ).bind(
      domain, emailDate || null,
      addinScore ?? null, aiScore ?? null, esp || null,
      html, notes || null,
      existing.id
    ).run();
    return json({ ok: true, id: existing.id, updated: true });
  }

  const result = await env.DB.prepare(
    `INSERT INTO reports (domain, sender, subject, email_date, addin_score, ai_score, esp, type, html, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    domain, sender || null, subject || null, emailDate || null,
    addinScore ?? null, aiScore ?? null, esp || null,
    type, html, notes || null
  ).run();

  return json({ ok: true, id: result.meta.last_row_id, updated: false });
}

async function handleList(payload, env) {
  if (!env.DB) return json({ error: 'D1 not configured' }, 503);

  const { results } = await env.DB.prepare(
    `SELECT id, domain, sender, subject, email_date, addin_score, ai_score, esp, type, notes, created_at
     FROM reports ORDER BY created_at DESC LIMIT 500`
  ).all();

  return json({ reports: results });
}

async function handleGet(payload, env) {
  if (!env.DB) return json({ error: 'D1 not configured' }, 503);

  const { id } = payload;
  if (!id) return json({ error: 'id required' }, 400);

  const row = await env.DB.prepare('SELECT html FROM reports WHERE id = ?').bind(id).first();
  if (!row) return new Response('Not found', { status: 404, headers: CORS_HEADERS });

  return new Response(row.html, {
    status: 200,
    headers: { ...CORS_HEADERS, 'Content-Type': 'text/html; charset=utf-8' },
  });
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

  // Detect ESP from Feedback-ID or hostname patterns
  const feedbackId   = (headers.match(/^Feedback-ID:\s*(.+)/im) || [])[1] || '';
  const espName      = /sendinblue|brevo/i.test(feedbackId + ptrHost) ? 'Sendinblue/Brevo'
                     : /mailchimp|mandrill/i.test(feedbackId + ptrHost) ? 'Mailchimp/Mandrill'
                     : /mailjet/i.test(feedbackId + ptrHost) ? 'Mailjet'
                     : /cleverreach/i.test(feedbackId + ptrHost) ? 'CleverReach'
                     : null;

  // Auth status for shared-IP guard
  const authLine   = headers.match(/^Authentication-Results:(.+(?:\r?\n[ \t].+)*)/im)?.[1] || '';
  const authOk     = /spf=pass/i.test(authLine) && /dkim=pass/i.test(authLine) && /dmarc=pass/i.test(authLine);
  const bclM       = headers.match(/BCL:(\d+)/i);
  const bclVal     = bclM ? parseInt(bclM[1], 10) : 0;

  // Build a verified-facts / forbidden-recommendations block placed AFTER headers
  // (recency effect: model reads this last and it overrides inferences from raw headers)
  const verifiedFacts = [];
  if (ptrHost)
    verifiedFacts.push(`PTR/Reverse-DNS für ${sendingIp} ist bereits konfiguriert: "${ptrHost}" — PTR-Einrichtung NICHT empfehlen`);
  if (espName)
    verifiedFacts.push(`ESP erkannt: ${espName} — "dedizierte IP beschaffen" NICHT empfehlen wenn der Sender erst wächst; stattdessen Warmup-Strategie und Engagement empfehlen`);
  if (authOk && bclVal < 4)
    verifiedFacts.push(`SPF/DKIM/DMARC/compauth sind alle grün und BCL < 4 — Authentifizierungsgrundlagen sind vollständig korrekt konfiguriert; keine Basis-Auth-Empfehlungen die das ignorieren`);

  // Build exclamation-mark interpretation guidance if the signal appears in the list
  const exclSignal = (addinSignals || []).find(s => /ausrufezeichen/i.test(s));
  const exclBlock = exclSignal
    ? `\n=== AUSRUFEZEICHEN — INTERPRETATIONSHINWEISE ===
Signal: "${exclSignal}"
Kontext für die Empfehlung:
- Density-Wert (pro 100 Wörter) ist das Primärsignal: B2B-E-Mails vertragen max. ~0.5/100, B2C-Newsletter bis ~1.5/100
- 2+ Ausrufezeichen im Betreff: eigenständiges starkes Signal (Betreff ist das erste, was Filter und Empfänger bewerten)
- Aufeinanderfolgende !! (doppelte Ausrufezeichen): aggressiv, zerstört Seriosität bei professionellen Empfängern
- Empfehle spezifisch: Anzahl nennen, Kontext (B2B/B2C) explizit einschätzen, und den tatsächlichen Effekt erklären (nicht nur "vermeiden")
`
    : '';

  const verifiedBlock = verifiedFacts.length
    ? `\n=== VERIFIZIERTE FAKTEN — DIESE PUNKTE NICHT ERNEUT EMPFEHLEN ===\n${verifiedFacts.map(f => `✓ ${f}`).join('\n')}\n`
    : '';

  return `Analysiere diesen Spam-Bericht und erstelle priorisierte Empfehlungen für den ABSENDER.

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
${bodyText.slice(0, 800)}
${exclBlock}${verifiedBlock}`;
}
