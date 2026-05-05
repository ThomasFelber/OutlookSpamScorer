/**
 * Cloudflare Worker — Claude AI spam analysis proxy
 *
 * Receives email data from the Outlook task pane, calls the Claude API,
 * and returns a structured spam verdict. The API key is stored as a
 * Worker secret (ANTHROPIC_API_KEY) and is never exposed to the client.
 */

const ALLOWED_ORIGIN = 'https://outlook-spam-scorer.pages.dev';
const CLAUDE_MODEL   = 'claude-haiku-4-5';
const MAX_TOKENS     = 1024;

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

    const { headers = '', bodyText = '', subject = '', senderEmail = '', origSrcUrls = [] } = payload;

    if (!headers && !bodyText) {
      return json({ error: 'No email data provided' }, 400);
    }

    // Trim to avoid huge token counts
    const trimmedHeaders  = headers.slice(0, 4000);
    const trimmedBodyText = bodyText.slice(0, 3000);

    const userPrompt = buildPrompt(trimmedHeaders, trimmedBodyText, subject, senderEmail, origSrcUrls);

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
          model:      CLAUDE_MODEL,
          max_tokens: MAX_TOKENS,
          system: [
            {
              type: 'text',
              text: `You are an expert email security analyst specialising in spam and phishing detection.
Analyse the provided email data carefully and respond with a single JSON object — no prose, no markdown fences.

JSON shape:
{
  "verdict":    "spam" | "ham" | "uncertain",
  "confidence": <integer 0–100>,
  "score":      <integer 0–10>,
  "signals":    ["<specific finding>", ...],
  "summary":    "<1–2 sentences in German explaining the verdict>"
}`,
              // Prompt caching for the static system prompt
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

    // Extract the text content from the response
    const rawText = claudeResponse.content?.[0]?.text ?? '';

    let analysis;
    try {
      // Claude should return pure JSON, but strip markdown fences just in case
      const cleaned = rawText.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '').trim();
      analysis = JSON.parse(cleaned);
    } catch {
      // Fallback: return raw text so the UI can still show something
      analysis = { verdict: 'uncertain', confidence: 0, score: null, signals: [], summary: rawText };
    }

    return json(analysis);
  },
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
  });
}

// ── Header helpers ────────────────────────────────────────────────────────────

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

// ── Prompt builder ────────────────────────────────────────────────────────────

function buildPrompt(headers, bodyText, subject, senderEmail, origSrcUrls = []) {
  // ── Extract key signals ───────────────────────────────────────────────────
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

  // Microsoft Exchange verdicts
  const scl        = getHdr(headers, 'X-MS-Exchange-Organization-SCL');
  const antispam   = getHdr(headers, 'X-Microsoft-Antispam') || '';
  const bcl        = (antispam.match(/BCL:(\d+)/) || [])[1] ?? null;
  const delivery   = getHdr(headers, 'X-Microsoft-Antispam-Mailbox-Delivery') || '';
  const destJunk   = /dest:J/i.test(delivery);
  const ofrJunk    = /OFR:SpamFilter/i.test(delivery);

  // Pattern signals
  const mergeTag       = /\{[A-Za-z][^}]{0,25}\}/.test(subject);
  const brokenEncoding = /Ã¶|Ã¼|Ã¤|Ã–/.test(bodyText + subject);
  const hasShortener   = /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly/i.test(bodyText);
  const canSpamBox     = /\bSte\.?\s+\d+\s*#\s*\d+|\bPMB\s*\d+/i.test(bodyText);
  const affiliateDiscl = /verwaltet\s+ihr\s+abonnement\s+nicht|does not manage your subscri/i.test(bodyText);

  // ── Alignment section ─────────────────────────────────────────────────────
  const align = (domain, label) => {
    if (!domain) return null;
    const match = domain === fromDomain;
    return `${label.padEnd(16)} ${domain.padEnd(40)} ${match ? '✓ aligned' : '⚠ MISMATCH'}`;
  };

  const alignLines = [
    fromDomain       ? `${'Von (From)'.padEnd(16)} ${fromDomain.padEnd(40)} (reference)` : null,
    align(returnPathDomain, 'Return-Path'),
    align(dkimDomain,       'DKIM d='),
    align(replyToDomain,    'Reply-To'),
  ].filter(Boolean).join('\n');

  // ── SCL description ───────────────────────────────────────────────────────
  const sclN   = scl ? parseInt(scl, 10) : null;
  const sclDesc = sclN == null       ? 'not present'
                : sclN <= 4          ? `${sclN} (clean)`
                : sclN <= 6          ? `${sclN} → JUNK (threshold 5–6)`
                :                     `${sclN} → SPAM (threshold 7–9)`;

  // ── HELO mismatch ─────────────────────────────────────────────────────────
  const receivedSpf2 = getHdr(headers, 'Received-SPF') || '';
  const heloM2       = receivedSpf2.match(/helo=([\w.-]+)/i);
  const heloDomain   = heloM2?.[1]?.toLowerCase() ?? null;
  const heloMismatch = heloDomain && fromDomain
    && heloDomain !== fromDomain
    && !heloDomain.endsWith('.' + fromDomain)
    && !fromDomain.endsWith('.' + heloDomain);

  // ── originalsrc (real URLs behind Microsoft Safe Links) ───────────────────
  const origSrcSection = origSrcUrls.length > 0
    ? `\n=== REAL LINK DESTINATIONS (unwrapped from Safe Links) ===\n${origSrcUrls.slice(0, 10).join('\n')}`
    : '';

  // ── Alignment (extended with HELO) ────────────────────────────────────────
  const alignLinesExt = [
    ...alignLines.split('\n').filter(Boolean),
    heloDomain ? `${'HELO'.padEnd(16)} ${heloDomain.padEnd(40)} ${heloMismatch ? '⚠ MISMATCH' : '✓ aligned'}` : null,
  ].filter(Boolean).join('\n');

  // ── Compose prompt ────────────────────────────────────────────────────────
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
