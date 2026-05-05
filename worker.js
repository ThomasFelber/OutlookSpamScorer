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

    const { headers = '', bodyText = '', subject = '', senderEmail = '' } = payload;

    if (!headers && !bodyText) {
      return json({ error: 'No email data provided' }, 400);
    }

    // Trim to avoid huge token counts
    const trimmedHeaders  = headers.slice(0, 4000);
    const trimmedBodyText = bodyText.slice(0, 3000);

    const userPrompt = buildPrompt(trimmedHeaders, trimmedBodyText, subject, senderEmail);

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

function buildPrompt(headers, bodyText, subject, senderEmail) {
  return `Analyse this email and return a JSON verdict.

SUBJECT:  ${subject}
FROM:     ${senderEmail}

=== RAW HEADERS ===
${headers}

=== BODY (plain text) ===
${bodyText}`;
}
