#!/usr/bin/env python3
"""Bulk-import all Delivery-Reports HTML files into D1 via the Worker save endpoint."""

import os, re, json, urllib.request, urllib.error
from pathlib import Path

WORKER_URL  = 'https://spam-scorer-ai.felber.workers.dev'
SAVE_TOKEN  = 'XWqnAysvnXKpA6VAnOt6llM3OqHSq6J4HERW-xrwtWE'
BASE        = Path('/Users/thomas/Documents/OutlookSpamScorer/Delivery-Reports')
SKIP        = {'index.html', 'db.html'}

ESP_KEYWORDS = [
    ('Mailjet',        ['mailjet']),
    ('Sinch',          ['sinch']),
    ('Emarsys',        ['emarsys']),
    ('Klaviyo',        ['klaviyo']),
    ('Salesforce',     ['exacttarget', 'salesforce', 'sfmc']),
    ('Braze',          ['braze']),
    ('Iterable',       ['iterable']),
    ('Amazon SES',     ['amazonses', 'amazon ses']),
    ('Sendgrid',       ['sendgrid']),
    ('Mailchimp',      ['mailchimp']),
    ('Rapidmail',      ['rapidmail']),
    ('CleverReach',    ['cleverreach']),
    ('Newsletter2Go',  ['newsletter2go']),
    ('Inxmail',        ['inxmail']),
    ('Episerver',      ['episerver', 'optimizely']),
]

def extract_meta(html: str, domain: str, filename: str) -> dict:
    low = html.lower()

    # type
    if 'anschreiben' in filename:
        ftype = 'anschreiben'
    elif 'aktionsplan' in filename or 'action-plan' in filename:
        ftype = 'aktionsplan'
    else:
        ftype = 'report'

    # sender — grab email address only
    sender = None
    m = re.search(r'<th[^>]*>Sender</th>\s*<td[^>]*>(.*?)</td>', html, re.IGNORECASE | re.DOTALL)
    if m:
        cell = re.sub(r'<[^>]+>', '', m.group(1)).strip()
        email_m = re.search(r'[\w.+%-]+@[\w.-]+\.[a-z]{2,}', cell, re.IGNORECASE)
        sender = email_m.group(0) if email_m else (cell[:120] if cell else None)

    # subject
    subject = None
    m = re.search(r'<th[^>]*>Subject</th>\s*<td[^>]*>(.*?)</td>', html, re.IGNORECASE | re.DOTALL)
    if m:
        subject = re.sub(r'<[^>]+>', '', m.group(1)).strip()[:255] or None

    # email_date — only keep if looks like a real date
    email_date = None
    m = re.search(r'<th[^>]*>Date</th>\s*<td[^>]*>(.*?)</td>', html, re.IGNORECASE | re.DOTALL)
    if m:
        raw = re.sub(r'<[^>]+>', '', m.group(1)).strip()
        # Accept ISO-like (2024-...) or anything with a 4-digit year
        if re.search(r'\b\d{4}\b', raw):
            iso = re.match(r'(\d{4}-\d{2}-\d{2})', raw)
            email_date = iso.group(1) if iso else raw[:50]
        # else discard partial dates like "Thu, 7 May"

    # scores
    addin_score = ai_score = None
    if ftype == 'report':
        scores = re.findall(r'metric-score[^>]*>(\d+)', html)
        if len(scores) >= 2:
            addin_score = int(scores[0])
            ai_score    = int(scores[1])
        elif len(scores) == 1:
            addin_score = int(scores[0])
        # fallback: look for "X/10" patterns in table cells
        if addin_score is None:
            m = re.search(r'(\d+)\s*/\s*10', html)
            if m:
                addin_score = int(m.group(1))

    # ESP
    esp = None
    for name, keywords in ESP_KEYWORDS:
        if any(kw in low for kw in keywords):
            esp = name
            break

    return dict(
        domain=domain, sender=sender, subject=subject,
        emailDate=email_date, addinScore=addin_score, aiScore=ai_score,
        esp=esp, type=ftype,
    )


def post_save(meta: dict, html: str) -> dict:
    payload = {**meta, 'mode': 'save', 'saveToken': SAVE_TOKEN, 'html': html}
    data    = json.dumps(payload).encode()
    req     = urllib.request.Request(
        WORKER_URL,
        data=data,
        headers={
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        },
        method='POST',
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def main():
    files = sorted([
        p for p in BASE.rglob('*.html')
        if p.name not in SKIP and p.parent != BASE
    ])
    print(f"Found {len(files)} files to import\n")

    ok = err = 0
    for i, path in enumerate(files, 1):
        domain   = path.parent.name
        filename = path.name
        html     = path.read_text(encoding='utf-8', errors='replace')
        meta     = extract_meta(html, domain, filename)

        label = f"[{i:02}/{len(files)}] {domain}/{filename}"
        try:
            result = post_save(meta, html)
            if result.get('ok'):
                ok += 1
                print(f"  ✓  {label}  →  id={result.get('id')}  ({meta['type']}, esp={meta['esp']})")
            else:
                err += 1
                print(f"  ✗  {label}  →  {result}")
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors='replace')[:200]
            err += 1
            print(f"  ✗  {label}  →  HTTP {e.code}: {body}")
        except Exception as e:
            err += 1
            print(f"  ✗  {label}  →  {e}")

    print(f"\nDone: {ok} imported, {err} errors.")


if __name__ == '__main__':
    main()
