// /api/lead — NEW lead pipeline (parallel to Formspree; NOT wired to live forms yet).
//   POST { parent_name, email, phone, grade, programs[], schedule[], best_time, message, type, _gotcha }
//   → emails the team via Resend (from the stem4u.com domain) and logs a row to a Google Sheet.
// Env vars (set in Vercel): RESEND_API_KEY, LEAD_FROM, LEAD_TO, SHEETS_WEBHOOK_URL, SHEETS_TOKEN
// Every var is optional — whichever is set, that channel runs. Missing keys are reported, never fatal.

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

module.exports = async (req, res) => {
  // CORS (same-origin in practice; permissive here so the test page works from anywhere)
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }

  try {
    let b = req.body;
    if (typeof b === 'string') {
      try { b = JSON.parse(b); }
      catch { b = Object.fromEntries(new URLSearchParams(b)); }
    }
    b = b || {};

    // Honeypot: if the hidden field is filled, it's a bot. Pretend success, do nothing.
    if (b._gotcha) { res.status(200).json({ ok: true, bot: true }); return; }

    const arr = (v) => (Array.isArray(v) ? v.join(', ') : (v || ''));
    const data = {
      type: b.type || 'Lead',
      parent_name: b.parent_name || '',
      email: b.email || '',
      phone: b.phone || '',
      grade: b.grade || '',
      programs: arr(b.programs),
      schedule: arr(b.schedule),
      best_time: b.best_time || '',
      message: b.message || '',
      submitted_at: new Date().toISOString(),
    };

    const results = { email: null, sheet: null };

    // 1) Email via Resend (sends from your own domain → no spam-folder problem)
    if (process.env.RESEND_API_KEY) {
      const rows = Object.entries(data)
        .map(([k, v]) => `<tr><td style="padding:5px 12px;color:#555;text-transform:capitalize">${k.replace(/_/g, ' ')}</td><td style="padding:5px 12px"><b>${escapeHtml(v) || '—'}</b></td></tr>`)
        .join('');
      const subj = `New ${data.type}: ${data.parent_name || 'Unknown'}${data.programs ? ' — ' + data.programs : ''}`;
      const payload = {
        from: process.env.LEAD_FROM || 'STEM4U <leads@stem4u.com>',
        to: (process.env.LEAD_TO || 'contact@stem4u.com').split(',').map((s) => s.trim()),
        subject: subj,
        html: `<h2 style="font-family:Arial;color:#0D2B7A">New ${escapeHtml(data.type)}</h2><table style="border-collapse:collapse;font-family:Arial;font-size:14px">${rows}</table>`,
      };
      if (data.email) payload.reply_to = data.email;
      const r = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      results.email = r.ok ? 'sent' : `error: ${await r.text()}`;
    } else {
      results.email = 'skipped (no RESEND_API_KEY)';
    }

    // 2) Log to Google Sheet via an Apps Script web-app webhook
    if (process.env.SHEETS_WEBHOOK_URL) {
      try {
        const r2 = await fetch(process.env.SHEETS_WEBHOOK_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...data, token: process.env.SHEETS_TOKEN || '' }),
        });
        results.sheet = r2.ok ? 'logged' : `error: ${r2.status}`;
      } catch (e) {
        results.sheet = `error: ${String(e)}`;
      }
    } else {
      results.sheet = 'skipped (no SHEETS_WEBHOOK_URL)';
    }

    res.status(200).json({ ok: true, results });
  } catch (e) {
    res.status(500).json({ error: 'Lead handler failed', detail: String(e) });
  }
};
