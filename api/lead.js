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
      parent_first_name: b.parent_first_name || '',
      parent_last_name: b.parent_last_name || '',
      child_first_name: b.child_first_name || '',
      child_last_name: b.child_last_name || '',
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
      const parentName = `${data.parent_first_name} ${data.parent_last_name}`.trim() || 'Unknown';
      const subj = `New ${data.type}: ${parentName}${data.programs ? ' — ' + data.programs : ''}`;
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

    // 1b) Friendly confirmation email to the parent (auto-reply)
    if (process.env.RESEND_API_KEY && data.email) {
      const first = escapeHtml(data.parent_first_name) || 'there';
      const isCoach = /coach/i.test(data.type);
      const childPart = data.child_first_name ? ` for ${escapeHtml(data.child_first_name)}` : '';
      const progPart = data.programs ? ` (interested in ${escapeHtml(data.programs)})` : '';
      const subject = isCoach ? 'Thanks for reaching out to STEM4U' : "You're on the STEM4U waitlist 🎉";
      const lead = isCoach
        ? `Thanks for reaching out to <b>STEM4U</b>${childPart}. One of our coaches will contact you soon to help you find the right fit.`
        : `Thanks for reserving a spot${childPart} at <b>STEM4U</b> — you're on our priority list${progPart}. We'll reach out personally as soon as enrollment opens.`;
      const chtml = `<div style="font-family:Arial,sans-serif;color:#0A1E52;max-width:540px;line-height:1.6">
        <h2 style="color:#0D2B7A;margin:0 0 8px">${isCoach ? 'Thanks — we\'ll be in touch! 📞' : "You're on the list! 🎉"}</h2>
        <p>Hi ${first},</p>
        <p>${lead}</p>
        <p>If you have any questions in the meantime, just reply to this email or write to <a href="mailto:contact@stem4u.com">contact@stem4u.com</a>.</p>
        <p>We can't wait to meet your young builder.</p>
        <p style="margin-top:18px">— The STEM4U Team<br><span style="color:#4A5A80;font-size:13px">Real tools. Real teams. Real engineers. · <a href="https://stem4u.com">stem4u.com</a></span></p>
      </div>`;
      const cr = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from: process.env.LEAD_FROM || 'STEM4U <contact@stem4u.com>',
          to: [data.email],
          reply_to: 'contact@stem4u.com',
          subject,
          html: chtml,
        }),
      });
      results.confirmation = cr.ok ? 'sent' : `error: ${await cr.text()}`;
    } else {
      results.confirmation = 'skipped';
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
