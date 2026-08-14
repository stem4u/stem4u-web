// /api/lead — NEW lead pipeline (parallel to Formspree; NOT wired to live forms yet).
//   POST { parent_name, email, phone, grade, programs[], schedule[], best_time, message, type, _gotcha }
//   → emails the team via Resend (from the stem4u.com domain) and logs a row to a Google Sheet.
// Env vars (set in Vercel): RESEND_API_KEY, LEAD_FROM, LEAD_TO, SHEETS_WEBHOOK_URL, SHEETS_TOKEN
// Every var is optional — whichever is set, that channel runs. Missing keys are reported, never fatal.

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

// --- abuse controls -------------------------------------------------------
const ALLOWED_HOSTS = ['stem4u.com', 'www.stem4u.com'];
const ALLOWED_ORIGIN = 'https://stem4u.com';
function hostOf(u) { try { return new URL(u).host.toLowerCase(); } catch { return ''; } }
function originOk(req) {
  const oh = hostOf(req.headers.origin || '');
  const rh = hostOf(req.headers.referer || '');
  if (oh) return ALLOWED_HOSTS.includes(oh);        // browsers always send Origin on POST
  if (rh) return ALLOWED_HOSTS.includes(rh);
  return true;                                       // no Origin/Referer (rare) → let rate limit + honeypot handle
}
const RL = new Map(); // ip -> [timestamps] (best-effort, per warm instance)
function rateLimited(ip, max = 6, windowMs = 10 * 60 * 1000) {
  const now = Date.now();
  const arr = (RL.get(ip) || []).filter((t) => now - t < windowMs);
  arr.push(now); RL.set(ip, arr);
  if (RL.size > 5000) RL.clear();
  return arr.length > max;
}
function clientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.headers['x-real-ip'] || 'unknown';
}
const isEmail = (s) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(s || ''));
const cap = (s, n) => String(s == null ? '' : s).slice(0, n);

module.exports = async (req, res) => {
  // CORS: only our own origin (blocks cross-site browser abuse; scripted abuse is caught by rate limit)
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }
  if (!originOk(req)) { res.status(403).json({ error: 'Forbidden origin' }); return; }
  if (rateLimited(clientIp(req))) { res.status(429).json({ error: 'Too many requests — please try again later.' }); return; }

  try {
    let b = req.body;
    if (typeof b === 'string') {
      try { b = JSON.parse(b); }
      catch { b = Object.fromEntries(new URLSearchParams(b)); }
    }
    b = b || {};

    // Honeypot: if the hidden field is filled, it's a bot. Pretend success, do nothing.
    if (b._gotcha) { res.status(200).json({ ok: true, bot: true }); return; }

    // Normalize + cap lengths (prevents oversized-payload / injection abuse)
    const arr = (v) => (Array.isArray(v) ? v.slice(0, 12).map((x) => cap(x, 60)).join(', ') : cap(v, 200));
    const data = {
      type: cap(b.type || 'Lead', 40),
      name: cap(b.name, 120),
      parent_first_name: cap(b.parent_first_name, 80),
      parent_last_name: cap(b.parent_last_name, 80),
      child_first_name: cap(b.child_first_name, 80),
      child_last_name: cap(b.child_last_name, 80),
      email: cap(b.email, 200),
      phone: cap(b.phone, 40),
      grade: cap(b.grade, 40),
      programs: arr(b.programs),
      schedule: arr(b.schedule),
      friend_request: cap(b.friend_request, 200),
      best_time: cap(b.best_time, 120),
      message: cap(b.message, 2000),
      submitted_at: new Date().toISOString(),
    };

    const results = { email: null, sheet: null };

    // 1) Email via Resend (sends from your own domain → no spam-folder problem)
    if (process.env.RESEND_API_KEY) {
      const rows = Object.entries(data)
        .map(([k, v]) => `<tr><td style="padding:5px 12px;color:#555;text-transform:capitalize">${k.replace(/_/g, ' ')}</td><td style="padding:5px 12px"><b>${escapeHtml(v) || '—'}</b></td></tr>`)
        .join('');
      const parentName = `${data.parent_first_name} ${data.parent_last_name}`.trim() || data.name || 'Unknown';
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

    // 1b) Friendly confirmation email to the parent (auto-reply) — only to a valid address
    if (process.env.RESEND_API_KEY && isEmail(data.email)) {
      const first = escapeHtml(data.parent_first_name || data.name) || 'there';
      const isGeneric = /coach|contact/i.test(data.type);   // coach requests + contact messages
      const childPart = data.child_first_name ? ` for ${escapeHtml(data.child_first_name)}` : '';
      const progPart = data.programs ? ` (interested in ${escapeHtml(data.programs)})` : '';
      const subject = isGeneric ? 'Thanks for reaching out to STEM4U' : "You're on the STEM4U waitlist";
      const lead = isGeneric
        ? `Thanks for reaching out to <b>STEM4U</b>${childPart}. We've received your message and someone from our team will get back to you soon.`
        : `Thanks for reserving a spot${childPart} at <b>STEM4U</b> — you're on our priority list${progPart}. We'll reach out personally as soon as enrollment opens.`;
      const chtml = `<div style="font-family:Arial,sans-serif;color:#0A1E52;max-width:540px;line-height:1.6">
        <h2 style="color:#0D2B7A;margin:0 0 8px">${isGeneric ? 'Thanks — we got your message' : "You're on the list"}</h2>
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
    res.status(500).json({ error: 'Lead handler failed' });
  }
};
