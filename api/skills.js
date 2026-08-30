// /api/skills — FTC skills-pick form → emails the team via Resend. No submission cap.
//   POST (JSON) { who, skills[], extra, _gotcha }
// Reuses the same env vars as /api/lead: RESEND_API_KEY, LEAD_FROM, LEAD_TO.
// Sends one email per submission to LEAD_TO (default contact@stem4u.com). No DB write.

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}
const ALLOWED_HOSTS = ['stem4u.com', 'www.stem4u.com'];
function hostOf(u) { try { return new URL(u).host.toLowerCase(); } catch { return ''; } }
function originOk(req) {
  const oh = hostOf(req.headers.origin || '');
  const rh = hostOf(req.headers.referer || '');
  if (oh) return ALLOWED_HOSTS.includes(oh);
  if (rh) return ALLOWED_HOSTS.includes(rh);
  return true; // no Origin/Referer (rare) → honeypot + rate limit still apply
}
const RL = new Map();
function clientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.headers['x-real-ip'] || 'unknown';
}
function rateLimited(ip, max = 12, windowMs = 10 * 60 * 1000) {
  const now = Date.now();
  const arr = (RL.get(ip) || []).filter((t) => now - t < windowMs);
  arr.push(now); RL.set(ip, arr);
  if (RL.size > 5000) RL.clear();
  return arr.length > max;
}
const cap = (s, n) => String(s == null ? '' : s).slice(0, n);

module.exports = async (req, res) => {
  if (req.method !== 'POST') { res.status(405).json({ ok: false, error: 'POST only' }); return; }

  let data = req.body;
  if (typeof data === 'string') { try { data = JSON.parse(data || '{}'); } catch { data = {}; } }
  data = data || {};

  if (data._gotcha) { res.status(200).json({ ok: true }); return;        } // honeypot → fake success
  if (!originOk(req)) { res.status(403).json({ ok: false, error: 'Bad origin' }); return; }
  if (rateLimited(clientIp(req))) { res.status(429).json({ ok: false, error: 'Too many submissions — try again shortly.' }); return; }

  const who = cap(data.who, 80).trim();
  let skills = Array.isArray(data.skills) ? data.skills : (data.skills ? [data.skills] : []);
  skills = skills.map((s) => cap(s, 60).trim()).filter(Boolean).slice(0, 8);   // ranked order preserved
  const extra = cap(data.extra, 200).trim();

  if (!who || skills.length === 0) {
    res.status(400).json({ ok: false, error: 'Name and at least one skill are required.' });
    return;
  }

  const subject = 'New FTC skill ranking — ' + who;
  const ranked = skills.map((s, i) => `<tr><td style="padding:2px 8px 2px 0;color:#E8651A;font-weight:700">${i + 1}.</td><td style="padding:2px 0">${escapeHtml(s)}</td></tr>`).join('');
  const html = `<div style="font-family:Inter,Arial,sans-serif;color:#2E2E2E">
      <h2 style="color:#1B2A4A;margin:0 0 10px">FTC Skills Ranking</h2>
      <p><b>Student:</b> ${escapeHtml(who)}</p>
      <p style="margin:0 0 4px"><b>Ranked (most &rarr; least interested):</b></p>
      <table style="border-collapse:collapse;font-size:14px">${ranked}</table>
      ${extra ? `<p style="margin-top:10px"><b>Also excited to try:</b> ${escapeHtml(extra)}</p>` : ''}
      <p style="color:#5A6472;font-size:12px;margin-top:14px">STEM4U · FTC 2026&ndash;27 skills survey</p>
    </div>`;

  try {
    if (!process.env.RESEND_API_KEY) {
      res.status(500).json({ ok: false, error: 'Email not configured' });
      return;
    }
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: process.env.LEAD_FROM || 'STEM4U <leads@stem4u.com>',
        to: (process.env.LEAD_TO || 'contact@stem4u.com').split(',').map((s) => s.trim()),
        subject,
        html,
      }),
    });
    if (!r.ok) { res.status(502).json({ ok: false, error: 'Email failed' }); return; }
    res.status(200).json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'Send failed' });
  }
};
