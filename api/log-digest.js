// /api/log-digest — daily failure digest. Invoked by Vercel Cron (see vercel.json).
// Looks at app_logs for the last 24h and, IF any registration failed, emails the
// team a recovery list (child, parent, email, phone, exact DB error). Sends nothing
// on a clean day. Manual run: GET with ?window=48 to widen the lookback hours.
'use strict';

const KEY = () => process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SECRET_KEY;
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

module.exports = async (req, res) => {
  // Protect the endpoint. When CRON_SECRET is set, Vercel Cron sends it as a
  // Bearer token automatically; a manual caller must supply the same.
  if (process.env.CRON_SECRET) {
    const auth = req.headers.authorization || '';
    if (auth !== `Bearer ${process.env.CRON_SECRET}`) { res.status(401).json({ ok: false, error: 'Unauthorized' }); return; }
  }

  const url = process.env.SUPABASE_URL, key = KEY();
  if (!url || !key) { res.status(500).json({ ok: false, error: 'Supabase env missing' }); return; }

  const hours = Math.min(Math.max(parseInt((req.query && req.query.window) || '24', 10) || 24, 1), 168);
  const since = new Date(Date.now() - hours * 3600 * 1000).toISOString();

  try {
    // Failures = anything logged at error level OR an explicit save_failed event.
    const path = `app_logs?select=created_at,source,event,level,status,email,child,message,detail`
      + `&created_at=gte.${encodeURIComponent(since)}`
      + `&or=(level.eq.error,event.eq.save_failed)`
      + `&order=created_at.desc`;
    const r = await fetch(`${url}/rest/v1/${path}`, { headers: { apikey: key, Authorization: `Bearer ${key}` } });
    if (!r.ok) { res.status(502).json({ ok: false, error: 'Query failed', detail: await r.text() }); return; }
    const rows = await r.json();

    if (!Array.isArray(rows) || rows.length === 0) {
      res.status(200).json({ ok: true, failures: 0, emailed: false, since });
      return; // clean day — stay quiet
    }

    let emailed = false;
    if (process.env.RESEND_API_KEY) {
      const trs = rows.map((e) => {
        const d = e.detail || {};
        const err = (d.db_error || d.error || '').toString().slice(0, 300);
        return `<tr>
          <td style="padding:4px 10px 4px 0;color:#555;white-space:nowrap">${esc(new Date(e.created_at).toLocaleString('en-US', { timeZone: 'America/New_York' }))}</td>
          <td style="padding:4px 10px 4px 0"><code>${esc(e.source)}/${esc(e.event)}</code></td>
          <td style="padding:4px 10px 4px 0"><b>${esc(e.child || '')}</b></td>
          <td style="padding:4px 10px 4px 0">${esc(d.parent || '')}</td>
          <td style="padding:4px 10px 4px 0">${esc(e.email || '')}</td>
          <td style="padding:4px 10px 4px 0">${esc(d.phone || '')}</td>
          <td style="padding:4px 10px 4px 0;color:#b02a2a">${esc(err)}</td>
        </tr>`;
      }).join('');
      const er = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from: process.env.LEAD_FROM || 'STEM4U <leads@stem4u.com>',
          to: (process.env.LEAD_TO || 'contact@stem4u.com').split(',').map((x) => x.trim()),
          subject: `⚠ STEM4U: ${rows.length} registration failure${rows.length > 1 ? 's' : ''} in the last ${hours}h`,
          html: `<h2 style="font-family:Arial;color:#b02a2a">${rows.length} registration failure${rows.length > 1 ? 's' : ''} — contact these families</h2>`
            + `<p style="font-family:Arial;font-size:13px;color:#555">These signups did not save. Reach out and re-register them. Full trail in Manage → Insights → Activity Log.</p>`
            + `<table style="border-collapse:collapse;font-family:Arial;font-size:13px"><thead><tr style="text-align:left;border-bottom:2px solid #ddd">`
            + `<th style="padding:4px 10px 4px 0">When (ET)</th><th style="padding:4px 10px 4px 0">What</th><th style="padding:4px 10px 4px 0">Child</th><th style="padding:4px 10px 4px 0">Parent</th><th style="padding:4px 10px 4px 0">Email</th><th style="padding:4px 10px 4px 0">Phone</th><th style="padding:4px 10px 4px 0">Error</th></tr></thead><tbody>${trs}</tbody></table>`,
        }),
      });
      emailed = er.ok;
    }

    res.status(200).json({ ok: true, failures: rows.length, emailed, since });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'Digest failed' });
  }
};
