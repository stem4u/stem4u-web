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
function pathOf(u) { try { return new URL(u).pathname; } catch { return ''; } }
function originOk(req) {
  const oh = hostOf(req.headers.origin || '');
  const ref = req.headers.referer || '';
  const rh = hostOf(ref);
  if (oh) return ALLOWED_HOSTS.includes(oh);        // browsers send Origin on POST
  if (rh) {
    if (!ALLOWED_HOSTS.includes(rh)) return false;
    if (pathOf(ref).startsWith('/api/')) return false; // self-referer = bot tell; a real form never refers from /api/*
    return true;
  }
  return true;                                       // no Origin/Referer (rare) → rate limit + honeypot + content guard handle
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

// --- spam scoring -----------------------------------------------------------
// A real parent form never has a link in the name, a phone in the message,
// SEO/marketing pitch language, or keyboard-mash gibberish. Score the tells;
// 3+ = spam. Spam is dropped (not emailed, not stored).
//
// Gibberish detector: counts "words" that look like keyboard mash — a 7+ char
// run with 5+ consecutive consonants, or almost no vowels. Real names (incl.
// long transliterated ones like "Krishnachandran") stay under the bar because
// they don't chain 5+ consonants and keep a normal vowel ratio.
function gibberishHits(text) {
  const words = String(text || '').toLowerCase().match(/[a-z]{7,}/g) || [];
  let hits = 0;
  for (const w of words) {
    const run = /[bcdfghjklmnpqrstvwxyz]{5,}/.test(w);
    const vr = (w.match(/[aeiou]/g) || []).length / w.length;
    if (run || vr < 0.18) hits++;
  }
  return hits;
}
function spamScore(d) {
  const name = `${d.parent_first_name || ''} ${d.parent_last_name || ''} ${d.child_first_name || ''} ${d.name || ''}`;
  const msg = d.message || '';
  const hay = `${name} ${msg}`.toLowerCase();
  const linkRe = /(https?:\/\/|www\.|t\.me\/|wa\.me\/|\btelegram\b|\bwhatsapp\b|\bbit\.ly\b|\bskype\b)/i;
  const pitchRe = /(free demo|back ?link|\bseo\b|search engine|website (owners|traffic)|contact pages?|rank(ing)? higher|boost your|marketing (platform|service)|grow your business|crypto|casino|\bloan\b|viagra|\bnft\b|investment opportunity)/i;
  const cyrillic = /[Ѐ-ӿ]/;
  let s = 0;
  if (linkRe.test(name)) s += 3;               // link in a name field = definitely a bot
  if (linkRe.test(msg)) s += 2;                // link in the message
  if (pitchRe.test(hay)) s += 3;               // sales/SEO vocabulary — no real parent writes this
  if (cyrillic.test(hay)) s += 2;              // non-Latin script
  if (/\+?\d[\d\s().-]{9,}/.test(msg)) s += 1; // a phone number buried in the message
  if (gibberishHits(msg) >= 2) s += 3;         // keyboard-mash message (e.g. "fkmdkdwdwkdwjj")
  if (gibberishHits(name) >= 1) s += 3;        // gibberish in a name field
  if (/\bstem4u\b/i.test(msg)) s += 2;         // echoing our own domain back = scraper/bot tell
  if (/contact/i.test(d.type) && !d.phone && !d.grade && !d.child_first_name && linkRe.test(msg)) s += 2;
  return s;
}
const looksSpammy = (d) => spamScore(d) >= 3;

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

    // Ignore empty / bot submissions: require at least one real piece of contact info.
    // Prevents blank rows from endpoint probes/crawlers. Pretend success, store nothing.
    const hasContent = data.email || data.phone || data.parent_first_name ||
      data.parent_last_name || data.child_first_name || data.child_last_name || data.name;
    if (!hasContent) { res.status(200).json({ ok: true, empty: true }); return; }

    // Spam / gibberish: REJECT it outright — no email, no sheet, no DB row.
    // Pretend success (200) so bots don't learn they were filtered.
    if (looksSpammy(data)) { res.status(200).json({ ok: true, rejected: true }); return; }

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

    // 3) Insert into Supabase `leads` table (server-side service role only)
    const SUPA_KEY = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SECRET_KEY;
    if (process.env.SUPABASE_URL && SUPA_KEY) {
      try {
        const row = {
          submitted_at: data.submitted_at,
          type: data.type,
          source: 'Website form',
          parent_first_name: data.parent_first_name,
          parent_last_name: data.parent_last_name,
          child_first_name: data.child_first_name,
          child_last_name: data.child_last_name,
          email: data.email ? data.email.toLowerCase() : '',
          phone: data.phone,
          grade: data.grade,
          programs: data.programs,
          schedule: data.schedule,
          friend_request: data.friend_request,
          best_time: data.best_time,
          message: data.message,
        };
        const rdb = await fetch(`${process.env.SUPABASE_URL}/rest/v1/leads`, {
          method: 'POST',
          headers: {
            apikey: SUPA_KEY,
            Authorization: `Bearer ${SUPA_KEY}`,
            'Content-Type': 'application/json',
            Prefer: 'return=minimal',
          },
          body: JSON.stringify(row),
        });
        results.db = rdb.ok ? 'inserted' : `error: ${rdb.status} ${await rdb.text()}`;
      } catch (e) {
        results.db = `error: ${String(e)}`;
      }
    } else {
      results.db = 'skipped (no SUPABASE env)';
    }

    res.status(200).json({ ok: true, results });
  } catch (e) {
    res.status(500).json({ error: 'Lead handler failed' });
  }
};
