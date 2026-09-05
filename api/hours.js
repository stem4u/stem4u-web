// /api/hours — INSTRUCTOR PORTAL endpoint (no manage login; per-instructor HMAC link).
// Lets an instructor (a) mark their team's kid attendance and (b) log their own worked hours.
//   GET ?i=&k=                     -> { ok, name, teams:[...] }        (validate link, who am I)
//   GET ?i=&k=&team=&date=         -> { ok, roster:[{id,name,present}], hours }
//   POST { i,k, action:'hours',      date, hours }
//   POST { i,k, action:'attendance', date, team, lead_id, name, present }
// Key = HMAC-SHA256(INSTRUCTOR_SECRET, tutor_id) base64url, first 16 chars. Instructor pay rate is NEVER returned.
// Env: INSTRUCTOR_SECRET, SUPABASE_URL, SUPABASE_SECRET_KEY|SUPABASE_SERVICE_KEY
'use strict';
const crypto = require('crypto');
const KEY = () => process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SECRET_KEY;
const cap = (s, n) => String(s == null ? '' : s).slice(0, n).trim();
const todayET = () => new Date().toLocaleDateString('en-CA', { timeZone: 'America/New_York' });

function insKey(id) {
  const secret = process.env.INSTRUCTOR_SECRET;
  if (!secret || !id) return null;
  return crypto.createHmac('sha256', secret).update(String(id)).digest('base64url').slice(0, 16);
}
function keyOk(id, k) {
  const want = insKey(id); if (!want) return null;
  const a = Buffer.from(String(k || '')), b = Buffer.from(want);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const ALLOWED = ['stem4u.com', 'www.stem4u.com'];
function originOk(req) {
  const h = (u) => { try { return new URL(u).host.toLowerCase(); } catch { return ''; } };
  const oh = h(req.headers.origin || ''), rh = h(req.headers.referer || '');
  if (oh) return ALLOWED.includes(oh); if (rh) return ALLOWED.includes(rh); return true;
}
const RL = new Map();
const clientIp = (req) => (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
function rateLimited(ip, max = 120, win = 10 * 60 * 1000) {
  const now = Date.now(); const arr = (RL.get(ip) || []).filter(t => now - t < win);
  arr.push(now); RL.set(ip, arr); if (RL.size > 5000) RL.clear(); return arr.length > max;
}

module.exports = async (req, res) => {
  const url = process.env.SUPABASE_URL, key = KEY();
  if (!url || !key) { res.status(500).json({ ok: false, error: 'Server not configured' }); return; }
  const H = { apikey: key, Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' };

  try {
    if (req.method === 'GET') {
      const sp = new URL(req.url, 'http://x').searchParams;
      const i = cap(sp.get('i'), 60), k = cap(sp.get('k'), 32);
      const ok = keyOk(i, k);
      if (ok === null) { res.status(503).json({ ok: false, error: 'Instructor portal not configured' }); return; }
      if (!ok) { res.status(403).json({ ok: false, error: 'This link isn’t valid — ask your coordinator for your instructor link.' }); return; }
      const tr = await fetch(`${url}/rest/v1/tutors?id=eq.${encodeURIComponent(i)}&select=name,active`, { headers: H });
      const trows = tr.ok ? await tr.json() : [];
      if (!trows[0]) { res.status(404).json({ ok: false, error: 'Instructor not found' }); return; }

      const team = cap(sp.get('team'), 40), date = cap(sp.get('date'), 10) || todayET();
      if (!team) {
        // link validation / hours screen — return name + teams + this instructor's hours for the date
        const lr = await fetch(`${url}/rest/v1/leads?select=assigned_team&deleted_at=is.null&assigned_team=not.is.null`, { headers: H });
        const lrows = lr.ok ? await lr.json() : [];
        const teams = [...new Set(lrows.map(l => (l.assigned_team || '').trim()).filter(Boolean))].sort();
        const hr = await fetch(`${url}/rest/v1/tutor_sessions?select=hours&tutor_id=eq.${encodeURIComponent(i)}&session_date=eq.${encodeURIComponent(date)}&team=eq.`, { headers: H });
        const hrows = hr.ok ? await hr.json() : [];
        res.status(200).json({ ok: true, name: trows[0].name, teams, hours: hrows[0] ? hrows[0].hours : null });
        return;
      }
      // roster for a team + present flags for the date + this instructor's hours for the date
      const lr = await fetch(`${url}/rest/v1/leads?select=id,child_first_name,child_last_name&assigned_team=eq.${encodeURIComponent(team)}&deleted_at=is.null&order=child_first_name`, { headers: H });
      const lrows = lr.ok ? await lr.json() : [];
      const cr = await fetch(`${url}/rest/v1/checkins?select=lead_id,present&session_date=eq.${encodeURIComponent(date)}`, { headers: H });
      const crows = cr.ok ? await cr.json() : [];
      const pres = {}; crows.forEach(c => { pres[c.lead_id] = !!c.present; });
      const roster = lrows.filter(l => (l.child_first_name || '').trim()).map(l => ({
        id: l.id,
        name: ((l.child_first_name || '').trim() + ' ' + ((l.child_last_name || '').trim() ? (l.child_last_name || '').trim()[0] + '.' : '')).trim(),
        present: !!pres[l.id],
      }));
      const hr = await fetch(`${url}/rest/v1/tutor_sessions?select=hours&tutor_id=eq.${encodeURIComponent(i)}&session_date=eq.${encodeURIComponent(date)}&team=eq.`, { headers: H });
      const hrows = hr.ok ? await hr.json() : [];
      res.status(200).json({ ok: true, roster, hours: hrows[0] ? hrows[0].hours : null });
      return;
    }

    if (req.method === 'POST') {
      if (!originOk(req)) { res.status(403).json({ ok: false, error: 'Bad origin' }); return; }
      if (rateLimited(clientIp(req))) { res.status(429).json({ ok: false, error: 'Too many updates — wait a moment.' }); return; }
      let b = req.body; if (typeof b === 'string') { try { b = JSON.parse(b || '{}'); } catch { b = {}; } } b = b || {};
      const i = cap(b.i, 60), k = cap(b.k, 32), action = cap(b.action, 20), date = cap(b.date, 10) || todayET();
      const ok = keyOk(i, k);
      if (ok === null) { res.status(503).json({ ok: false, error: 'Not configured' }); return; }
      if (!ok) { res.status(403).json({ ok: false, error: 'Invalid link' }); return; }

      if (action === 'hours') {
        const hours = (b.hours === '' || b.hours == null) ? null : Number(b.hours);
        if (hours == null || !isFinite(hours) || hours < 0 || hours > 24) { res.status(400).json({ ok: false, error: 'Enter hours between 0 and 24.' }); return; }
        const row = { session_date: date, team: '', tutor_id: i, hours };
        const r = await fetch(`${url}/rest/v1/tutor_sessions?on_conflict=session_date,team,tutor_id`, {
          method: 'POST', headers: { ...H, Prefer: 'resolution=merge-duplicates,return=minimal' }, body: JSON.stringify(row),
        });
        if (!r.ok) { res.status(502).json({ ok: false, error: 'Could not save hours.', detail: await r.text() }); return; }
        res.status(200).json({ ok: true }); return;
      }

      if (action === 'attendance') {
        const team = cap(b.team, 40), lead_id = cap(b.lead_id, 60), name = cap(b.name, 80);
        const present = b.present === true || b.present === 'true';
        if (!lead_id) { res.status(400).json({ ok: false, error: 'lead_id required' }); return; }
        const row = { session_date: date, team: team || null, lead_id, child_name: name || null, present, method: 'instructor', updated_at: new Date().toISOString() };
        const r = await fetch(`${url}/rest/v1/checkins?on_conflict=session_date,lead_id`, {
          method: 'POST', headers: { ...H, Prefer: 'resolution=merge-duplicates,return=minimal' }, body: JSON.stringify(row),
        });
        if (!r.ok) { res.status(502).json({ ok: false, error: 'Could not save attendance.', detail: await r.text() }); return; }
        res.status(200).json({ ok: true }); return;
      }

      res.status(400).json({ ok: false, error: 'Unknown action' });
      return;
    }

    res.status(405).json({ ok: false, error: 'GET or POST only' });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'Instructor portal handler failed' });
  }
};
