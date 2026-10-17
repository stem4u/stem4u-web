// /api/_log.js — shared, best-effort activity logger for the public endpoints.
// Underscore prefix => Vercel does NOT expose this as a route; it's a helper.
//
// logEvent({ source, event, level, ok, status, email, child, message, detail, req })
//   writes one row to public.app_logs. It NEVER throws and NEVER blocks the
//   response for long (2.5s timeout) — logging must not be able to break a
//   registration. Requires SUPABASE_URL + SUPABASE_SECRET_KEY|SUPABASE_SERVICE_KEY.
'use strict';

const KEY = () => process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SECRET_KEY;
const cap = (s, n) => (s == null ? null : String(s).slice(0, n));

function clientIp(req) {
  if (!req) return null;
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.headers['x-real-ip'] || null;
}

async function logEvent(f = {}) {
  try {
    const url = process.env.SUPABASE_URL, key = KEY();
    if (!url || !key) return; // nothing to write to

    const req = f.req;
    const row = {
      source: cap(f.source, 40),
      event: cap(f.event, 60),
      level: cap(f.level, 10) || 'info',
      ok: typeof f.ok === 'boolean' ? f.ok : null,
      status: Number.isFinite(f.status) ? f.status : null,
      email: cap(f.email, 200),
      child: cap(f.child, 200),
      message: cap(f.message, 500),
      detail: f.detail == null ? null : f.detail, // jsonb
      ip: f.ip || clientIp(req),
      user_agent: cap(f.user_agent || (req && req.headers && req.headers['user-agent']) || '', 300),
    };

    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 2500);
    try {
      await fetch(`${url}/rest/v1/app_logs`, {
        method: 'POST',
        headers: { apikey: key, Authorization: `Bearer ${key}`, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
        body: JSON.stringify(row),
        signal: ctrl.signal,
      });
    } finally { clearTimeout(t); }
  } catch (e) { /* best-effort: logging must never break the caller */ }

  // Independent FILE copy: mirror the same event to a Google Sheet (Apps Script web app),
  // so the activity log exists outside the database too. Best-effort; never blocks/throws.
  // Set LOG_SHEETS_WEBHOOK_URL (falls back to SHEETS_WEBHOOK_URL) + SHEETS_TOKEN in Vercel.
  try {
    const hook = process.env.LOG_SHEETS_WEBHOOK_URL || process.env.SHEETS_WEBHOOK_URL;
    if (hook) {
      const payload = {
        kind: 'log',
        ts: new Date().toISOString(),
        source: cap(f.source, 40), event: cap(f.event, 60), level: cap(f.level, 10) || 'info',
        ok: typeof f.ok === 'boolean' ? f.ok : null, status: Number.isFinite(f.status) ? f.status : null,
        email: cap(f.email, 200), child: cap(f.child, 200), message: cap(f.message, 500),
        detail: f.detail == null ? '' : (typeof f.detail === 'string' ? f.detail : JSON.stringify(f.detail)).slice(0, 2000),
        token: process.env.SHEETS_TOKEN || '',
      };
      const c2 = new AbortController();
      const t2 = setTimeout(() => c2.abort(), 2500);
      try {
        await fetch(hook, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), signal: c2.signal });
      } finally { clearTimeout(t2); }
    }
  } catch (e) { /* best-effort: the file mirror must never break the caller */ }
}

module.exports = { logEvent };
