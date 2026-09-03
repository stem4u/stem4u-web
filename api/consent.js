// /api/consent — public parent signing endpoint for the STEM4U enrollment
// agreement (waivers + consents + emergency info). Stores one signed row in
// Supabase (consent_signatures). Legal e-signature under Virginia UETA / E-SIGN:
// typed name + email + timestamp + IP + consent flags.
//
// POST { child_name, child_dob, programs, parent_name, parent_email, parent_phone,
//        contact2_name, contact2_phone, allergies, conditions, medications,
//        physician, hospital, insurance, emerg_med, emerg_med_use, emerg_med_where,
//        emerg_self_carry, emerg_staff_help, pickup1, pickup2, self_signout,
//        photo_choice, agree_policies, agree_medical, agree_payment, agree_esign,
//        signature_name, signature_relation, signed_date, lead_id,
//        'cf-turnstile-response' }
//
// Env: SUPABASE_URL, SUPABASE_SECRET_KEY|SUPABASE_SERVICE_KEY, TURNSTILE_SECRET (optional)
'use strict';

const POLICIES_VERSION = '2026-09-02';

const KEY = () => process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SECRET_KEY;
const cap = (s, n) => String(s == null ? '' : s).slice(0, n);
const isEmail = (s) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(s || ''));
const bool = (v) => v === true || v === 'true' || v === 'on' || v === 1 || v === '1';

const ALLOWED_HOSTS = ['stem4u.com', 'www.stem4u.com'];
function hostOf(u) { try { return new URL(u).host.toLowerCase(); } catch { return ''; } }
function pathOf(u) { try { return new URL(u).pathname; } catch { return ''; } }
function originOk(req) {
  const oh = hostOf(req.headers.origin || '');
  const ref = req.headers.referer || '';
  const rh = hostOf(ref);
  if (oh) return ALLOWED_HOSTS.includes(oh);
  if (rh) {
    if (!ALLOWED_HOSTS.includes(rh)) return false;
    if (pathOf(ref).startsWith('/api/')) return false;
    return true;
  }
  return true;
}
const RL = new Map();
function rateLimited(ip, max = 8, windowMs = 10 * 60 * 1000) {
  const now = Date.now();
  const arr = (RL.get(ip) || []).filter((t) => now - t < windowMs);
  arr.push(now); RL.set(ip, arr);
  if (RL.size > 5000) RL.clear();
  return arr.length > max;
}
function clientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.headers['x-real-ip'] || 'unknown';
}

async function verifyTurnstile(token, ip) {
  if (!token) return false;
  try {
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ secret: process.env.TURNSTILE_SECRET, response: token, remoteip: ip || '' }),
    });
    const j = await r.json();
    return !!(j && j.success);
  } catch { return false; }
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') { res.status(405).json({ ok: false, error: 'POST only' }); return; }

  const url = process.env.SUPABASE_URL, key = KEY();
  if (!url || !key) { res.status(500).json({ ok: false, error: 'Server not configured' }); return; }

  if (!originOk(req)) { res.status(403).json({ ok: false, error: 'Bad origin' }); return; }
  if (rateLimited(clientIp(req))) { res.status(429).json({ ok: false, error: 'Too many submissions — wait a moment.' }); return; }

  let b = req.body;
  if (typeof b === 'string') { try { b = JSON.parse(b || '{}'); } catch { b = {}; } }
  b = b || {};

  // honeypot
  if (cap(b._gotcha, 100).trim()) { res.status(200).json({ ok: true }); return; }

  // CAPTCHA (only enforced once TURNSTILE_SECRET is set)
  if (process.env.TURNSTILE_SECRET) {
    const token = b['cf-turnstile-response'] || b.turnstile || '';
    if (!(await verifyTurnstile(token, clientIp(req)))) {
      res.status(403).json({ ok: false, error: 'Please complete the “I’m human” check and try again.' });
      return;
    }
  }

  // ---- required fields ----
  const child_name = cap(b.child_name, 120).trim();
  const parent_name = cap(b.parent_name, 120).trim();
  const parent_email = cap(b.parent_email, 160).trim();
  const signature_name = cap(b.signature_name, 120).trim();
  const photo_choice = cap(b.photo_choice, 12).trim().toLowerCase();

  const missing = [];
  if (!child_name) missing.push('child_name');
  if (!parent_name) missing.push('parent_name');
  if (!isEmail(parent_email)) missing.push('parent_email');
  if (!signature_name) missing.push('signature_name');
  if (!['yes', 'limited', 'no'].includes(photo_choice)) missing.push('photo_choice');
  if (!bool(b.agree_policies)) missing.push('agree_policies');
  if (!bool(b.agree_medical)) missing.push('agree_medical');
  if (!bool(b.agree_payment)) missing.push('agree_payment');
  if (!bool(b.agree_esign)) missing.push('agree_esign');
  if (missing.length) { res.status(400).json({ ok: false, error: 'Please complete all required fields.', missing }); return; }

  const row = {
    lead_id: cap(b.lead_id, 60).trim() || null,
    child_name,
    child_dob: cap(b.child_dob, 40).trim() || null,
    programs: cap(b.programs, 200).trim() || null,
    parent_name,
    parent_email,
    parent_phone: cap(b.parent_phone, 40).trim() || null,
    contact2_name: cap(b.contact2_name, 120).trim() || null,
    contact2_phone: cap(b.contact2_phone, 40).trim() || null,
    allergies: cap(b.allergies, 500).trim() || null,
    conditions: cap(b.conditions, 500).trim() || null,
    medications: cap(b.medications, 500).trim() || null,
    physician: cap(b.physician, 200).trim() || null,
    hospital: cap(b.hospital, 200).trim() || null,
    insurance: cap(b.insurance, 200).trim() || null,
    emerg_med: cap(b.emerg_med, 300).trim() || null,
    emerg_med_use: cap(b.emerg_med_use, 300).trim() || null,
    emerg_med_where: cap(b.emerg_med_where, 200).trim() || null,
    emerg_self_carry: bool(b.emerg_self_carry),
    emerg_staff_help: bool(b.emerg_staff_help),
    pickup1: cap(b.pickup1, 200).trim() || null,
    pickup2: cap(b.pickup2, 200).trim() || null,
    self_signout: (cap(b.self_signout, 8).trim().toLowerCase() || null),
    photo_choice,
    agree_policies: true,
    agree_medical: true,
    agree_payment: true,
    agree_esign: true,
    signature_name,
    signature_relation: cap(b.signature_relation, 20).trim() || null,
    signed_date: cap(b.signed_date, 20).trim() || new Date().toISOString().slice(0, 10),
    ip: clientIp(req),
    user_agent: cap(req.headers['user-agent'] || '', 300),
    policies_version: POLICIES_VERSION,
  };

  try {
    const r = await fetch(`${url}/rest/v1/consent_signatures`, {
      method: 'POST',
      headers: {
        apikey: key, Authorization: `Bearer ${key}`,
        'Content-Type': 'application/json', Prefer: 'return=representation',
      },
      body: JSON.stringify(row),
    });
    if (!r.ok) { res.status(502).json({ ok: false, error: 'Could not save — please try again.', detail: await r.text() }); return; }
    const saved = await r.json();
    const id = Array.isArray(saved) && saved[0] ? saved[0].id : null;
    res.status(200).json({ ok: true, id });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'Consent handler failed' });
  }
};
