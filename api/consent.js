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

const { logEvent } = require('./_log');

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

  // LOG FIRST — record every inbound submission the instant it arrives, BEFORE any
  // honeypot / CAPTCHA / validation can drop it. This is the bare-minimum trace: a
  // registration can never again be invisible. Best-effort; never blocks the request.
  try {
    await logEvent({
      req, source: 'consent', event: 'submission_received', level: 'info', ok: true,
      email: cap(b.parent_email, 160).trim() || null, child: cap(b.child_name, 120).trim() || null,
      message: 'Consent submission received (pre-validation)',
      detail: {
        programs: cap(b.programs, 200).trim() || null, camp: cap(b.camp, 120).trim() || null,
        parent: cap(b.parent_name, 120).trim() || null, phone: cap(b.parent_phone, 40).trim() || null,
        grade: cap(b.grade, 40).trim() || null, honeypot: !!cap(b._gotcha, 100).trim(),
      },
    });
  } catch (_) { /* logging must never block a registration */ }

  // NOTE: a honeypot used to live here and SILENTLY returned {ok:true} (dropping the
  // submission) whenever the hidden _gotcha field had any value. Browser autofill fills
  // that hidden field, so real registrations vanished with no row, no log, no email.
  // It is removed on purpose — spam is handled by Turnstile + rate-limit + origin check.
  // We still record if it was filled, but we NEVER drop the submission.
  const honeypotFilled = !!cap(b._gotcha, 100).trim();

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
    contact2_relation: cap(b.contact2_relation, 120).trim() || null,
    contact2_phone: cap(b.contact2_phone, 40).trim() || null,
    contact2_email: cap(b.contact2_email, 160).trim().toLowerCase() || null,
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
    agree_tutor: bool(b.agree_tutor),
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
    if (!r.ok) {
      const detail = await r.text();
      // Durable log of the failure (exact DB error + who it was) — survives forever.
      await logEvent({
        req, source: 'consent', event: 'save_failed', level: 'error', ok: false, status: r.status,
        email: parent_email, child: child_name,
        message: cap(b.camp, 120).trim() ? 'Camp signup did NOT save' : 'Enrollment consent did NOT save',
        detail: { db_error: String(detail).slice(0, 2000), camp: cap(b.camp, 120).trim() || null, programs: row.programs, parent: parent_name, phone: row.parent_phone },
      });
      // DEBUG: email the exact DB error so we can see why camp signups aren't saving.
      if (process.env.RESEND_API_KEY) {
        try {
          await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({
              from: process.env.LEAD_FROM || 'STEM4U <leads@stem4u.com>',
              to: (process.env.LEAD_TO || 'contact@stem4u.com').split(',').map((x) => x.trim()),
              subject: '⚠ Camp/consent save FAILED — recover this family',
              html: `<h3 style="font-family:Arial;color:#b02a2a">A signup did NOT save — contact this family</h3>`
                + `<table style="font-family:Arial;font-size:14px">`
                + `<tr><td>Child</td><td><b>${String((b.child_first||'')+' '+(b.child_last||'')).replace(/[<>]/g,'')}</b></td></tr>`
                + `<tr><td>Parent</td><td><b>${String((b.parent_first||'')+' '+(b.parent_last||'')).replace(/[<>]/g,'')}</b></td></tr>`
                + `<tr><td>Email</td><td><b>${String(b.parent_email||'').replace(/[<>]/g,'')}</b></td></tr>`
                + `<tr><td>Phone</td><td><b>${String(b.parent_phone||'').replace(/[<>]/g,'')}</b></td></tr>`
                + `<tr><td>Camp</td><td>${String(b.camp||'').replace(/[<>]/g,'')}</td></tr>`
                + `</table>`
                + `<pre style="font-family:monospace;font-size:12px;white-space:pre-wrap;color:#666">status ${r.status}\n${String(detail).replace(/[&<>]/g,'')}</pre>`,
            }),
          });
        } catch (e) { /* ignore */ }
      }
      res.status(502).json({ ok: false, error: 'Could not save — please try again.', detail });
      return;
    }
    const saved = await r.json();
    const id = Array.isArray(saved) && saved[0] ? saved[0].id : null;
    const isCamp = !!cap(b.camp, 120).trim();

    // Durable success log — one row per signed submission.
    await logEvent({
      req, source: 'consent', event: isCamp ? 'camp_signup' : 'enrollment_consent',
      level: 'info', ok: true, status: 200, email: parent_email, child: child_name,
      message: isCamp ? ('Camp signup saved — ' + cap(b.camp, 120).trim()) : 'Enrollment consent saved',
      detail: { consent_id: id, programs: row.programs, grade: cap(b.grade, 40).trim() || null, photo_choice, parent: parent_name, phone: row.parent_phone },
    });

    // Notify the team on every signed submission (camp registration OR enrollment
    // consent). Best-effort — mirrors /api/lead. Needs RESEND_API_KEY + LEAD_TO.
    if (process.env.RESEND_API_KEY) {
      try {
        const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
        const campName = cap(b.camp, 120).trim();
        const kind = campName ? ('Camp registration — ' + campName) : 'Enrollment consent';
        const fields = [['Child', child_name], ['Parent', parent_name], ['Email', parent_email], ['Phone', row.parent_phone || ''], ['Program', row.programs || campName || ''], ['Grade', cap(b.grade, 40).trim() || ''], ['Photos', photo_choice], ['Signed', row.signed_date]];
        const trs = fields.filter((f) => f[1]).map(([k, v]) => `<tr><td style="padding:3px 12px 3px 0;color:#555">${esc(k)}</td><td style="padding:3px 0"><b>${esc(v)}</b></td></tr>`).join('');
        await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            from: process.env.LEAD_FROM || 'STEM4U <leads@stem4u.com>',
            to: (process.env.LEAD_TO || 'contact@stem4u.com').split(',').map((x) => x.trim()),
            subject: `New ${kind}: ${child_name}`,
            html: `<h2 style="font-family:Arial;color:#0D2B7A">New ${esc(kind)}</h2><table style="border-collapse:collapse;font-family:Arial;font-size:14px">${trs}</table><p style="font-family:Arial;font-size:12px;color:#888">Signed waiver on file · ${esc(row.signed_date)}</p>`,
          }),
        });
      } catch (e) {
        // The email backup failed to send — log it so a broken backup is never silent.
        await logEvent({ req, source: 'consent', event: 'alert_email_failed', level: 'warn', ok: false,
          email: parent_email, child: child_name, message: 'Signup saved, but the backup/alert email failed to send',
          detail: { error: String(e && e.message || e).slice(0, 300), to: process.env.LEAD_TO || 'contact@stem4u.com' } });
      }
    } else {
      // No email backup configured at all — log it loudly so you know the backup is OFF.
      await logEvent({ req, source: 'consent', event: 'alert_email_not_configured', level: 'warn', ok: false,
        email: parent_email, child: child_name, message: 'Signup saved, but NO email backup is configured (set RESEND_API_KEY + LEAD_TO)',
        detail: { programs: row.programs } });
    }

    // Camp signups: also create a Manage lead so the camper shows in the roster /
    // Classes & Fees / Attendance. Gated to camp submissions (b.camp) so regular
    // enrollment consents don't create duplicate leads. Non-fatal.
    if (cap(b.camp, 120).trim()) {
      // Map each camp (the page sends data.camp) to its team, roster class, and program label.
      const campName = cap(b.camp, 120).trim();
      const CAMP_MAP = {
        'Oct 30 STEM4U Camp':    { team: 'Oct 30',      class_id: 'CAMP-OCT30', programs: 'Day Camp',    note: 'Signed up via the Oct 30 camp page. Waiver signed.' },
        'Robo Rumble (Nov 2-3)': { team: 'Robo Rumble', class_id: 'CAMP-RR',    programs: 'Robo Rumble', note: 'Signed up via the Robo Rumble camp page. Waiver signed.' },
      };
      const CM = CAMP_MAP[campName] || { team: (campName || 'Camp').slice(0, 60), class_id: null, programs: 'Day Camp', note: 'Signed up via a camp page. Waiver signed.' };
      const CAMP_CLASS_ID = CM.class_id;
      const CAMP_TEAM = CM.team;
      try {
        const sp = (full) => { const t = String(full || '').trim().split(/\s+/); return { first: t.shift() || '', last: t.join(' ') }; };
        const cn = b.child_first ? { first: cap(b.child_first, 80), last: cap(b.child_last, 80) } : sp(child_name);
        const pn = b.parent_first ? { first: cap(b.parent_first, 80), last: cap(b.parent_last, 80) } : sp(parent_name);
        const leadRow = {
          submitted_at: new Date().toISOString(),
          type: 'Camp',
          source: 'Camp Signup',
          assigned_team: CAMP_TEAM,
          parent_first_name: pn.first,
          parent_last_name: pn.last,
          child_first_name: cn.first,
          child_last_name: cn.last,
          email: parent_email.toLowerCase(),
          parent2_email: cap(b.contact2_email, 160).trim().toLowerCase() || null,
          phone: cap(b.parent_phone, 40).trim() || null,
          grade: cap(b.grade, 40).trim() || null,
          programs: CM.programs,
          message: CM.note,
          status: 'new',
          acq: (function (a) { if (!a || typeof a !== 'object') return null; const ks = ['utm_source','utm_medium','utm_campaign','utm_content','utm_term','gclid','fbclid','referrer','landing','ts']; const o = {}; for (const k of ks) { if (a[k]) o[k] = String(a[k]).slice(0, 300); } return Object.keys(o).length ? o : null; })(b.acq),
        };
        // return=representation so we get the new lead id back to enroll it
        const leadResp = await fetch(`${url}/rest/v1/leads`, {
          method: 'POST',
          headers: { apikey: key, Authorization: `Bearer ${key}`, 'Content-Type': 'application/json', Prefer: 'return=representation' },
          body: JSON.stringify(leadRow),
        });
        let leadId = null;
        try { const lrows = await leadResp.json(); leadId = Array.isArray(lrows) && lrows[0] ? lrows[0].id : null; } catch (_) {}
        // Auto-enroll the camper in the mapped camp class so they show in the roster,
        // Classes & Fees, Attendance and Accounts Receivable without manual steps.
        if (leadId && CAMP_CLASS_ID) {
          try {
            await fetch(`${url}/rest/v1/class_enrollments?on_conflict=lead_id,class_id`, {
              method: 'POST',
              headers: { apikey: key, Authorization: `Bearer ${key}`, 'Content-Type': 'application/json', Prefer: 'resolution=ignore-duplicates,return=minimal' },
              body: JSON.stringify({ lead_id: leadId, class_id: CAMP_CLASS_ID }),
            });
          } catch (e) { /* enrollment is best-effort; lead + consent are already saved */ }
        }
        await logEvent({
          req, source: 'consent', event: 'camp_lead_created', level: leadId ? 'info' : 'warn',
          ok: !!leadId, status: leadResp.status, email: parent_email, child: child_name,
          message: leadId ? 'Manage lead + enrollment created for camper' : 'Camp consent saved but lead was NOT created',
          detail: { lead_id: leadId, team: CAMP_TEAM, class_id: CAMP_CLASS_ID, parent: parent_name, phone: row.parent_phone },
        });
      } catch (e) {
        await logEvent({ req, source: 'consent', event: 'camp_lead_created', level: 'error', ok: false, email: parent_email, child: child_name, message: 'Exception creating camp lead', detail: { error: String(e && e.message || e).slice(0, 500), parent: parent_name, phone: row.parent_phone } });
      }
    }

    res.status(200).json({ ok: true, id });
  } catch (e) {
    // Last-resort fallback: an unexpected crash must NOT be silent. Log it, and email the
    // family's details so they can be recovered even if nothing saved.
    const errDetail = { error: String(e && e.message || e).slice(0, 500), programs: cap(b.programs, 200).trim() || null, camp: cap(b.camp, 120).trim() || null, parent: cap(b.parent_name, 120).trim() || null, phone: cap(b.parent_phone, 40).trim() || null };
    try {
      await logEvent({ req, source: 'consent', event: 'handler_exception', level: 'error', ok: false,
        email: cap(b.parent_email, 160).trim() || null, child: cap(b.child_name, 120).trim() || null,
        message: 'Consent handler threw — submission may not have saved', detail: errDetail });
    } catch (_) {}
    if (process.env.RESEND_API_KEY) {
      try {
        const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
        await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            from: process.env.LEAD_FROM || 'STEM4U <leads@stem4u.com>',
            to: (process.env.LEAD_TO || 'contact@stem4u.com').split(',').map((x) => x.trim()),
            subject: '⚠ Registration ERROR — recover this family',
            html: `<h3 style="font-family:Arial;color:#b02a2a">A registration hit an error and may not have saved — contact this family</h3>`
              + `<table style="font-family:Arial;font-size:14px">`
              + `<tr><td>Child</td><td><b>${esc(cap(b.child_name, 120) || ((b.child_first || '') + ' ' + (b.child_last || '')))}</b></td></tr>`
              + `<tr><td>Parent</td><td><b>${esc(cap(b.parent_name, 120) || ((b.parent_first || '') + ' ' + (b.parent_last || '')))}</b></td></tr>`
              + `<tr><td>Email</td><td><b>${esc(b.parent_email || '')}</b></td></tr>`
              + `<tr><td>Phone</td><td><b>${esc(b.parent_phone || '')}</b></td></tr>`
              + `<tr><td>Program</td><td>${esc(b.programs || b.camp || '')}</td></tr></table>`
              + `<pre style="font-family:monospace;font-size:12px;color:#666;white-space:pre-wrap">${esc(errDetail.error)}</pre>`,
          }),
        });
      } catch (_) {}
    }
    res.status(500).json({ ok: false, error: 'Consent handler failed' });
  }
};
