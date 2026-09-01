// /api/checkin — kid self check-in.
//   GET  ?team=OtterBots        -> { team, roster:[{id, name}] }  (first name + last initial)
//   POST { team, lead_id, name } -> upserts today's attendance (present, method 'self')
// Uses the same Supabase env as /api/lead. Attendance keyed on (session_date, lead_id).

const ALLOWED_HOSTS = ['stem4u.com', 'www.stem4u.com'];
function hostOf(u){ try{ return new URL(u).host.toLowerCase(); }catch{ return ''; } }
function originOk(req){
  const oh = hostOf(req.headers.origin||''); const rh = hostOf(req.headers.referer||'');
  if (oh) return ALLOWED_HOSTS.includes(oh);
  if (rh) return ALLOWED_HOSTS.includes(rh);
  return true;
}
const RL = new Map();
function clientIp(req){ return (req.headers['x-forwarded-for']||'').split(',')[0].trim() || req.headers['x-real-ip'] || 'unknown'; }
function rateLimited(ip,max=40,windowMs=10*60*1000){ const now=Date.now(); const a=(RL.get(ip)||[]).filter(t=>now-t<windowMs); a.push(now); RL.set(ip,a); if(RL.size>5000)RL.clear(); return a.length>max; }
const cap=(s,n)=>String(s==null?'':s).slice(0,n);
const KEY=()=>process.env.SUPABASE_SERVICE_KEY||process.env.SUPABASE_SECRET_KEY;
function todayET(){ return new Date().toLocaleDateString('en-CA',{timeZone:'America/New_York'}); } // YYYY-MM-DD

// Per-team access key: unguessable code baked into each team's QR link.
// key = base64url(HMAC-SHA256(CHECKIN_SECRET, team)).slice(0,10). No secret => not configured.
const crypto = require('crypto');
function teamKey(team){ const s=process.env.CHECKIN_SECRET||''; if(!s) return null; return crypto.createHmac('sha256',s).update(String(team)).digest('base64url').slice(0,10); }
function keyOk(team,k){ const exp=teamKey(team); if(exp===null) return null; if(!k) return false; const A=Buffer.from(String(k)),B=Buffer.from(exp); return A.length===B.length && crypto.timingSafeEqual(A,B); }

module.exports = async (req, res) => {
  const url = process.env.SUPABASE_URL, key = KEY();
  if (!url || !key) { res.status(500).json({ ok:false, error:'Server not configured' }); return; }
  const H = { apikey:key, Authorization:`Bearer ${key}`, 'Content-Type':'application/json' };

  try {
    if (req.method === 'GET') {
      const sp = new URL(req.url,'http://x').searchParams;
      const team = cap((sp.get('team')||''), 40).trim();
      const k = cap((sp.get('k')||''), 20).trim();
      if (!team) { res.status(400).json({ ok:false, error:'team required' }); return; }
      const ok = keyOk(team, k);
      if (ok === null) { res.status(503).json({ ok:false, error:'Check-in not configured' }); return; }
      if (!ok) { res.status(403).json({ ok:false, error:'Invalid or missing check-in code' }); return; }
      const r = await fetch(`${url}/rest/v1/leads?select=id,child_first_name,child_last_name&assigned_team=eq.${encodeURIComponent(team)}&deleted_at=is.null&order=child_first_name`, { headers:H });
      const rows = await r.json();
      if (!r.ok) { res.status(502).json({ ok:false, error:'roster read failed' }); return; }
      const roster = (Array.isArray(rows)?rows:[])
        .filter(l => (l.child_first_name||'').trim())
        .map(l => ({ id:l.id, name:((l.child_first_name||'').trim()+' '+((l.child_last_name||'').trim()?((l.child_last_name||'').trim()[0]+'.'):'')).trim() }));
      res.status(200).json({ ok:true, team, roster });
      return;
    }

    if (req.method === 'POST') {
      if (!originOk(req)) { res.status(403).json({ ok:false, error:'Bad origin' }); return; }
      if (rateLimited(clientIp(req))) { res.status(429).json({ ok:false, error:'Too many check-ins — wait a moment.' }); return; }
      let b = req.body; if (typeof b==='string'){ try{ b=JSON.parse(b||'{}'); }catch{ b={}; } } b=b||{};
      const team = cap(b.team,40).trim(), lead_id = cap(b.lead_id,60).trim(), name = cap(b.name,80).trim(), k = cap(b.k,20).trim();
      if (!lead_id || !name) { res.status(400).json({ ok:false, error:'lead_id and name required' }); return; }
      const ok = keyOk(team, k);
      if (ok === null) { res.status(503).json({ ok:false, error:'Check-in not configured' }); return; }
      if (!ok) { res.status(403).json({ ok:false, error:'Invalid or missing check-in code' }); return; }
      const row = { session_date:todayET(), team:team||null, lead_id, child_name:name, present:true, method:'self', updated_at:new Date().toISOString() };
      const r = await fetch(`${url}/rest/v1/checkins?on_conflict=session_date,lead_id`, {
        method:'POST', headers:{ ...H, Prefer:'resolution=merge-duplicates,return=minimal' }, body:JSON.stringify(row),
      });
      if (!r.ok) { res.status(502).json({ ok:false, error:'check-in failed', detail: await r.text() }); return; }
      res.status(200).json({ ok:true });
      return;
    }

    res.status(405).json({ ok:false, error:'GET or POST only' });
  } catch (e) {
    res.status(500).json({ ok:false, error:'Check-in handler failed' });
  }
};
