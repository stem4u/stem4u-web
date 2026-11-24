// Verifies a coach PIN server-side and sets an httpOnly unlock cookie.
// Accepts any PIN listed in DOC_PINS (comma-separated), so both the
// resources PIN and the CS&AI hub PIN keep working.
export default function handler(req, res) {
  if (req.method !== 'POST') { res.status(405).json({ ok: false }); return; }
  let pin = '';
  try {
    const b = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    pin = String(b.pin || '').trim();
  } catch (_) {}

  const pins = String(process.env.DOC_PINS || process.env.DOC_PIN || '').split(',').map(s => s.trim()).filter(Boolean);
  const token = process.env.DOCS_UNLOCK_TOKEN || '';
  if (!pins.length || !token) {
    res.status(500).json({ ok: false, error: 'not_configured',
      missing: [!pins.length && 'DOC_PINS', !token && 'DOCS_UNLOCK_TOKEN'].filter(Boolean) });
    return;
  }

  if (!pins.includes(pin)) { res.status(401).json({ ok: false }); return; }

  const maxAge = 60 * 60 * 8; // 8 hours
  res.setHeader('Set-Cookie',
    `s4u_unlock=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`);
  res.status(200).json({ ok: true });
}
