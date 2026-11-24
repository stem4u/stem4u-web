// Edge Middleware: gate private STEM4U content behind a server-verified unlock cookie.
//   - every /assets/*.pdf  (coach packs, lesson decks, build guides)
//   - a fixed list of private HTML pages (Learn hubs + interactive figures)
// Un-authed requests (including a direct URL paste) are redirected to /unlock.html.
// Non-PDF files under /assets (images, etc.) stay public.
export const config = {
  matcher: [
    '/assets/:path*',
    '/csai-k2-hub.html',
    '/csai-3to5-hub.html',
    '/csai-6to8-hub.html',
    '/sci-k2-hub.html',
    '/sci-3to5-hub.html',
    '/sci-6to8-hub.html',
    '/microbit-hub.html',
    '/forest-roots.html',
    '/pollinator-alley.html',
    '/biowatch-monitor.html',
    '/rootwatch-deck.html',
    '/biowatch-deck.html',
    '/pollinator-alley-deck.html',
    '/mission-models.html',
    '/biobuzz-ref.html',
  ],
};

const PROTECTED_HTML = new Set([
  '/csai-k2-hub.html',
  '/csai-3to5-hub.html',
  '/csai-6to8-hub.html',
  '/sci-k2-hub.html',
  '/sci-3to5-hub.html',
  '/sci-6to8-hub.html',
  '/microbit-hub.html',
  '/forest-roots.html',
  '/pollinator-alley.html',
  '/biowatch-monitor.html',
  '/rootwatch-deck.html',
  '/biowatch-deck.html',
  '/pollinator-alley-deck.html',
  '/mission-models.html',
  '/biobuzz-ref.html',
]);

export default function middleware(request) {
  const url = new URL(request.url);
  const p = url.pathname;
  const pl = p.toLowerCase();

  const isAssetPdf = pl.startsWith('/assets/') && pl.endsWith('.pdf');
  const isProtectedHtml = PROTECTED_HTML.has(p);
  if (!isAssetPdf && !isProtectedHtml) return; // everything else stays public

  const token = process.env.DOCS_UNLOCK_TOKEN || '';
  const cookie = request.headers.get('cookie') || '';
  const m = cookie.match(/(?:^|;\s*)s4u_unlock=([^;]+)/);
  if (token && m && m[1] === token) return; // valid cookie -> allow

  const to = new URL('/unlock.html', request.url);
  to.searchParams.set('next', p + url.search);
  return Response.redirect(to, 302);
}
