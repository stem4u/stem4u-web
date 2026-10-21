// Edge Middleware: gate every /assets/*.pdf behind a server-verified unlock cookie.
// Un-authed requests (including direct URL paste) are redirected to /unlock.html.
export const config = { matcher: '/assets/:path*' };

export default function middleware(request) {
  const url = new URL(request.url);
  // Only protect PDFs; images and other static assets stay public.
  if (!url.pathname.toLowerCase().endsWith('.pdf')) return;

  const token = process.env.DOCS_UNLOCK_TOKEN || '';
  const cookie = request.headers.get('cookie') || '';
  const m = cookie.match(/(?:^|;\s*)s4u_unlock=([^;]+)/);
  if (token && m && m[1] === token) return; // valid cookie -> allow

  const to = new URL('/unlock.html', request.url);
  to.searchParams.set('next', url.pathname + url.search);
  return Response.redirect(to, 302);
}
