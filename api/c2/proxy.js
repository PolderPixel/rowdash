// Read-only proxy to the Concept2 Logbook API for the signed-in user.
// Only paths under users/me are allowed: GET /api/c2/proxy?path=users/me/results&number=250
import { C2, getSession } from '../../lib/c2.js';

const ALLOWED = /^users\/me(\/results(\/\d+(\/strokes)?)?)?$/;

export async function GET(request) {
  const url = new URL(request.url);
  const path = url.searchParams.get('path') || '';
  if (!ALLOWED.test(path)) return Response.json({ error: 'path not allowed' }, { status: 400 });

  const auth = await getSession(request);
  if (!auth) return Response.json({ error: 'not_connected' }, { status: 401 });

  const upstream = new URL(`${C2}/api/${path}`);
  url.searchParams.forEach((v, k) => { if (k !== 'path') upstream.searchParams.set(k, v); });

  const res = await fetch(upstream, {
    headers: { Accept: 'application/vnd.c2logbook.v1+json', Authorization: `Bearer ${auth.session.a}` },
  });
  const headers = new Headers({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  if (auth.setCookie) headers.append('Set-Cookie', auth.setCookie);
  const body = res.status === 401 ? JSON.stringify({ error: 'not_connected' }) : await res.text();
  return new Response(body, { status: res.status, headers });
}
