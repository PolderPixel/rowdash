// Shared helpers for the Concept2 Logbook connection.
// The OAuth tokens live in an encrypted, HttpOnly cookie, so no database is needed
// and the browser never sees the tokens or the client secret.
import crypto from 'node:crypto';

export const C2 = 'https://log.concept2.com';
export const SCOPE = 'user:read,results:read';
const SESSION_COOKIE = 'c2session';
const YEAR = 365 * 24 * 3600;

function key() {
  const secret = process.env.SESSION_SECRET;
  if (!secret) throw new Error('SESSION_SECRET is not set');
  return crypto.createHash('sha256').update(secret).digest();
}

export function seal(obj) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key(), iv);
  const data = Buffer.concat([cipher.update(JSON.stringify(obj), 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), data]).toString('base64url');
}

export function unseal(text) {
  try {
    const buf = Buffer.from(text, 'base64url');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key(), buf.subarray(0, 12));
    decipher.setAuthTag(buf.subarray(12, 28));
    return JSON.parse(Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString('utf8'));
  } catch {
    return null;
  }
}

export function getCookie(request, name) {
  const header = request.headers.get('cookie') || '';
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return null;
}

export function cookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

export function redirectUri(request) {
  return process.env.C2_REDIRECT_URI || `${new URL(request.url).origin}/api/c2/callback`;
}

export function redirect(location, cookies = []) {
  const headers = new Headers({ Location: location, 'Cache-Control': 'no-store' });
  cookies.forEach(c => headers.append('Set-Cookie', c));
  return new Response(null, { status: 302, headers });
}

// End of the login when it ran in its own window: tell the app (which kept its Bluetooth
// connection to the PM5) how it went, then close. The app listens on a BroadcastChannel.
export function popupResult(ok, message = '', cookies = []) {
  const payload = JSON.stringify({ ok, message });
  const html = `<!doctype html><html lang="nl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>RowDash</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b0f14;color:#e8edf3;
font:16px system-ui,sans-serif;text-align:center;padding:24px;box-sizing:border-box}a{color:#4fc3f7}</style></head>
<body><div><p>${ok ? 'Logbook gekoppeld.' : message.replace(/</g, '&lt;')}</p>
<p>Je kunt dit venster sluiten en teruggaan naar RowDash.</p><p><a href="/">Naar RowDash</a></p></div>
<script>try{new BroadcastChannel('rowdash-c2').postMessage(${payload})}catch(e){}
try{window.opener&&window.opener.postMessage(${payload},location.origin)}catch(e){}
setTimeout(function(){window.close()},600)</script></body></html>`;
  const headers = new Headers({ 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
  cookies.forEach(c => headers.append('Set-Cookie', c));
  return new Response(html, { status: 200, headers });
}

// Exchange an authorization code or refresh token for a fresh session.
export async function requestToken(params) {
  const res = await fetch(`${C2}/oauth/access_token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: new URLSearchParams({
      client_id: process.env.C2_CLIENT_ID,
      client_secret: process.env.C2_CLIENT_SECRET,
      scope: SCOPE,
      ...params,
    }),
  });
  if (!res.ok) throw new Error(`token request failed (${res.status})`);
  const t = await res.json();
  return { a: t.access_token, r: t.refresh_token || params.refresh_token, e: Date.now() + (t.expires_in || 3600) * 1000 };
}

export function sessionCookie(session) {
  return cookie(SESSION_COOKIE, seal(session), YEAR);
}
export function clearSessionCookie() {
  return cookie(SESSION_COOKIE, '', 0);
}

// Returns { session, setCookie } with a valid access token, refreshing it if needed; null if not connected.
export async function getSession(request) {
  const raw = getCookie(request, SESSION_COOKIE);
  const session = raw && unseal(raw);
  if (!session) return null;
  if (session.e - Date.now() > 60_000) return { session, setCookie: null };
  try {
    const fresh = await requestToken({ grant_type: 'refresh_token', refresh_token: session.r });
    return { session: fresh, setCookie: sessionCookie(fresh) };
  } catch {
    return null;
  }
}
