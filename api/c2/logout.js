// Forget the Concept2 Logbook connection on this device.
import { clearSessionCookie } from '../../lib/c2.js';

export function POST() {
  return new Response(null, { status: 204, headers: { 'Set-Cookie': clearSessionCookie() } });
}
