// Concept2 sends the user back here after they approve access.
import { cookie, getCookie, redirect, redirectUri, requestToken, sessionCookie } from '../../lib/c2.js';

export async function GET(request) {
  const params = new URL(request.url).searchParams;
  const fail = msg => redirect('/#c2error=' + encodeURIComponent(msg), [cookie('c2state', '', 0)]);

  if (params.get('error')) return fail('Toegang tot het Logbook is geweigerd.');
  const code = params.get('code');
  const state = params.get('state');
  if (!code || !state || state !== getCookie(request, 'c2state')) {
    return fail('De koppeling is verlopen of ongeldig. Probeer het opnieuw.');
  }
  try {
    const session = await requestToken({ grant_type: 'authorization_code', code, redirect_uri: redirectUri(request) });
    return redirect('/#historie', [sessionCookie(session), cookie('c2state', '', 0)]);
  } catch (err) {
    return fail(`Koppelen mislukt: ${err.message}`);
  }
}
