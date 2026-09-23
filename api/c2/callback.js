// Concept2 sends the user back here after they approve access.
import { cookie, getCookie, popupResult, redirect, redirectUri, requestToken, sessionCookie } from '../../lib/c2.js';

export async function GET(request) {
  const params = new URL(request.url).searchParams;
  const state = params.get('state');
  const popup = !!state && state.endsWith('.p');
  const clearState = cookie('c2state', '', 0);
  const fail = msg => popup ? popupResult(false, msg, [clearState])
                            : redirect('/#c2error=' + encodeURIComponent(msg), [clearState]);

  if (params.get('error')) return fail('Toegang tot het Logbook is geweigerd.');
  const code = params.get('code');
  if (!code || !state || state !== getCookie(request, 'c2state')) {
    return fail('De koppeling is verlopen of ongeldig. Probeer het opnieuw.');
  }
  try {
    const session = await requestToken({ grant_type: 'authorization_code', code, redirect_uri: redirectUri(request) });
    const cookies = [sessionCookie(session), clearState];
    return popup ? popupResult(true, '', cookies) : redirect('/#historie', cookies);
  } catch (err) {
    return fail(`Koppelen mislukt: ${err.message}`);
  }
}
