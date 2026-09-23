// Start the Concept2 Logbook OAuth flow.
import crypto from 'node:crypto';
import { C2, SCOPE, cookie, redirect, redirectUri } from '../../lib/c2.js';

export function GET(request) {
  if (!process.env.C2_CLIENT_ID) {
    return redirect('/#c2error=' + encodeURIComponent('De Concept2-koppeling is nog niet ingesteld (C2_CLIENT_ID ontbreekt).'));
  }
  const state = crypto.randomBytes(16).toString('hex');
  const url = new URL(`${C2}/oauth/authorize`);
  url.search = new URLSearchParams({
    client_id: process.env.C2_CLIENT_ID,
    scope: SCOPE,
    response_type: 'code',
    redirect_uri: redirectUri(request),
    state,
  });
  return redirect(url.toString(), [cookie('c2state', state, 600)]);
}
