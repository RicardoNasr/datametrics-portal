// /api/shopify/token-exchange.js
// Modern token acquisition for embedded apps using Shopify managed installation.
//
// Apps rendered in Shopify Admin use TOKEN EXCHANGE, not the OAuth callback
// flow. When the embedded app loads, App Bridge gives it a session token. The
// app sends that session token here; we:
//   1. Verify the session token (it's a JWT signed with our client secret)
//   2. Exchange it for an OFFLINE access token via Shopify's token endpoint
//   3. Upsert the token into public.clients (so n8n can use it for syncs)
//
// This self-heals: every time anyone opens the app, the token is refreshed.
//
// Required env vars:
//   SHOPIFY_CLIENT_ID, SHOPIFY_CLIENT_SECRET
//   SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY

import crypto from 'crypto';

// ---------- CORS ----------
function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.setHeader('Access-Control-Max-Age', '86400');
}

// ---------- session token verification ----------
function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

function verifySessionToken(token, clientId, clientSecret) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid JWT format');

  const [headerB64, payloadB64, sigB64] = parts;
  const expected = crypto
    .createHmac('sha256', clientSecret)
    .update(`${headerB64}.${payloadB64}`)
    .digest();
  const actual = base64UrlDecode(sigB64);
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
    throw new Error('Invalid session token signature');
  }

  const payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf8'));
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && now >= payload.exp) throw new Error('Session token expired');
  if (payload.nbf && now < payload.nbf) throw new Error('Session token not yet valid');
  if (payload.aud !== clientId) throw new Error('Session token audience mismatch');
  if (!payload.dest || typeof payload.dest !== 'string') {
    throw new Error('Session token missing dest claim');
  }
  return payload;
}

function shopFromDest(dest) {
  const m = dest.match(/^https:\/\/([a-z0-9][a-z0-9-]*\.myshopify\.com)$/i);
  if (!m) throw new Error('Invalid dest claim');
  return m[1];
}

// ---------- handler ----------
export default async function handler(req, res) {
  setCors(res);

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // 1. Get + verify the session token
  const auth = req.headers.authorization || '';
  const sessionToken = auth.replace(/^Bearer\s+/i, '').trim();
  if (!sessionToken) {
    return res.status(401).json({ error: 'Missing session token' });
  }

  let claims, shop;
  try {
    claims = verifySessionToken(
      sessionToken,
      process.env.SHOPIFY_CLIENT_ID,
      process.env.SHOPIFY_CLIENT_SECRET
    );
    shop = shopFromDest(claims.dest);
  } catch (err) {
    console.warn('Session token verification failed:', err.message);
    return res.status(401).json({ error: 'Invalid session token' });
  }

  // 2. Exchange the session token for an OFFLINE access token
  let tokenData;
  try {
    const exchangeRes = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      },
      body: new URLSearchParams({
        client_id: process.env.SHOPIFY_CLIENT_ID,
        client_secret: process.env.SHOPIFY_CLIENT_SECRET,
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        subject_token: sessionToken,
        subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
        requested_token_type: 'urn:shopify:params:oauth:token-type:offline-access-token',
      }).toString(),
    });

    if (!exchangeRes.ok) {
      const errText = await exchangeRes.text();
      console.error('Token exchange failed:', exchangeRes.status, errText);
      return res.status(502).json({ error: 'Token exchange failed' });
    }

    tokenData = await exchangeRes.json();
  } catch (err) {
    console.error('Token exchange error:', err);
    return res.status(502).json({ error: 'Token exchange error' });
  }

  const accessToken = tokenData.access_token;
  if (!accessToken) {
    console.error('No access_token in token-exchange response:', tokenData);
    return res.status(502).json({ error: 'No access token returned' });
  }

  console.log(
    `Token exchanged for ${shop} | scope=${tokenData.scope} | ` +
    `expires_in=${tokenData.expires_in || 'permanent'}`
  );

  // 3. Build a tolerant payload and upsert into public.clients
  const now = new Date();
  const tokenPayload = {
    shopify_access_token: accessToken,
    shopify_installed_at: now.toISOString(),
    updated_at: now.toISOString(),
  };
  if (tokenData.refresh_token) {
    tokenPayload.shopify_refresh_token = tokenData.refresh_token;
  }
  if (typeof tokenData.expires_in === 'number') {
    tokenPayload.shopify_token_expires_at = new Date(
      now.getTime() + tokenData.expires_in * 1000
    ).toISOString();
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  try {
    // Lookup existing row
    const findRes = await fetch(
      `${supabaseUrl}/rest/v1/clients` +
        `?shopify_domain=eq.${encodeURIComponent(shop)}` +
        `&select=client_id,status`,
      {
        headers: {
          'apikey': supabaseKey,
          'Authorization': `Bearer ${supabaseKey}`,
        },
      }
    );

    if (!findRes.ok) {
      console.error('Supabase lookup failed:', await findRes.text());
      return res.status(500).json({ error: 'Database lookup failed' });
    }

    const existing = await findRes.json();

    if (Array.isArray(existing) && existing.length > 0) {
      // UPDATE — preserve existing status (don't downgrade a paying client)
      const clientId = existing[0].client_id;
      const patchRes = await fetch(
        `${supabaseUrl}/rest/v1/clients?client_id=eq.${clientId}`,
        {
          method: 'PATCH',
          headers: {
            'apikey': supabaseKey,
            'Authorization': `Bearer ${supabaseKey}`,
            'Content-Type': 'application/json',
            'Prefer': 'return=minimal',
          },
          body: JSON.stringify(tokenPayload),
        }
      );
      if (!patchRes.ok) {
        console.error('Supabase UPDATE failed:', await patchRes.text());
        return res.status(500).json({ error: 'Failed to save token' });
      }
      console.log(`✅ Token updated for existing client ${clientId} (${shop})`);
      return res.status(200).json({ ok: true, shop, status: existing[0].status });
    } else {
      // INSERT new client as pending_onboarding
      const newClientId = 100000 + (Date.now() % 100000);
      const insertPayload = {
        client_id: newClientId,
        client_name: shop.replace('.myshopify.com', ''),
        slug: shop.replace('.myshopify.com', ''),
        shopify_domain: shop,
        status: 'pending_onboarding',
        is_active: false,
        ...tokenPayload,
      };
      const postRes = await fetch(`${supabaseUrl}/rest/v1/clients`, {
        method: 'POST',
        headers: {
          'apikey': supabaseKey,
          'Authorization': `Bearer ${supabaseKey}`,
          'Content-Type': 'application/json',
          'Prefer': 'return=minimal',
        },
        body: JSON.stringify(insertPayload),
      });
      if (!postRes.ok) {
        console.error('Supabase INSERT failed:', await postRes.text());
        return res.status(500).json({ error: 'Failed to save new client' });
      }
      console.log(`✅ Created new client ${newClientId} for ${shop} (pending_onboarding)`);
      return res.status(200).json({ ok: true, shop, status: 'pending_onboarding' });
    }
  } catch (err) {
    console.error('Supabase write error:', err);
    return res.status(500).json({ error: 'Database write error' });
  }
}
