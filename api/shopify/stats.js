// /api/shopify/stats.js
// Returns live counts (orders / products / customers / currency) for the
// current merchant's store, for display in the embedded app.
//
// Flow:
//   1. Handle CORS preflight (OPTIONS) — required because the embedded app
//      calls this cross-origin from admin.shopify.com with an Authorization header
//   2. Verify the App Bridge session token
//   3. Extract shop from the token's `dest` claim
//   4. Look up the offline access token in public.clients
//   5. Call Shopify GraphQL Admin API with that access token
//   6. Return the counts

import crypto from 'crypto';

// ---------- CORS ----------
// Set permissive CORS headers on EVERY response (including errors + preflight).
// Shopify embeds the app under admin.shopify.com, so requests are cross-origin.
function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
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
  if (parts.length !== 3) throw new Error('Invalid JWT');

  const [headerB64, payloadB64, sigB64] = parts;
  const expected = crypto
    .createHmac('sha256', clientSecret)
    .update(`${headerB64}.${payloadB64}`)
    .digest();
  const actual = base64UrlDecode(sigB64);
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
    throw new Error('Bad signature');
  }

  const payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf8'));
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && now >= payload.exp) throw new Error('Token expired');
  if (payload.aud !== clientId) throw new Error('Token audience mismatch');
  return payload;
}

function shopFromDest(dest) {
  const m = dest.match(/^https:\/\/([a-z0-9][a-z0-9-]*\.myshopify\.com)$/i);
  if (!m) throw new Error('Bad dest claim');
  return m[1];
}

// ---------- handler ----------
export default async function handler(req, res) {
  setCors(res);

  // Preflight
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  if (req.method !== 'GET' && req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const auth = req.headers.authorization || '';
  const sessionToken = auth.replace(/^Bearer\s+/i, '').trim();
  if (!sessionToken) return res.status(401).json({ error: 'Missing token' });

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

  // Lookup access token from Supabase
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  const lookupRes = await fetch(
    `${supabaseUrl}/rest/v1/clients` +
      `?shopify_domain=eq.${encodeURIComponent(shop)}` +
      `&select=shopify_access_token`,
    {
      headers: {
        'apikey': supabaseKey,
        'Authorization': `Bearer ${supabaseKey}`,
      },
    }
  );

  if (!lookupRes.ok) {
    console.error('Supabase lookup failed:', await lookupRes.text());
    return res.status(500).json({ error: 'Database error' });
  }

  const rows = await lookupRes.json();
  if (!Array.isArray(rows) || rows.length === 0 || !rows[0].shopify_access_token) {
    return res.status(404).json({ error: 'No access token on file for this shop' });
  }

  const accessToken = rows[0].shopify_access_token;

  // Query Shopify GraphQL Admin API
  const query = `
    query {
      shop { currencyCode }
      ordersCount { count }
      productsCount { count }
      customersCount { count }
    }
  `;

  try {
    const gqlRes = await fetch(
      `https://${shop}/admin/api/2026-01/graphql.json`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Shopify-Access-Token': accessToken,
        },
        body: JSON.stringify({ query }),
      }
    );

    if (!gqlRes.ok) {
      const errText = await gqlRes.text();
      console.error('Shopify GraphQL failed:', gqlRes.status, errText);
      return res.status(502).json({ error: 'Shopify API error' });
    }

    const gqlJson = await gqlRes.json();
    const data = gqlJson.data || {};

    return res.status(200).json({
      shop,
      orders:    data.ordersCount    ? data.ordersCount.count    : null,
      products:  data.productsCount  ? data.productsCount.count  : null,
      customers: data.customersCount ? data.customersCount.count : null,
      currency:  data.shop           ? data.shop.currencyCode     : null,
    });
  } catch (err) {
    console.error('Shopify GraphQL error:', err);
    return res.status(502).json({ error: 'Shopify API error' });
  }
}
