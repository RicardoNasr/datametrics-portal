// /api/shopify/dashboard-link.js
// Called from the embedded app.html when the merchant clicks "Open Dashboard".
// Verifies the App Bridge session token, looks up the client, and returns a
// short-lived magic-link URL that auto-logs them into the portal.
//
// Required env vars:
//   SHOPIFY_CLIENT_ID, SHOPIFY_CLIENT_SECRET
//   SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY
//   MAGIC_LINK_SECRET

import crypto from 'crypto';

// ---------- CORS ----------
function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.setHeader('Access-Control-Max-Age', '86400');
}

// ---------- helpers ----------
function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

function base64UrlEncode(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function verifySessionToken(token, clientId, clientSecret) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid JWT format');

  const [headerB64, payloadB64, signatureB64] = parts;
  const expectedSig = crypto
    .createHmac('sha256', clientSecret)
    .update(`${headerB64}.${payloadB64}`)
    .digest();
  const actualSig = base64UrlDecode(signatureB64);

  if (expectedSig.length !== actualSig.length || !crypto.timingSafeEqual(expectedSig, actualSig)) {
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
  const match = dest.match(/^https:\/\/([a-z0-9][a-z0-9-]*\.myshopify\.com)$/i);
  if (!match) throw new Error('Invalid dest claim');
  return match[1];
}

function signMagicToken(clientId, expiresInSeconds, secret) {
  const payload = {
    client_id: clientId,
    exp: Math.floor(Date.now() / 1000) + expiresInSeconds,
    nonce: crypto.randomBytes(8).toString('hex'),
  };
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', secret).update(payloadB64).digest();
  return `${payloadB64}.${base64UrlEncode(sig)}`;
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

  const authHeader = req.headers.authorization || '';
  const sessionToken = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (!sessionToken) {
    return res.status(401).json({ error: 'Missing Authorization header' });
  }

  let claims;
  try {
    claims = verifySessionToken(
      sessionToken,
      process.env.SHOPIFY_CLIENT_ID,
      process.env.SHOPIFY_CLIENT_SECRET
    );
  } catch (err) {
    console.error('Session token verification failed:', err.message);
    return res.status(401).json({ error: 'Invalid session token' });
  }

  let shop;
  try {
    shop = shopFromDest(claims.dest);
  } catch (err) {
    return res.status(400).json({ error: 'Invalid session token claims' });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  const lookupRes = await fetch(
    `${supabaseUrl}/rest/v1/clients` +
      `?shopify_domain=eq.${encodeURIComponent(shop)}` +
      `&select=client_id,status,subscription_end_date`,
    {
      headers: {
        'apikey': supabaseKey,
        'Authorization': `Bearer ${supabaseKey}`,
      },
    }
  );

  if (!lookupRes.ok) {
    console.error('Supabase lookup failed:', await lookupRes.text());
    return res.status(500).json({ error: 'Database lookup failed' });
  }

  const rows = await lookupRes.json();
  if (!Array.isArray(rows) || rows.length === 0) {
    return res.status(404).json({
      error: 'no_client',
      message: 'No DataMetrics account found for this store yet.',
    });
  }

  const client = rows[0];
  const magicSecret = process.env.MAGIC_LINK_SECRET;
  if (!magicSecret) {
    console.error('MAGIC_LINK_SECRET not set');
    return res.status(500).json({ error: 'Server misconfiguration' });
  }

  if (client.status === 'active') {
    const magicToken = signMagicToken(client.client_id, 300, magicSecret); // 5 min
    const dashboardUrl =
      `https://datametrics-portal.vercel.app/?magic=${encodeURIComponent(magicToken)}`;
    return res.status(200).json({ kind: 'dashboard', url: dashboardUrl });
  }

  // Not active (pending_onboarding, expired, etc) → show the demo dashboard
  // using a magic token for Lune (client_id 100001), so the reviewer / prospect
  // sees real data without any login. 10-minute expiry is plenty for a review.
  const demoMagicToken = signMagicToken(100001, 600, magicSecret);
  const demoUrl =
    `https://datametrics-portal.vercel.app/?magic=${encodeURIComponent(demoMagicToken)}`;
  return res.status(200).json({ kind: 'demo', url: demoUrl });
}
