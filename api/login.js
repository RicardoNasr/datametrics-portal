// /api/login.js
// Portal authentication endpoint. Supports two flows:
//   A) slug + passwordHash (existing flow for normal client logins)
//   B) magic-token (new flow for auto-login from the Shopify embedded app)
//
// Returns a signed Metabase embed URL with client_id locked inside the JWT.
//
// Required env vars:
//   SUPABASE_URL
//   SUPABASE_SERVICE_ROLE_KEY
//   METABASE_SECRET_KEY
//   METABASE_SITE_URL          e.g. https://metabase-v0-50-19-hjp5.onrender.com
//   MAGIC_LINK_SECRET          (for verifying magic tokens issued by dashboard-link.js)

import crypto from 'crypto';

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

// Sign a Metabase embedding JWT
function signMetabaseJwt(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  const sig = crypto
    .createHmac('sha256', secret)
    .update(`${headerB64}.${payloadB64}`)
    .digest();
  return `${headerB64}.${payloadB64}.${base64UrlEncode(sig)}`;
}

// Verify a magic-link token issued by /api/shopify/dashboard-link.js
function verifyMagicToken(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 2) throw new Error('Invalid magic token format');
  const [payloadB64, sigB64] = parts;

  const expectedSig = crypto.createHmac('sha256', secret).update(payloadB64).digest();
  const actualSig = base64UrlDecode(sigB64);

  if (
    expectedSig.length !== actualSig.length ||
    !crypto.timingSafeEqual(expectedSig, actualSig)
  ) {
    throw new Error('Magic token signature invalid');
  }

  const payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf8'));
  const now = Math.floor(Date.now() / 1000);
  if (!payload.exp || now >= payload.exp) throw new Error('Magic token expired');
  if (!payload.client_id) throw new Error('Magic token missing client_id');

  return payload;
}

// Build the signed Metabase embed URL for a given client row
function buildMetabaseUrl(clientRow) {
  const dashboardId = clientRow.dashboard_id || 2;
  const payload = {
    resource: { dashboard: dashboardId },
    params: { client: clientRow.client_id },
    exp: Math.floor(Date.now() / 1000) + 60 * 60, // 1 hour
  };

  const token = signMetabaseJwt(payload, process.env.METABASE_SECRET_KEY);
  const siteUrl = process.env.METABASE_SITE_URL;
  if (!siteUrl) throw new Error('METABASE_SITE_URL env var not set');
  // Trim trailing slash if present
  const base = siteUrl.replace(/\/+$/, '');
  return `${base}/embed/dashboard/${token}#bordered=false&titled=false`;
}

// Look up a client by either client_id or slug+passwordHash
async function lookupClient(filterParams) {
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  const url =
    `${supabaseUrl}/rest/v1/clients` +
    `?${filterParams}` +
    `&select=client_id,slug,dashboard_id,status,subscription_end_date,is_active,trial_data_ready_at,trial_started_at`;

  const res = await fetch(url, {
    headers: {
      'apikey': supabaseKey,
      'Authorization': `Bearer ${supabaseKey}`,
    },
  });

  if (!res.ok) {
    console.error('Supabase lookup failed:', res.status, await res.text());
    return null;
  }
  const rows = await res.json();
  return Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
}

// Decide what a client should see, based on status / expiry / data readiness.
// Returns one of:
//   { state: 'ready',     url, isDemo }
//   { state: 'preparing' }
//   { state: 'expired',   expiredKind: 'trial' | 'paid' }
function resolveAccessState(client, isDemo) {
  const today = new Date().toISOString().slice(0, 10);
  const expired =
    client.subscription_end_date && client.subscription_end_date < today;

  // Expiry is checked first, for everyone (trial AND paid).
  if (expired) {
    return {
      state: 'expired',
      expiredKind: client.status === 'active' ? 'paid' : 'trial',
    };
  }

  // Active paying client → full dashboard.
  if (client.status === 'active') {
    return { state: 'ready', url: buildMetabaseUrl(client), isDemo: false };
  }

  // Trial client → needs data to be ready first.
  if (client.status === 'trial') {
    if (!client.trial_data_ready_at) {
      return { state: 'preparing' };
    }
    return { state: 'ready', url: buildMetabaseUrl(client), isDemo: !!isDemo };
  }

  // pending_onboarding / anything else → not ready yet.
  return { state: 'preparing' };
}

// ---------- handler ----------

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { slug, passwordHash, magicToken } = req.body || {};

  // ===== Flow B: magic-token (Shopify embedded app auto-login) =====
  if (magicToken) {
    let claims;
    try {
      claims = verifyMagicToken(magicToken, process.env.MAGIC_LINK_SECRET);
    } catch (err) {
      console.warn('Magic token rejected:', err.message);
      return res.status(401).json({ error: 'Invalid or expired link' });
    }

    const client = await lookupClient(`client_id=eq.${claims.client_id}`);
    if (!client) {
      return res.status(404).json({ error: 'Client not found' });
    }

    try {
      const access = resolveAccessState(client, claims.demo === true);
      return res.status(200).json(access);
    } catch (err) {
      console.error('Failed to resolve access state:', err.message);
      return res.status(500).json({ error: 'Server misconfiguration' });
    }
  }

  // ===== Flow A: slug + passwordHash (existing) =====
  if (!slug || !passwordHash) {
    return res.status(400).json({ error: 'Missing credentials' });
  }

  const client = await lookupClient(
    `slug=eq.${encodeURIComponent(slug)}&password_hash=eq.${encodeURIComponent(passwordHash)}`
  );

  if (!client) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  try {
    const access = resolveAccessState(client, false);
    return res.status(200).json(access);
  } catch (err) {
    console.error('Failed to resolve access state:', err.message);
    return res.status(500).json({ error: 'Server misconfiguration' });
  }
}
}
