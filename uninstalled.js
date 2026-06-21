// /api/shopify/uninstalled.js
// Handles Shopify's app/uninstalled webhook, which fires IMMEDIATELY when a
// merchant uninstalls the app (unlike shop/redact, which arrives ~48h later).
//
// We do NOT delete the client row. Instead we stamp uninstalled_at and mark the
// status, so the trial lifecycle is durable: a merchant cannot uninstall and
// reinstall to farm a fresh 10-day trial. token-exchange-v2.js reads
// uninstalled_at on the next install and locks the shop to trial_expired.
//
// Subscribe this URL to the `app/uninstalled` topic in the Shopify app config.
//
// Required env vars: SHOPIFY_CLIENT_SECRET, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY

import crypto from 'crypto';

export const config = {
  api: { bodyParser: false }, // raw body needed for HMAC verification
};

function verifyShopifyWebhook(req, rawBody) {
  const hmacHeader = req.headers['x-shopify-hmac-sha256'];
  if (!hmacHeader) return false;
  const generated = crypto
    .createHmac('sha256', process.env.SHOPIFY_CLIENT_SECRET)
    .update(rawBody, 'utf8')
    .digest('base64');
  const a = Buffer.from(generated);
  const b = Buffer.from(hmacHeader);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const rawBody = Buffer.concat(chunks).toString('utf8');

  if (!verifyShopifyWebhook(req, rawBody)) {
    console.error('app/uninstalled HMAC verification failed');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const shopDomain = req.headers['x-shopify-shop-domain'];
  console.log(`app/uninstalled received for ${shopDomain}`);

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!supabaseUrl || !supabaseKey) {
    console.error('Missing Supabase env vars');
    // Still 200 so Shopify doesn't retry forever; we logged it.
    return res.status(200).json({ message: 'Acknowledged (no DB write)' });
  }

  try {
    // Stamp uninstalled_at + clear the live token. Do NOT delete the row and do
    // NOT clear trial_started_at / subscription_end_date — those are what make
    // the trial "used up" permanently.
    await fetch(
      `${supabaseUrl}/rest/v1/clients?shopify_domain=eq.${encodeURIComponent(shopDomain)}`,
      {
        method: 'PATCH',
        headers: {
          'apikey': supabaseKey,
          'Authorization': `Bearer ${supabaseKey}`,
          'Content-Type': 'application/json',
          'Prefer': 'return=minimal',
        },
        body: JSON.stringify({
          uninstalled_at: new Date().toISOString(),
          is_active: false,
          shopify_access_token: null, // token is revoked by Shopify on uninstall
          updated_at: new Date().toISOString(),
        }),
      }
    );
    console.log(`Stamped uninstalled_at for ${shopDomain}`);
  } catch (err) {
    console.error('Error stamping uninstall:', err);
    // fall through to 200 — Shopify expects a quick 200
  }

  return res.status(200).json({ message: 'Uninstall recorded' });
}
