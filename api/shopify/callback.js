// /api/shopify/callback.js
// Step 2 of Shopify OAuth: Shopify redirects here after the merchant approves
// the install. We:
//   1. Verify the request actually came from Shopify (HMAC check)
//   2. Exchange the authorization code for an access token
//   3. Store the token in public.clients (upsert by shopify_domain)
//   4. Redirect back into the Shopify Admin embedded app
//
// Required env vars on Vercel:
//   SHOPIFY_CLIENT_ID
//   SHOPIFY_CLIENT_SECRET
//   SUPABASE_URL
//   SUPABASE_SERVICE_ROLE_KEY

import crypto from 'crypto';

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  cookieHeader.split(';').forEach(cookie => {
    const [name, ...rest] = cookie.trim().split('=');
    cookies[name] = rest.join('=');
  });
  return cookies;
}

// Trial configuration
const TRIAL_DAYS = 10;
const TRIAL_DASHBOARD_ID = 5; // one-page "KPI Dashboard — Trial Mode"

// Fields written when a store STARTS its trial (first install only).
function buildTrialStartFields(now) {
  const end = new Date(now.getTime() + TRIAL_DAYS * 24 * 60 * 60 * 1000);
  return {
    status: 'trial',
    is_active: true,
    dashboard_id: TRIAL_DASHBOARD_ID,
    trial_started_at: now.toISOString(),
    subscription_end_date: end.toISOString().slice(0, 10), // DATE column (YYYY-MM-DD)
    // trial_data_ready_at intentionally left NULL — n8n sets it when the
    // 10-day backfill finishes. Portal shows "preparing" until then.
  };
}

// Fire-and-forget trigger to the n8n trial backfill workflow.
// Never blocks or fails the install — if n8n is down, the merchant still
// installs successfully; the backfill can be re-run manually.
async function fireTrialBackfill(clientId, shop, accessToken) {
  const webhookUrl = process.env.N8N_INSTALL_WEBHOOK_URL;
  if (!webhookUrl) {
    console.warn('N8N_INSTALL_WEBHOOK_URL not set — skipping trial backfill trigger');
    return;
  }
  try {
    const resp = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        // Shared secret so the webhook can reject calls that aren't from us.
        'x-datametrics-secret': process.env.N8N_INSTALL_WEBHOOK_SECRET || '',
      },
      body: JSON.stringify({
        client_id: clientId,
        shop_domain: shop,
        access_token: accessToken,
        trial_days: TRIAL_DAYS,
      }),
    });
    if (!resp.ok) {
      console.error('n8n trial backfill trigger returned', resp.status, await resp.text());
    } else {
      console.log(`✅ Trial backfill triggered for client ${clientId} (${shop})`);
    }
  } catch (err) {
    // Swallow — install must succeed even if the trigger fails.
    console.error('n8n trial backfill trigger error (non-fatal):', err.message);
  }
}

export default async function handler(req, res) {
  const { shop, code, hmac, state } = req.query;

  // --- 1. Validate required params ---
  if (!shop || !code || !hmac) {
    return res.status(400).send('Missing required parameters from Shopify');
  }

  // Validate shop format (prevents open redirect / SSRF)
  if (!/^[a-z0-9][a-z0-9-]*\.myshopify\.com$/i.test(shop)) {
    return res.status(400).send('Invalid shop parameter');
  }

  // --- 2. Verify the nonce (state) ---
  // Soft check: some browsers strip the cookie on the round-trip. HMAC is the
  // hard security check below.
  const cookies = parseCookies(req.headers.cookie);
  const savedNonce = cookies.shopify_nonce;
  if (savedNonce && savedNonce !== state) {
    console.warn('Nonce mismatch (soft warning):', { savedNonce, state });
  }

  // --- 3. Verify HMAC signature ---
  const clientSecret = process.env.SHOPIFY_CLIENT_SECRET;

  const queryParams = { ...req.query };
  delete queryParams.hmac;
  delete queryParams.signature;
  const sortedParams = Object.keys(queryParams)
    .sort()
    .map(key => `${key}=${queryParams[key]}`)
    .join('&');

  const generatedHmac = crypto
    .createHmac('sha256', clientSecret)
    .update(sortedParams)
    .digest('hex');

  // Constant-time compare
  const a = Buffer.from(generatedHmac, 'utf8');
  const b = Buffer.from(hmac, 'utf8');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    console.error('HMAC validation failed for shop:', shop);
    return res.status(403).send('HMAC validation failed');
  }

  // --- 4. Exchange authorization code for access token ---
  let tokenData;
  try {
    const tokenResponse = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: process.env.SHOPIFY_CLIENT_ID,
        client_secret: clientSecret,
        code: code,
      }),
    });

    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      console.error('Token exchange failed:', tokenResponse.status, errorText);
      return res.status(500).send('Failed to exchange code for access token');
    }

    tokenData = await tokenResponse.json();
  } catch (err) {
    console.error('Token exchange error:', err);
    return res.status(500).send('Token exchange error');
  }

  const accessToken = tokenData.access_token;
  if (!accessToken) {
    console.error('No access_token in Shopify response:', tokenData);
    return res.status(500).send('No access token returned by Shopify');
  }

  // --- 5. Build a tolerant token payload ---
  // Only include columns that have a non-null value, so the same code works
  // for both legacy permanent tokens (shpca_*) and new expiring tokens.
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
  if (typeof tokenData.refresh_token_expires_in === 'number') {
    tokenPayload.shopify_refresh_token_expires_at = new Date(
      now.getTime() + tokenData.refresh_token_expires_in * 1000
    ).toISOString();
  }

  console.log(
    `Token captured for ${shop} | scopes=${tokenData.scope} | ` +
    `expires_in=${tokenData.expires_in || 'permanent'} | ` +
    `has_refresh=${!!tokenData.refresh_token}`
  );

  // --- 6. Upsert into public.clients by shopify_domain ---
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !supabaseKey) {
    console.error('Missing Supabase env vars on Vercel');
    return res.status(500).send('Server misconfiguration');
  }

  try {
    // Lookup existing row by shopify_domain
    const findUrl =
      `${supabaseUrl}/rest/v1/clients` +
      `?shopify_domain=eq.${encodeURIComponent(shop)}` +
      `&select=client_id,status,trial_started_at,subscription_end_date`;

    const findResponse = await fetch(findUrl, {
      headers: {
        'apikey': supabaseKey,
        'Authorization': `Bearer ${supabaseKey}`,
      },
    });

    if (!findResponse.ok) {
      const errorBody = await findResponse.text();
      console.error('Supabase lookup failed:', findResponse.status, errorBody);
      return res.status(500).send('Database lookup failed');
    }

    const existing = await findResponse.json();

    // Track whether we should fire the backfill after the DB write.
    let backfillClientId = null;

    if (Array.isArray(existing) && existing.length > 0) {
      // --- UPDATE existing client ---
      const clientId = existing[0].client_id;
      const alreadyTrialed = existing[0].trial_started_at != null;
      const currentStatus = existing[0].status;

      // Build the patch: always refresh the token. Additionally, START a trial
      // ONLY if this store has never trialed before AND isn't already a paying
      // client. This is the reinstall guard — an uninstall/reinstall cannot
      // reset the trial clock or re-trigger the backfill.
      let patchPayload = { ...tokenPayload };

      if (!alreadyTrialed && currentStatus !== 'active') {
        patchPayload = { ...patchPayload, ...buildTrialStartFields(now) };
        backfillClientId = clientId;
        console.log(`Starting trial for existing row ${clientId} (${shop})`);
      } else {
        console.log(
          `Reinstall guard: client ${clientId} already ` +
          `${alreadyTrialed ? 'trialed' : 'active'} — token refreshed only, no trial reset`
        );
      }

      const patchResponse = await fetch(
        `${supabaseUrl}/rest/v1/clients?client_id=eq.${clientId}`,
        {
          method: 'PATCH',
          headers: {
            'apikey': supabaseKey,
            'Authorization': `Bearer ${supabaseKey}`,
            'Content-Type': 'application/json',
            'Prefer': 'return=minimal',
          },
          body: JSON.stringify(patchPayload),
        }
      );

      if (!patchResponse.ok) {
        const errorBody = await patchResponse.text();
        console.error('Supabase UPDATE failed:', patchResponse.status, errorBody);
        return res.status(500).send('Failed to save token (update)');
      }

      console.log(`✅ Token updated for existing client ${clientId} (${shop})`);
    } else {
      // --- INSERT new client (starts trial immediately) ---
      // Generate a client_id between 100000–199999 to match Lune's range.
      const newClientId = 100000 + (Date.now() % 100000);
      const insertPayload = {
        client_id: newClientId,
        client_name: shop.replace('.myshopify.com', ''),
        slug: shop.replace('.myshopify.com', ''),
        shopify_domain: shop,
        ...tokenPayload,
        ...buildTrialStartFields(now),
      };

      const postResponse = await fetch(`${supabaseUrl}/rest/v1/clients`, {
        method: 'POST',
        headers: {
          'apikey': supabaseKey,
          'Authorization': `Bearer ${supabaseKey}`,
          'Content-Type': 'application/json',
          'Prefer': 'return=minimal',
        },
        body: JSON.stringify(insertPayload),
      });

      if (!postResponse.ok) {
        const errorBody = await postResponse.text();
        console.error('Supabase INSERT failed:', postResponse.status, errorBody);
        return res.status(500).send('Failed to save new client');
      }

      backfillClientId = newClientId;
      console.log(`✅ Created new client ${newClientId} for ${shop} (status=trial)`);
    }

    // Fire the trial backfill if a trial was just started (insert or first
    // install of a pre-created row). Non-blocking — install succeeds regardless.
    if (backfillClientId != null) {
      await fireTrialBackfill(backfillClientId, shop, accessToken);
    }
  } catch (err) {
    console.error('Supabase write error:', err);
    return res.status(500).send('Database write error');
  }

  // --- 7. Clear nonce cookie and redirect back into Shopify Admin ---
  res.setHeader(
    'Set-Cookie',
    'shopify_nonce=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0'
  );

  // CRITICAL: include shop + host so App Bridge can initialize on the
  // embedded page. The host param is base64url(shop/admin) — Shopify usually
  // passes it through, but we fall back if it's missing.
  const hostParam =
    req.query.host ||
    Buffer.from(`${shop}/admin`).toString('base64').replace(/=+$/, '');

  const clientId = process.env.SHOPIFY_CLIENT_ID;
  const redirectUrl =
    `https://${shop}/admin/apps/${clientId}` +
    `?shop=${encodeURIComponent(shop)}` +
    `&host=${encodeURIComponent(hostParam)}`;

  return res.redirect(302, redirectUrl);
}
