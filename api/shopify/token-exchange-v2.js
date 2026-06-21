// BUILD-MARKER: 2026-06-14-v7-TRIAL-LIFECYCLE — adds trial-start + self-healing backfill firing
// /api/shopify/token-exchange-v2.js
// Modern token acquisition for embedded apps using Shopify managed installation.
//
// Apps rendered in Shopify Admin use TOKEN EXCHANGE, not the OAuth callback
// flow. When the embedded app loads, App Bridge gives it a session token. The
// app sends that session token here; we:
//   1. Verify the session token (it's a JWT signed with our client secret)
//   2. Exchange it for an EXPIRING OFFLINE access token via Shopify's token endpoint
//      (with one-time migration if the shop has a legacy non-expiring token)
//   3. Upsert the token into public.clients (so n8n can use it for syncs)
//   4. NEW: If this is a fresh trial (no trial_started_at, not active), set
//      trial-start fields so the merchant sees the trial dashboard.
//   5. NEW: If status='trial' and trial_data_ready_at IS NULL, fire the
//      n8n trial-backfill webhook with the FRESH expiring token. This is
//      self-healing — every app open retries the backfill until it succeeds.
//
// This makes the endpoint the single entry point for both production (managed
// install via App Store) and any flow that re-opens the embedded app.
//
// Required env vars:
//   SHOPIFY_CLIENT_ID, SHOPIFY_CLIENT_SECRET
//   SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY
//   N8N_INSTALL_WEBHOOK_URL, N8N_INSTALL_WEBHOOK_SECRET  (NEW — same vars callback.js uses)

import crypto from 'crypto';

// ---------- Trial configuration (mirrors callback.js) ----------
const TRIAL_DAYS = 10;
const TRIAL_DASHBOARD_ID = 7; // [Trial] KPI_Dashboard — Executive Overview only, Shopify-only

function buildTrialStartFields(now) {
  const end = new Date(now.getTime() + TRIAL_DAYS * 24 * 60 * 60 * 1000);
  // Start of the 10-day backfill window — used to seed onboarding_since so
  // vw_client_date_bounds (and the MVs built on it) include the trial's date range.
  const onboardingStart = new Date(now.getTime() - TRIAL_DAYS * 24 * 60 * 60 * 1000);
  return {
    status: 'trial',
    is_active: true,
    dashboard_id: TRIAL_DASHBOARD_ID,
    trial_started_at: now.toISOString(),
    subscription_end_date: end.toISOString().slice(0, 10), // DATE column (YYYY-MM-DD)
    onboarding_since: onboardingStart.toISOString().slice(0, 10),  // matches the 10-day backfill window
  };
}

// Fire-and-forget trigger to the n8n trial backfill workflow.
// Never blocks or fails the install — if n8n is down, the merchant still
// gets a valid token; the next app open will retry the backfill.
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
    console.error('n8n trial backfill trigger error (non-fatal):', err.message);
  }
}

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
  console.log('>>> token-exchange-v2 BUILD v7-TRIAL-LIFECYCLE invoked, method=', req.method);
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

  // 2. Exchange the session token for an EXPIRING OFFLINE access token
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
        // "1" requests an expiring offline token (required for new public apps).
        expiring: '1',
      }).toString(),
    });

    if (!exchangeRes.ok) {
      const errText = await exchangeRes.text();
      console.error('Token exchange failed:', exchangeRes.status, errText);
      return res.status(502).json({ error: 'Token exchange failed' });
    }

    tokenData = await exchangeRes.json();

    console.log('TOKEN-EXCHANGE v7-TRIAL-LIFECYCLE running for', shop,
      '| initial expires_in =', tokenData.expires_in,
      '| token prefix =', (tokenData.access_token || '').slice(0, 10));

    // ---- MIGRATION FALLBACK ----
    // If this shop already had a NON-expiring offline token from a previous
    // install, Shopify returns that same non-expiring token here and ignores
    // expiring=1 (offline tokens are sticky per shop/install). We detect that
    // (no expires_in) and run the one-time migration request: exchange the
    // non-expiring offline token FOR an expiring one. Shopify revokes the old
    // non-expiring token on success.
    if (!tokenData.expires_in && tokenData.access_token) {
      console.log(`Got non-expiring token for ${shop} — running migration to expiring…`);
      const migrateRes = await fetch(`https://${shop}/admin/oauth/access_token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json',
        },
        body: new URLSearchParams({
          client_id: process.env.SHOPIFY_CLIENT_ID,
          client_secret: process.env.SHOPIFY_CLIENT_SECRET,
          grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
          subject_token: tokenData.access_token,
          subject_token_type: 'urn:shopify:params:oauth:token-type:offline-access-token',
          requested_token_type: 'urn:shopify:params:oauth:token-type:offline-access-token',
          expiring: '1',
        }).toString(),
      });

      const migrateBody = await migrateRes.text();
      console.log('MIGRATION raw response:', migrateRes.status, migrateBody);

      if (migrateRes.ok) {
        let migrated = {};
        try { migrated = JSON.parse(migrateBody); } catch (e) {}
        if (migrated.expires_in) {
          console.log(`✅ Migrated ${shop} to expiring token (expires_in=${migrated.expires_in})`);
          tokenData = migrated;
        } else {
          console.warn(`Migration returned no expires_in for ${shop}; using original token.`);
        }
      } else {
        console.error('Migration request failed:', migrateRes.status, migrateBody);
      }
    }
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
    `Token ready for ${shop} | scope=${tokenData.scope} | ` +
    `expires_in=${tokenData.expires_in || 'permanent'}`
  );

  // 3. Build a tolerant token payload
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

  // 4. Upsert into public.clients
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  // Track outcomes for the final backfill decision
  let backfillClientId = null;     // set if we should fire the backfill below
  let returnStatus = null;          // for the JSON response

  try {
    // Lookup existing row — also pull trial fields needed for lifecycle decisions
    const findRes = await fetch(
      `${supabaseUrl}/rest/v1/clients` +
        `?shopify_domain=eq.${encodeURIComponent(shop)}` +
        `&select=client_id,status,trial_started_at,trial_data_ready_at`,
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
      // --- UPDATE existing row ---
      const clientId        = existing[0].client_id;
      const alreadyTrialed  = existing[0].trial_started_at != null;
      const trialDataReady  = existing[0].trial_data_ready_at != null;
      const currentStatus   = existing[0].status;

      // Decide what to patch. Always refresh the token. Additionally:
      //   - If the store has never trialed AND isn't already active, START the trial.
      //   - Otherwise, preserve existing trial / active state.
      let patchPayload = { ...tokenPayload };
      let newStatus = currentStatus;

      if (!alreadyTrialed && currentStatus !== 'active') {
        patchPayload = { ...patchPayload, ...buildTrialStartFields(now) };
        newStatus = 'trial';
        console.log(`Starting trial for existing row ${clientId} (${shop})`);
      } else {
        console.log(
          `Reinstall guard: client ${clientId} already ` +
          `${alreadyTrialed ? 'trialed' : 'active'} — token refreshed only, no trial reset`
        );
      }

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
          body: JSON.stringify(patchPayload),
        }
      );
      if (!patchRes.ok) {
        console.error('Supabase UPDATE failed:', await patchRes.text());
        return res.status(500).json({ error: 'Failed to save token' });
      }
      console.log(`✅ Token updated for existing client ${clientId} (${shop})`);

      // SELF-HEALING BACKFILL DECISION:
      // Fire if (a) we just started the trial, OR
      //         (b) the client is in trial but data isn't ready yet (retry path).
      // Skip for: active customers, or trials that already have data ready.
      const justStartedTrial = !alreadyTrialed && currentStatus !== 'active';
      const trialNeedsBackfill = newStatus === 'trial' && !trialDataReady;
      if (justStartedTrial || trialNeedsBackfill) {
        backfillClientId = clientId;
      }
      returnStatus = newStatus;
    } else {
      // --- INSERT new row — starts trial immediately ---
      const newClientId = 100000 + (Date.now() % 100000);
      const insertPayload = {
        client_id: newClientId,
        client_name: shop.replace('.myshopify.com', ''),
        slug: shop.replace('.myshopify.com', ''),
        shopify_domain: shop,
        ...tokenPayload,
        ...buildTrialStartFields(now),
        // trial_data_ready_at intentionally left NULL — n8n sets it when the
        // 10-day backfill finishes.
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
      console.log(`✅ Created new client ${newClientId} for ${shop} (status=trial)`);
      backfillClientId = newClientId;
      returnStatus = 'trial';
    }
  } catch (err) {
    console.error('Supabase write error:', err);
    return res.status(500).json({ error: 'Database write error' });
  }

  // 5. Fire the trial backfill (non-blocking) if appropriate.
  //    The webhook uses the FRESH expiring token we just minted, so the n8n
  //    workflow can hit Shopify's Admin API without 403.
  if (backfillClientId != null) {
    await fireTrialBackfill(backfillClientId, shop, accessToken);
  }

  return res.status(200).json({ ok: true, shop, status: returnStatus });
}
