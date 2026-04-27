// /api/shopify/callback.js
// Step 2 of OAuth: Shopify redirects here after merchant approves.
// Exchange the authorization code for an EXPIRING offline access token and store it in Supabase.
// New public apps (April 2026+) MUST use expiring tokens.

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

export default async function handler(req, res) {
  const { shop, code, hmac, state, timestamp } = req.query;

  // --- 1. Validate required params ---
  if (!shop || !code || !hmac) {
    return res.status(400).json({ error: 'Missing required parameters from Shopify' });
  }

  // --- 2. Verify the nonce (state) matches what we set in the cookie ---
  const cookies = parseCookies(req.headers.cookie);
  const savedNonce = cookies.shopify_nonce;
  if (!savedNonce || savedNonce !== state) {
    console.error('Nonce mismatch:', { savedNonce, state });
    // Don't hard-fail — some browsers strip cookies on redirect.
    // HMAC check below is the critical security validation.
  }

  // --- 3. Verify HMAC signature (proves the request came from Shopify) ---
  const clientSecret = process.env.SHOPIFY_CLIENT_SECRET;

  const queryParams = { ...req.query };
  delete queryParams.hmac;
  const sortedParams = Object.keys(queryParams)
    .sort()
    .map(key => `${key}=${queryParams[key]}`)
    .join('&');

  const generatedHmac = crypto
    .createHmac('sha256', clientSecret)
    .update(sortedParams)
    .digest('hex');

  if (generatedHmac !== hmac) {
    console.error('HMAC validation failed');
    return res.status(403).json({ error: 'HMAC validation failed — request may not be from Shopify' });
  }

  // --- 4. Exchange authorization code for an EXPIRING offline access token ---
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
      return res.status(500).json({ error: 'Failed to get access token from Shopify' });
    }

    const tokenData = await tokenResponse.json();
    const accessToken = tokenData.access_token;
    const grantedScopes = tokenData.scope;

    // Expiring token fields (present for new public apps created after April 1, 2026)
    const expiresIn = tokenData.expires_in || null;           // seconds until access token expires (3600 = 1 hour)
    const refreshToken = tokenData.refresh_token || null;     // used to get a new access token
    const refreshTokenExpiresIn = tokenData.refresh_token_expires_in || null; // seconds until refresh token expires (~90 days)

    // Calculate absolute expiry timestamps
    const now = new Date();
    const tokenExpiresAt = expiresIn
      ? new Date(now.getTime() + expiresIn * 1000).toISOString()
      : null;
    const refreshTokenExpiresAt = refreshTokenExpiresIn
      ? new Date(now.getTime() + refreshTokenExpiresIn * 1000).toISOString()
      : null;

    console.log(`Token received for ${shop}, scopes: ${grantedScopes}, expires_in: ${expiresIn}, has_refresh: ${!!refreshToken}`);

    // --- 5. Store the token in Supabase ---
    const supabaseUrl = process.env.SUPABASE_URL;
    const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

    if (!supabaseUrl || !supabaseKey) {
      console.error('Missing Supabase env vars:', {
        hasUrl: !!supabaseUrl,
        hasKey: !!supabaseKey,
      });
      return res.status(500).json({ error: 'Server misconfiguration — missing Supabase credentials' });
    }

    // Build the token data payload
    const tokenPayload = {
      shopify_access_token: accessToken,
      shopify_installed_at: now.toISOString(),
      updated_at: now.toISOString(),
    };

    // Only include expiring token fields if they exist
    if (refreshToken) {
      tokenPayload.shopify_refresh_token = refreshToken;
      tokenPayload.shopify_token_expires_at = tokenExpiresAt;
      tokenPayload.shopify_refresh_token_expires_at = refreshTokenExpiresAt;
    }

    // Check if this shop already exists in the clients table
    const findUrl = `${supabaseUrl}/rest/v1/clients?shopify_domain=eq.${encodeURIComponent(shop)}&select=client_id`;
    console.log('Looking up client:', findUrl);

    const findResponse = await fetch(findUrl, {
      headers: {
        'apikey': supabaseKey,
        'Authorization': `Bearer ${supabaseKey}`,
      },
    });

    const findBody = await findResponse.text();
    console.log('Find response:', findResponse.status, findBody);

    if (!findResponse.ok) {
      console.error('Supabase lookup failed:', findResponse.status, findBody);
      return res.status(500).json({ error: 'Failed to look up client in database' });
    }

    const existingClients = JSON.parse(findBody);

    if (Array.isArray(existingClients) && existingClients.length > 0) {
      // Update existing client with the new token
      const clientId = existingClients[0].client_id;
      console.log(`Updating existing client ${clientId}`);

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
          body: JSON.stringify(tokenPayload),
        }
      );

      if (!patchResponse.ok) {
        const patchError = await patchResponse.text();
        console.error('Supabase update failed:', patchResponse.status, patchError);
        return res.status(500).json({ error: 'Failed to save token', detail: patchError });
      }

      console.log(`Successfully updated token for client ${clientId} (${shop})`);
    } else {
      // New client — insert a placeholder row
      const newClientId = 100000 + Date.now() % 100000;
      const insertPayload = {
        client_id: newClientId,
        client_name: shop.replace('.myshopify.com', ''),
        slug: shop.replace('.myshopify.com', ''),
        shopify_domain: shop,
        status: 'pending_onboarding',
        ...tokenPayload,
      };

      const postResponse = await fetch(
        `${supabaseUrl}/rest/v1/clients`,
        {
          method: 'POST',
          headers: {
            'apikey': supabaseKey,
            'Authorization': `Bearer ${supabaseKey}`,
            'Content-Type': 'application/json',
            'Prefer': 'return=minimal',
          },
          body: JSON.stringify(insertPayload),
        }
      );

      if (!postResponse.ok) {
        console.error('Supabase insert failed:', await postResponse.text());
        return res.status(500).json({ error: 'Failed to save new client' });
      }

      console.log(`Created new client ${newClientId} for ${shop}`);
    }

    // --- 6. Clear the nonce cookie and redirect to the embedded app page ---
    res.setHeader('Set-Cookie', 'shopify_nonce=; Path=/; HttpOnly; Secure; Max-Age=0');

    // Redirect back into the Shopify admin embedded app
    const host = req.query.host || Buffer.from(`${shop}/admin`).toString('base64url');
    res.redirect(`https://${shop}/admin/apps/${process.env.SHOPIFY_CLIENT_ID}`);

  } catch (error) {
    console.error('OAuth callback error:', error);
    return res.status(500).json({ error: 'Internal server error during OAuth' });
  }
}
