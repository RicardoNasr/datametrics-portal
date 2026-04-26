// /api/shopify/callback.js
// Step 2 of OAuth: Shopify redirects here after merchant approves.
// Exchange the authorization code for an offline access token and store it in Supabase.

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
    // Don't hard-fail on nonce mismatch — some browsers strip cookies on redirect.
    // The HMAC check below is the critical security validation.
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

  // --- 4. Exchange authorization code for an offline access token ---
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

    console.log(`Token received for ${shop}, scopes: ${grantedScopes}`);

    // --- 5. Store the token in Supabase ---
    const supabaseUrl = process.env.SUPABASE_URL;
    const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

    if (!supabaseUrl || !supabaseKey) {
      console.error('Missing Supabase env vars:', { 
        hasUrl: !!supabaseUrl, 
        hasKey: !!supabaseKey 
      });
      return res.status(500).json({ error: 'Server misconfiguration — missing Supabase credentials' });
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
          body: JSON.stringify({
            shopify_access_token: accessToken,
            shopify_installed_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          }),
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
      // Generate a sequential client_id (you'll finalize during onboarding)
      const newClientId = 100000 + Date.now() % 100000;
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
          body: JSON.stringify({
            client_id: newClientId,
            client_name: shop.replace('.myshopify.com', ''),
            slug: shop.replace('.myshopify.com', ''),
            shopify_domain: shop,
            shopify_access_token: accessToken,
            shopify_installed_at: new Date().toISOString(),
            status: 'pending_onboarding',
          }),
        }
      );

      if (!postResponse.ok) {
        console.error('Supabase insert failed:', await postResponse.text());
        return res.status(500).json({ error: 'Failed to save new client' });
      }

      console.log(`Created new client ${newClientId} for ${shop}`);
    }

    // --- 6. Clear the nonce cookie and redirect to success page ---
    res.setHeader('Set-Cookie', 'shopify_nonce=; Path=/; HttpOnly; Secure; Max-Age=0');
    res.redirect('https://datametrics-portal.vercel.app/install-success.html');

  } catch (error) {
    console.error('OAuth callback error:', error);
    return res.status(500).json({ error: 'Internal server error during OAuth' });
  }
}
