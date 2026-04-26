// /api/shopify/callback.js
// Step 2 of OAuth: Shopify redirects here after merchant approves.
// Exchange the code for a permanent access token and store it in Supabase.

import crypto from 'crypto';

export default async function handler(req, res) {
  const { shop, code, hmac, state, timestamp } = req.query;

  // --- 1. Validate required params ---
  if (!shop || !code || !hmac) {
    return res.status(400).json({ error: 'Missing required parameters' });
  }

  // --- 2. Verify HMAC signature (proves request came from Shopify) ---
  const clientSecret = process.env.SHOPIFY_CLIENT_SECRET;

  // Build the message string from all query params except hmac
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
    return res.status(403).json({ error: 'HMAC validation failed' });
  }

  // --- 3. Exchange authorization code for permanent access token ---
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
      console.error('Token exchange failed:', errorText);
      return res.status(500).json({ error: 'Failed to get access token from Shopify' });
    }

    const tokenData = await tokenResponse.json();
    const accessToken = tokenData.access_token;

    // --- 4. Store the token in Supabase ---
    // First, check if this shop already exists in the clients table
    const supabaseUrl = process.env.SUPABASE_URL;
    const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

    // Try to find existing client by shopify_domain
    const findResponse = await fetch(
      `${supabaseUrl}/rest/v1/clients?shopify_domain=eq.${encodeURIComponent(shop)}&select=client_id`,
      {
        headers: {
          'apikey': supabaseKey,
          'Authorization': `Bearer ${supabaseKey}`,
        },
      }
    );

    const existingClients = await findResponse.json();

    if (existingClients.length > 0) {
      // Update existing client with the new token
      const clientId = existingClients[0].client_id;
      await fetch(
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

      console.log(`Updated token for existing client ${clientId} (${shop})`);
    } else {
      // New client — insert a placeholder row
      // You'll fill in client_name, slug, etc. manually during onboarding
      const newClientId = Date.now(); // temporary ID, you can change this
      await fetch(
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
            shopify_domain: shop,
            shopify_access_token: accessToken,
            shopify_installed_at: new Date().toISOString(),
            status: 'pending_onboarding',
          }),
        }
      );

      console.log(`Created new client ${newClientId} for ${shop}`);
    }

    // --- 5. Redirect to a success page ---
    res.redirect('https://datametrics-portal.vercel.app/install-success');

  } catch (error) {
    console.error('OAuth callback error:', error);
    return res.status(500).json({ error: 'Internal server error during OAuth' });
  }
}
