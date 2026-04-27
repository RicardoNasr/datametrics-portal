// /api/shopify/refresh-token.js
// Refreshes an expiring Shopify offline access token using the stored refresh_token.
// Called by n8n workflows or a cron job before making API calls.
//
// Usage: POST /api/shopify/refresh-token
// Body: { "client_id": 100001 }
// Or:   { "shop": "storename.myshopify.com" }
//
// Returns the new access token (also updates Supabase automatically).

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed. Use POST.' });
  }

  // Simple auth check — only allow requests with the service key
  const authHeader = req.headers['x-service-key'];
  if (authHeader !== process.env.REFRESH_SERVICE_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { client_id, shop } = req.body || {};

  if (!client_id && !shop) {
    return res.status(400).json({ error: 'Provide client_id or shop' });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  try {
    // --- 1. Look up the client and their tokens ---
    const filter = client_id
      ? `client_id=eq.${client_id}`
      : `shopify_domain=eq.${encodeURIComponent(shop)}`;

    const lookupUrl = `${supabaseUrl}/rest/v1/clients?${filter}&select=client_id,shopify_domain,shopify_access_token,shopify_refresh_token,shopify_token_expires_at`;

    const lookupRes = await fetch(lookupUrl, {
      headers: {
        'apikey': supabaseKey,
        'Authorization': `Bearer ${supabaseKey}`,
      },
    });

    if (!lookupRes.ok) {
      return res.status(500).json({ error: 'Failed to look up client' });
    }

    const clients = await lookupRes.json();
    if (!clients.length) {
      return res.status(404).json({ error: 'Client not found' });
    }

    const client = clients[0];

    // --- 2. Check if refresh is actually needed ---
    if (!client.shopify_refresh_token) {
      // Non-expiring token (Lune or legacy clients) — no refresh needed
      return res.status(200).json({
        message: 'Non-expiring token — no refresh needed',
        access_token: client.shopify_access_token,
        client_id: client.client_id,
      });
    }

    const expiresAt = new Date(client.shopify_token_expires_at);
    const now = new Date();
    const bufferMs = 5 * 60 * 1000; // 5-minute buffer

    if (expiresAt.getTime() - now.getTime() > bufferMs) {
      // Token still valid — return current one
      return res.status(200).json({
        message: 'Token still valid',
        access_token: client.shopify_access_token,
        expires_at: client.shopify_token_expires_at,
        client_id: client.client_id,
      });
    }

    // --- 3. Refresh the token ---
    console.log(`Refreshing token for client ${client.client_id} (${client.shopify_domain})`);

    const refreshRes = await fetch(`https://${client.shopify_domain}/admin/oauth/access_token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: process.env.SHOPIFY_CLIENT_ID,
        client_secret: process.env.SHOPIFY_CLIENT_SECRET,
        grant_type: 'refresh_token',
        refresh_token: client.shopify_refresh_token,
      }),
    });

    if (!refreshRes.ok) {
      const errText = await refreshRes.text();
      console.error('Token refresh failed:', refreshRes.status, errText);
      return res.status(500).json({ error: 'Token refresh failed', detail: errText });
    }

    const tokenData = await refreshRes.json();

    // Calculate new expiry timestamps
    const newExpiresAt = tokenData.expires_in
      ? new Date(now.getTime() + tokenData.expires_in * 1000).toISOString()
      : null;
    const newRefreshExpiresAt = tokenData.refresh_token_expires_in
      ? new Date(now.getTime() + tokenData.refresh_token_expires_in * 1000).toISOString()
      : null;

    // --- 4. Update Supabase with new tokens ---
    const updatePayload = {
      shopify_access_token: tokenData.access_token,
      updated_at: now.toISOString(),
    };

    if (newExpiresAt) updatePayload.shopify_token_expires_at = newExpiresAt;
    if (tokenData.refresh_token) updatePayload.shopify_refresh_token = tokenData.refresh_token;
    if (newRefreshExpiresAt) updatePayload.shopify_refresh_token_expires_at = newRefreshExpiresAt;

    const patchRes = await fetch(
      `${supabaseUrl}/rest/v1/clients?client_id=eq.${client.client_id}`,
      {
        method: 'PATCH',
        headers: {
          'apikey': supabaseKey,
          'Authorization': `Bearer ${supabaseKey}`,
          'Content-Type': 'application/json',
          'Prefer': 'return=minimal',
        },
        body: JSON.stringify(updatePayload),
      }
    );

    if (!patchRes.ok) {
      console.error('Failed to save refreshed token:', await patchRes.text());
      return res.status(500).json({ error: 'Token refreshed but failed to save' });
    }

    console.log(`Token refreshed for client ${client.client_id}`);

    return res.status(200).json({
      message: 'Token refreshed successfully',
      access_token: tokenData.access_token,
      expires_at: newExpiresAt,
      client_id: client.client_id,
    });

  } catch (error) {
    console.error('Refresh token error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
