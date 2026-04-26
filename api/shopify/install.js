// /api/shopify/install.js
// Step 1 of OAuth: Redirect the merchant to Shopify's authorization page

export default function handler(req, res) {
  const { shop } = req.query;

  // Validate shop parameter
  if (!shop || !shop.endsWith('.myshopify.com')) {
    return res.status(400).json({ 
      error: 'Missing or invalid shop parameter. Use ?shop=storename.myshopify.com' 
    });
  }

  const clientId = process.env.SHOPIFY_CLIENT_ID;
  const redirectUri = 'https://datametrics-portal.vercel.app/api/shopify/callback';
  const scopes = 'read_orders,read_products,read_inventory,read_customers,read_reports,read_analytics';

  // Generate a random nonce for CSRF protection
  const nonce = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

  // Build the Shopify authorization URL
  const authUrl = `https://${shop}/admin/oauth/authorize?` +
    `client_id=${clientId}` +
    `&scope=${scopes}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${nonce}`;

  // Redirect merchant to Shopify
  res.redirect(authUrl);
}
