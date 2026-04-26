// /api/shopify/install.js
// Handles the initial app load from Shopify after merchant clicks install link.
// Redirects merchant through the OAuth authorization code flow to capture the access token.

import crypto from 'crypto';

export default function handler(req, res) {
  // Shopify sends shop, timestamp, hmac when loading the app URL after install
  // A direct visit with ?shop= also works for manual installs
  const shop = req.query.shop;

  if (!shop) {
    return res.status(400).send('Missing shop parameter. Use ?shop=yourstore.myshopify.com');
  }

  // Validate shop format to prevent open redirect attacks
  const shopRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]*\.myshopify\.com$/;
  if (!shopRegex.test(shop)) {
    return res.status(400).send('Invalid shop domain format.');
  }

  const clientId = process.env.SHOPIFY_CLIENT_ID;
  const redirectUri = 'https://datametrics-portal.vercel.app/api/shopify/callback';
  const scopes = 'read_orders,read_products,read_inventory,read_customers,read_reports,read_analytics';

  // Generate a nonce for CSRF protection and store it in a cookie
  const nonce = crypto.randomBytes(16).toString('hex');

  // Set nonce as a short-lived cookie so we can verify it in the callback
  res.setHeader('Set-Cookie', `shopify_nonce=${nonce}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`);

  // Build the Shopify OAuth authorization URL
  const authUrl = `https://${shop}/admin/oauth/authorize?` +
    `client_id=${clientId}` +
    `&scope=${scopes}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${nonce}`;

  // Redirect merchant to Shopify's authorization screen
  res.redirect(authUrl);
}
