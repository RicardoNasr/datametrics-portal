// /api/shopify/gdpr.js
// Handles all 3 mandatory GDPR webhooks for Shopify public apps:
//   - customers/data_request  → Merchant requests customer data export
//   - customers/redact        → Merchant requests customer data deletion
//   - shop/redact             → Merchant uninstalls app, requests shop data deletion
//
// These must exist and return 200 OK. Shopify verifies them during app review.
// Actual data deletion happens within 30 days as stated in our privacy policy.

import crypto from 'crypto';

function verifyShopifyWebhook(req, body) {
  const hmacHeader = req.headers['x-shopify-hmac-sha256'];
  if (!hmacHeader) return false;

  const generatedHmac = crypto
    .createHmac('sha256', process.env.SHOPIFY_CLIENT_SECRET)
    .update(body, 'utf8')
    .digest('base64');

  return crypto.timingSafeEqual(
    Buffer.from(generatedHmac),
    Buffer.from(hmacHeader)
  );
}

export const config = {
  api: {
    bodyParser: false, // Need raw body for HMAC verification
  },
};

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Read raw body for HMAC verification
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  const rawBody = Buffer.concat(chunks).toString('utf8');

  // Verify the webhook is from Shopify
  if (!verifyShopifyWebhook(req, rawBody)) {
    console.error('GDPR webhook HMAC verification failed');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const topic = req.headers['x-shopify-topic'];
  const shopDomain = req.headers['x-shopify-shop-domain'];

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  console.log(`GDPR webhook received: ${topic} from ${shopDomain}`);

  switch (topic) {
    case 'customers/data_request': {
      // Merchant is requesting data we hold about a specific customer.
      // Log it so we can respond manually within 30 days.
      const { customer, orders_requested } = payload;
      console.log(`Customer data request for customer ${customer?.id} from ${shopDomain}`);
      console.log(`Orders requested: ${orders_requested?.join(', ') || 'none'}`);

      // In a production system, you'd queue this for processing.
      // For now, log and acknowledge.
      return res.status(200).json({ message: 'Data request received. Will process within 30 days.' });
    }

    case 'customers/redact': {
      // Merchant is requesting we delete data for a specific customer.
      const { customer, orders_to_redact } = payload;
      console.log(`Customer redact request for customer ${customer?.id} from ${shopDomain}`);

      // TODO: When you have customer-level data deletion logic, implement it here.
      // For now, log and acknowledge. Actual deletion within 30 days.
      return res.status(200).json({ message: 'Customer redact request received. Will delete within 30 days.' });
    }

    case 'shop/redact': {
      // Merchant has uninstalled the app. Delete all their data within 30 days.
      const { shop_id, shop_domain } = payload;
      console.log(`Shop redact request for ${shop_domain} (ID: ${shop_id})`);

      // TODO: Implement shop data deletion — remove all rows for this client
      // from your tables (orders, sales, meta ads, etc.) within 30 days.
      // Optionally mark the client as "pending_deletion" in public.clients.

      try {
        const supabaseUrl = process.env.SUPABASE_URL;
        const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

        if (supabaseUrl && supabaseKey) {
          // Mark client for deletion
          await fetch(
            `${supabaseUrl}/rest/v1/clients?shopify_domain=eq.${encodeURIComponent(shop_domain)}`,
            {
              method: 'PATCH',
              headers: {
                'apikey': supabaseKey,
                'Authorization': `Bearer ${supabaseKey}`,
                'Content-Type': 'application/json',
                'Prefer': 'return=minimal',
              },
              body: JSON.stringify({
                status: 'pending_deletion',
                updated_at: new Date().toISOString(),
              }),
            }
          );
          console.log(`Marked ${shop_domain} as pending_deletion`);
        }
      } catch (err) {
        console.error('Error marking shop for deletion:', err);
        // Still return 200 — we've logged the request
      }

      return res.status(200).json({ message: 'Shop redact request received. Will delete all data within 30 days.' });
    }

    default:
      console.log(`Unknown GDPR topic: ${topic}`);
      return res.status(200).json({ message: 'Acknowledged' });
  }
}
