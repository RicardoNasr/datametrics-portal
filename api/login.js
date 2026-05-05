import jwt from 'jsonwebtoken';

// Validate required env vars at module load — fail loud if anything is missing
const REQUIRED_ENV = [
  'SUPABASE_URL',
  'SUPABASE_SERVICE_ROLE_KEY',
  'METABASE_SECRET_KEY',
  'METABASE_SITE_URL',
];

const missingEnv = REQUIRED_ENV.filter((k) => !process.env[k]);
if (missingEnv.length > 0) {
  // This will surface in Vercel build/runtime logs immediately
  console.error(`FATAL: Missing required env vars: ${missingEnv.join(', ')}`);
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Hard fail if config is incomplete — never silently fall back
  if (missingEnv.length > 0) {
    console.error(`Login attempt blocked: missing env vars: ${missingEnv.join(', ')}`);
    return res.status(500).json({ error: 'Server misconfigured' });
  }

  const { slug, passwordHash } = req.body;
  if (!slug || !passwordHash) {
    return res.status(400).json({ error: 'Missing credentials' });
  }

  try {
    const supabaseRes = await fetch(
      `${process.env.SUPABASE_URL}/rest/v1/clients?select=client_id,dashboard_id,subscription_end_date&slug=eq.${encodeURIComponent(slug)}&password_hash=eq.${passwordHash}&is_active=eq.true`,
      {
        headers: {
          'apikey': process.env.SUPABASE_SERVICE_ROLE_KEY,
          'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`
        }
      }
    );

    const data = await supabaseRes.json();

    if (!Array.isArray(data) || data.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const client = data[0];

    if (client.subscription_end_date) {
      const expiry = new Date(client.subscription_end_date);
      if (expiry < new Date()) {
        return res.status(403).json({ error: 'subscription_expired' });
      }
    }

    // No fallback — dashboard_id must be set explicitly per client
    if (!client.dashboard_id) {
      console.error(`Login error: client ${client.client_id} has no dashboard_id`);
      return res.status(500).json({ error: 'Dashboard not configured' });
    }

    const payload = {
      resource: { dashboard: client.dashboard_id },
      params: { "client": client.client_id },
      exp: Math.round(Date.now() / 1000) + (60 * 60 * 24)
    };

    const token = jwt.sign(payload, process.env.METABASE_SECRET_KEY);
    const embedUrl = `${process.env.METABASE_SITE_URL}/embed/dashboard/${token}#bordered=false&titled=false`;

    return res.status(200).json({ url: embedUrl });

  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
}
