import jwt from 'jsonwebtoken';

export default async function handler(req, res) {
  // Only allow POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { slug, passwordHash } = req.body;

  if (!slug || !passwordHash) {
    return res.status(400).json({ error: 'Missing credentials' });
  }

  try {
    // 1. Validate credentials against Supabase
    const supabaseRes = await fetch(
      `${process.env.SUPABASE_URL}/rest/v1/clients?select=client_id,dashboard_id,subscription_end_date&slug=eq.${encodeURIComponent(slug)}&password_hash=eq.${passwordHash}&is_active=eq.true`,
      {
        headers: {
          'apikey': process.env.SUPABASE_ANON_KEY,
          'Authorization': `Bearer ${process.env.SUPABASE_ANON_KEY}`,
          'Accept-Profile': 'myapp'
        }
      }
    );

    const data = await supabaseRes.json();

    if (!data || data.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const client = data[0];

    // 2. Check subscription expiry
    if (client.subscription_end_date) {
      const expiry = new Date(client.subscription_end_date);
      if (expiry < new Date()) {
        return res.status(403).json({ error: 'subscription_expired' });
      }
    }

    // 3. Sign JWT for Metabase static embedding
    const METABASE_SITE_URL = process.env.METABASE_SITE_URL || 'https://metabase-9tn9.onrender.com';
    const dashboardId = client.dashboard_id || 2;

    const payload = {
      resource: { dashboard: dashboardId },
      params: {
        "client": client.client_id
      },
      exp: Math.round(Date.now() / 1000) + (60 * 60) // 1 hour expiry
    };

    const token = jwt.sign(payload, process.env.METABASE_SECRET_KEY);

    const embedUrl = `${METABASE_SITE_URL}/embed/dashboard/${token}#bordered=false&titled=false`;

    return res.status(200).json({ url: embedUrl });

  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
}
