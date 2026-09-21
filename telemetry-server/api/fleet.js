// GET /api/fleet — latest report per machine, for the dashboard.
// Auth: optional. If DASH_TOKEN is set, callers must pass ?token=... or the
//       X-Guard-Token header (so the dashboard isn't world-readable).
const { getDb } = require('./_db');

module.exports = async (req, res) => {
  const expected = process.env.DASH_TOKEN;
  if (expected) {
    const got = (req.query && req.query.token) || req.headers['x-guard-token'];
    if (got !== expected) return res.status(401).json({ error: 'unauthorized' });
  }
  try {
    const db = await getDb();
    const machines = await db.collection('latest')
      .find({}, { projection: { _id: 0, 'events.recent': 0 } })
      .sort({ received_at: -1 })
      .limit(2000)
      .toArray();
    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).json(machines);
  } catch (e) {
    return res.status(500).json({ error: String(e && e.message || e) });
  }
};
