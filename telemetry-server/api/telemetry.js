// POST /api/telemetry  — ingest one agent telemetry report.
// Body: the JSON produced by the Guard agent (telemetry.py build_report()).
// Auth: optional shared secret. If INGEST_TOKEN is set, agents must send it as
//       the X-Guard-Token header (configure the same value on the agent).
const { getDb } = require('./_db');

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'POST only' });
  }
  const expected = process.env.INGEST_TOKEN;
  if (expected && req.headers['x-guard-token'] !== expected) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  try {
    let body = req.body;
    if (typeof body === 'string') { try { body = JSON.parse(body); } catch (_) {} }
    if (!body || typeof body !== 'object') {
      return res.status(400).json({ error: 'invalid body' });
    }
    // prefer the hashed-MAC machine_id; fall back to hostname so a report always
    // lands in the fleet view even if machine_id is missing.
    const machineId = (body.host && (body.host.machine_id || body.host.hostname)) || null;
    const doc = Object.assign({}, body, {
      machine_id: machineId,
      src_ip: (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || null,
      received_at: new Date().toISOString(),
    });

    const db = await getDb();
    // full history (capped-ish by TTL index you can add) + latest-per-machine
    await db.collection('reports').insertOne(doc);
    if (machineId) {
      await db.collection('latest').replaceOne({ machine_id: machineId }, doc, { upsert: true });
    }
    return res.status(200).json({ status: 'ok', machine_id: machineId });
  } catch (e) {
    return res.status(500).json({ error: String(e && e.message || e) });
  }
};
