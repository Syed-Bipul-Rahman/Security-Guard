// Shared MongoDB connection, cached across serverless invocations.
// The connection string is read ONLY from the MONGODB_URI env var (set it in
// Vercel → Project → Settings → Environment Variables). Never hardcode it.
const { MongoClient } = require('mongodb');

let cached = global._guardMongo;
if (!cached) cached = global._guardMongo = { conn: null, promise: null };

async function getDb() {
  if (cached.conn) return cached.conn;
  if (!cached.promise) {
    const uri = process.env.MONGODB_URI;
    if (!uri) throw new Error('MONGODB_URI env var is not set');
    const dbName = process.env.MONGODB_DB || 'guard';
    cached.promise = MongoClient
      .connect(uri, { maxPoolSize: 5, serverSelectionTimeoutMS: 8000 })
      .then((client) => client.db(dbName));
  }
  cached.conn = await cached.promise;
  return cached.conn;
}

module.exports = { getDb };
