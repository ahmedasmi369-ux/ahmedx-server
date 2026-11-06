// AHMED X update server (runs on Render). Two jobs, and it holds no secrets:
// 1. Updates: stores the latest SIGNED update and serves it at GET /config. A publish is accepted only if it is
//    signed by the private key on the owner's PC (checked with AO_PUBKEY) and newer than the current one.
// 2. Check-ins: each phone posts a small report (POST /hello: hashed device + hashed license, model, Android,
//    app version, its last 50 actions). Saved in a free Postgres database (DATABASE_URL, e.g. Neon) with each
//    device's history (last 2000 actions), so nothing is lost when the free server restarts. Without
//    DATABASE_URL they are kept in memory only. The owner's panel reads them with a request signed by the same
//    private key (GET /pull) and can wipe them (POST /clear, signed). Nothing is stored on the owner's PC.
// Env: AO_PUBKEY (base64 SPKI DER, P-256), AO_CONFIG (last published envelope, kept across restarts),
//      DATABASE_URL (optional Postgres connection string), PORT.
const http = require('http');
const crypto = require('crypto');

const pub = crypto.createPublicKey({ key: Buffer.from(process.env.AO_PUBKEY || '', 'base64'), format: 'der', type: 'spki' });
let current = null;
let currentVersion = -1;

function check(envelope) {
  const env = typeof envelope === 'string' ? JSON.parse(envelope) : envelope;
  const payload = Buffer.from(env.payload, 'base64');
  if (!crypto.verify('sha256', payload, pub, Buffer.from(env.sig, 'base64'))) throw new Error('bad signature');
  const version = Number(JSON.parse(payload.toString('utf8')).version) || 0;
  return { text: JSON.stringify({ payload: env.payload, sig: env.sig }), version };
}

try { if (process.env.AO_CONFIG) { const c = check(process.env.AO_CONFIG); current = c.text; currentVersion = c.version; } }
catch (e) { console.log('stored AO_CONFIG ignored:', e.message); }

// ---------- check-ins ----------
const MAX_DEVICES = 20000;
const MAX_EVENTS = 2000; // history kept per device
const devices = new Map(); // memory fallback: device hash -> report with history
let pool = null; // Postgres when DATABASE_URL is set
let dbError = '';
if (process.env.DATABASE_URL) {
  const { Pool } = require('pg');
  // Neon links end with sslmode=require (pg checks the certificate fully) and channel_binding=require.
  pool = new Pool({
    connectionString: process.env.DATABASE_URL, max: 4, idleTimeoutMillis: 30_000,
    enableChannelBinding: /channel_binding=require/.test(process.env.DATABASE_URL),
  });
  pool.on('error', (e) => { dbError = e.message; });
  pool.query(`CREATE TABLE IF NOT EXISTS ao_devices (
      d TEXT PRIMARY KEY, report JSONB NOT NULL, events JSONB NOT NULL DEFAULT '[]', first BIGINT NOT NULL, seen BIGINT NOT NULL)`)
    .then(() => { dbError = ''; console.log('users database ready'); })
    .catch((e) => { dbError = e.message; console.log('users database error:', e.message); });
}
const mergeEvents = (old, add) => {
  const ids = new Set(old.map((e) => e.i));
  return old.concat(add.filter((e) => !ids.has(e.i))).sort((a, b) => a.t - b.t).slice(-MAX_EVENTS);
};
const hex64 = (v) => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const str = (v, n) => (typeof v === 'string' ? v : '').replace(/[\u0000-\u001f]/g, ' ').slice(0, n);

function hello(body) {
  const b = JSON.parse(body);
  if (!hex64(b.d)) throw new Error('bad device');
  const events = (Array.isArray(b.e) ? b.e : []).slice(-50).map((e) => ({
    i: Number(e.i) || 0, t: Number(e.t) || 0, k: str(e.k, 12), x: str(e.x, 80), r: str(e.r, 60),
  }));
  const now = Date.now();
  const report = {
    d: b.d, u: hex64(b.u) ? b.u : '', n: str(b.n, 40), s: str(b.s, 40), m: str(b.m, 60), a: str(b.a, 12), v: str(b.v, 20),
    root: str(b.root, 30), sec: str(b.sec, 40),
  };
  if (pool) return saveToDb(report, events, now);
  const old = devices.get(b.d);
  if (!old && devices.size >= MAX_DEVICES) {
    const oldest = [...devices.entries()].sort((x, y) => x[1].seen - y[1].seen)[0];
    if (oldest) devices.delete(oldest[0]);
  }
  devices.set(b.d, { ...report, first: old ? old.first : now, seen: now, events: mergeEvents(old ? old.events : [], events) });
}

async function saveToDb(report, events, now) {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const r = await c.query('SELECT events FROM ao_devices WHERE d = $1 FOR UPDATE', [report.d]);
    if (!r.rows.length) {
      const n = await c.query('SELECT count(*)::int AS n FROM ao_devices');
      if (n.rows[0].n >= MAX_DEVICES) await c.query('DELETE FROM ao_devices WHERE d = (SELECT d FROM ao_devices ORDER BY seen LIMIT 1)');
    }
    const merged = mergeEvents(r.rows.length ? r.rows[0].events : [], events);
    await c.query(`INSERT INTO ao_devices (d, report, events, first, seen) VALUES ($1, $2, $3, $4, $4)
      ON CONFLICT (d) DO UPDATE SET report = EXCLUDED.report, events = EXCLUDED.events, seen = EXCLUDED.seen`,
    [report.d, JSON.stringify(report), JSON.stringify(merged), now]);
    await c.query('COMMIT');
  } catch (e) { await c.query('ROLLBACK').catch(() => {}); throw e; } finally { c.release(); }
}

// Every device with its last 200 actions (what the panel shows).
async function allDevices() {
  if (!pool) return [...devices.values()].map((x) => ({ ...x, events: x.events.slice(-200) }));
  const r = await pool.query('SELECT report, events, first, seen FROM ao_devices ORDER BY seen DESC');
  return r.rows.map((x) => ({ ...x.report, first: Number(x.first), seen: Number(x.seen), events: x.events.slice(-200) }));
}

// Panel requests: signature over "<WHAT>:" + ts with the owner's key, ts within 5 minutes.
// AO-PULL reads the users list; AO-CLEAR wipes it (a different word, so a read can't be replayed as a wipe).
function signedBy(url, what) {
  const ts = Number(url.searchParams.get('ts'));
  const sig = url.searchParams.get('sig') || '';
  if (!ts || Math.abs(Date.now() - ts) > 5 * 60_000) return false;
  try { return crypto.verify('sha256', Buffer.from(what + ':' + ts), pub, Buffer.from(sig, 'base64')); } catch { return false; }
}
const storage = () => (pool ? (dbError ? 'database error: ' + dbError : 'database') : 'memory (set DATABASE_URL to keep users across restarts)');

http.createServer((req, res) => {
  const send = (code, body, type = 'application/json') => {
    res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store' });
    res.end(body);
  };
  const url = new URL(req.url, 'http://x');
  const readBody = (limit, done) => {
    let body = '';
    req.on('data', (d) => { body += d; if (body.length > limit) req.destroy(); });
    req.on('end', () => done(body));
  };
  if (req.method === 'GET' && url.pathname === '/config') return current ? send(200, current) : send(404, '{"error":"nothing published yet"}');
  if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/health'))
    return send(200, JSON.stringify({ ok: true, version: currentVersion, users: storage() }));
  if (req.method === 'POST' && url.pathname === '/publish') {
    return readBody(2_000_000, (body) => {
      try {
        const c = check(body);
        if (c.version <= currentVersion) return send(409, '{"error":"older or same version"}');
        current = c.text; currentVersion = c.version;
        send(200, JSON.stringify({ ok: true, version: c.version }));
      } catch (e) { send(400, JSON.stringify({ error: e.message })); }
    });
  }
  if (req.method === 'POST' && url.pathname === '/hello') {
    return readBody(64_000, (body) => {
      Promise.resolve().then(() => hello(body))
        .then(() => send(200, '{"ok":true}'))
        .catch((e) => send(400, JSON.stringify({ error: e.message })));
    });
  }
  if (req.method === 'GET' && url.pathname === '/pull') {
    if (!signedBy(url, 'AO-PULL')) return send(403, '{"error":"not allowed"}');
    return allDevices()
      .then((list) => send(200, JSON.stringify({ now: Date.now(), storage: storage(), devices: list })))
      .catch((e) => send(500, JSON.stringify({ error: 'database: ' + e.message })));
  }
  if (req.method === 'POST' && url.pathname === '/clear') {
    if (!signedBy(url, 'AO-CLEAR')) return send(403, '{"error":"not allowed"}');
    devices.clear();
    return (pool ? pool.query('DELETE FROM ao_devices') : Promise.resolve())
      .then(() => send(200, '{"ok":true}'))
      .catch((e) => send(500, JSON.stringify({ error: 'database: ' + e.message })));
  }
  send(404, '{"error":"not found"}');
}).listen(process.env.PORT || 10000, () => console.log('AHMED X update server ready, version', currentVersion));
