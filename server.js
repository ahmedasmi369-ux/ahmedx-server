// AHMED X update server (runs on Render). Two jobs, and it holds no secrets:
// 1. Updates: stores the latest SIGNED update and serves it at GET /config. A publish is accepted only if it is
//    signed by the private key on the owner's PC (checked with AO_PUBKEY) and newer than the current one.
// 2. Check-ins: each phone posts a small report (POST /hello: hashed device + hashed license, model, Android,
//    app version, its last 50 actions). Only the latest report per device is kept, in memory. The owner's panel
//    pulls them with a request signed by the same private key (GET /pull) and keeps the history on the PC.
// Env: AO_PUBKEY (base64 SPKI DER, P-256), AO_CONFIG (last published envelope, kept across restarts), PORT.
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
const devices = new Map(); // device hash -> latest report
const hex64 = (v) => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const str = (v, n) => (typeof v === 'string' ? v : '').replace(/[\u0000-\u001f]/g, ' ').slice(0, n);

function hello(body) {
  const b = JSON.parse(body);
  if (!hex64(b.d)) throw new Error('bad device');
  const events = (Array.isArray(b.e) ? b.e : []).slice(-50).map((e) => ({
    i: Number(e.i) || 0, t: Number(e.t) || 0, k: str(e.k, 12), x: str(e.x, 80), r: str(e.r, 60),
  }));
  const report = {
    d: b.d, u: hex64(b.u) ? b.u : '', n: str(b.n, 40), s: str(b.s, 40), m: str(b.m, 60), a: str(b.a, 12), v: str(b.v, 20),
    root: str(b.root, 30), sec: str(b.sec, 40), e: events, seen: Date.now(),
  };
  if (!devices.has(b.d) && devices.size >= MAX_DEVICES) {
    const oldest = [...devices.entries()].sort((x, y) => x[1].seen - y[1].seen)[0];
    if (oldest) devices.delete(oldest[0]);
  }
  devices.set(b.d, report);
}

// Panel pull: signature over "AO-PULL:" + ts with the owner's key, ts within 5 minutes.
function pullAllowed(url) {
  const ts = Number(url.searchParams.get('ts'));
  const sig = url.searchParams.get('sig') || '';
  if (!ts || Math.abs(Date.now() - ts) > 5 * 60_000) return false;
  try { return crypto.verify('sha256', Buffer.from('AO-PULL:' + ts), pub, Buffer.from(sig, 'base64')); } catch { return false; }
}

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
    return send(200, JSON.stringify({ ok: true, version: currentVersion }));
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
      try { hello(body); send(200, '{"ok":true}'); } catch (e) { send(400, JSON.stringify({ error: e.message })); }
    });
  }
  if (req.method === 'GET' && url.pathname === '/pull') {
    if (!pullAllowed(url)) return send(403, '{"error":"not allowed"}');
    return send(200, JSON.stringify({ now: Date.now(), devices: [...devices.values()] }));
  }
  send(404, '{"error":"not found"}');
}).listen(process.env.PORT || 10000, () => console.log('AHMED X update server ready, version', currentVersion));
