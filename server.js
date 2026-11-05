// AHMED X update server (runs on Render). Stores the latest SIGNED update and serves it to the app.
// It holds no secrets: an update is accepted only if it is signed by the private key on the owner's PC
// (checked with AO_PUBKEY) and is newer than the current one, so nobody else can publish or roll back.
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

http.createServer((req, res) => {
  const send = (code, body, type = 'application/json') => {
    res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store' });
    res.end(body);
  };
  if (req.method === 'GET' && req.url === '/config') return current ? send(200, current) : send(404, '{"error":"nothing published yet"}');
  if (req.method === 'GET' && (req.url === '/' || req.url === '/health'))
    return send(200, JSON.stringify({ ok: true, version: currentVersion }));
  if (req.method === 'POST' && req.url === '/publish') {
    let body = '';
    req.on('data', d => { body += d; if (body.length > 2_000_000) req.destroy(); });
    req.on('end', () => {
      try {
        const c = check(body);
        if (c.version <= currentVersion) return send(409, '{"error":"older or same version"}');
        current = c.text; currentVersion = c.version;
        send(200, JSON.stringify({ ok: true, version: c.version }));
      } catch (e) { send(400, JSON.stringify({ error: e.message })); }
    });
    return;
  }
  send(404, '{"error":"not found"}');
}).listen(process.env.PORT || 10000, () => console.log('AHMED X update server ready, version', currentVersion));
