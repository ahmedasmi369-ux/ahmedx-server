# AHMED X update server

Tiny Node server for Render. It stores the latest update published from the owner's admin panel and serves it to the app at `GET /config`.

- No secrets here. An update (`POST /publish`) is accepted only if it is signed by the owner's private key (checked with the `AO_PUBKEY` env var) and is newer than the current one.
- Env vars on Render: `AO_PUBKEY` (public key, base64), `AO_CONFIG` (last published update, set by the panel so it survives restarts).
- Render settings: Runtime Node, Build command `npm install`, Start command `node server.js`, Instance type Free.
