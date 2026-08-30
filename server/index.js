// server/index.js — start here: `node server/index.js`
import http from 'node:http';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { router } from './app.js';
import { readJsonBody, sendError } from './http-utils.js';

// --- Minimal .env loader (no `dotenv` package available offline) ---
function loadEnv() {
  const envPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '.env');
  if (!fs.existsSync(envPath)) return;
  for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const idx = trimmed.indexOf('=');
    if (idx === -1) continue;
    const key = trimmed.slice(0, idx).trim();
    const value = trimmed.slice(idx + 1).trim().replace(/^["']|["']$/g, '');
    if (!(key in process.env)) process.env[key] = value;
  }
}
loadEnv();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const PORT = Number(process.env.PORT || 4173);

const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp', '.ico': 'image/x-icon' };

function serveStatic(req, res, pathname) {
  let filePath = pathname === '/' ? '/index.html' : pathname;
  const resolved = path.normalize(path.join(PUBLIC_DIR, filePath));
  if (!resolved.startsWith(PUBLIC_DIR)) { res.writeHead(400); res.end(); return; } // path traversal guard
  fs.readFile(resolved, (err, data) => {
    if (err) {
      // SPA fallback for client-side routes
      fs.readFile(path.join(PUBLIC_DIR, 'index.html'), (err2, index) => {
        if (err2) { res.writeHead(404); res.end('Not found'); return; }
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(index);
      });
      return;
    }
    const ext = path.extname(resolved);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;

  if (pathname.startsWith('/api/')) {
    try {
      if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
        // File/avatar uploads are base64 JSON bodies, ~33% larger than the
        // raw file — give those routes more headroom than the 1MB default.
        const isUpload = /\/api\/vault\/items\/[^/]+\/file$/.test(pathname) || pathname === '/api/profile/avatar' || pathname === '/api/vault/import';
        req.body = await readJsonBody(req, isUpload ? 10_000_000 : 1_000_000);
      } else {
        req.body = {};
      }
    } catch (err) {
      sendError(res, err.status || 400, err.publicMessage || 'Invalid request.');
      return;
    }
    const matched = await router.dispatch(req, res, pathname);
    if (!matched) sendError(res, 404, 'Not found.');
    return;
  }

  if (req.method === 'GET') {
    serveStatic(req, res, pathname);
  } else {
    res.writeHead(405);
    res.end();
  }
});

server.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`VAULTIXgusTAR server listening on http://localhost:${PORT}`);
  if (!process.env.VAULTIX_KEY_PEPPER) {
    console.log('[VAULTIXgusTAR] NOTE: VAULTIX_KEY_PEPPER not set — see .env.example. Fine for local dev, required before any real deployment.');
  }
});

export default server;
