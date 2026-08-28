// server/http-utils.js
//
// A tiny dependency-free router. There is no Express in this sandbox (no
// network access to install it), so this implements just enough of the
// same shape — app.get/post/put/delete(path, handler) — to keep app.js
// readable. Swapping to Express later means deleting this file and keeping
// every route handler's body almost unchanged.

import { randomUUID } from 'node:crypto';

export function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  });
  return out;
}

export function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${opts.path || '/'}`);
  parts.push('HttpOnly');
  parts.push('SameSite=Strict');
  if (opts.secure !== false) parts.push('Secure'); // PRODUCTION NOTE: requires HTTPS; see README
  if (opts.maxAge) parts.push(`Max-Age=${opts.maxAge}`);
  if (opts.expires === 0) parts.push('Max-Age=0');
  const existing = res.getHeader('Set-Cookie');
  const cookieStr = parts.join('; ');
  if (existing) {
    res.setHeader('Set-Cookie', Array.isArray(existing) ? [...existing, cookieStr] : [existing, cookieStr]);
  } else {
    res.setHeader('Set-Cookie', cookieStr);
  }
}

export function readJsonBody(req, maxBytes = 1_000_000) {
  return new Promise((resolve, reject) => {
    let data = '';
    let size = 0;
    const MAX = maxBytes; // 1MB default — basic DoS/abuse guard; raised per-route in index.js for file/avatar uploads
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX) {
        reject(Object.assign(new Error('Payload too large'), { status: 413 }));
        req.destroy();
        return;
      }
      data += chunk;
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch {
        reject(Object.assign(new Error('Invalid JSON'), { status: 400 }));
      }
    });
    req.on('error', reject);
  });
}

export function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    // Baseline security headers (see README for the full production list —
    // HSTS is omitted here because this dev server runs over plain HTTP)
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'",
  });
  res.end(payload);
}

// PRODUCTION NOTE (generic error messages, no account enumeration / stack traces):
export function sendError(res, status, message) {
  sendJson(res, status, { error: message });
}

function compilePath(path) {
  const paramNames = [];
  const regexStr = path
    .replace(/\/:[a-zA-Z_]+/g, (m) => {
      paramNames.push(m.slice(2));
      return '/([^/]+)';
    });
  return { regex: new RegExp(`^${regexStr}$`), paramNames };
}

export class Router {
  constructor() {
    this.routes = [];
  }
  add(method, path, ...handlers) {
    const { regex, paramNames } = compilePath(path);
    this.routes.push({ method, regex, paramNames, handlers });
  }
  get(path, ...h) { this.add('GET', path, ...h); }
  post(path, ...h) { this.add('POST', path, ...h); }
  put(path, ...h) { this.add('PUT', path, ...h); }
  delete(path, ...h) { this.add('DELETE', path, ...h); }

  async dispatch(req, res, pathname) {
    for (const route of this.routes) {
      if (route.method !== req.method) continue;
      const match = route.regex.exec(pathname);
      if (!match) continue;
      const params = {};
      route.paramNames.forEach((name, i) => { params[name] = decodeURIComponent(match[i + 1]); });
      req.params = params;
      req.id = randomUUID();
      try {
        // Handlers run in sequence. Middleware (authenticate/requireCsrf/
        // requireUnlocked) either return normally — attaching things like
        // req.user — or throw to abort the chain; only the final handler
        // in the list is expected to actually write a response.
        for (const handler of route.handlers) {
          await handler(req, res);
          if (res.writableEnded) break;
        }
      } catch (err) {
        if (err.status) {
          sendError(res, err.status, err.publicMessage || 'Request could not be completed.');
        } else {
          // Never leak stack traces / internals to the client.
          // eslint-disable-next-line no-console
          console.error('[VAULTIXgusTAR] Unhandled error:', err);
          sendError(res, 500, 'Something went wrong. Please try again.');
        }
      }
      return true;
    }
    return false;
  }
}

export function httpErr(status, publicMessage) {
  return Object.assign(new Error(publicMessage), { status, publicMessage });
}
