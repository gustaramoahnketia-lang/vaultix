import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export async function startTestServer() {
  const tmpDb = path.join(os.tmpdir(), `vaultix-test-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
  process.env.VAULTIX_DB_PATH = tmpDb;
  process.env.VAULTIX_DATA_DIR = os.tmpdir();
  // Import AFTER setting env so db.js opens the temp file.
  const { router } = await import('../server/app.js');
  const { readJsonBody, sendError } = await import('../server/http-utils.js');

  const server = http.createServer(async (req, res) => {
    try {
      const url0 = new URL(req.url, 'http://internal');
      const isUpload = /\/api\/vault\/items\/[^/]+\/file$/.test(url0.pathname) || url0.pathname === '/api/profile/avatar' || url0.pathname === '/api/vault/import';
      req.body = ['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method) ? await readJsonBody(req, isUpload ? 10_000_000 : 1_000_000) : {};
    } catch (err) {
      sendError(res, err.status || 400, err.publicMessage || 'Invalid request.');
      return;
    }
    const url = new URL(req.url, 'http://internal');
    const matched = await router.dispatch(req, res, url.pathname);
    if (!matched) sendError(res, 404, 'Not found.');
  });

  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  return {
    port,
    baseUrl: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve) => server.close(resolve)),
    cleanup: () => { try { fs.unlinkSync(tmpDb); } catch {} },
  };
}

/** A tiny fetch wrapper that keeps cookies + CSRF token like a browser session would. */
export function makeClient(baseUrl) {
  let cookie = '';
  let csrfToken = '';
  async function request(method, urlPath, body) {
    const headers = { 'Content-Type': 'application/json' };
    if (cookie) headers.Cookie = cookie;
    if (csrfToken) headers['x-csrf-token'] = csrfToken;
    const res = await fetch(baseUrl + urlPath, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const setCookie = res.headers.get('set-cookie');
    if (setCookie) cookie = setCookie.split(';')[0];
    let json = null;
    try { json = await res.json(); } catch {}
    if (json && json.csrfToken) csrfToken = json.csrfToken;
    return { status: res.status, body: json };
  }
  return {
    get: (p) => request('GET', p),
    post: (p, b) => request('POST', p, b),
    put: (p, b) => request('PUT', p, b),
    delete: (p, b) => request('DELETE', p, b),
    setCsrf: (t) => { csrfToken = t; },
    getCookie: () => cookie,
  };
}
