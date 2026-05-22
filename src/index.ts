// AgentPKI real-issuer reference — Cloudflare Worker entry point.
//
// Routes:
//   GET  /.well-known/agentpki-issuer.json   — public (issuer directory)
//   GET  /.well-known/agentpki-crl.json      — public (revocation list)
//   POST /mint                               — Bearer-auth (issues a passport)
//   POST /admin/revoke                       — Bearer-auth (revokes a jti)
//   GET  /health                             — public liveness probe
//   GET  /                                   — service info
//
// All Bearer-auth endpoints require:
//   Authorization: Bearer <INTERNAL_MINT_SECRET>
// set as a Cloudflare Worker Secret (NOT in source).

import { loadPrivateKey } from './keys.js';
import { requireBearer } from './auth.js';
import { buildIssuerDirectory } from './directory.js';
import { buildCrl, revokePassport } from './crl.js';
import { handleMint } from './mint.js';
import type { Env } from './env.js';

const CORS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'authorization, content-type',
  'Access-Control-Max-Age': '86400',
};

// Lazy singleton so we don't decode the key on every request
let cachedKey: ReturnType<typeof loadPrivateKey> | null = null;
function key(env: Env) {
  if (!cachedKey) cachedKey = loadPrivateKey(env.ISSUER_PRIVATE_KEY_HEX);
  return cachedKey;
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (req.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    // ─── Public: well-known directory ─────────────────────────────
    if (req.method === 'GET' && url.pathname === '/.well-known/agentpki-issuer.json') {
      const k = key(env);
      const doc = await buildIssuerDirectory(env, k.spkiBase64);
      return json(doc, 200, {
        'Cache-Control': 'public, max-age=300, stale-while-revalidate=3600',
      });
    }

    // ─── Public: CRL ──────────────────────────────────────────────
    if (req.method === 'GET' && url.pathname === '/.well-known/agentpki-crl.json') {
      const crl = await buildCrl(env);
      return json(crl, 200, {
        'Cache-Control': 'public, max-age=60, stale-while-revalidate=300',
      });
    }

    // ─── Public: liveness ─────────────────────────────────────────
    if (req.method === 'GET' && url.pathname === '/health') {
      return json({ ok: true, ts: Math.floor(Date.now() / 1000) });
    }

    // ─── Public: service info ─────────────────────────────────────
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '')) {
      return json({
        service: 'agentpki-real-issuer',
        version: '0.1.0-alpha.1',
        issuer: env.ISSUER_DOMAIN,
        name: env.ISSUER_NAME,
        tier: parseInt(env.ISSUER_TIER, 10) || 1,
        endpoints: {
          directory: 'GET /.well-known/agentpki-issuer.json',
          crl: 'GET /.well-known/agentpki-crl.json',
          mint: 'POST /mint (Bearer-auth)',
          revoke: 'POST /admin/revoke (Bearer-auth)',
          health: 'GET /health',
        },
        spec: 'https://agentpki.dev/spec/v0.1',
      });
    }

    // ─── Auth-required: /mint ─────────────────────────────────────
    if (req.method === 'POST' && url.pathname === '/mint') {
      const auth = requireBearer(req, env.INTERNAL_MINT_SECRET);
      if (!auth.ok) return json({ error: 'unauthorized', detail: auth.reason }, 401);

      let body: unknown;
      try {
        body = await req.json();
      } catch (e) {
        return json({ error: 'malformed_json', detail: e instanceof Error ? e.message : String(e) }, 400);
      }

      const k = key(env);
      const result = await handleMint(body, env, k.privateKey);
      if (!result.ok) {
        return json({ error: result.error, detail: result.detail }, result.status);
      }
      return json(result.data, 200, { 'Cache-Control': 'no-store' });
    }

    // ─── Auth-required: /admin/revoke ─────────────────────────────
    if (req.method === 'POST' && url.pathname === '/admin/revoke') {
      const auth = requireBearer(req, env.INTERNAL_MINT_SECRET);
      if (!auth.ok) return json({ error: 'unauthorized', detail: auth.reason }, 401);

      let body: { jti?: string; reason?: string };
      try {
        body = (await req.json()) as { jti?: string; reason?: string };
      } catch {
        return json({ error: 'malformed_json' }, 400);
      }
      if (!body.jti) return json({ error: 'missing_jti' }, 400);

      const entry = await revokePassport(env, body.jti, body.reason ?? 'manual');
      return json({ revoked: true, entry });
    }

    return json({ error: 'not_found', detail: `${req.method} ${url.pathname}` }, 404);
  },
} satisfies ExportedHandler<Env>;

function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...CORS,
      ...extra,
    },
  });
}
