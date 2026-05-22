// /mint handler — issues a fresh AgentPKI passport for an authenticated caller.
//
// Caller MUST present a valid Bearer token (INTERNAL_MINT_SECRET).
// Request body specifies the agent identity + scope + optional cnf pubkey.
// Returns the signed PASETO v4.public token + metadata.

import { signPassport, util, type PassportPayload, type TrustTier } from '@agentpki/sdk';
import type { Env } from './env.js';

export interface MintRequest {
  sub: string;                           // agent identifier
  scope?: string[];
  lifetime?: number;                     // seconds; clamped to [60, 86400]
  aud?: string | string[];               // optional audience
  cnf_pubkey_base64url?: string;         // base64url 32-byte Ed25519 pubkey for Mode B
  rate?: { rpm?: number; daily?: number };
  ext?: Record<string, unknown>;
}

export interface MintResponse {
  token: string;
  jti: string;
  issued_at: number;
  expires_at: number;
  kid: string;
}

const DEFAULT_LIFETIME = 3600;
const MIN_LIFETIME = 60;
const MAX_LIFETIME = 86400;

export async function handleMint(
  body: unknown,
  env: Env,
  privateKey: Uint8Array,
): Promise<{ ok: true; data: MintResponse } | { ok: false; status: number; error: string; detail?: string }> {
  if (typeof body !== 'object' || body === null) {
    return { ok: false, status: 400, error: 'malformed_body' };
  }
  const req = body as MintRequest;

  if (typeof req.sub !== 'string' || req.sub.length < 3) {
    return { ok: false, status: 400, error: 'missing_or_invalid_sub' };
  }

  // Clamp lifetime
  const requested = req.lifetime ?? DEFAULT_LIFETIME;
  if (typeof requested !== 'number' || !Number.isFinite(requested)) {
    return { ok: false, status: 400, error: 'invalid_lifetime' };
  }
  const lifetime = Math.min(MAX_LIFETIME, Math.max(MIN_LIFETIME, Math.floor(requested)));

  // Validate scope
  const scope = Array.isArray(req.scope) ? req.scope.filter((s) => typeof s === 'string') : [];

  // Validate optional cnf pubkey
  let cnf: PassportPayload['cnf'];
  if (typeof req.cnf_pubkey_base64url === 'string' && req.cnf_pubkey_base64url.length > 0) {
    try {
      const decoded = util.base64urlDecode(req.cnf_pubkey_base64url);
      if (decoded.length !== 32) {
        return { ok: false, status: 400, error: 'invalid_cnf_pubkey', detail: 'expected 32-byte Ed25519 key' };
      }
      cnf = { jwk: { kty: 'OKP', crv: 'Ed25519', x: req.cnf_pubkey_base64url } };
    } catch (e) {
      return { ok: false, status: 400, error: 'invalid_cnf_pubkey', detail: e instanceof Error ? e.message : String(e) };
    }
  }

  const tier = (parseInt(env.ISSUER_TIER, 10) || 1) as TrustTier;
  const now = Math.floor(Date.now() / 1000);
  const jti = util.randomHex(16);

  const payload: PassportPayload = {
    v: 1,
    iss: env.ISSUER_DOMAIN,
    sub: req.sub,
    iat: now,
    exp: now + lifetime,
    jti,
    tier,
  };
  if (scope.length > 0) payload.scope = scope;
  if (req.aud) payload.aud = req.aud;
  if (req.rate) payload.rate = req.rate;
  if (cnf) payload.cnf = cnf;
  if (req.ext) payload.ext = req.ext;

  let token: string;
  try {
    token = signPassport(payload, { privateKey, kid: env.KID });
  } catch (e) {
    return { ok: false, status: 500, error: 'sign_failed', detail: e instanceof Error ? e.message : String(e) };
  }

  // Audit-log the mint (best-effort, never blocks the response)
  try {
    await env.ISSUER_STATE.put(
      `mint:${jti}`,
      JSON.stringify({ sub: req.sub, scope, tier, iat: now, exp: now + lifetime }),
      { expirationTtl: 86400 * 7 }, // 7-day audit retention
    );
  } catch {
    // ignore — audit failure doesn't break the mint
  }

  return {
    ok: true,
    data: {
      token,
      jti,
      issued_at: now,
      expires_at: now + lifetime,
      kid: env.KID,
    },
  };
}
