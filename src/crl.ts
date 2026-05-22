// Certificate Revocation List management.
//
// Revoked passport jtis are stored in KV under "revoked:<jti>". When the
// well-known CRL endpoint is requested, we list all "revoked:" keys and
// build the CRL document.
//
// Production note: at scale (>10k revoked passports) you should snapshot
// the CRL into a single KV entry rather than scanning per-request.

import type { Env } from './env.js';

export interface CrlEntry {
  jti: string;
  revoked_at: number;
  reason: string;
}

const CRL_TTL_SECONDS = 300; // CRL is cached for 5 minutes by edge consumers

export async function buildCrl(env: Env): Promise<{
  v: 1;
  issuer: string;
  generated_at: number;
  next_update: number;
  revoked: CrlEntry[];
}> {
  const now = Math.floor(Date.now() / 1000);

  // List all keys starting with "revoked:" (max 1000 per page; for prod
  // CRLs >1000 you need cursor-based pagination here).
  const list = await env.ISSUER_STATE.list({ prefix: 'revoked:', limit: 1000 });
  const revoked: CrlEntry[] = [];
  for (const k of list.keys) {
    const entry = await env.ISSUER_STATE.get(k.name, 'json');
    if (entry) revoked.push(entry as CrlEntry);
  }

  return {
    v: 1,
    issuer: env.ISSUER_DOMAIN,
    generated_at: now,
    next_update: now + CRL_TTL_SECONDS,
    revoked,
  };
}

export async function revokePassport(
  env: Env,
  jti: string,
  reason: string,
): Promise<CrlEntry> {
  const entry: CrlEntry = {
    jti,
    revoked_at: Math.floor(Date.now() / 1000),
    reason,
  };
  // Long retention — revocations live for the natural lifetime of the
  // issued passport (≤ 24h) plus operator's audit window (we keep 90 days)
  await env.ISSUER_STATE.put(`revoked:${jti}`, JSON.stringify(entry), {
    expirationTtl: 90 * 86400,
  });
  return entry;
}
