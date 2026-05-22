// Bearer-token auth for the internal /mint endpoint.
//
// Production issuers MUST NOT expose /mint publicly — anyone with access
// to /mint can issue passports for any agent under your domain. The
// simplest defense is a shared bearer secret known to your internal
// agent infrastructure. Rotate it on a schedule (90-day recommended).
//
// Upgrade paths:
//   - mTLS via Cloudflare Access (zero-trust)
//   - HMAC-SHA256 over (path + body + timestamp) — replay-resistant
//   - OIDC bearer from your existing identity provider

const AUTH_HEADER = 'authorization';
const BEARER_PREFIX = 'Bearer ';

export interface AuthResult {
  ok: boolean;
  reason?: string;
}

export function requireBearer(
  request: Request,
  expectedSecret: string | undefined,
): AuthResult {
  if (!expectedSecret) {
    return { ok: false, reason: 'INTERNAL_MINT_SECRET not configured on server' };
  }
  const header = request.headers.get(AUTH_HEADER);
  if (!header) {
    return { ok: false, reason: 'missing Authorization header' };
  }
  if (!header.startsWith(BEARER_PREFIX)) {
    return { ok: false, reason: 'Authorization must be Bearer scheme' };
  }
  const provided = header.slice(BEARER_PREFIX.length).trim();
  if (!constantTimeEqual(provided, expectedSecret)) {
    return { ok: false, reason: 'invalid bearer token' };
  }
  return { ok: true };
}

/**
 * Constant-time string comparison to prevent timing oracles.
 * Slightly more careful than `provided === expected`.
 */
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    // Still compare the rest to keep timing similar
    let mismatch = 1;
    const len = Math.max(a.length, b.length);
    for (let i = 0; i < len; i++) {
      const ca = i < a.length ? a.charCodeAt(i) : 0;
      const cb = i < b.length ? b.charCodeAt(i) : 0;
      mismatch |= ca ^ cb;
    }
    return false;
  }
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}
