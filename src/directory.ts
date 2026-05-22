// Builds the issuer directory document served at
// /.well-known/agentpki-issuer.json per spec §6.2.

import type { IssuerDirectory, TrustTier } from '@agentpki/sdk';
import type { Env } from './env.js';

const REVOKED_KEYS_KV_KEY = 'revoked_keys';

export async function buildIssuerDirectory(env: Env, spkiBase64: string): Promise<IssuerDirectory> {
  const tier = (parseInt(env.ISSUER_TIER, 10) || 1) as TrustTier;
  const validFrom = parseInt(env.KEY_VALID_FROM, 10) || 1714521600;
  const validTo = parseInt(env.KEY_VALID_TO, 10) || 1893456000;

  // Load revoked keys from KV (allows rotation without redeploy)
  let revokedKeys: Array<{ kid: string; revoked_at: number; reason: string }> = [];
  try {
    const raw = await env.ISSUER_STATE.get(REVOKED_KEYS_KV_KEY, 'json');
    if (Array.isArray(raw)) revokedKeys = raw;
  } catch {
    // KV miss or transient error — directory still serves with empty list
  }

  const doc: IssuerDirectory = {
    v: 1,
    issuer: env.ISSUER_DOMAIN,
    name: env.ISSUER_NAME,
    tier,
    current_keys: [
      {
        kid: env.KID,
        alg: 'Ed25519',
        pubkey: spkiBase64,
        valid_from: validFrom,
        valid_to: validTo,
      },
    ],
    crl_url: `https://${env.ISSUER_DOMAIN}/.well-known/agentpki-crl.json`,
    abuse_report_url: `https://${env.ISSUER_DOMAIN}/abuse`,
    contact: {
      abuse: `mailto:${env.ABUSE_CONTACT_EMAIL}`,
      security: `mailto:${env.SECURITY_CONTACT_EMAIL}`,
    },
  };
  if (revokedKeys.length > 0) doc.revoked_keys = revokedKeys;
  return doc;
}
