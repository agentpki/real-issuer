// Key loading + decoding helpers.
//
// In this reference, the issuer's Ed25519 private key is loaded from a
// Cloudflare Worker Secret (ISSUER_PRIVATE_KEY_HEX). Workers Secrets are
// encrypted at rest, isolated per Worker, and never appear in logs.
//
// Migration path to a real HSM/KMS:
//   v0.2: replace `loadPrivateKey` with a call to GCP Cloud KMS for
//         Ed25519 sign operations. The Worker keeps NO key material in
//         memory; KMS performs the signature when requested.
//   The KMS path adds ~30-50 ms per mint, so consider whether you mint
//   often enough to keep the Worker-Secret model (fast) or rare enough
//   that KMS (most secure) is acceptable.

import { generateKeyPair, getPublicKey, publicKeyToSpkiBase64 } from '@agentpki/sdk';

export interface IssuerKeyMaterial {
  privateKey: Uint8Array;  // 32-byte Ed25519 seed
  publicKey: Uint8Array;   // 32-byte compressed
  spkiBase64: string;      // for publication in the directory document
}

/**
 * Load the issuer's private key from the Worker Secret.
 *
 * Throws if ISSUER_PRIVATE_KEY_HEX is missing or malformed — fail fast at
 * cold-start rather than serving requests with no signing identity.
 */
export function loadPrivateKey(secretHex: string | undefined): IssuerKeyMaterial {
  if (!secretHex || typeof secretHex !== 'string') {
    throw new Error(
      'ISSUER_PRIVATE_KEY_HEX is not set. Run: wrangler secret put ISSUER_PRIVATE_KEY_HEX',
    );
  }
  const trimmed = secretHex.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(trimmed)) {
    throw new Error(
      `ISSUER_PRIVATE_KEY_HEX must be 64 lowercase hex chars (32 bytes); got ${trimmed.length}`,
    );
  }
  const privateKey = hexToBytes(trimmed);
  const publicKey = getPublicKey(privateKey);
  return {
    privateKey,
    publicKey,
    spkiBase64: publicKeyToSpkiBase64(publicKey),
  };
}

/**
 * Generate a fresh keypair. Use this once during initial setup to populate
 * ISSUER_PRIVATE_KEY_HEX. NOT called at runtime in production.
 */
export function generate(): { privateKeyHex: string; publicKeyHex: string; spki: string } {
  const { privateKey, publicKey } = generateKeyPair();
  return {
    privateKeyHex: bytesToHex(privateKey),
    publicKeyHex: bytesToHex(publicKey),
    spki: publicKeyToSpkiBase64(publicKey),
  };
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += bytes[i]!.toString(16).padStart(2, '0');
  }
  return s;
}
