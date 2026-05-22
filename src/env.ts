// Shape of the env object the Worker receives at request time.
// Mirrors wrangler.toml [vars] + [[kv_namespaces]] + secrets.

export interface Env {
  // From [vars]
  ISSUER_DOMAIN: string;
  ISSUER_NAME: string;
  ISSUER_TIER: string;        // "1" | "2" | "3"
  KID: string;
  KEY_VALID_FROM: string;
  KEY_VALID_TO: string;
  ABUSE_CONTACT_EMAIL: string;
  SECURITY_CONTACT_EMAIL: string;

  // From [[kv_namespaces]]
  ISSUER_STATE: KVNamespace;

  // From `wrangler secret put`
  ISSUER_PRIVATE_KEY_HEX: string;
  INTERNAL_MINT_SECRET: string;
}
