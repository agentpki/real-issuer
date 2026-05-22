# AgentPKI real-issuer reference

> Production-grade AgentPKI issuer running as a Cloudflare Worker. Fork this
> repo to run your own issuer at your own domain. Worker-Secret–backed
> signing key, KV-backed state, bearer-authenticated `/mint` endpoint.

Unlike the [demo issuer](https://github.com/agentpki/demo-issuer) (hardcoded keypair, public `/mint`), this reference is designed to be **deployed at your real domain** with your real signing keys, where only your authenticated agent infrastructure can mint passports.

- **Spec:** https://agentpki.dev/spec/v0.1
- **Verifier:** https://verify.agentpki.dev (or any AgentPKI-conformant verifier)

## Architecture

```
                          ┌─────────────────────────────────┐
   YOUR AGENT FLEET       │   YOUR DOMAIN (your-co.com)     │
   ─────────────────      │                                  │
   bearer-auth POST /mint │   Cloudflare Worker (this repo)  │
   ──────────────────────►│                                  │
                          │   ▸ Loads ISSUER_PRIVATE_KEY_HEX │
                          │     from Worker Secret           │
   GET /.well-known/...   │   ▸ Stores state in KV           │
   ──────────────────────►│     (revoked jtis, mint audit)   │
                          │   ▸ Signs with @agentpki/sdk     │
                          └─────────────────────────────────┘
                                       │
                                       │ verifier fetches /.well-known
                                       ▼
                          ┌─────────────────────────────────┐
                          │   ANY AgentPKI verifier         │
                          │   (verify.agentpki.dev, vendor) │
                          └─────────────────────────────────┘
```

## Setup (15 minutes, one-time)

### 1. Fork + clone

```bash
git clone https://github.com/agentpki/real-issuer your-issuer
cd your-issuer
pnpm install
```

### 2. Generate your issuer keypair

```bash
cd ../sdk-typescript
pnpm tsx examples/gen-demo-key.ts
```

Output looks like:

```
export const DEMO_KEY_ID = 'demo-2026-q2';
export const DEMO_PRIVATE_KEY_HEX = '1847f748...';
export const DEMO_PUBLIC_KEY_HEX  = '228121d3...';
```

**Copy the `DEMO_PRIVATE_KEY_HEX` value** — you'll need it for the Worker Secret. Never check this into git.

### 3. Edit `wrangler.toml`

Set the `[vars]` block to your real values:

```toml
[vars]
ISSUER_DOMAIN = "your-co.com"
ISSUER_NAME = "Your Company, Inc."
ISSUER_TIER = "1"                              # 1=DNS, 2=KYB, 3=hardware-attested
KID = "your-co-2026-q2"                        # whatever identifier you like
KEY_VALID_FROM = "1714521600"                  # UNIX seconds; "now" for fresh keys
KEY_VALID_TO   = "1893456000"                  # UNIX seconds; 5 years out is fine
ABUSE_CONTACT_EMAIL    = "abuse@your-co.com"
SECURITY_CONTACT_EMAIL = "security@your-co.com"
```

Also pick a distinct Worker `name = "..."` at the top.

### 4. Create the KV namespace

```bash
npx wrangler@latest kv namespace create ISSUER_STATE
```

The output contains an `id`. Paste it into `wrangler.toml`:

```toml
[[kv_namespaces]]
binding = "ISSUER_STATE"
id = "<paste here>"
```

### 5. Set Worker Secrets

```bash
# The private key from step 2:
npx wrangler@latest secret put ISSUER_PRIVATE_KEY_HEX
# (paste the hex value, press Enter)

# A random 32+ char string for /mint auth (use a password manager to generate):
npx wrangler@latest secret put INTERNAL_MINT_SECRET
# (paste your random secret, press Enter)
```

### 6. Attach your domain

Uncomment the `[[routes]]` block in `wrangler.toml` and set `pattern` + `zone_name` to your domain.

> **Your domain must already be on Cloudflare DNS** for wrangler to auto-attach. If you bought the domain via Cloudflare Registrar, it already is. Otherwise, add your domain in the Cloudflare dashboard first.

### 7. Deploy

```bash
pnpm run release
```

### 8. Verify

```bash
# Public — should return your issuer directory
curl https://your-co.com/.well-known/agentpki-issuer.json

# Public — CRL (empty until you revoke something)
curl https://your-co.com/.well-known/agentpki-crl.json

# Auth-required — should return 401 without the bearer
curl -X POST https://your-co.com/mint -d '{}'

# Auth-required — should return a passport
curl -X POST https://your-co.com/mint \
  -H "Authorization: Bearer $INTERNAL_MINT_SECRET" \
  -H 'content-type: application/json' \
  -d '{
        "sub": "agent:your-co.com/research-bot-v1",
        "scope": ["read:articles", "read:public-data"],
        "lifetime": 3600
      }'
```

## API

### `POST /mint` — issue a passport

**Auth:** `Authorization: Bearer <INTERNAL_MINT_SECRET>`

**Body:**

```json
{
  "sub": "agent:your-co.com/research-bot-v1",
  "scope": ["read:articles", "read:public-data"],
  "lifetime": 3600,
  "aud": "*",
  "cnf_pubkey_base64url": "OPTIONAL — base64url 32-byte Ed25519 pubkey for Mode B",
  "rate": { "rpm": 60, "daily": 10000 },
  "ext": { "your-co.com/internal-trace": "abc123" }
}
```

**Response:**

```json
{
  "token": "v4.public.eyJ...",
  "jti": "0e4f8a2c91b34e7b9c5d8a1e2f3b4c5d",
  "issued_at": 1747857600,
  "expires_at": 1747861200,
  "kid": "your-co-2026-q2"
}
```

### `POST /admin/revoke` — revoke a passport

**Auth:** `Authorization: Bearer <INTERNAL_MINT_SECRET>`

```json
{ "jti": "0e4f8a2c91b34e7b9c5d8a1e2f3b4c5d", "reason": "suspected-compromise" }
```

Revoked `jti`s appear in `/.well-known/agentpki-crl.json` within ~5 minutes (KV propagation + verifier CRL cache TTL).

### `GET /.well-known/agentpki-issuer.json` — directory document

Standard AgentPKI issuer directory per spec §6.2. Public. Cached for 5 min by edge consumers.

### `GET /.well-known/agentpki-crl.json` — revocation list

Standard CRL per spec §10. Public. Cached for 1 min by edge consumers.

## Production posture upgrades

| Concern | Reference (this repo) | Production-grade |
|---|---|---|
| Private key storage | Worker Secret (encrypted at rest, isolated per Worker) | GCP Cloud KMS (`asymmetricSign`) — Worker never holds key in memory |
| `/mint` auth | Static bearer secret | mTLS via Cloudflare Access; or OIDC bearer |
| `/mint` audit log | KV with 7-day TTL | Append to D1 / external SIEM |
| CRL distribution | Per-request list on KV | Snapshot + Bloom filter rebuild on revocation |
| Key rotation | Manual (deploy with new `KID`, revoke old via `/admin/revoke-key`) | Scheduled cron with auto-rotation, overlap window |
| Tier | T1 (DNS-verified by `/.well-known` discovery) | T2 (KYB via AgentPKI root) or T3 (TEE attestation in `ext`) |

The migration paths are documented inline in the relevant source files (`src/keys.ts`, `src/auth.ts`).

## License

MIT.
