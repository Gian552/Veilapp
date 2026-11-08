# VEIL

A privacy-first, end-to-end encrypted messenger whose server is designed to know as little as possible.

* **No real name, phone number or email.** You get a random two-word username (`VelvetFalcon`) and a password.
* **End-to-end encrypted** with X3DH and the Double Ratchet (the Signal protocols), plus sealed sender: the server never stores who sent a message.
* **No stored IP addresses, no message timestamps, no read receipts or presence by default, no analytics, no third-party requests.**
* **Multi-device** without trusting the server: devices are certified by your identity key and linked by typing a one-time code that the server never sees.
* **Optional recovery key**; the server cannot reset your password into your data.
* **Panic Reset**: abandon the identity, delete the account server-side in one transaction, wipe the device, and start over unlinked.

VEIL is **not anonymous against a network observer or the server operator in real time**, cannot protect a compromised
device, and cannot delete copies your contacts already have. Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

> Status: functional and tested, **not independently audited**. Do not rely on it for high-risk use until it is.

## Documentation

| Document | Contents |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | components, identities, auth, protocol, data model, configuration |
| [CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md) | primitives, key hierarchy, X3DH and Double Ratchet details, deviations, limits |
| [METADATA.md](docs/METADATA.md) | every stored field, what a database dump reveals, retention |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | 15 adversaries: what they see, can't see, mitigations, tests |
| [PANIC_RESET.md](docs/PANIC_RESET.md) | the reset workflow, failure handling, backups |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | production setup, logging, TLS, backups, operations |
| [SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md) | findings of the internal review and remaining risks |

## Repository

```
packages/crypto   @veil/crypto  all cryptography (audit target)
packages/shared   @veil/shared  API contract (strict zod schemas), username word lists
packages/client   @veil/client  headless client engine (browser + Node)
apps/server       @veil/server  Fastify + PostgreSQL (PGlite for dev/tests)
apps/web          @veil/web     React SPA
deploy/           Caddy, Docker Compose, Postgres roles, backups
```

## Running locally

Requirements: Node.js ≥ 22, npm ≥ 10. No database server is needed for development: the server falls back to an embedded
PostgreSQL (PGlite) stored in `.veil-data/`.

```sh
npm ci
npm run dev:server     # http://127.0.0.1:8787, ephemeral dev secret, embedded Postgres
npm run dev:web        # http://127.0.0.1:5173, proxies /v1 to the server
```

Open http://127.0.0.1:5173, create an identity, then open a second browser profile to create another and start a conversation.

## Tests and checks

```sh
npm test               # all unit, integration and end-to-end tests (vitest)
npm run typecheck      # TypeScript, all workspaces
npm run build          # server bundle + web bundle
npm run audit:deps     # npm audit of production dependencies
```

The test suite includes RFC/IETF known-answer vectors for every primitive, protocol-property tests (forward secrecy, replay,
tampering, out-of-order delivery), and full client-to-server scenarios: multi-device sync, malicious-server key substitution,
recovery, and Panic Reset under network interruption, lost responses, crashes and storage failures. It also scans database dumps,
logs and local storage for leaked plaintext, passwords, tokens and IP addresses.

## Production

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). In short: `VEIL_SERVER_SECRET` (≥ 32 random bytes), PostgreSQL, the provided
Caddy configuration (TLS, access logs disabled), encrypted backups with ≤ 7-day retention, and `veil-admin replay-deletions` after any restore.
