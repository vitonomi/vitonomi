<p align="center">
  <img src="landing/public/vitonomi_logo.png" width="180" alt="Vito, the vitonomi mascot" />
</p>

<h1 align="center">vitonomi</h1>

<p align="center">
  <strong>Sensitive data, in your own hands.</strong><br />
  <em>Self-hostable · Post-quantum · Autonomi-compatible · Open source</em>
</p>

<p align="center">
  <a href="https://vitonomi.com">vitonomi.com</a> ·
  <a href="https://app.vitonomi.com">app.vitonomi.com</a> ·
  <a href="docs/README.md">Specifications</a> ·
  <a href="CLAUDE.md">Contributing</a> ·
  <a href="LICENSE">AGPL-3.0</a>
</p>

---

## What is vitonomi?

vitonomi is a privacy-first, self-hostable storage platform for the
sensitive personal data you don't want scattered across corporate
clouds. At MVP, vitonomi stores **credentials** (a zero-knowledge
password manager) and **email aliases** (receive-only addresses on
`vito.gg` or any custom domain you own). Photos, videos, documents,
and more types follow in v1.1+ on the same data layer.

You hold the keys. The hub stores opaque ciphertext. Your vaults
store opaque encrypted chunks. Even our own servers can never read
your data — the architecture forbids it.

**Architecture in one sentence.** Users run one or more **vaults**
(storage daemons on home hardware or a VPS) coordinated by a thin
**hub** (control plane); clients reach their main vault over libp2p;
inbound mail to alias addresses is encrypted in RAM by the open-
source **`vitonomi-mx`** SMTP receiver and forwarded as ciphertext to
the user's hub.

**Autonomi-compatible from day one.** vitonomi chunks and DataMaps
are byte-for-byte compatible with the
[Autonomi](https://autonomi.com) 2.0 network. In MVP they live on
your vaults; in v1.1 they can be pushed to the Autonomi network as
an additional replica target with zero format migration. See
[`docs/autonomi-compat.md`](docs/autonomi-compat.md).

**Post-quantum end to end.** ML-DSA-65 (signatures), ML-KEM-768 (key
encapsulation), XChaCha20-Poly1305 (AEAD), Argon2id (KDF). No
Ed25519, no X25519. No harvest-now-decrypt-later risk.

## Status

Pre-MVP. The repo is under active development on a public 13-phase
roadmap. Phase 0 (tooling, workspaces, CI), Phase 0.1 (landing site),
and most of Phase 0.5 (post-pivot restructure: AGPL relicense, new
`vault/`/`hub/`/`mx/` workspace stubs, `web/` → `clients/web/` move,
spec-suite foundation in `docs/`) are complete. Phase 1 (`core/`
foundations) is next.

The full plan lives in the workspace-level `PROJECT.md`. Each phase
has a clear deliverable list and verification gate.

## Repository layout

This is the **public** AGPL-3.0 repository. The private repository at
`github.com/vitonomi/cloud` holds only the proprietary hosted-service
layer (Stripe billing, treasury, internal analytics, infra-as-code)
and consumes this repo through its public APIs.

| Package        | Purpose                                                                         |
| -------------- | ------------------------------------------------------------------------------- |
| `core/`        | Shared library — crypto, types, protocol interfaces, snapshot chain.            |
| `vault/`       | Vault daemon. `vitonomi-vault` binary. Phase 3 stub today.                      |
| `hub/`         | Hub control-plane server. `vitonomi-hub` binary. Phase 4 stub today.            |
| `mx/`          | `vitonomi-mx` SMTP relay. Log-free, RAM-only. Phase 8 stub today.               |
| `cli/`         | User-facing `vitonomi` CLI; dispatches to daemon binaries plus recovery.        |
| `landing/`     | Astro static site at [vitonomi.com](https://vitonomi.com).                      |
| `clients/web/` | Next.js App Router PWA. Phase 6 scaffold.                                       |
| `clients/`     | Reserved for future client surfaces (mobile, browser extensions in v1.1+).      |
| `docs/`        | Specification suite (CC-BY-4.0). [docs/README.md](docs/README.md) is the index. |

Everything runs on npm workspaces from the repo root.

## Quick start

Requirements: Node 20+ and npm 10+.

```bash
git clone https://github.com/vitonomi/vitonomi.git
cd vitonomi
npm install

npm test          # Vitest across all workspaces
npm run lint      # ESLint flat config
npm run typecheck # tsc -b across project references
npm run build     # build every workspace
```

Run the landing site locally:

```bash
npm run dev -w @vitonomi/landing
# → http://localhost:4321
```

Run the CLI banner (Phase 0 placeholder):

```bash
npm start -w @vitonomi/cli
```

Daemon stubs (`vault`, `hub`, `mx`) currently exit with a
"Phase N stub — see PROJECT.md" message. Real implementations land
in their respective phases.

## Documentation

The specification suite in [`docs/`](docs/) is licensed CC-BY-4.0 so
any party can implement a compatible client. Reading order:

- [`docs/README.md`](docs/README.md) — suite index + status table
- [`docs/architecture.md`](docs/architecture.md) — components, trust
  boundaries, deployment topology, data lifecycle
- [`docs/autonomi-compat.md`](docs/autonomi-compat.md) — the
  byte-for-byte compatibility commitment
- [`docs/data-format.md`](docs/data-format.md) — every byte that
  vitonomi persists or transmits (incremental from Phase 2 onward)
- [`docs/threat-model.md`](docs/threat-model.md) — adversaries and
  defences (full review at Phase 11)
- [`docs/monorepo.md`](docs/monorepo.md) — workspace topology

Spec docs that land in later phases (`record-types.md`,
`encryption-flows.md`, `protocol.md`, `api-spec.yaml`,
`self-hosting.md`, `relay-ops.md`, `relay-reproducible-build.md`)
exist as stubs today; each points back to the suite index.

## Core boundaries

Four invariants govern this repo and are enforced by code review and
tooling. They are non-negotiable:

- **Encryption boundary.** All crypto lives in `core/`, runs
  client-side, and never crosses into `clients/web/`, `cli/`,
  `vault/`, `hub/`, or `mx/`. Servers never see plaintext.
- **API boundary.** Clients talk to the hub only through
  [`docs/api-spec.yaml`](docs/api-spec.yaml). Streaming protocols
  (libp2p, vault↔hub, mx push) live in
  [`docs/protocol.md`](docs/protocol.md). The private `cloud/`
  repo is never imported from any public package.
- **Self-hosted must work.** Every feature ships a self-hosted code
  path. The hosted offering at `app.vitonomi.com` is one deployment
  of the same AGPL binaries.
- **Open-source trust.** Core, vault, hub, mx, CLI, web, and landing
  are all AGPL-3.0 and reproducibly built where it matters
  (`vitonomi-mx` first).

## Meet Vito

<p align="left">
  <img src="landing/public/vito/vito.png" width="120" alt="Vito, the vitonomi mascot" />
</p>

Vito is the vitonomi mascot: a hardworking forest ant who carries a
camera and a bindle full of your secrets. He keeps things safe so
you don't have to think about it. Say hi in an issue or PR — he
appreciates the attention.

## License

This repository is licensed under the
[GNU Affero General Public License, version 3.0 only](LICENSE)
(AGPL-3.0-only). Run it, fork it, audit it, run it on your own
hardware. Hosting it as a competing managed service requires you to
make the same source available to your users on the same terms.

The specification suite under [`docs/`](docs/) is licensed
[CC-BY-4.0](docs/LICENSE) so any party can implement a compatible
client without inheriting the AGPL.

Contributions require sign-off via the project's CLA (configured in
Phase 12; until then, contributions are accepted only from the core
team).
