<p align="center">
  <img src="landing/public/vito/vito.png" width="180" alt="Vito, the vitonomi mascot" />
</p>

<h1 align="center">vitonomi</h1>

<p align="center">
  <strong>Private photo storage. Paid once. Yours forever.</strong><br />
  <em>Self-encrypted · Post-quantum · Open source</em>
</p>

<p align="center">
  <a href="https://vitonomi.com">vitonomi.com</a> ·
  <a href="https://vitonomi.app">vitonomi.app</a> ·
  <a href="CLAUDE.md">Contributing</a> ·
  <a href="https://mariadb.com/bsl11/">BSL 1.1</a>
</p>

---

## What is vitonomi?

vitonomi is privacy-first photo storage on the
[Autonomi](https://autonomi.com) network with optional confidential AI tagging
via [Venice.ai](https://venice.ai). Users pay once to store their library
forever. Photos are self-encrypted on the device, so our servers — and every
node that hosts a chunk — only ever see opaque ciphertext.

Every asymmetric key is post-quantum secure (ML-DSA-65 for signatures,
ML-KEM-768 for key encapsulation), matching Autonomi 2.0's own stack.

## Status

Pre-MVP. The codebase is under active development on a public roadmap.
Phase 0 (tooling, workspaces, CI) and Phase 0.1 (landing site) are complete.
Phase 1 (core/ foundations) is next. See the workspace-level `PROJECT.md` for
the full 12-phase plan.

## Repository layout

This is the **public** repo, source-available under BSL 1.1. The proprietary
hosted backend (`cloud/`) lives in a separate private repo.

| Package    | Purpose                                                                 |
| ---------- | ----------------------------------------------------------------------- |
| `core/`    | Shared library — crypto, Autonomi storage backend, tag index, recovery. |
| `cli/`     | Standalone recovery & upload tool. Works without any vitonomi server.   |
| `web/`     | Next.js app for both hosted and self-hosted modes (Phase 6 scaffold).   |
| `landing/` | Astro static site at [vitonomi.com](https://vitonomi.com).              |
| `docs/`    | Specs: OpenAPI, data format, flows, architecture references.            |

Everything runs on npm workspaces from the root.

## Quick start

Requirements: Node 20+ and npm 10+.

```bash
git clone https://github.com/vitonomi/vitonomi.git
cd vitonomi
npm install

npm test          # all workspace tests
npm run lint      # ESLint + format check
npm run typecheck # tsc -b across references
npm run build     # build every workspace package
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

## Documentation

- [`CLAUDE.md`](CLAUDE.md) — governance, conventions, non-negotiable boundaries
- [`docs/monorepo.md`](docs/monorepo.md) — workspace strategy
- [`docs/api-spec.yaml`](docs/api-spec.yaml) — public/cloud API contract (OpenAPI 3.1)
- [`docs/flows.md`](docs/flows.md) — upload, retrieval, disaster recovery
- [`docs/autonomi-reference.md`](docs/autonomi-reference.md) — Autonomi 2.0 facts
- [`docs/venice-ai-reference.md`](docs/venice-ai-reference.md) — confidential AI details

## Core boundaries

A few principles govern this repo and are enforced by code review and tooling:

- **Encryption boundary.** All crypto lives in `core/`, runs client-side, and
  never crosses into `web/` or `cli/` business logic.
- **API boundary.** `web/` talks to the hosted backend only through
  [`docs/api-spec.yaml`](docs/api-spec.yaml). Never imports cloud-repo code.
- **Self-hosted must work.** Every feature ships a self-hosted code path.
- **Open source trust.** The core library and data format are auditable.

## Meet Vito

<p align="left">
  <img src="landing/public/vito/vito.png" width="120" alt="Vito, the vitonomi mascot" />
</p>

Vito is the vitonomi mascot: a hardworking forest ant who carries a camera
and a bindle full of your memories. He keeps things safe so you don't have to
think about it. Say hi in an issue or PR — he appreciates the attention.

## License

Source-available under the [Business Source License 1.1](https://mariadb.com/bsl11/).
Use it freely for non-commercial purposes; reselling vitonomi as a competing
hosted service is restricted. The license converts to Apache 2.0 four years
after each release.

The public documentation in `docs/` is CC-BY-4.0 so anyone can implement a
compatible client.
