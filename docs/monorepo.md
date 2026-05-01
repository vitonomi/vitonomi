---
formatVersion: 1
status: stable
last-reviewed: 2026-05-01
---

# vitonomi monorepo topology

The vitonomi project lives in two repositories. This document is the
public-facing reference for that split and for the workspace layout
inside the public repo.

## The two-repo split

- **`github.com/vitonomi/vitonomi`** — the public, AGPL-3.0 repository.
  Contains every component a user runs: vault daemon, hub server,
  vitonomi-mx SMTP relay, the PWA client, the CLI, the landing site,
  and the shared library that ties them together. Everything in this
  doc set documents this repo.
- **`github.com/vitonomi/cloud`** — the private, proprietary repository.
  Contains only the hosted-service-specific layer: subscription
  billing, treasury management, internal analytics, and infrastructure-
  as-code for the hosted deployment of `vito.gg`. It depends on the
  AGPL hub through its public APIs only — there is no special
  hosted-only fork of the hub binary.

The split exists so that:

1. Every user-runnable binary stays AGPL and auditable. Self-hosters
   never need access to anything in the private repo.
2. Hosted-service-specific commercial logic (Stripe, plan gating,
   cost-basis accounting, infra-as-code) stays out of the AGPL
   surface to keep the open-source product cleanly defined.

## Public-repo workspaces

The public repo is an npm workspaces monorepo:

```
vitonomi/
  core/         shared library — crypto, types, protocol interfaces
  vault/        vault daemon — bin: vitonomi-vault
  hub/          hub control-plane server — bin: vitonomi-hub
  mx/           vitonomi-mx SMTP relay — bin: vitonomi-mx
  cli/          user-facing `vitonomi` command — dispatches to daemon bins
  landing/      Astro static site for vitonomi.com
  clients/
    web/        PWA (Next.js, mobile-ready) — MVP
    mobile/     React Native iOS + Android — v1.1+ (not scaffolded)
    ext/        browser extensions — v1.1+ (not scaffolded)
  docs/         specification suite (this directory)
```

The `clients/` directory is the only category prefix in the layout. It
exists because there will be N sibling client surfaces (PWA, mobile,
browser extensions). Every other workspace is a singleton at the top
level.

## Workspace dependency graph

```
core ◄── vault
core ◄── hub
core ◄── mx
core ◄── cli
core ◄── clients/web

cli ──► (execs daemon binaries via `vitonomi vault start`, etc.)
```

`core/` has no internal dependencies on other workspaces. Every other
package depends on `core` and only on `core`.

## Per-package layout

Each workspace follows the same canonical shape:

```
<package>/
  src/                         implementation
  tests/                       sibling test directory (not colocated)
  package.json                 strict exports map; no default exports
  tsconfig.json                extends ../tsconfig.base.json
  README.md                    purpose, install, dev, test, gotchas
  CLAUDE.md                    agent-facing rules for this package
```

Tests live in a sibling `tests/` directory rather than colocated with
source so that `tests/security/` (for crypto packages) is a single,
auditable location.

## Tooling

| Concern       | Choice                                            |
| ------------- | ------------------------------------------------- |
| Language      | TypeScript 5.6+ strict, no `any`                  |
| Module system | ES modules (NodeNext), no CommonJS                |
| Workspaces    | npm workspaces (not pnpm)                         |
| Build         | TypeScript project references via `tsc -b`        |
| Test runner   | Vitest                                            |
| Linter        | ESLint flat config (typescript-eslint + import)   |
| Formatter     | Prettier (with prettier-plugin-astro for landing) |
| Pre-commit    | Husky + lint-staged                               |
| CI            | GitHub Actions, Node 20 + 22 matrix               |
| OpenAPI       | spectral lint                                     |

The Node version is pinned in `.nvmrc` and `engines` (≥20).

## Build commands

Per-workspace, run from the repo root:

```bash
npm install                              # install everything
npm run typecheck                        # tsc -b across all workspaces
npm run lint                             # ESLint across the repo
npm run format                           # Prettier write
npm test                                 # Vitest across all workspaces
npm run dev -w @vitonomi/clients/web     # PWA dev server
npm run dev -w @vitonomi/hub             # hub dev server
npm run dev -w @vitonomi/vault           # vault dev server
npm run dev -w @vitonomi/mx              # mx dev server
npm run dev -w @vitonomi/landing         # landing dev server
```

## Cross-references

- Full per-component architecture: [`architecture.md`](architecture.md).
- Component lifecycles: [`encryption-flows.md`](encryption-flows.md).
- Wire protocols between components: [`protocol.md`](protocol.md).
- HTTP API contract: [`api-spec.yaml`](api-spec.yaml).
- Repository contributing guide: `../CONTRIBUTING.md` (in repo root,
  added in Phase 0.5 cleanup).
