# vitonomi monorepo strategy

The public repo (`vitonomi/`) uses **npm workspaces** to host three packages
that share a single dependency tree, single TypeScript baseline, and single
test runner:

```
vitonomi/
├── package.json            ← root, declares workspaces
├── tsconfig.base.json      ← strict TS settings inherited by every package
├── tsconfig.json           ← root project references for editor tooling
├── eslint.config.js        ← flat config, applied across all packages
├── .prettierrc.json
├── vitest.config.ts        ← root config; per-package configs extend it
├── core/                   ← @vitonomi/core — shared library (crypto, storage, types)
├── web/                    ← @vitonomi/web — Next.js app (hosted + self-hosted)
└── cli/                    ← @vitonomi/cli — recovery + upload tool
```

## Why npm workspaces (and not pnpm/turbo/nx)

- **Zero extra tools**: every contributor already has `npm`. No per-machine
  install of pnpm or a build orchestrator.
- **No remote-cache lock-in**: builds and tests run the same locally and in CI.
- **Three packages, one boundary**: the workspace is small enough that we don't
  need task graph caching. If we ever exceed ~6 packages, revisit.
- **Self-hosters benefit**: anyone cloning the repo can `npm install` and run
  the CLI without learning a new package manager.

## Inter-package consumption

`web/` and `cli/` consume `core/` as `"@vitonomi/core": "*"` workspace
dependencies. `core/` is the only package that builds emitted `.d.ts` files
for downstream type checking; `web/` and `cli/` build their own outputs but
do not need to be consumed by anything else in this repo.

## What lives where

- **`core/`** — anything client-side that must work offline or in a Web Worker.
  Crypto, Autonomi storage backend, tag index, recovery, types.
- **`cli/`** — Node-only entry points that wrap `core/` for terminal use:
  upload, recover, export, import, and the `storage smoke` integration command.
- **`web/`** — Next.js app. Imports `core/` and the OpenAPI-generated client.
  Holds React components, route handlers, runtime config loader.

## What does **not** live in this repo

- **`cloud/`** is a separate private repo. It is not a workspace member.
- The OpenAPI spec at `docs/api-spec.yaml` is the only contract that crosses
  the public/cloud boundary.

## Versioning

All packages share the same version, bumped together. We do not publish
`@vitonomi/core` to npm in MVP — self-hosters install from the workspace.
Independent versioning can be revisited if the library gains external consumers.
