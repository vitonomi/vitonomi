---
formatVersion: 1
status: partial
last-reviewed: 2026-05-01
---

# vitonomi specification suite

These documents specify how vitonomi works at a level of detail
sufficient for an independent re-implementation. They are licensed
under [CC-BY-4.0](LICENSE) so that any party can build a compatible
client.

vitonomi is a privacy-first, self-hostable storage platform for
sensitive personal data. Users hold their own keys; servers see
opaque ciphertext only; data lives on user-controlled storage. The
chunk and DataMap formats are byte-for-byte compatible with the
Autonomi 2.0 network so chunks can flow into the network as an
additional replica target without format migration.

## Reading order

For a new contributor (human or AI agent) joining the project:

1. **[architecture.md](architecture.md)** — the mental model.
   Components, trust boundaries, deployment topologies, and the
   data lifecycle in summary. Read this first.
2. **[autonomi-compat.md](autonomi-compat.md)** — the load-bearing
   commitment that vitonomi chunks and DataMaps are byte-identical
   to Autonomi 2.0.
3. **[data-format.md](data-format.md)** — every byte that vitonomi
   persists or transmits, in normative detail.
4. **[record-types.md](record-types.md)** — per-data-type record
   plaintext schemas (credentials, aliases, alias messages, etc.).
5. **[encryption-flows.md](encryption-flows.md)** — every user-
   visible cryptographic operation as a sequence of primitive calls.
6. **[protocol.md](protocol.md)** + **[api-spec.yaml](api-spec.yaml)**
   — wire formats. Streaming protocols (libp2p, vault↔hub, mx push)
   in `protocol.md`; HTTP/REST in OpenAPI 3.1 in `api-spec.yaml`.
7. **[threat-model.md](threat-model.md)** — adversary classes and
   what we defend against.
8. **[self-hosting.md](self-hosting.md)** —
   **[relay-ops.md](relay-ops.md)** —
   **[relay-reproducible-build.md](relay-reproducible-build.md)** —
   operator guides for self-hosters.
9. **[monorepo.md](monorepo.md)** — codebase topology.

## Document index

| Doc                                                        | Purpose                                            | formatVersion | Status         |
| ---------------------------------------------------------- | -------------------------------------------------- | ------------- | -------------- |
| [README.md](README.md)                                     | Suite index (this file)                            | 1             | partial        |
| [LICENSE](LICENSE)                                         | CC-BY-4.0 covering all of `docs/`                  | —             | stable         |
| [architecture.md](architecture.md)                         | System overview, components, trust model, topology | 1             | draft          |
| [data-format.md](data-format.md)                           | Bytes-on-disk for all persistent artefacts         | 1             | partial        |
| [record-types.md](record-types.md)                         | Per-data-type record schemas                       | —             | TBD (Phase 5+) |
| [autonomi-compat.md](autonomi-compat.md)                   | Byte-for-byte compatibility statement              | 1             | stub           |
| [encryption-flows.md](encryption-flows.md)                 | End-to-end crypto flows per user action            | —             | TBD (Phase 5+) |
| [protocol.md](protocol.md)                                 | Streaming wire protocols                           | —             | TBD (Phase 3+) |
| [api-spec.yaml](api-spec.yaml)                             | OpenAPI 3.1 for client ↔ hub                       | —             | TBD (Phase 4+) |
| [threat-model.md](threat-model.md)                         | Adversaries + defences                             | 1             | stub           |
| [self-hosting.md](self-hosting.md)                         | Operator guide                                     | —             | TBD (Phase 4+) |
| [relay-ops.md](relay-ops.md)                               | vitonomi-mx operations                             | —             | TBD (Phase 8)  |
| [relay-reproducible-build.md](relay-reproducible-build.md) | Reproducible build for mx                          | —             | TBD (Phase 8)  |
| [monorepo.md](monorepo.md)                                 | Workspace topology                                 | 1             | stable         |

## Versioning policy

Each spec doc carries YAML frontmatter:

```yaml
---
formatVersion: 1
status: draft | stub | partial | stable
last-reviewed: YYYY-MM-DD
---
```

- **`formatVersion: 1`** is the MVP target. Any breaking change
  in normative content bumps to `2` and adds a "Migration from v1"
  section.
- **`status` lifecycle.** `stub` (header + outline only) →
  `draft` (first complete pass) → `partial` (filled in across
  phases as relevant subsystems land) → `stable` (post-Phase 12
  review, no breaking changes expected before v1.1).
- **`last-reviewed`** is updated on every PR that touches normative
  content.

## Cross-doc compatibility matrix

When any document bumps its `formatVersion`, the documents that
reference it MUST be updated in the same PR. The matrix below
records the latest known-compatible version pairs:

| Doc                                                                     | Compatible with |
| ----------------------------------------------------------------------- | --------------- |
| TBD (matrix lands in Phase 5 when first cross-doc version pair appears) | —               |

CI's `scripts/check-spec-refs.sh` script verifies that every internal
link in the suite resolves to an existing file + anchor; broken
links fail the build.

## Test vectors

`docs/vectors/` contains golden hex/JSON files referenced from
[data-format.md](data-format.md). Every byte-format-defining
section has at least one round-trippable vector. Implementations
MUST round-trip every vector; CI runs the round-trip on every
commit.

## Reporting issues with the specs

Spec bugs (ambiguities, contradictions, missing fields) are tracked
in the public repo's `bug` issue template. Security-relevant spec
issues follow the responsible-disclosure process in `SECURITY.md`.

## Out-of-scope at the spec layer

- Implementation guidance (specific libraries, code organisation,
  performance tuning) — that's a job for `CLAUDE.md` files in each
  package and the per-package READMEs.
- UI / UX flows — separate design docs, not part of this suite.
- The static-site build of `docs.vitonomi.com` — Phase 12.
