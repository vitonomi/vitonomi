---
paths:
  - "core/**"
  - "core-wasm/**"
---
# core/ rules (Rust crate)

- This is the trust foundation. Every function here may be
  security-critical.
- All crypto operations (encrypt, decrypt, key derivation, signing,
  challenge/response, admin-chain signing) live here.
- Never depend on `vault`, `hub`, `mx`, `vito-cli`, or `clients/*`
  crates — `core` has zero downstream dependencies.
- Every public item gets `///` rustdoc with at least a one-line
  summary. Security-relevant items also get an `# Examples` block
  demonstrating correct use, and a `# Errors` section listing the
  failure modes.
- Every crypto function needs tests for: correct round-trip, wrong-key
  rejection, tampered-data detection, empty-input handling, and (where
  applicable) algorithm-confusion / cross-key-isolation.
- `#![deny(unsafe_code)]` at the crate root. No `unsafe` outside
  `core-wasm/` FFI shims, and only with a `// SAFETY:` comment when
  needed.
- Storage operations go through the `VaultStorage` trait — never call
  Autonomi APIs directly outside of the bridge implementation
  (`AutonomiBridge` trait).
- Types and data-format definitions are canonical here — every other
  crate (and `clients/web` via `core-wasm`) imports them.
- Secret types implement `ZeroizeOnDrop` via the `zeroize` crate.
- Constant-time comparisons via the `subtle` crate; never `==` on
  secret bytes.
- All randomness flows through `core::crypto::random::get_random_bytes`;
  no direct `getrandom` / `rand` outside that module.
- Property-based tests via `proptest` for round-trip operations.
- Argon2id has a `test-crypto` feature that swaps in an m=8 MiB / t=1
  profile for fast tests; production builds must use the prod profile
  (m≥256 MiB, t=3, p=1) and a CI guard test verifies this.
