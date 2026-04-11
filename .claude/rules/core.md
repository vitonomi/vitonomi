---
paths:
  - "core/**"
---
# core/ rules

- This is the trust foundation. Every function here may be security-critical.
- All crypto operations (encrypt, decrypt, key derivation, signing) live here.
- Never import from `web/` or `cli/` — core has zero app-layer dependencies.
- Every public function needs JSDoc with parameter/return types documented.
- Every crypto function needs tests for: correct round-trip, wrong key rejection,
  tampered data detection, empty input handling.
- Storage operations go through the `StorageBackend` interface — never call
  Autonomi APIs directly outside of the backend implementation.
- Types and data format definitions are canonical here — web/ and cli/ import them.
