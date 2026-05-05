---
formatVersion: 1
status: stub
last-reviewed: 2026-05-01
---

# vitonomi threat model

This document enumerates the adversaries vitonomi defends against,
the defences in place, and the attacks explicitly out of scope. It
drives security-test coverage and informs every design decision.

**Status: stub.** This document will be filled in incrementally
across phases and finalised at Phase 11 (security review). Each
adversary section is sketched with what we will write — full
defence analysis lands when the relevant subsystem implementation
is reviewed.

## Adversary classes

### Account takeover

- **Capability.** Phishing, credential stuffing, session-token
  theft, malware on user device.
- **Defences (sketch).** Argon2id with strong parameters; auth key
  is derived client-side and never the raw password; session
  tokens are short-lived; logout-everywhere endpoint; no password
  reset flow that compromises encryption-key material (only
  seed-phrase recovery).
- **Out of scope.** A compromised user device is game-over for that
  device; vitonomi does not defend the user's local OS.

### Malicious hub

- **Capability.** A hosted-hub operator (vitonomi, or a third party
  running our hub binary) goes rogue and tries to read user content,
  read user metadata, or impersonate users.
- **Hub-blindness invariant (binding).** Vitonomi commits to the
  stronger "hub reads no plaintext user data, including metadata"
  property. The hub stores only:
  - `cluster_id` (32-byte hash, no info content) for routing.
  - Public keys (ML-DSA-65 / ML-KEM-768) — public by design.
  - Opaque random ids (`user_id`, `vault_id`, `session_id`,
    `invite_nonce`, `challenge_id`).
  - Connection-observable state (`last_seen`, online/offline,
    hashed remote IP).
  - Signed envelope shells with sealed bodies (chain entries,
    invite outer summaries).
  - Reserved version/epoch fields.

  Username, vault names, admin chain payloads, Argon2 salts,
  invite inner payloads — every other previously-plaintext field —
  is now sealed. See [`architecture.md`](architecture.md#hub-blindness-trust-topology)
  and [`data-format.md`](data-format.md) for byte-level details.

- **What the invariant gives you.** A hosted-hub operator cannot:
  - Decrypt any user content (records, chunks, head pointers,
    inbox messages, key blob).
  - Read cluster membership beyond opaque pubkeys.
  - Read admin chain action contents.
  - Bulk-grind usernames (Argon2id over a per-cluster pepper that
    requires the password to recover; see Login below).
  - Forge any user signature (ML-DSA-65 secret keys never leave
    the client).
  - Forge an admin chain entry (cluster admin sk never leaves the
    admin's client).

- **What the invariant does NOT give you.**
  - **Targeted username confirmation.** A hosted hub running a
    cluster the user registered on can probe `lookup_id =
    argon2id(candidate_username || cluster_pepper, salt=cluster_id)`
    one candidate at a time. Argon2 cost makes bulk infeasible;
    targeted ("is `birkeal` registered?") leaks per-attempt. OPAQUE
    PAKE upgrade in v1.1+ closes this.
  - **Connection / behavioural metadata.** When vaults are online,
    when admin logs in, IP-based geolocation. The WS broker role
    requires the hub to observe these. Hosted operators can build
    behavioural profiles. Self-hosted users have no such operator.
  - **Chain integrity if the hub is the only chain replica.** A
    malicious hosted hub can suppress, fork, or truncate-replay
    chain entries to single-vault clusters. Mitigated by mandatory
    peer-vault gossip (multi-vault clusters) plus mandatory offline
    chain export to the seed-phrase backup file (single-vault
    clusters). See [Adversarial hub against chain
    integrity](#adversarial-hub-against-chain-integrity).
  - **Stripe customer ID ↔ cluster_id linkage** in the hosted
    commercial layer. Inherent to billing; documented in
    `cloud/CLAUDE.md`. Self-hosted has no such linkage.
  - **Denial of service.** A hub operator can drop traffic, refuse
    to broker rendezvous, or shut down. Cluster restore on a fresh
    hub is the recovery path.

### Adversarial hub against chain integrity

Even with sealed payloads, a malicious hub can attack the *ordering*
of the admin chain since `seq` and `prev_hash` are plaintext (they
must be, for the hub to perform admission gating on the outer admin
signature). Specifically:

- **Suppression.** Hub refuses to serve seq N to a vault, returns
  seq N-1 as head. Detectable only if another vault contradicts.
- **Forking.** If the cluster admin signs two distinct entries at
  the same `(seq, prev_hash)` (admin error or admin-key
  compromise), the hub can serve one to vault A and the other to
  vault B. Each vault sees a self-consistent chain.
- **Old-prefix replay.** Hub serves a brand-new vault during
  enrollment a truncated prefix that hides revocations.

These attacks are *only detectable by vault peer gossip or out-of-
band offline chain copies*. Mitigations are normative:

1. Vault-bus emits `ChainAdvertise { highest_seq, head_hash }` on
   every reconnect; vaults log + alert on regression vs. local
   state and request peer copies.
2. `cluster restore` accepts chain exports from vaults only, never
   from the dying hub.
3. **Single-vault clusters MUST maintain an offline chain copy.**
   `vitonomi-cli` exports the latest chain to the seed-phrase
   backup file at every login and warns when the backup is stale
   > 7 days. Single-vault hub-blindness without the offline copy
   is partial — the user gets confidentiality but not integrity
   against a malicious hub.

### Malicious vault

- **Capability.** A vault on compromised hardware (or run by an
  adversarial peer in a multi-vault cluster) attempts to read user
  content.
- **Defences (sketch).** Chunks are AEAD-encrypted with user keys
  before self-encryption; no convergent dedup means no
  confirmation-of-file attack; per-user labelling on quotas does
  not leak content.
- **Out of scope.** A vault can deny access to its chunks. With
  N≥2 vault replication, single-vault loss is recoverable.

### Malicious vitonomi-mx (relay) operator

- **Capability.** mx process holds plaintext during DATA-phase
  reception; an adversarial operator might try to log or persist
  that plaintext.
- **Defences (sketch).** Open-source binary, reproducible build,
  no disk writes during reception (verified by inotify probe in CI),
  no log writes during reception (verified by log-scan in CI).
- **TEE-attested deployment** is a v1.1 strengthening that lets a
  user verify the running binary is the audited one.
- **Out of scope.** A user who does not trust the hosted relay can
  run the same `vitonomi-mx` binary themselves with their own
  domain — at that point the user IS the relay operator.
- See [`relay-ops.md`](relay-ops.md) and
  [`relay-reproducible-build.md`](relay-reproducible-build.md).

### Malicious peer-vault in a multi-vault cluster

- **Capability.** Friend's vault in the user's cluster attempts to
  read the user's data.
- **Defences (sketch).** Per-user AEAD keys; the friend's vault
  holds opaque ciphertext that the friend cannot decrypt; the
  friend can see byte counts and chunk addresses but not content.

### Malicious client device

- **Capability.** User's device is compromised; an attacker can
  observe the user's keys in memory, intercept input, etc.
- **Defences (sketch).** Out of scope. vitonomi does not defend the
  user's local OS.

### Supply-chain attack

- **Capability.** Malicious crates.io dependency, malicious npm
  dependency in `clients/web`, compromised CI, malicious PR.
- **Defences (sketch).** Workspace-wide dependency pins via
  `Cargo.lock` committed to the repo; `cargo deny` with a strict
  license allow-list + advisory blocklist + per-crate dependency
  bans (encryption-boundary lint); `cargo audit` on every PR;
  SLSA Level 3 provenance for `vitonomi-mx` releases; npm
  `package-lock.json` committed for `clients/web` with `npm audit`
  in CI; secret scanning in CI; reproducible builds for
  security-critical binaries.

### Quantum adversary (CRQC — cryptographically relevant quantum computer)

- **Capability.** Future quantum computer breaks classical
  asymmetric crypto; harvest-now-decrypt-later attacker stores
  current ciphertext for future decryption.
- **Defences.** ML-DSA-65 + ML-KEM-768 + XChaCha20-Poly1305 +
  Argon2id end-to-end. No Ed25519, no X25519, no RSA, no ECDH.
  256-bit symmetric keys throughout.
- **Status.** **DECLARED OUT OF SCOPE AS A FEASIBLE ATTACK.** Every
  asymmetric primitive is post-quantum; every symmetric primitive is
  Grover-resistant.

### Confirmation-of-file attacks

- **Capability.** An adversary suspects a user has plaintext X and
  wants to verify by examining stored chunks.
- **Defences.** AEAD-then-self-encrypt layering. Same plaintext +
  different users → different AEAD ciphertext → different chunks.
  No convergent dedup. See
  [`autonomi-compat.md`](autonomi-compat.md) for the rationale.

### Network adversary (passive observer)

- **Capability.** Observes TLS / libp2p traffic; correlates
  metadata.
- **Defences (sketch).** All transport is encrypted (TLS for HTTP,
  Noise for libp2p). Some metadata leakage (sizes, timing,
  destinations) is unavoidable for a working system; we do not
  claim traffic-analysis resistance.

### DNS adversary

- **Capability.** Hijacks user's domain MX or TXT records during
  custom-domain verification.
- **Defences (sketch).** Verification challenge is a one-time
  high-entropy string; verification re-checks DNS at submission;
  re-verification on `verifiedAt` expiry can be required for
  high-value domains.

## Out-of-scope attacks

- Hardware extraction of keys from a compromised user device.
- Side-channel attacks (cache timing, power analysis) on user
  devices.
- Coerced disclosure (legal demand for user keys) — vitonomi cannot
  produce keys it does not hold.

## Reporting vulnerabilities

See `SECURITY.md` in the repository root for the responsible-
disclosure process. The 90-day disclosure window applies to all
vitonomi-published binaries.
