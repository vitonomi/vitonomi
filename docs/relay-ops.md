---
formatVersion: 1
status: partial
last-reviewed: 2026-05-15
---

# vitonomi-mx operations

Operator guide for `vitonomi-mx`, the log-free RAM-only SMTP
relay introduced in Phase 7. The relay receives inbound mail on
port 25, AEAD-seals each message in RAM against the addressee
alias's published ML-KEM-768 pubkey, and pushes the resulting
ciphertext envelope to the user's hub. Plaintext never reaches
the disk and never appears in logs.

## Process model

- One Rust binary, `vitonomi-mx`. Configured via per-binary
  TOML at `$XDG_CONFIG_HOME/vitonomi/mx.toml` plus
  `VITONOMI_MX_*` env vars plus `--config <path>` /
  `--bind-addr` / `--port` / `--data-dir` flags. Use
  `vitonomi-mx init` to write a default config.
- Three subcommands: `init` (write config), `start` (run the
  SMTP listener), `status` (print the loaded config — useful
  for verifying overrides without booting the listener).
- One persistent state directory (`paths.data_dir`, default
  `$XDG_DATA_HOME/vitonomi/mx`):
  - `identity.bin` — the relay's ML-DSA-65 signing key, mode
    `0600`.
  - `tls/cert.pem`, `tls/key.pem` — the wildcard TLS material
    when running in dev (rcgen-generated on first start).

## Configuration reference

```toml
[server]
bind_addr   = "0.0.0.0"      # 127.0.0.1 in dev, 0.0.0.0 in prod
port        = 25              # SMTP. CI/tests use ephemeral high ports.
base_domain = "vito.gg"       # The base the relay is authoritative for.

[hub]
url         = "https://hub.vitonomi.com"

[paths]
data_dir    = "/var/lib/vitonomi-mx"

[tls]
cert_pem    = ""              # Empty → dev mode generates rcgen self-signed wildcard.
key_pem     = ""              # Production: provide PEM paths from your ACME wildcard.

[relay]
id_hex      = ""              # 16-byte hex RelayId issued by the hub on
                              # POST /v1/admin/relays. Empty until first registration.

[logging]
level       = "info"
format      = "json"
```

## Identity provisioning

1. `vitonomi-mx init` — writes the default `mx.toml`. On first
   `start`, the relay generates an ML-DSA-65 keypair and
   persists the secret at `<data_dir>/identity.bin` (0600).
2. The operator copies the printed pubkey (or extracts it
   from `identity.bin` via a future `mx identity show`).
3. An admin session calls `POST /v1/admin/relays` with
   `(relay_pubkey, allowed_namespaces)`. The hub returns a
   16-byte `RelayId`.
4. The operator pastes the hex-encoded `RelayId` into
   `mx.toml` under `[relay] id_hex`. Restart the relay.
5. From then on every `POST /v1/mx/messages` carries
   `sig_relay` over deterministic CBOR of `(relay_id,
   alias_directory_lookup, envelope, server_received_at_ms)`.

## Wildcard TLS

The relay binds **a single wildcard certificate per configured
base** — `*.vito.gg`, `*.inbox.example.com`, etc. **Per-subdomain
certificates leak the relay's tenant list via Certificate
Transparency logs and are forbidden.** A CI gate
(`mx::tls::tests::dev_cert_san_does_not_contain_per_subdomain_entry`)
fails any cert SAN that looks per-subdomain.

- **Dev**: leave `tls.cert_pem` / `tls.key_pem` empty. On first
  start the relay calls rcgen to generate
  `<data_dir>/tls/cert.pem` and `tls/key.pem` with a single SAN
  `*.<base_domain>`.
- **Production**: provision a wildcard cert via ACME DNS-01
  (Let's Encrypt supports wildcards only over DNS-01). Point
  `tls.cert_pem` / `tls.key_pem` at the issued PEMs. The relay
  reloads on restart; ACME renewal needs an external systemd
  timer + `kill -HUP` (graceful reload is a v1.1 follow-up).

## Operability metrics

The relay exposes per-base-domain counters, **never per-alias**.
A per-alias key would leak the tenant list to anyone scraping
the metrics endpoint.

```text
PerBaseCounters {
  accepted:        u64    // inbound messages successfully pushed to hub
  silent_dropped:  u64    // dropped because addressee alias is unknown
  bytes_accepted:  u64    // post-DATA, pre-encryption bytes
  session_aborts:  u64    // TLS / mailin / hub-push transport errors
}
```

A future `mx status` extension will print these to stdout. The
counters are tested by
`mx::operability::metrics::tests::metrics_snapshot_keys_are_only_base_domains`.

## SMTP semantics under hub-blindness

- **HELO / EHLO**: standard. STARTTLS is offered on every
  session.
- **MAIL FROM**: accepted; sender is **never logged**.
- **RCPT TO**: returns `250 OK` for **every** recipient
  regardless of whether the alias actually exists. Plugs the
  SMTP-RCPT enumeration channel. Alias-existence is checked at
  `data_end` via the hub's alias directory; on miss the
  message is silent-dropped (counter incremented; no log line
  carries the address).
- **DATA**: streamed into a 25 MiB-capped `Vec<u8>` buffer
  allocated, used, and zeroized inside one async function whose
  stack frame drops before return. No file writes.
- **QUIT**: standard.

## Privacy posture

The relay process must hold:

- Zero plaintext on disk (verified by the
  `relay_privacy_assertion` integration test's inotify probe;
  Linux only).
- Zero plaintext in logs (verified by a `tracing::Layer` that
  scans every emitted event for sender / recipient / subject
  patterns).
- Per-base-domain metrics only (verified by
  `metrics_snapshot_keys_are_only_base_domains`).

A tracing redaction layer drops or redacts events whose target
matches `mailin*` AND whose fields contain `from|to|rcpt|sender|
recipient|subject|body|message|address|envelope` —
defence-in-depth against third-party SMTP-library logging.

## Self-hosting

`vitonomi-mx` is the same binary as the hosted relay. Self-hosters
configure `[server] base_domain`, set up a wildcard A/MX record
at their DNS provider, and provision their own ACME wildcard
cert. The hub (whether hosted or self-hosted) must allow-list
the relay's ML-DSA-65 pubkey via `POST /v1/admin/relays`.

Self-hosters typically want `[server] bind_addr = "0.0.0.0"`,
port 25, behind a reverse-NAT or fronted directly by a public IP.
