---
paths:
  - "clients/cli/**"
---
# clients/cli/ rules (Rust binary `vitonomi-cli`)

- Full CLI client (binary: `vitonomi-cli`): credentials, aliases,
  recovery, cluster management.
- Standalone tool: depends on `core` only — no web framework, no
  database driver.
- Must work without any vitonomi infrastructure (pure self-hosted
  operation against a self-hosted hub).
- Subcommands (mini-MVP scope): `cluster {create, restore}`, `login`,
  `logout`, `vault {invite, list}`, `status`, `init`. Recovery
  commands re-derive keys from the seed phrase via `core`.
- Use `clap` (derive feature) for argument parsing. Return `Result`
  from `lib::run` so tests can drive the CLI without `process::exit`.
- Use `dialoguer` for password / confirm prompts; tests inject stdin
  via an injectable `Prompts` trait.
- Configuration via `figment`-loaded TOML at
  `$XDG_CONFIG_HOME/vitonomi/cli.toml`; specific flags
  (`--config`, `--hub`) override the file. The `init` subcommand
  writes the default config.
- All status/progress output via `tracing` (stderr); user-facing
  data goes to stdout for pipe-friendly use.
- Exit codes: 0 = success, 1 = user error, 2 = network error,
  3 = crypto error.
- State file at `$XDG_STATE_HOME/vitonomi/state.json` (mode 0600;
  refuse to read if perms wrong).
- HTTP transport: `reqwest` with `rustls-tls` and a custom
  `ServerCertVerifier` when a hub cert fingerprint is cached; system
  trust store + first-connect warning otherwise.
