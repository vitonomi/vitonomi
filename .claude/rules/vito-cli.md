---
paths:
  - "vito-cli/**"
---
# vito-cli/ rules (Rust binary `vito`)

- Thin helper CLI (binary: `vito`): installs, updates, and manages
  vitonomi modules (vaults, clients, etc.).
- Can interact with `vitonomi-cli` for delegated operations.
- Standalone tool: depends on `core` only — no web framework, no
  database driver.
- Must work without any vitonomi infrastructure (pure self-hosted
  operation).
- Use `clap` (derive feature) for argument parsing.
- Configuration via `figment`-loaded TOML at
  `$XDG_CONFIG_HOME/vitonomi/vito.toml` (added if/when this binary
  needs persistent settings).
- All status/progress output via `tracing` (stderr); user-facing
  data goes to stdout for pipe-friendly use.
- Exit codes: 0 = success, 1 = user error, 2 = network error,
  3 = crypto error.
