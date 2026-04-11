---
paths:
  - "cli/**"
---
# cli/ rules

- Standalone tool: depends only on core/, no web framework dependency.
- Must work without any vitonomi infrastructure (pure self-hosted operation).
- Commands: `vitonomi recover` (fetch vault + chunks, reconstruct library),
  `vitonomi upload` (upload photos from command line).
- Use a CLI framework (e.g., commander) for argument parsing.
- All output to stderr for status/progress, stdout for data (pipe-friendly).
- Exit codes: 0 = success, 1 = user error, 2 = network error, 3 = crypto error.
