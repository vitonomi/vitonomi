---
paths:
  - "docs/**"
---
# docs/ rules

- Published specifications — these are the contract between public and cloud repos.
- `api-spec.yaml` is the single source of truth for the hosted API. Update the
  spec before implementing changes in cloud/.
- `data-format.md` is CC-BY-4.0 — anyone can implement a compatible client.
  Changes here are breaking changes that affect interoperability.
- Keep docs precise and versioned. Include format version numbers.
- No proprietary information in docs/ — this is part of the public repo.
