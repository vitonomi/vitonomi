---
paths:
  - "web/**"
---
# web/ rules

- Next.js App Router. Fetch data in Server Components with async/await.
- Two runtime modes (hosted vs self-hosted) — determined by config, not build flags.
  Every feature must work in both modes or gracefully degrade in self-hosted.
- Import crypto/storage operations from `core/` only — never implement crypto here.
- Use React Server Components by default. Add `"use client"` only when needed
  (interactivity, hooks, browser APIs).
- State management: React context + hooks. No Redux or external state libraries
  unless explicitly decided.
- All user-facing text must be translatable (i18n-ready from the start).
- `CloudProvider` is a thin HTTP client calling `docs/api-spec.yaml` endpoints.
  `DirectProvider` talks to Autonomi directly via core/.
