import { createLogger, formatBanner, VITONOMI_VERSION } from '@vitonomi/core';

// Phase 0 placeholder: prints a banner so the verification gate passes.
// Phase 6 replaces this with the Next.js App Router scaffold.

const mode = process.env['VITONOMI_MODE'] ?? 'hosted';
const log = createLogger({ scope: 'web' });

const banner = formatBanner({ app: 'web', version: VITONOMI_VERSION, mode });
process.stdout.write(`${banner}\n`);
log.info('web placeholder started', { mode });
