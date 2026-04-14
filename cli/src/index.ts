#!/usr/bin/env node
import { createLogger, formatBanner, VITONOMI_VERSION } from '@vitonomi/core';

const log = createLogger({ scope: 'cli' });

const banner = formatBanner({ app: 'cli', version: VITONOMI_VERSION });

// Banner goes to stdout (machine-pipeable); structured logs go to stderr.
process.stdout.write(`${banner}\n`);
log.info('cli started', { argv: process.argv.slice(2) });
