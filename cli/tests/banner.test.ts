import { formatBanner, VITONOMI_VERSION } from '@vitonomi/core';
import { describe, expect, it } from 'vitest';

describe('cli banner', () => {
  it('renders the cli banner with the current vitonomi version', () => {
    const banner = formatBanner({ app: 'cli', version: VITONOMI_VERSION });
    expect(banner).toBe(`vitonomi cli v${VITONOMI_VERSION}`);
  });
});
