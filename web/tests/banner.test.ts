import { formatBanner, VITONOMI_VERSION } from '@vitonomi/core';
import { describe, expect, it } from 'vitest';

describe('web banner', () => {
  it('renders the hosted-mode banner', () => {
    const banner = formatBanner({ app: 'web', version: VITONOMI_VERSION, mode: 'hosted' });
    expect(banner).toBe(`vitonomi web (hosted) v${VITONOMI_VERSION}`);
  });

  it('renders the self-hosted-mode banner', () => {
    const banner = formatBanner({ app: 'web', version: VITONOMI_VERSION, mode: 'selfhosted' });
    expect(banner).toBe(`vitonomi web (selfhosted) v${VITONOMI_VERSION}`);
  });
});
