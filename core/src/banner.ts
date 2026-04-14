export const VITONOMI_VERSION = '0.0.0-phase0';

export interface BannerInfo {
  readonly app: string;
  readonly version: string;
  readonly mode?: string;
}

export function formatBanner(info: BannerInfo): string {
  const mode = info.mode ? ` (${info.mode})` : '';
  return `vitonomi ${info.app}${mode} v${info.version}`;
}
