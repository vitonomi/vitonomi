export const SITE = {
  name: 'vitonomi',
  domain: 'https://vitonomi.com',
  appUrl: 'https://vitonomi.app',
  repoUrl: 'https://github.com/vitonomi/vitonomi',
  docsBaseUrl: 'https://github.com/vitonomi/vitonomi/blob/main/docs',
  defaultTitle: 'vitonomi — private photo storage. Paid once. Yours forever.',
  defaultDescription:
    'Privacy-first photo storage on the Autonomi network. Self-encrypted on your device. Post-quantum secure. Open source.',
  twitterHandle: '@vitonomi',
  themeColor: '#ffffff',
  locale: 'en',
  logoPath: '/vitonomi_logo.png',
  signetPath: '/vitonomi_signet.png',
} as const;

export interface PageMeta {
  readonly title: string;
  readonly description: string;
  readonly path: string;
  readonly noindex?: boolean;
  readonly ogImage?: string;
}

export function canonicalUrl(path: string): string {
  const trimmed = path.replace(/\/+$/, '');
  return `${SITE.domain}${trimmed.length > 0 ? trimmed : ''}`;
}

export function absoluteUrl(path: string): string {
  return `${SITE.domain}${path.startsWith('/') ? path : `/${path}`}`;
}
