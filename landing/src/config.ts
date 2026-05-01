export const SITE = {
  name: 'vitonomi',
  domain: 'https://vitonomi.com',
  appUrl: 'https://vitonomi.app',
  repoUrl: 'https://github.com/vitonomi/vitonomi',
  docsBaseUrl: 'https://github.com/vitonomi/vitonomi/blob/main/docs',
  defaultTitle: 'vitonomi — unified private storage for all your sensitive data',
  defaultDescription:
    'Self-hostable, post-quantum encrypted storage platform. Credentials and email aliases at launch. Photos, documents, and more coming soon. AGPL-3.0.',
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
