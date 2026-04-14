import sitemap from '@astrojs/sitemap';
import { defineConfig } from 'astro/config';

// vitonomi.com is the canonical landing host. The sitemap integration emits
// sitemap-index.xml + sitemap-0.xml for every page under src/pages/.
export default defineConfig({
  site: 'https://vitonomi.com',
  integrations: [
    sitemap({
      filter: (page) => !page.includes('/coming-soon'),
    }),
  ],
  build: {
    inlineStylesheets: 'auto',
  },
  compressHTML: true,
});
