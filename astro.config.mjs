import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';

// Set SITE_URL in the build environment once the production domain is chosen.
const site = process.env.SITE_URL ?? 'https://aegisvault.app';

export default defineConfig({
  site,
  integrations: [sitemap()],
  build: { inlineStylesheets: 'auto' },
  trailingSlash: 'never',
});
