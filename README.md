# Aegis website

The commercial website for Aegis (marketing pages, pricing, support entry points), built with [Astro](https://astro.build). It lives on this branch, deliberately separate from the product code on `main`.

Aegis is another application written by [Rinse Repeat Labs](https://RinseRepeatLabs.com/).

## Develop

```bash
npm install
npm run dev        # http://localhost:4321
npm run build      # type-check, then static build into dist/
npm run preview
```

Requires Node 22.

## Layout

| Path | What it is |
|---|---|
| `DESIGN_PLAN.md` | Positioning, brand system, site map, page specs, pricing structure, infrastructure choices, launch phases |
| `src/data/site.ts` | Every URL, email and form id the site uses. Edit this first. |
| `src/data/plans.ts` | Pricing tiers and the comparison table |
| `src/data/faq.ts` | FAQ content per page |
| `src/data/changelog.ts` | Release notes shown at `/changelog` |
| `src/styles/global.css` | Design tokens (light and dark), type, buttons, tables, forms |
| `src/layouts/Base.astro` | Document shell: fonts, meta, Open Graph, JSON-LD, nav, footer |
| `src/components/` | Nav, Footer, Logo, hero, pricing tiers, FAQ, vault illustration, key hierarchy |
| `src/pages/` | One file per route |
| `public/` | Favicons, `robots.txt`, `.well-known/security.txt` |

Routes: `/`, `/personal`, `/business`, `/pricing`, `/security`, `/download`, `/support`, `/about`, `/changelog`, `/enterprise/contact`, `/legal/privacy`, `/legal/terms`, `/legal/subprocessors`, `/404`.

## Before launch

1. Set the production domain: `SITE_URL` in the build environment, `public/robots.txt`, `public/.well-known/security.txt`.
2. Fill in `src/data/site.ts`: app origin, support and sales addresses, status page, Formspree form ids.
3. Add `public/og.png` (1200 by 630, shield on navy, wordmark, tagline). The layout already references it.
4. Have counsel review `src/pages/legal/*`. They are marked as drafts on the page.
5. Confirm the hosting provider in `src/pages/legal/subprocessors.astro`.

## Deploy

The GitHub Actions workflow on this branch (`.github/workflows/website.yml`) type-checks and builds on every push and uploads `dist/` as an artifact. For hosting, connect this branch to Cloudflare Pages (build command `npm run build`, output `dist`) or any static host. The product's own GitHub Pages deployment stays on `main` and is unaffected.

Fonts are self-hosted through Fontsource, so the site makes no third-party requests on page load.
