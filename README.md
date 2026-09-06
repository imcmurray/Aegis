# Aegis website

The commercial website for Aegis (marketing pages, pricing, support entry points) lives on this branch, deliberately separate from the product code on `main`.

| Path | What it is |
|---|---|
| [`DESIGN_PLAN.md`](./DESIGN_PLAN.md) | Positioning, brand system, site map, page-by-page spec, pricing structure, infrastructure choices, launch phases |
| [`mockup/index.html`](./mockup/index.html) | High-fidelity homepage mockup implementing the plan (self-contained HTML, open it in a browser) |
| [`assets/favicon.svg`](./assets/favicon.svg) | The Aegis shield mark, copied from `ui/public/favicon.svg` on `main` |

Aegis is another application written by [Rinse Repeat Labs](https://RinseRepeatLabs.com/).

## Working on this branch

```bash
git fetch origin website
git switch website
# open mockup/index.html, or:
npx --yes serve . -l 4174
```

When the site is built for real (the plan recommends Astro + Tailwind), the project scaffold goes at the root of this branch and `mockup/` can be retired.
