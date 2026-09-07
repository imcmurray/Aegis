# Aegis: Production Website Design Plan

A plan for the commercial website at which people learn about, try, buy, and get support for Aegis, with distinct Personal and Business (Teams / Enterprise) offerings. Aegis is built by [Rinse Repeat Labs](https://RinseRepeatLabs.com/).

The site itself is built with Astro on this branch. See [`README.md`](./README.md) for how to run and deploy it.

---

## 1. Positioning

**One line:** *Aegis is an open-source, zero-knowledge password manager. Your vault is encrypted on your device with a passphrase only you know, and nobody else, including us, can read it.*

**Why people should believe it (proof points to surface everywhere):**

| Claim | Evidence already in the repo |
|---|---|
| Zero-knowledge | Argon2id → WrapKek → memory-only RootSecret → per-vault keys; sealing happens in WASM in the browser (`docs/CRYPTO.md`) |
| Modern cryptography | Argon2id, XChaCha20-Poly1305, HKDF-SHA256; hybrid Ed25519 + ML-DSA-65 sync and X25519 + ML-KEM-768 sharing (v2) |
| Auditable | MIT / Apache-2.0, public source, published threat model (`docs/THREAT_MODEL.md`) |
| No lock-in | Encrypted `.aegis` export/import, self-hostable static build, optional Freenet mesh |
| No account required | Free tier works with a browser and nothing else |

**Audience split**

- **Personal:** privacy-conscious individuals and families who distrust cloud password managers after recent breaches. They want: no account, open source, works offline, cheap.
- **Business:** small teams up to regulated enterprises. They want: admin control, shared vaults, SSO, audit logs, a support SLA, a DPA, and someone to call.

**Naming caution.** "Aegis" is already used by an unrelated Android authenticator app. Recommend marketing the product as **Aegis Vault** (domain ideas: `aegisvault.app`, `aegis.rinserepeatlabs.com`) and keep the plain "Aegis" as the short name inside the app. Get a trademark search done before launch.

---

## 2. Brand system

Derived from the existing app icon (`ui/public/favicon.svg`: a blue "encrypted" shield on a navy gradient) and the app's own CSS variables, so product and marketing site feel like one thing.

### Logo

- **Mark:** the shield from `favicon.svg`, unchanged. Use it at 24px next to the wordmark in the nav, 32–40px in the footer, 512px for Open Graph and app-store imagery.
- **Wordmark:** "Aegis" in Inter, weight 600, tracking -0.02em, color Ink (dark mode: Mist).
- **Lockup rule:** mark left, wordmark right, gap = 0.5× mark height. Never recolor the shield; the blue-on-navy is the brand.
- **Clear space:** one shield-width on all sides.

### Color

| Token | Hex | Use |
|---|---|---|
| `ink` | `#0f1419` | Dark surfaces, headline text on light |
| `navy` | `#1a2740` | Dark gradient start (from the icon) |
| `slate` | `#1a2332` | Dark elevated cards |
| `border-dark` | `#2d3a4d` | Hairlines on dark |
| `aegis-blue` | `#3d9cf0` | Primary accent on dark surfaces, the shield color |
| `aegis-blue-deep` | `#1f6fc0` | Primary accent on light surfaces (WCAG AA on white) |
| `blue-hover` | `#5aaff5` | Hover on dark |
| `mist` | `#e7ecf3` | Text on dark |
| `muted` | `#8b9bb4` | Secondary text on dark |
| `paper` | `#f7f9fc` | Light page background |
| `paper-2` | `#eef2f7` | Light elevated / alternating sections |
| `success` | `#4fb35a` / `#7fd962` (dark) | Health checks, checkmarks |
| `danger` | `#d64550` / `#f07178` (dark) | Warnings only |

**Palette rule:** one accent. Blue means "action" or "protected". Everything else is neutral. Elegance here comes from restraint, not from gradients everywhere: the only gradient permitted is the navy → ink one from the icon, used on the hero and the footer.

### Typography

| Role | Face | Notes |
|---|---|---|
| Display / H1–H2 | **Instrument Serif** (Google Fonts) | Used sparingly for hero and section headlines. Italic for one emphasized word per headline. Gives a considered, editorial feel that generic SaaS sites lack. |
| Body / UI / H3+ | **Inter** | Matches the Rinse Repeat Labs site. 16–18px body, 1.6 line height. |
| Code / crypto details | **JetBrains Mono** | Algorithm names, envelope formats, CLI snippets. |

Type scale (desktop): 64 / 44 / 32 / 24 / 18 / 16 / 14. Headline tracking -0.02em. Max line length 65 characters.

### Voice

Plain, specific, unhurried. Say what the cryptography does in one sentence, then link to the doc. Never "military-grade". Never a claim we cannot point to in the source.

### Imagery

- **Product shots** of the real vault UI (dark theme) inside a thin device frame, on a `paper` background with a soft shadow. No stock photos of padlocks or hooded hackers.
- **Diagrams** drawn in the brand palette: the key hierarchy (passphrase → WrapKek → RootSecret → per-vault keys) and the trust boundary diagram from the threat model. These are the site's "hero visuals" for the Security page.
- **Icons:** Material Symbols Rounded, weight 400, to match the shield mark (which is Material's `encrypted_add`).

### Motion

Subtle only: 200ms fades on hover, a single unlock animation on the hero (shield outline draws, then fills blue). Respect `prefers-reduced-motion`.

---

## 3. Site map

```
/                      Home
/personal              Individuals & Families
/business              Teams & Enterprise
/pricing               All plans, monthly/annual toggle, comparison table, FAQ
/security              Architecture, cryptography, threat model, open source, audits
/download              Web app link, desktop/mobile/extension (as they ship), self-host guide
/docs/*                Product documentation (getting started, guides, reference)
/support               Help center search, contact form, status link, SLA info
/enterprise/contact    Sales form (seats, SSO, compliance needs)
/about                 Mission, team, "Built by Rinse Repeat Labs" with link
/blog                  Release notes, security write-ups
/changelog             Rendered from CHANGELOG.md
/legal/privacy  /legal/terms  /legal/dpa  /legal/subprocessors
/status → status.<domain>   (external status page)
/app  → vault.<domain>      (the actual product; separate origin)
```

**Global nav (desktop):** Logo · Personal · Business · Pricing · Security · Docs · [Log in] · **[Open vault]**
**Global nav (mobile):** Logo · hamburger · **[Open vault]**

**Global footer:** four columns (Product / Company / Resources / Legal), then a bottom bar:
> Shield mark · "Aegis is another application from **Rinse Repeat Labs** →" (links to https://RinseRepeatLabs.com/) · © year · MIT / Apache-2.0 · GitHub · status dot.

The RRL attribution appears in three places: footer bottom bar (every page), the About page ("From the makers"), and the `<meta name="author">` / Organization JSON-LD.

---

## 4. Page-by-page

### 4.1 Home

| # | Section | Content | Design notes |
|---|---|---|---|
| 1 | Nav | As above | Transparent over hero, becomes `paper` with hairline on scroll |
| 2 | Hero | H1: "Your passwords. Your keys. *Nobody else's.*" Sub: one-sentence zero-knowledge explanation. CTAs: **Open the free vault** (primary), *See how it works* (secondary). Small line: "No account. No install. Open source." | Navy→ink gradient, left-aligned copy (max 560px), product screenshot in device frame on the right, breaking the section bottom edge |
| 3 | Trust bar | Argon2id · XChaCha20-Poly1305 · Ed25519 + ML-DSA-65 · X25519 + ML-KEM-768 · Open source · Zero-knowledge | Monospace labels, muted, single row |
| 4 | How it works | 3 steps: Choose a passphrase → Your device encrypts everything → Sync or export, still encrypted | Numbered cards on `paper`, tiny diagrams |
| 5 | Features | Entries, folders & labels · TOTP codes · Generator and health · Recovery Kit · Encrypted backups · Multi-device sync · Share an entry · Key rotation · Works offline | 4×2 grid, icon + title + one line |
| 6 | Security spotlight | Key hierarchy diagram + "We published our threat model" + link | Dark section, the only other dark block |
| 7 | Personal / Business split | Two cards side by side, each with a 3-bullet summary and a CTA to its page | Equal weight; Business card gets a "Teams · Enterprise" eyebrow |
| 8 | Pricing snapshot | Free / Personal / Teams / Enterprise cards, annual price, "Compare plans →" | Personal highlighted with a blue top border |
| 9 | Open-source proof | GitHub stars, license badges, "Read the source" CTA, latest release tag | Replaces testimonials until real ones exist |
| 10 | FAQ | 6 questions (see §7) | Accordion |
| 11 | Final CTA | "Start with the free vault. Upgrade when you need sync or a team." | Gradient band |
| 12 | Footer | As above, with RRL attribution | |

### 4.2 Personal (`/personal`)

Hero: "Privacy that doesn't need an account." Sections: what you get free; Personal plan benefits (hosted encrypted sync, priority support, family vault sharing when shipped); "Move from 1Password / Bitwarden / LastPass" import guide; FAQ specific to individuals; CTA.

### 4.3 Business (`/business`)

Hero: "Zero-knowledge for the whole team." Sections: Shared collections with role-based access; Admin console (invite, revoke, enforce passphrase policy); SSO / SCIM (Enterprise); Audit log export; Self-host or dedicated tenant; Compliance (SOC 2 roadmap, DPA, subprocessor list); Support SLA table; **Talk to sales** form. Logos row reserved for design partners.

### 4.4 Pricing (`/pricing`)

Toggle monthly/annual (annual default, shows 2 months free). Four cards, then a full comparison table, then "Which plan is right for me?" and billing FAQ (refunds, currency, VAT, seat changes, education/non-profit discount).

Proposed plans (adjust freely; the structure matters more than the numbers):

| Plan | Price | Includes |
|---|---|---|
| **Free** | $0 | Browser vault, unlimited entries, TOTP, generator, encrypted export/import, self-host, community support |
| **Personal** | $2.99/mo · $29/yr | Everything in Free + hosted encrypted sync across devices, encrypted cloud backup, email support (2 business days) |
| **Family** | $4.99/mo · $49/yr | Personal for up to 6 people + shared family vault |
| **Teams** | $4 / user / mo | Shared collections, admin console, role-based access, audit log, priority support (1 business day) |
| **Enterprise** | Custom | SSO/SCIM, policy enforcement, dedicated tenant or self-host with support, DPA, uptime SLA, named contact |

### 4.5 Security (`/security`)

This page carries the credibility of the whole site. Sections: Zero-knowledge in one paragraph; Architecture diagram; Cryptography table (straight from `docs/CRYPTO.md`); Key hierarchy diagram; What we can and cannot see (a table adapted from the threat model, including the honest "stolen unlocked device: not protected" rows); Open source and reproducible builds; Responsible disclosure / security.txt; Audit status (state plainly "not yet independently audited; audit planned Q_ 20__" until one exists).

### 4.6 Support (`/support`)

Search box over docs; top articles; contact form (plan-aware: paid users get a priority queue); links to status page and GitHub Discussions; SLA summary by plan; "Report a vulnerability" link.

### 4.7 About (`/about`)

Mission paragraph; "From the makers": Aegis is another application written by Rinse Repeat Labs, a software studio building mobile, web, and desktop applications. Link to https://RinseRepeatLabs.com/. Optional: other RRL apps row.

---

## 5. Homepage copy (first draft)

- **H1:** Your passwords. Your keys. *Nobody else's.*
- **Sub:** Aegis encrypts your vault on your device with a passphrase only you know. We never see it, and neither does anyone else. Open source, no account required.
- **Primary CTA:** Open the free vault
- **Secondary CTA:** See how it works
- **Trust line:** Argon2id · XChaCha20-Poly1305 · Ed25519 + ML-DSA-65 · X25519 + ML-KEM-768 · MIT / Apache-2.0
- **How it works:**
  1. **Choose a passphrase.** It never leaves your device. Argon2id turns it into a key that unlocks your vault.
  2. **Everything is sealed locally.** Passwords, notes, and TOTP seeds are encrypted with XChaCha20-Poly1305 before they touch storage.
  3. **Sync or export, still encrypted.** Move between devices with an encrypted file, or let our sync relay carry ciphertext it cannot read.
- **Business card:** Zero-knowledge for the whole team. Shared collections, admin controls, SSO, and a support SLA, with the same guarantee: we cannot read your vault.
- **Final CTA:** Start with the free vault. Upgrade when you need sync or a team.

---

## 6. Commercial and support infrastructure

| Need | Recommendation | Why |
|---|---|---|
| Marketing site | **Astro**, plain CSS design tokens, self-hosted fonts via Fontsource, deployed on Cloudflare Pages | Static, fast, no third-party requests on page load; docs and blog can live in the same project. Built on this branch. |
| Product app | Existing Vite build on its own origin (`vault.<domain>`) | Separate origin keeps marketing scripts away from the vault's security boundary |
| Billing | **Stripe Checkout** + Customer Portal, Stripe Tax | Hosted pages, no card data on our side, handles VAT |
| Licensing | Signed license token (Ed25519, we already use it) stored in the vault metadata; app checks feature flags offline | Works with zero-knowledge: the license says *who paid*, never *what is inside* |
| Accounts | Email + magic link for billing only; the vault never depends on the account | Keeps "no account required" true for Free |
| Help center | Astro docs section or Mintlify | Searchable, versioned with the product |
| Support inbox | Plain or Help Scout, with plan tag from Stripe | Priority queues per plan |
| Status page | Instatus or Better Stack | Enterprise buyers ask on day one |
| Analytics | Plausible or Fathom (cookieless) | Consistent with the privacy positioning; no cookie banner needed |
| Sales | Form → shared inbox, plus Cal.com booking link | Enough until volume justifies a CRM |

**Legal pages to draft before launch:** Privacy Policy, Terms of Service, DPA (Business), Subprocessor list, Refund policy, `security.txt`, responsible disclosure policy.

---

## 7. FAQ content

1. **Can Rinse Repeat Labs read my passwords?** No. Encryption and decryption happen on your device. Our servers only ever hold ciphertext.
2. **What if I forget my passphrase?** Export a Recovery Kit and store its recovery secret separately. Without the passphrase, or the kit and secret together, the vault cannot be opened, by design.
3. **Do I need an account?** Not for the free vault. A billing account is only needed for paid sync and team features.
4. **Is it really open source?** Yes, MIT / Apache-2.0. Build it yourself and compare hashes.
5. **What is Freenet mode?** An optional, experimental way to sync over a decentralized network with no relay at all. Most people should use the default browser vault.
6. **Has Aegis been audited?** State current status honestly and link the Security page.

---

## 8. Honest gaps to close before selling Business plans

The website can only promise what the product does. Today the repo ships a single-user browser vault with encrypted export/import and an experimental Freenet mesh. Before the Teams and Enterprise pages go live these need to exist, or be clearly labeled "coming":

1. Hosted encrypted sync relay (the paid Personal feature).
2. Shared collections (single-entry hybrid sharing shipped in v2.0.0-rc.1; team collections are not yet built).
3. Admin console, roles, and audit log export.
4. SSO / SCIM.
5. Native apps and browser extension (autofill is the feature buyers expect first).
6. An independent security audit, or a dated plan for one.

Suggested launch sequence: **Free + Personal first** (sync relay + billing), collect early users and testimonials, then open a **Teams early-access waitlist** on the Business page while sharing and the admin console are built.

---

## 9. Accessibility, performance, SEO

- WCAG 2.2 AA: all text ≥ 4.5:1 (use `aegis-blue-deep` on light backgrounds), visible focus rings, keyboard-navigable accordions and menus, reduced-motion support.
- Lighthouse targets: Performance ≥ 95, Accessibility 100, Best Practices 100, SEO 100. No client-side framework on marketing pages; fonts self-hosted with `font-display: swap`.
- Security headers on the marketing origin: CSP, HSTS, `X-Content-Type-Options`, `Referrer-Policy`. The vault origin keeps its own stricter CSP.
- SEO: per-page titles and descriptions, Open Graph image (shield on navy, 1200×630), `SoftwareApplication` + `Organization` JSON-LD (author: Rinse Repeat Labs), sitemap, canonical URLs, `/changelog` and `/blog` for fresh content.

---

## 10. Build phases

| Phase | Scope | Est. effort |
|---|---|---|
| 1. Foundation | Astro project, design tokens, nav/footer, Home, Security, Pricing (Free + Personal), Download, Legal, About with RRL attribution | 1–2 weeks |
| 2. Commerce | Stripe Checkout, billing account, license token in app, support inbox, status page | 1–2 weeks after the sync relay exists |
| 3. Business | Business page, Enterprise contact, DPA, comparison table, Teams waitlist | 1 week |
| 4. Content | Docs migration, blog, changelog automation, OG images, import guides | ongoing |
| 5. Launch QA | Lighthouse, accessibility audit, cross-browser, copy review, analytics events | 3 days |

---

## 11. Assets checklist

- [ ] `favicon.svg` (existing) exported to PNG at 16/32/48/180/192/512
- [ ] OG image 1200×630 (shield on navy gradient, wordmark, tagline)
- [ ] Product screenshots: unlock screen, vault list, entry detail, password health, TOTP (dark theme, 2× DPR)
- [ ] Key hierarchy diagram (SVG, brand colors)
- [ ] Trust boundary diagram (SVG)
- [ ] Rinse Repeat Labs wordmark or logo for the footer attribution (request from RRL site assets)
