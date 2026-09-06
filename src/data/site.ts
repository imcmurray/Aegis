export const site = {
  name: 'Aegis',
  productName: 'Aegis Vault',
  tagline: 'Open-source, zero-knowledge password manager',
  description:
    'Aegis is an open-source, zero-knowledge password manager. Your vault is encrypted on your device with a passphrase only you know.',
  // The live vault. Move this to the production app origin when it exists.
  appUrl: 'https://imcmurray.github.io/Aegis/',
  repoUrl: 'https://github.com/imcmurray/Aegis',
  docsUrl: 'https://github.com/imcmurray/Aegis/tree/main/docs',
  statusUrl: '#',
  supportEmail: 'support@rinserepeatlabs.com',
  salesEmail: 'sales@rinserepeatlabs.com',
  securityEmail: 'security@rinserepeatlabs.com',
  // Formspree form ids. Create the forms and paste the ids here.
  forms: { support: 'YOUR_SUPPORT_FORM_ID', sales: 'YOUR_SALES_FORM_ID' },
  maker: { name: 'Rinse Repeat Labs', url: 'https://RinseRepeatLabs.com/' },
  license: 'MIT / Apache-2.0',
  latestRelease: 'v0.1.1',
  year: new Date().getFullYear(),
} as const;

export const nav = [
  { label: 'Personal', href: '/personal' },
  { label: 'Business', href: '/business' },
  { label: 'Pricing', href: '/pricing' },
  { label: 'Security', href: '/security' },
  { label: 'Docs', href: site.docsUrl },
] as const;

export const footerColumns = [
  {
    title: 'Product',
    links: [
      { label: 'Personal', href: '/personal' },
      { label: 'Business', href: '/business' },
      { label: 'Pricing', href: '/pricing' },
      { label: 'Download', href: '/download' },
      { label: 'Changelog', href: '/changelog' },
    ],
  },
  {
    title: 'Resources',
    links: [
      { label: 'Documentation', href: site.docsUrl },
      { label: 'Security', href: '/security' },
      { label: 'GitHub', href: site.repoUrl },
      { label: 'Verify a build', href: '/download#verify' },
    ],
  },
  {
    title: 'Support',
    links: [
      { label: 'Help center', href: '/support' },
      { label: 'Contact', href: '/support#contact' },
      { label: 'Status', href: site.statusUrl },
      { label: 'Report a vulnerability', href: '/security#disclosure' },
    ],
  },
  {
    title: 'Company',
    links: [
      { label: 'About', href: '/about' },
      { label: 'Rinse Repeat Labs', href: site.maker.url },
      { label: 'Privacy', href: '/legal/privacy' },
      { label: 'Terms', href: '/legal/terms' },
    ],
  },
] as const;
