export type Plan = {
  id: string;
  name: string;
  price: string;
  unit?: string;
  per: string;
  features: string[];
  cta: { label: string; href: string; style: 'accent' | 'outline' };
  highlight?: boolean;
  tag?: string;
};

export const plans: Plan[] = [
  {
    id: 'free',
    name: 'Free',
    price: '$0',
    per: 'forever, no account',
    features: ['Browser vault, unlimited entries', 'TOTP, generator, password health', 'Encrypted export and import', 'Self-host the static build', 'Community support'],
    cta: { label: 'Open vault', href: '/download', style: 'outline' },
  },
  {
    id: 'personal',
    name: 'Personal',
    price: '$29',
    unit: '/ year',
    per: 'or $2.99 a month',
    features: ['Everything in Free', 'Encrypted sync across devices', 'Encrypted cloud backup', 'Email support, 2 business days'],
    cta: { label: 'Start Personal', href: '/pricing#personal', style: 'accent' },
    highlight: true,
    tag: 'Most popular',
  },
  {
    id: 'teams',
    name: 'Teams',
    price: '$4',
    unit: '/ user / mo',
    per: 'billed annually',
    features: ['Shared collections and roles', 'Admin console', 'Audit log export', 'Priority support, 1 business day'],
    cta: { label: 'Join early access', href: '/enterprise/contact', style: 'outline' },
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    price: 'Custom',
    per: 'annual agreement',
    features: ['SSO / SCIM and policy enforcement', 'Dedicated tenant or self-host', 'DPA and uptime SLA', 'Named support contact'],
    cta: { label: 'Talk to sales', href: '/enterprise/contact', style: 'outline' },
  },
];

export const comparison: { feature: string; values: [string, string, string, string] }[] = [
  { feature: 'Unlimited entries, folders, labels', values: ['Yes', 'Yes', 'Yes', 'Yes'] },
  { feature: 'One-time codes (TOTP)', values: ['Yes', 'Yes', 'Yes', 'Yes'] },
  { feature: 'Password generator and health', values: ['Yes', 'Yes', 'Yes', 'Yes'] },
  { feature: 'Recovery Kit', values: ['Yes', 'Yes', 'Yes', 'Yes'] },
  { feature: 'Encrypted export and import', values: ['Yes', 'Yes', 'Yes', 'Yes'] },
  { feature: 'Share a single entry (hybrid post-quantum)', values: ['Yes', 'Yes', 'Yes', 'Yes'] },
  { feature: 'Cryptographic key rotation', values: ['Yes', 'Yes', 'Yes', 'Yes'] },
  { feature: 'Self-host the static build', values: ['Yes', 'Yes', 'Yes', 'Yes'] },
  { feature: 'Encrypted sync across devices', values: ['Manual, via export', 'Yes', 'Yes', 'Yes'] },
  { feature: 'Encrypted cloud backup', values: ['No', 'Yes', 'Yes', 'Yes'] },
  { feature: 'Family vault (up to 6 people)', values: ['No', 'Add Family, $49 / year', 'No', 'No'] },
  { feature: 'Shared collections, role-based access', values: ['No', 'No', 'Yes', 'Yes'] },
  { feature: 'Admin console, passphrase policy', values: ['No', 'No', 'Yes', 'Yes'] },
  { feature: 'Audit log export', values: ['No', 'No', 'Yes', 'Yes'] },
  { feature: 'SSO and SCIM', values: ['No', 'No', 'No', 'Yes'] },
  { feature: 'Dedicated tenant or supported self-host', values: ['No', 'No', 'No', 'Yes'] },
  { feature: 'Support', values: ['Community', 'Email, 2 business days', 'Priority, 1 business day', 'Named contact, SLA'] },
  { feature: 'DPA and security questionnaire', values: ['No', 'No', 'On request', 'Yes'] },
];
