export type Faq = { q: string; a: string };

export const homeFaq: Faq[] = [
  { q: 'Can Rinse Repeat Labs read my passwords?', a: 'No. Encryption and decryption happen on your device, in your browser. Our servers only ever hold ciphertext, and the key that opens it is derived from a passphrase we never receive.' },
  { q: 'What if I forget my passphrase?', a: 'Generate a recovery key in settings and store it offline. Without the passphrase or the recovery key the vault cannot be opened, by anyone, by design.' },
  { q: 'Do I need an account?', a: 'Not for the free vault. A billing account is only needed for paid sync and team features, and it never holds the key to your vault.' },
  { q: 'Is it really open source?', a: 'Yes, MIT or Apache-2.0, your choice. The browser vault, the crypto core, the sync contract and the documentation are all in the public repository.' },
  { q: 'What is Freenet mode?', a: 'An optional, experimental way to sync over a decentralised network with no relay at all. Most people should use the default browser vault and Personal sync.' },
  { q: 'Has Aegis been independently audited?', a: 'Not yet. The threat model and cryptography are published for review now, and an independent audit is planned before Teams leaves early access. We will link the report on the Security page when it exists.' },
];

export const personalFaq: Faq[] = [
  { q: 'Where is my vault stored on the free plan?', a: 'In your browser, in IndexedDB, sealed with your passphrase. Clearing site data deletes it, so export an encrypted backup regularly.' },
  { q: 'How do I move to a new computer?', a: 'Export the encrypted .aegis file from the old browser, open Aegis on the new one, and import the file with your passphrase. On the Personal plan, sync does this for you.' },
  { q: 'Can I switch from another password manager?', a: 'Yes. Import guides for 1Password, Bitwarden and LastPass are in the documentation, and the importer runs entirely on your device.' },
  { q: 'What happens if I stop paying?', a: 'Your vault stays yours. Sync and cloud backup pause, the local vault keeps working, and you can export at any time.' },
];

export const businessFaq: Faq[] = [
  { q: 'Can an administrator recover an employee vault?', a: 'Only through an escrow policy the organisation turns on deliberately, where a recovery key is wrapped for the admin at enrolment. Without that policy, nobody but the user can open the vault.' },
  { q: 'Can we self-host?', a: 'Yes. The vault is a static build you can serve from your own infrastructure, and Enterprise agreements include supported self-hosting of the sync relay.' },
  { q: 'Do you offer a DPA?', a: 'Yes, on Teams by request and as standard on Enterprise. The subprocessor list is published on the legal pages.' },
  { q: 'What does early access mean for Teams?', a: 'Shared collections and the admin console are being built now. Early-access customers get the features as they land, a direct line to the team, and locked pricing.' },
];

export const pricingFaq: Faq[] = [
  { q: 'Which plan is right for me?', a: 'Use Free if one browser is enough. Choose Personal when you want your vault on more than one device without manual exports. Teams is for sharing credentials with colleagues, and Enterprise adds identity integration and contractual support.' },
  { q: 'Can I cancel any time?', a: 'Yes. Monthly plans stop at the end of the period. Annual plans can be refunded within 30 days of purchase.' },
  { q: 'What currencies and taxes apply?', a: 'Prices are in USD. VAT or sales tax is calculated at checkout based on your billing address.' },
  { q: 'How do seat changes work on Teams?', a: 'Add seats at any time and pay a prorated amount. Removed seats are credited at the next renewal.' },
  { q: 'Do you offer discounts?', a: 'Yes, for education and registered non-profits. Contact support with proof of status.' },
];
