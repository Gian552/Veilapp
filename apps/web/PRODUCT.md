# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

People who want to talk privately without handing a service their real identity: no name, phone number or email.
They use VEIL in ordinary situations (daily conversations) and in tense ones (a device may be lost, seized, or about
to be; an account may have to be abandoned quickly). Many are not technical, but they care that the tool is honest
about what it protects and what it does not.

## Product Purpose

VEIL is an end-to-end encrypted messenger whose server is designed to know as little as possible. Success means a
person can create an identity, talk, verify who they are talking to, and, if needed, abandon the identity, all
without the service ever holding their real-world identity or readable messages.

## Positioning

Privacy by architecture, not by policy: random two-word usernames (e.g. `VelvetFalcon`), sealed sender, no stored
IPs or message timestamps, the server never confirms whether an account exists, and Panic Reset abandons an identity
completely. VEIL states its limits plainly and never claims to be "100% anonymous".

## Operating Context

- Single-page web app, served with a strict Content Security Policy (`default-src 'self'`): no external fonts,
  scripts, images or analytics. Self-hosted assets only.
- The vault is unlocked with a password on every start; sessions auto-lock after inactivity.
- Screens: onboarding (random username, password, recovery key), sign-in/unlock, linking a new device by typed code,
  chat list and conversation, safety-number verification, settings (privacy, devices and sessions, keys and recovery,
  data export, Panic Reset), security explanation, Panic Reset progress.
- Used on desktop and phones.

## Capabilities and Constraints

- Messages carry no timestamps; order is logical. No presence, typing or last-seen. Read receipts and display names
  are opt-in.
- Contacts are identified only by their username and their safety number (60 digits).
- Starting a conversation never reveals whether the person exists ("If this person exists, they will receive your messages").
- Panic Reset reports each step only once the system has evidence it happened.

## Brand Commitments

- Name: VEIL. Dark-first interface, default dark (confirmed by the user).
- Serious and trustworthy: not playful or colourful, and no hacker/crypto/terminal look (confirmed by the user).
- A distinctive identity of its own rather than a copy of an existing messenger (confirmed by the user).
- Honest, plain language; no "unhackable", "military-grade" or "100% anonymous" claims.

## Evidence on Hand

No testimonials, customers, audits or metrics exist; never fabricate them. The project is not independently audited.

## Product Principles

1. Say only what is true: every security claim in the UI must hold in the code.
2. Calm under pressure: the most dangerous actions (Panic Reset, key changes) are clear, deliberate and unhurried.
3. Show less, mean more: minimal visible metadata, minimal text; explanations where a decision is made, not everywhere.
4. The person, not the system: name things by what users understand, not by protocol names.

## Accessibility & Inclusion

Keyboard navigation, visible focus, sufficient contrast in dark mode, respects reduced motion, usable on phones.
