---
name: VEIL
description: A private messenger set as a numbered account. Your identity is an engraved plate; everything else stays in the vault.
colors:
  vault-0: "#08140f"
  vault-1: "#0c1c16"
  vault-2: "#10241d"
  vault-3: "#152d25"
  vault-4: "#1b372d"
  vault-5: "#244337"
  vault-6: "#2f5345"
  hairline: "#1f3a2f"
  parchment: "#ede6d3"
  parchment-muted: "#a9bbb0"
  parchment-faint: "#839a8d"
  brass: "#c9a45c"
  brass-strong: "#e2c588"
  brass-ink: "#13201a"
  verdigris: "#86c9ab"
  copper: "#e3a072"
  oxblood: "#e0847a"
  oxblood-strong: "#efa197"
  bubble-out: "#24372a"
typography:
  display:
    fontFamily: "Spectral, Georgia, 'Times New Roman', serif"
    fontSize: "clamp(2.25rem, 4.4vw, 3.5rem)"
    fontWeight: 500
    lineHeight: 1.06
    letterSpacing: "-0.02em"
  headline:
    fontFamily: "Spectral, Georgia, 'Times New Roman', serif"
    fontSize: "2.375rem"
    fontWeight: 500
    lineHeight: 1.12
    letterSpacing: "-0.025em"
  title:
    fontFamily: "Spectral, Georgia, 'Times New Roman', serif"
    fontSize: "1.625rem"
    fontWeight: 500
    lineHeight: 1.25
    letterSpacing: "-0.005em"
  title-sm:
    fontFamily: "Spectral, Georgia, 'Times New Roman', serif"
    fontSize: "1.25rem"
    fontWeight: 500
    lineHeight: 1.25
  name:
    fontFamily: "Spectral, Georgia, 'Times New Roman', serif"
    fontSize: "1.0625rem"
    fontWeight: 500
    lineHeight: 1.3
  numerals:
    fontFamily: "Spectral, Georgia, 'Times New Roman', serif"
    fontSize: "1.1875rem"
    fontWeight: 500
    letterSpacing: "0.05em"
    fontFeature: "tnum, lnum"
  wordmark:
    fontFamily: "Spectral, Georgia, 'Times New Roman', serif"
    fontSize: "1.0625rem"
    fontWeight: 500
    letterSpacing: "0.34em"
  body:
    fontFamily: "'Hanken Grotesk Variable', system-ui, -apple-system, 'Segoe UI', sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.55
  label:
    fontFamily: "'Hanken Grotesk Variable', system-ui, -apple-system, 'Segoe UI', sans-serif"
    fontSize: "0.875rem"
    fontWeight: 500
  caption:
    fontFamily: "'Hanken Grotesk Variable', system-ui, -apple-system, 'Segoe UI', sans-serif"
    fontSize: "0.78125rem"
    fontWeight: 400
  key:
    fontFamily: "'IBM Plex Mono', ui-monospace, 'SF Mono', Menlo, Consolas, monospace"
    fontSize: "1rem"
    fontWeight: 400
    letterSpacing: "0.06em"
rounded:
  sm: "8px"
  md: "12px"
  lg: "16px"
  bubble: "18px"
  composer: "20px"
  pill: "999px"
spacing:
  "1": "4px"
  "2": "8px"
  "3": "12px"
  "4": "16px"
  "5": "24px"
  "6": "32px"
  "7": "48px"
components:
  button-primary:
    backgroundColor: "{colors.brass}"
    textColor: "{colors.brass-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.md}"
    padding: "0 16px"
    height: "38px"
  button-primary-hover:
    backgroundColor: "{colors.brass-strong}"
  button-secondary:
    backgroundColor: "{colors.vault-3}"
    textColor: "{colors.parchment}"
    typography: "{typography.label}"
    rounded: "{rounded.md}"
    padding: "0 16px"
    height: "38px"
  button-secondary-hover:
    backgroundColor: "{colors.vault-4}"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.parchment-muted}"
    rounded: "{rounded.md}"
    padding: "0 16px"
    height: "38px"
  button-danger:
    backgroundColor: "transparent"
    textColor: "{colors.oxblood}"
    rounded: "{rounded.md}"
    padding: "0 16px"
    height: "38px"
  button-danger-solid:
    backgroundColor: "{colors.oxblood}"
    textColor: "{colors.brass-ink}"
    rounded: "{rounded.md}"
    padding: "0 16px"
    height: "38px"
  input:
    backgroundColor: "{colors.vault-2}"
    textColor: "{colors.parchment}"
    rounded: "{rounded.md}"
    padding: "8px 12px"
    height: "40px"
  plate:
    backgroundColor: "{colors.vault-3}"
    textColor: "{colors.parchment}"
    rounded: "{rounded.pill}"
    size: "40px"
  plate-own:
    backgroundColor: "{colors.brass}"
    textColor: "{colors.brass-ink}"
    rounded: "{rounded.pill}"
    size: "48px"
  message-in:
    backgroundColor: "{colors.vault-3}"
    textColor: "{colors.parchment}"
    rounded: "{rounded.bubble}"
    padding: "10px 15px"
  message-out:
    backgroundColor: "{colors.bubble-out}"
    textColor: "{colors.parchment}"
    rounded: "{rounded.bubble}"
    padding: "10px 15px"
  tag-verified:
    textColor: "{colors.verdigris}"
    rounded: "{rounded.pill}"
    padding: "0 7px"
---

# Design System: VEIL

## Overview

**Creative North Star: "The Numbered Account"**

VEIL is set like a private bank vault: a single ramp of bottle green carries every surface, parchment carries the words, and brass is the engraved metal reserved for the one thing that belongs to you. Your identity is a monogram plate and a name set in an engraved serif; the people you talk to are quieter green plates on ruled lines. Nothing floats; sections are separated by hairlines the way entries are separated in a ledger.

The mood is calm, discreet and deliberate. Density is moderate: a 324px leather-dark rail, a conversation stage, and an on-demand verification panel. Interface chrome speaks in a quiet grotesk so the serif can be reserved for names, headings and numbers. Dangerous acts are set in oxblood hairlines and stay unhurried.

The system rejects the grey generic-messenger look and the neon-terminal privacy costume. Dark is the default; a parchment light variant follows `prefers-color-scheme` with the same roles.

**Key Characteristics:**
- One green tonal ramp for every neutral; no grey.
- Brass only for your own plate, primary actions, the selected-plate ring and focus.
- Verdigris means verified, oxblood means danger, copper means warning. Nothing else gets colour.
- Spectral for names, headings and numbers; Hanken Grotesk for UI; IBM Plex Mono only for recovery keys and link codes.
- Hairline-ruled sections and lists instead of padded floating cards.

## Colors

A monochrome vault green with parchment text and one metal, plus three signal colours that each carry a single meaning.

### Primary
- **Engraved Brass** (`brass`): your own monogram plate, primary buttons, the ring around the selected conversation plate. Hover lifts to **Polished Brass** (`brass-strong`), which is also the focus ring. Text on brass is **Brass Ink** (`brass-ink`), a near-black green.

### Secondary
- **Verdigris** (`verdigris`): verified state only: the verified seal dot in the conversation list, the "verified" line under a conversation header, verified tags. Soft fill is the same hue at 13% alpha.

### Tertiary
- **Oxblood** (`oxblood`, hover `oxblood-strong`): danger only: danger-zone rules and headings, Panic Reset, destructive buttons, failed messages, field errors.
- **Copper** (`copper`): warnings: connecting state, key-change alerts in the list preview, warning notices and "not set up" badges.

### Neutral
- **Vault ramp** (`vault-0` to `vault-6`, deepest to lightest): `vault-0` is the leather rail, side panel and composer well; `vault-1` the page background; `vault-2` inputs and base surfaces; `vault-3` raised surfaces, incoming bubbles, other people's plates and the selected list row; `vault-4` hover surfaces and the active segment; `vault-6` strong borders and the plate edge.
- **Hairline** (`hairline`): every list rule, section rule and divider.
- **Parchment** (`parchment`): primary text. **Muted** (`parchment-muted`) for secondary text and previews; **Faint** (`parchment-faint`) for hints, timestamps and system lines.
- **Outgoing bubble** (`bubble-out`): a slightly warmer green with a 30% brass hairline.

The light variant swaps the ramp to parchment (`#f1ece0` background, `#e6e0cf` rail), text to deep green (`#14241d`), and darkens brass to `#8a6a2c`; roles are identical.

### Named Rules
**The Two Jobs Rule.** Brass marks only what is yours and what is chosen: your plate, the primary action, the selected-plate ring and focus. If brass appears anywhere else, it is a mistake.

**The One Meaning Rule.** Verdigris is "verified", oxblood is "danger", copper is "warning". A signal colour never decorates and never stands in for another state.

## Typography

**Display Font:** Spectral (with Georgia, Times New Roman)
**Body Font:** Hanken Grotesk Variable (with system-ui)
**Label/Mono Font:** IBM Plex Mono, for recovery keys and link codes only

**Character:** An engraved bookish serif for everything that is a name, a heading or a number, against a quiet grotesk for the machinery. The serif is set at weight 500 throughout; the mono appears only where a human must copy characters exactly.

### Hierarchy
- **Display** (Spectral 500, clamp(2.25rem, 4.4vw, 3.5rem), 1.06): the welcome/intro headline, max 14ch.
- **Headline** (Spectral 500, 2.375rem, 1.12): page and flow h1.
- **Title** (Spectral 500, 1.625rem / 1.25rem, 1.25): h2 and h3 section headings, conversation header name (1.25rem).
- **Name** (Spectral 500, 1.0625rem, 1.3): contact names in the conversation list; your own name at 1.1875rem.
- **Numerals** (Spectral 500, 1.1875rem, tabular lining figures, 0.05em): safety-number digits, reset counts (1.625rem).
- **Wordmark** (Spectral 500, 1.0625rem, 0.34em tracking): "VEIL" in capitals, nothing else.
- **Body** (Hanken 400, 1rem, 1.55): running text; ledes capped at 56-60ch.
- **Label** (Hanken 500, 0.875rem): buttons, field labels, navigation.
- **Caption** (Hanken 400, 0.78125rem): hints, connection state, status lines.
- **Key** (Plex Mono 400, 1rem, 0.06em): recovery-key grids; link codes at 1.35rem, 0.12em.

### Named Rules
**The Engraving Rule.** Serif is for names, headings and numbers; grotesk for everything you operate. Never set a button or label in Spectral.

**The Copy-Exact Rule.** Monospace exists only for strings a person must transcribe: recovery keys and link codes.

## Layout

The app shell is a two-column grid: a 324px rail and a fluid stage; at 1100px and below the 348px verification panel becomes a fixed overlay from the right; at 760px and below the shell collapses to a single pane that toggles between rail and stage with back buttons. Centered flows (onboarding, sign-in, linking, reset) run at 520px, widening to 1040px for the two-column intro, which stacks below 860px. Settings and security pages sit in a 760px column with 48px top padding.

Spacing follows a 4px base (4, 8, 12, 16, 24, 32, 48). Lists use 12px vertical row padding; sections use 24px vertical padding between hairlines. Message columns pad with clamp(16px, 4vw, 56px); bubbles cap at min(68%, 560px), 86% on mobile.

## Elevation & Depth

Depth is tonal, not cast. Surfaces step up the vault ramp, and edges are drawn with 1px inset hairlines rather than shadows. Real shadows exist only for things that genuinely sit above the page.

### Shadow Vocabulary
- **Overlay** (`box-shadow: 0 1px 0 rgba(255,255,255,0.04) inset, 0 18px 40px -12px rgba(0,0,0,0.6)`): dialogs, the side panel when it overlays, and the safety-number plate.
- **Plate edge** (`box-shadow: inset 0 0 0 1px` vault-6, or brass-strong on your own plate): the engraved rim of every monogram plate.
- **Brass hairline** (`box-shadow: inset 0 0 0 1px rgba(201,164,92,0.5)`): the rim of your identity panel, the generated-name display and the safety-number plate.

### Named Rules
**The Ruled Ledger Rule.** Sections, notices, the existence note and the danger zone are separated by hairlines, top and bottom, with no fill and no radius. A container gets a fill only when it is a plate.

## Shapes

Monogram plates are perfect circles. Controls are gently rounded (12px); plates-as-panels (your identity, the safety-number plate, choice buttons) use 16px; small chrome uses 8px; tags, badges and icon buttons are pills. Message bubbles are 18px with a 6px tail corner on the sender's side, and grouped messages square the joining corner to 6px. The composer is a 20px well. Rules are always 1px; oxblood rules mark danger.

## Components

### Buttons
Quiet green slabs with one brass voice.
- **Shape:** gently rounded (12px), 38px tall; large 46px, small 30px; icon buttons are 38px circles.
- **Primary:** brass fill, brass-ink text, 500 weight, 0 16px padding; hover to polished brass.
- **Secondary:** vault-3 fill with a vault-6 hairline; hover vault-4.
- **Ghost:** transparent, muted text; hover vault-3 fill and parchment text.
- **Danger:** transparent with oxblood hairline and text, hover a 12% oxblood wash; solid danger uses an oxblood fill for the final confirm.
- **Focus:** 2px polished-brass outline, 2px offset. Disabled at 50% opacity. Transitions 180ms on cubic-bezier(0.16, 1, 0.3, 1).

### Chips / Tags
- **Tags:** 18px-high pills, 11px 500 text; neutral on vault-4, verified/warn/danger on their soft fills.
- **Badges:** pill with a vault-6 hairline, caption size; signal variants drop the border for a soft fill.

### Cards / Containers
- **Sections** (`card`): no fill, no radius; 24px vertical padding under a hairline top rule.
- **Danger zone:** the same ruled section with an oxblood top rule and oxblood heading.
- **Notices:** hairline top and bottom, the top rule recoloured copper or oxblood for warn/danger, with the strong line in the same colour.

### Inputs / Fields
- **Style:** vault-2 fill, vault-6 hairline, 12px radius, 40px tall; hover lifts the border to faint parchment.
- **Focus:** border turns polished brass with a 3px brass-soft ring. Caret is brass.
- **Error:** caption text in oxblood below the field.
- **Composer:** a vault-0 well (20px radius) that gains a brass hairline and brass-soft ring on focus-within.

### Navigation
- **Rail:** vault-0 leather column with a hairline right edge. A three-segment control on vault-2 (active segment vault-4). Settings sections are 42px rows ruled by hairlines; the active row becomes a vault-3 fill and loses its rule.
- **Conversation list:** rows of plate, serif name and muted preview, ruled by hairlines; hover vault-2; the selected row is a 12px-radius vault-3 fill with a 1.5px brass ring on its plate. Verified contacts carry a 10px verdigris seal.

### Monogram Plate (signature)
A circle with the two initials of the username's two words in Spectral 500, 0.04em tracking. Others' plates are vault-3 with a vault-6 rim; your own is solid brass with a polished-brass rim and brass-ink letters. Sizes 30, 40, 48 and 88px. The plate carries no generated pattern; identity is verified by safety number, not by appearance.

### Safety-Number Plate (signature)
A 16px-radius panel in the verification side panel, rimmed with the brass hairline, holding the shared number in a three-column grid of Spectral tabular lining numerals, followed by the primary "Numbers match" action.

### Recovery Key and Link Code
Recovery keys sit in a vault-2 grid of mono groups (0.06em, centered, select-all) with a vault-6 hairline; link codes are a single mono line at 1.35rem, 0.12em tracking.

## Do's and Don'ts

### Do:
- **Do** derive every neutral from the vault ramp (`vault-0` to `vault-6`) and the hairline.
- **Do** keep brass to your plate, primary actions, the selected-plate ring and focus.
- **Do** separate sections, notices and danger zones with 1px hairlines and no fill.
- **Do** set names, headings and numbers in Spectral 500, and tabular lining figures for any digits a person compares.
- **Do** show your identity as the brass monogram plate and others as green plates.
- **Do** keep the light variant role-for-role identical to dark.

### Don't:
- **Don't** use verdigris for anything but "verified", or oxblood for anything but danger.
- **Don't** wrap ruled sections in padded, rounded, filled cards.
- **Don't** use monospace for usernames, labels or body text.
- **Don't** add generated patterns or colours to contact plates.
- **Don't** set UI controls in the serif.
- **Don't** introduce grey neutrals or a second accent hue.
