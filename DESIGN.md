---
name: "Sentinel"
description: "A screenprinted technical editorial system for explicit cross-device authorization."
colors:
  paper: "#f4efe3"
  registration-ink: "#182e29"
  process-cyan: "#148da2"
  process-amber: "#e8aa29"
  process-scarlet: "#d84843"
  action-scarlet-dark: "#a42e2a"
  amber-readable: "#9d6800"
  inverse-soft: "#dfe9df"
  rule: "rgba(24, 46, 41, 0.66)"
typography:
  display:
    fontFamily: '"Nimbus Sans Narrow", "Noto Sans", sans-serif'
    fontSize: "clamp(3.5rem, 4.7vw, 5rem)"
    fontWeight: 850
    lineHeight: 0.88
    letterSpacing: "-0.025em"
  section-headline:
    fontFamily: '"Nimbus Sans Narrow", "Noto Sans", sans-serif'
    fontSize: "clamp(3rem, 5vw, 5.3rem)"
    fontWeight: 850
    lineHeight: 0.88
    letterSpacing: "-0.025em"
  body:
    fontFamily: '"Noto Sans", ui-sans-serif, sans-serif'
    fontSize: "0.96rem"
    fontWeight: 400
    lineHeight: 1.65
  title:
    fontFamily: '"Noto Sans", ui-sans-serif, sans-serif'
    fontSize: "1.05rem"
    fontWeight: 700
    lineHeight: 1.2
  label:
    fontFamily: '"Noto Sans", ui-sans-serif, sans-serif'
    fontSize: "0.68rem"
    fontWeight: 800
    lineHeight: 1.2
    letterSpacing: "0.1em"
rounded:
  none: "0"
  registration-plate: "1rem"
  round: "50%"
spacing:
  xs: "0.5rem"
  sm: "1rem"
  md: "1.5rem"
  lg: "2rem"
  xl: "3rem"
  section: "clamp(4rem, 8vw, 8rem) clamp(2rem, 6vw, 6rem)"
components:
  action-outline:
    backgroundColor: "transparent"
    textColor: "{colors.action-scarlet-dark}"
    typography: "{typography.body}"
    rounded: "{rounded.none}"
    padding: "0.95rem 1.2rem"
  action-outline-hover:
    backgroundColor: "{colors.process-scarlet}"
    textColor: "{colors.paper}"
    rounded: "{rounded.none}"
    padding: "0.95rem 1.2rem"
  stage-card:
    backgroundColor: "transparent"
    textColor: "{colors.registration-ink}"
    rounded: "{rounded.none}"
    padding: "1.5rem 1.5rem 2rem"
  session-core:
    backgroundColor: "{colors.registration-ink}"
    textColor: "{colors.paper}"
    typography: "{typography.label}"
    rounded: "{rounded.round}"
    size: "8.8rem"
---

# Design System: Sentinel

## Overview

**Creative North Star: "The Registration Point"**

Sentinel looks like a technical plate pulled through a three-ink screenprinting press. Desktop, persistent state, and mobile are not illustrated as separate product screenshots; they are cyan, amber, and scarlet passes whose transparent overlap produces the session. Warm paper grain, slight optical density shifts, registration marks, and hard editorial rules make the system tactile without compromising technical precision.

The system is assertive but honest. Condensed headlines state the mechanism in a poster-like voice, while compact sans-serif copy carries caveats and implementation status plainly. Its visual drama comes from process, overlap, and scale—not cyber imagery, glossy dashboards, gradients, or claims of production maturity.

**Key Characteristics:**

- Three transparent process inks converge around a dark registration core.
- Warm, visibly textured paper is the default canvas.
- Narrow uppercase display type is paired with quiet, readable technical copy.
- One-pixel rules and registration marks organize content instead of floating cards.
- Scarlet is the action and emphasis ink; amber owns status and focus; cyan identifies the initiating device.
- Responsive layouts preserve the poster composition before simplifying it into a vertical technical narrative.

## Colors

The palette behaves as literal ink on paper: cyan, amber, and scarlet remain individually legible, become richer where they overlap, and sit against near-black green registration ink.

### Primary

- **Process Scarlet:** The decisive ink for actions, active navigation, approval emphasis, and the mobile pass. Use it selectively so a scarlet mark always signals consequence or direction.

### Secondary

- **Process Cyan:** Identifies desktop-originated information and the first protocol state.
- **Process Amber:** Identifies persisted state, status, and keyboard focus. The darker readable amber is reserved for small text on paper.

### Neutral

- **Warm Press Paper:** The base surface and inverse text color. Always carry the real screenprint paper texture on full-page and process-ink fields.
- **Registration Ink:** Primary copy, structural silhouettes, the architecture field, and the session core.
- **Registration Rule:** Structural dividers and crosshairs. Rules remain visibly lighter than body copy.
- **Inverse Soft Ink:** Long-form copy on the dark architecture field, softened to reduce glare.

### Named Rules

**The Three-Pass Rule.** Cyan means desktop, amber means persisted state, and scarlet means mobile or approval; do not casually reassign these inks.

**The Ink, Not Glow Rule.** Color is applied as flat translucent print with multiply overlap and paper grain. Never turn the palette into neon light, gradients, or luminous effects.

## Typography

**Display Font:** Nimbus Sans Narrow (falling back to Noto Sans, then sans-serif)
**Body Font:** Noto Sans (falling back to the platform UI sans-serif)

**Character:** The display face is compressed, forceful, and typographic-poster driven. The body face is neutral and compact, letting protocol facts, limitations, and navigation stay legible beside the expressive headline scale.

### Hierarchy

- **Display** (850, fluid hero scale, 0.88 line-height): Uppercase hero declarations; use deliberate line breaks and allow scarlet to carry the second clause.
- **Section Headline** (850, fluid section scale, 0.88 line-height): Large uppercase section arguments, usually held to roughly 12–15 characters per line.
- **Title** (700, compact): Stage and content labels; sentence case keeps them distinct from poster headlines.
- **Body** (400, compact, 1.65 line-height): Explanations and product truth, generally constrained to 38–55rem or about 55 characters on dark fields.
- **Label** (800, tight size, 0.1em tracking): Navigation metadata, state roles, and registration annotations in uppercase.

### Named Rules

**The Compressed Declaration Rule.** Use narrow uppercase type only for short declarations and section anchors; never compress paragraph copy.

**The Honest Small Print Rule.** Limitations and build status remain readable body text, not visually buried legal copy.

## Layout

Desktop uses an editorial shell with a sticky 17rem side rail and an unbounded main canvas. The opening viewport splits into a dominant registration target and a narrower argument column using `minmax()` tracks; the target keeps a minimum 46rem stage so the overlap reads as a physical composition rather than an icon. Subsequent sections alternate large asymmetric headings, four-column protocol rows, and two-column tonal fields.

Spacing is generous at section scale and compact within technical records. Structural rhythm comes from one-pixel rules, aligned edges, and repeated 1–3rem internal intervals rather than card gutters. At 1000px the rail becomes a horizontal masthead, the target and argument stack, and secondary rail content disappears. At 680px multi-column content becomes single-column and protocol stages become ruled rows. At 480px the target, type, and navigation compress further; the primary action moves directly below the hero declaration while the explanatory copy follows the protocol states.

**The Poster-to-Record Rule.** Preserve the large registration image and declaration first; on narrow screens, reorder supporting facts into a linear technical record instead of shrinking the desktop grid wholesale.

## Elevation & Depth

The system uses no shadows. Depth is created by `mix-blend-mode: multiply`, translucent process passes, the repeated paper texture, dark/light field inversion, and the physical stacking of rings and crosshairs. Architecture rows use strong tonal bands rather than raised containers.

### Named Rules

**The Flat Press Rule.** Surfaces remain physically flat at every state; hover changes ink fill, never elevation.

**The Honest Overprint Rule.** Overlap must reveal mixed color and texture. Do not replace it with opaque shapes or simulated glass blur.

## Shapes

The dominant geometry is registration hardware: circles, concentric rings, crosshairs, square crop marks, and a single rotated rounded square representing persisted state. Most interface containers and actions are square-cornered. The 1rem radius belongs only to the amber registration plate; 50% rounding is reserved for literal circles, status dots, and the session core.

Borders are thin registration rules except for actions and the small brand mark, which use a two-pixel decisive stroke. Never introduce a general-purpose rounded-card language.

## Components

### Buttons

- **Shape:** Square-cornered outlined action with a two-pixel process-scarlet stroke.
- **Primary:** Transparent paper field, dark scarlet text, strong weight, compact vertical padding, and a deliberately wide arrow gap.
- **Hover / Focus:** Hover floods the control with process scarlet and reverses text to paper over 180ms ease-out. Keyboard focus uses a three-pixel amber outline with a five-pixel offset.

### Cards / Containers

- **Corner Style:** Square and ruled by default; protocol stages are cells in a shared grid, not isolated cards.
- **Background:** Paper remains visible through protocol cells. Architecture records use solid cyan, amber, and scarlet tonal fields against registration ink.
- **Shadow Strategy:** None; see the Flat Press Rule.
- **Border:** One-pixel registration rules divide related records.
- **Internal Padding:** Protocol cells use 1.5rem horizontally with 2rem at the foot.

### Navigation

The desktop rail is a sticky editorial index separated by a single registration rule. Links are compact sentence-case sans text with square markers; the active destination switches both marker fill and label to scarlet. At tablet width navigation moves beside the brand and loses its markers; on narrow phones it becomes a horizontally scrollable, non-wrapping row.

### Registration Target

Three equal process fields overlap with multiply blending: cyan and scarlet circles flank a rotated amber rounded square. Concentric paper-colored rings, vertical crosshairs, small labels, and the dark circular session core make the convergence explicit. The three entry animations settle toward alignment over roughly one second with an ease-out curve; reduced-motion users receive effectively static passes.

### Protocol State Line

States form a compact, wrapping sequence with arrows retained inside each state group. CREATED is cyan, SCANNED uses readable amber, APPROVED is scarlet, and EXCHANGED resolves to registration ink. This color sequence is semantic and must stay stable.

### Registration Mark

The brand symbol is constructed from a square stroke, cut-out paper cross, and centered circular target. Keep it monochrome in registration ink and pair it with the widely tracked uppercase wordmark.

## Do's and Don'ts

### Do:

- **Do** use the actual repeating `screenprint-paper.webp` texture on the page and process-ink fields.
- **Do** preserve the cyan → amber → scarlet process story and let multiply overlap create secondary colors naturally.
- **Do** use rules, aligned cells, crosshairs, and registration marks to establish structure.
- **Do** state current and planned capabilities with the same visual clarity as the central promise.
- **Do** disable meaningful travel for reduced-motion users while preserving the final aligned composition.

### Don't:

- **Don't** use generic cybersecurity imagery, glowing locks, code rain, glass panels, or blue-purple gradients.
- **Don't** add drop shadows, floating rounded cards, or pill-shaped actions.
- **Don't** flatten the overprint target into a decorative logo; it explains how the system works.
- **Don't** use scarlet as ambient decoration or reassign the three process inks arbitrarily.
- **Don't** claim production readiness, complete phishing resistance, customers, audits, or metrics through visual copy or badges.
