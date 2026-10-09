# Design Guidelines

---

## Visual Style
- **Aesthetic:** Clean, minimal modern SaaS — light mode, generous white space, editorial confidence
- **Mood:** Professional, trustworthy, quietly ambitious — feels like a real product, not a template
- **Inspiration:** Linear, Notion, Framer — structured layout with expressive typography

---

## Color Palette
- **Primary / Accent:** `#5EA832` — CTAs, checkmarks, toggles, badge dots, popular plan button
- **Accent Light:** `#EEF7E6` — badge backgrounds, accent tints
- **Accent Hover:** `#4D8E28` — button hover state
- **Background:** `#FFFFFF` — page base
- **Surface / Subtle:** `#F8F8F8` — section fills, active tab backgrounds
- **Card (Muted):** `#F5F5F4` — testimonial card backgrounds (NOT white)
- **Dark / Inverted:** `#111111` — CTA banner background, navbar CTA button
- **Text Primary:** `#111111` — headings, bold UI text
- **Text Secondary:** `#666666` — body copy, descriptions
- **Text Muted:** `#999999` — captions, labels, pricing subtexts
- **Border:** `#E8E8E8` — card edges, dividers, section lines
- **Border Dashed:** `rgba(17,17,17,0.18)` — decorative column lines
- **Data Viz:** `#E8D87A` — chart bars and lines (warm yellow — independent of brand accent)

---

## Typography
- **Heading Font:** Playfair Display — bold serif, weight 700–800, used exclusively for H1/H2
- **Body Font:** Inter — clean sans-serif, weight 400–600, used for everything else
- **H1 / Hero:** Playfair Display, `clamp(40px, 5.5vw, 72px)`, weight 800, line-height 1.1, letter-spacing -0.02em
- **H2 / Section:** Playfair Display, `clamp(28px, 3.5vw, 52px)`, weight 700, line-height 1.15 — centered for social proof sections, left-aligned for feature deep-dives
- **H3 / Cards:** Inter, 18–20px, weight 600, line-height 1.3
- **Body:** Inter, 16px, weight 400, line-height 1.65, `#666666`
- **Labels / Captions:** Inter, 13–14px, weight 500, `#999999` — sometimes uppercase with letter-spacing
- **Pricing Numbers:** Playfair Display, 52px, weight 800 — the price dollar amount uses the display font

---

## Spacing & Layout
- **Overall feel:** Very airy — sections breathe, content never crowds
- **Section padding:** `80–128px` top/bottom
- **Card padding:** `24–32px` internal
- **Grid:** 12-column, max-width `1200px`, centered
- **8px spacing scale:** All spacing multiples of 8 (8, 16, 24, 32, 48, 64, 80, 96, 128px)
- **Mobile:** Stacked single-column; feature cards collapse to 1-up

---

## Borders & Radius
- **Border radius:** `6px` small elements, `10px` buttons/inputs, `14px` cards, `20px` large sections, `999px` pills/badges
- **Card borders:** `1px solid #E8E8E8` — present on feature cards and popular pricing card; absent on testimonial cards
- **Testimonial cards:** No border — background color (`#F5F5F4`) provides separation instead
- **Dashed decorative lines:** `1.5px dashed rgba(17,17,17,0.18)` — vertical lines in section margins

---

## Shadows & Elevation
- **Default cards:** `0 1px 3px rgba(0,0,0,0.06)` — barely-there lift
- **Feature / hero cards:** `0 4px 16px rgba(0,0,0,0.07), 0 2px 4px rgba(0,0,0,0.04)` — soft, low-spread
- **Popular pricing card:** `0 8px 32px rgba(0,0,0,0.10)` — slightly more prominent to signal elevation
- **Hero UI floaters:** `0 20px 60px rgba(0,0,0,0.12)` — largest shadow for floating visual effect
- **Style:** All shadows are soft and diffused — no hard drop shadows anywhere

---

## Buttons
- **Primary (hero/CTA):** `background: #5EA832`, white text, `border-radius: 10px`, `padding: 12px 28px`, Inter weight 500. Hover: `translateY(-2px)` + green box-shadow
- **Navbar CTA:** `background: #111111`, white text — dark, not green
- **Popular pricing CTA:** Green fill, full-width, `border-radius: 10px`
- **Non-popular pricing CTA:** Plain text only — no background, no border, no button treatment
- **Ghost / secondary:** Outline border or plain text link

---

## Background Patterns
- **Diagonal crosshatch:** Very subtle SVG pattern (`stroke: #E0E0E0, stroke-width: 0.5`) used on pricing section and feature tab section backgrounds — not on every section
- **Hero glow:** Faint radial gradient of accent-light color behind the hero center (`opacity: 0.45`) — gives subtle depth without being a "glow blob"

---

## Icons
- **Library:** Lucide Icons — stroke style, weight 1.5–2px
- **Sizes:** 16px inline, 20px default, 24px feature section icons
- **Tab icons:** Small colored rounded-square boxes (28×28px) with warm tint backgrounds (orange, yellow, light green tones) — NOT brand green
- **Checkmark style:** Filled circle with checkmark (`check-circle`) in `#5EA832` — used in feature lists and pricing
- **No emoji used anywhere**

---

## Key Components

**Navbar:** Sticky, white, logo left + nav links + dark CTA right. Bottom border appears on scroll via JS class toggle.

**Announcement Badge:** Pill shape, accent-light background, accent text, small pulsing dot on left side.

**Hero UI Cards:** Three floating cards (slightly rotated side cards) with realistic data — bar charts with warm yellow bars, transaction lists with dollar amounts, line charts with tooltips. Cards float on a slow sine animation (5s, staggered).

**Logo Strip:** Horizontal auto-scrolling marquee of grayscale logos at 45% opacity, full-width, bound by thin horizontal rules top and bottom.

**Feature Tab Section:** Horizontal tab nav with colored icon boxes → 2-column layout below (left: text/checklist, right: product UI screenshot). Background uses diagonal crosshatch.

**Pricing — Asymmetric Layout:** Three plans, no uniform card treatment. Outer plans (Basic, Pro) have transparent backgrounds and plain text CTAs. Center plan (Popular) gets a card with border + shadow + green filled button + "POPULAR" label above the card boundary. Pricing numbers use the display serif font.

**Testimonial Cards:** Light gray (`#F5F5F4`) background, no border, arranged in a 3×2 grid with 1px gap acting as the visual divider. Company logo sits at the top of each card in black. No quotation mark decoration.

**FAQ Accordion:** Clean list — question text + ChevronDown icon (rotates 180° on open). Answer slides via `max-height` transition. Separated by bottom borders only.

---

## Micro-Animations
- **Scroll reveal:** Section headings and cards fade up from `translateY(20px)` on viewport entry (staggered with 80ms delay between siblings)
- **Hero card float:** Continuous gentle sine movement (`translateY: 0 → -10px`), side cards offset by ~1.8s/3.4s
- **Stat counter:** Numbers animate from 0 to target on scroll with ease-out-cubic easing (~1400ms)
- **Pricing toggle:** Prices fade out + slide down slightly, update, then fade back in (180ms delay)
- **Badge dot:** Pulsing scale + opacity cycle (2s loop)
- **Logo marquee:** Pauses on hover
- **No:** Spinning, bouncing, or attention-seeking animations anywhere

---

## Overall Replication Notes
- **Serif headings are the #1 design identity marker** — if you use sans-serif headings it immediately reads as a generic template
- Warm yellow chart bars (`#E8D87A`) are independent of the brand color — never use the accent green in data visualizations
- Pricing asymmetry is intentional and important — don't default to 3 identical cards
- Testimonial cards derive separation from background color, not borders
- The crosshatch pattern appears on ~2 sections maximum — don't overuse it
- Keep hero UI card content realistic: actual company names, dollar figures, task names, dates — lorem ipsum destroys credibility
- Dashed column lines in section margins are a recurring structural motif
- Color palette is extremely tight: white + one accent + warm yellow for charts — resist adding new colors
