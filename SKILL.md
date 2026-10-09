---
name: modern-saas-design
description: Design and build websites and web apps in a polished, modern SaaS style — clean light-mode layouts, bold serif headings, floating UI mockups in heroes, structured section patterns, subtle dashed decorative lines, and purposeful micro-animations. Use this skill whenever the user says "modern SaaS", "SaaS design", "startup landing page", "SaaS style", or asks to design a website, landing page, marketing site, or web app that should look professional and product-focused. Also trigger when the user wants a design that feels like Linear, Stripe, Notion, or similar modern SaaS products. Always use this skill before writing any code or producing any design — do NOT attempt modern SaaS design from memory alone.
---

# Modern SaaS Design Skill

Produce polished, designer-quality modern SaaS websites and web apps. Output should feel built by a real designer — not generated. Zero AI slop. Zero emoji. Zero purple-gradient-on-white clichés.

Reference aesthetic: Clean white base, bold editorial serif headings, green accent, asymmetric pricing, floating UI cards with warm data viz colors, subtle diagonal background patterns.

---

## Step 0 — Ask Clarifying Questions First

Before writing any code, send this in one message:

```
Before I start, a few quick questions:

1. **Color palette** — Any brand colors?
   Default: white bg + near-black text + green accent (#5EA832).
   Presets: indigo (B2B tools), sky blue (devtools), emerald (fintech), violet (AI).

2. **Heading font feel** — Headings should feel:
   - Editorial & classic (Playfair Display) ← default
   - Sharp & geometric (Sora, DM Sans, Outfit)
   - Technical & precise (IBM Plex Sans, Space Grotesk)

3. **Dark or light mode?** Default: Light

4. **Sections needed?**
   Default: Hero → Logos → Feature Cards → Feature Tabs → Pricing → Testimonials → CTA → Footer

5. **Product UI assets?** Default: Generated charts/kanban/metric cards
```

If the user says "use defaults" or "just go for it" — apply all defaults immediately.

---

## Step 1 — Design System

Use CSS custom properties for all values. Never hardcode.

```css
:root {
  --bg-page: #FFFFFF; --bg-subtle: #F8F8F8; --bg-muted: #F5F5F4;
  --bg-dark: #111111;
  --bg-pattern: url("data:image/svg+xml,%3Csvg width='20' height='20' viewBox='0 0 20 20' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M0 0l20 20M20 0L0 20' stroke='%23E0E0E0' stroke-width='0.5'/%3E%3C/svg%3E");

  --text-primary: #111111; --text-secondary: #666666; --text-muted: #999999;
  --border: #E8E8E8; --border-dashed: rgba(17,17,17,0.18);

  /* Accent — GREEN default; swap per brand */
  --accent: #5EA832; --accent-hover: #4D8E28;
  --accent-light: #EEF7E6; --accent-fg: #FFFFFF;

  /* Data viz — warm yellow for charts, NOT the brand accent */
  --chart-bar: #E8D87A; --chart-area: rgba(232,216,122,0.25);

  --s1:8px; --s2:16px; --s3:24px; --s4:32px;
  --s5:48px; --s6:64px; --s7:80px; --s8:96px; --s9:128px;

  --font-display: 'Playfair Display', Georgia, serif; /* HEADINGS */
  --font-body: 'Inter', system-ui, sans-serif;         /* BODY/UI  */

  --radius-sm:6px; --radius-md:10px; --radius-lg:14px;
  --radius-xl:20px; --radius-pill:999px;

  --shadow-sm: 0 1px 3px rgba(0,0,0,0.06);
  --shadow-md: 0 4px 16px rgba(0,0,0,0.07), 0 2px 4px rgba(0,0,0,0.04);
  --shadow-lg: 0 8px 32px rgba(0,0,0,0.10);
  --shadow-float: 0 20px 60px rgba(0,0,0,0.12);
  --max-w: 1200px;
}
```

Google Fonts:
```html
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@700;800&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
```

**Typography rules:**
- H1: `font-display`, `clamp(40px,5.5vw,72px)`, weight 800, line-height 1.1, letter-spacing -0.02em
- H2: `font-display`, `clamp(28px,3.5vw,52px)`, weight 700, line-height 1.15, **centered**
- H2 in feature deep-dive sections: **left-aligned**, not centered
- H3/card headings: `font-body`, 18–20px, weight 600
- Body: `font-body`, 16px, weight 400, line-height 1.65, `--text-secondary`
- Caption/label: `font-body`, 13–14px, weight 500, `--text-muted`
- **CRITICAL: Headings = serif. Everything else (nav, body, cards, buttons, labels) = sans-serif. Never mix.**

---

## Step 2 — Navbar

- Sticky; white bg; bottom border `1px solid var(--border)` fades in on scroll
- Layout: `[Logo] → [Nav links] → [Login] → [Dark CTA button]`
- Nav links: Inter 15px, weight 500, `--text-secondary`, hover → `--text-primary` at 200ms
- CTA: `background: var(--text-primary); color: #fff; border-radius: var(--radius-md); padding: 9px 20px`
- Scroll JS: `nav.classList.toggle('scrolled', scrollY > 40)` → adds `box-shadow: 0 1px 20px rgba(0,0,0,0.07)`

---

## Step 3 — Hero Section

Structure (top-to-bottom, centered):
1. Announcement pill badge (accent-light bg, accent text, pulsing dot)
2. Large serif H1 (max ~9 words)
3. Subtext (Inter, `--text-secondary`, max-width 520px)
4. Primary CTA (accent fill) + Secondary (ghost/text link)
5. Three floating UI cards

```css
/* Announcement badge */
.badge { display:inline-flex; align-items:center; gap:8px; background:var(--accent-light);
  color:var(--accent); border-radius:var(--radius-pill); padding:6px 14px; font-size:13px; font-weight:500; }
.badge-dot { width:6px; height:6px; border-radius:50%; background:var(--accent);
  animation:pulse-dot 2s ease-in-out infinite; }
@keyframes pulse-dot { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.4;transform:scale(1.4)} }

/* Dashed vertical column lines (decorative) */
.dashed-line { position:absolute; top:0; bottom:0; width:0;
  border-left:1.5px dashed var(--border-dashed); pointer-events:none; }

/* Soft radial glow behind hero */
.hero-glow { position:absolute; top:-60px; left:50%; transform:translateX(-50%);
  width:800px; height:500px;
  background:radial-gradient(ellipse, var(--accent-light) 0%, transparent 65%);
  opacity:0.45; pointer-events:none; z-index:0; }
```

**Hero UI cards** — white, `border: 1px solid var(--border)`, `border-radius: var(--radius-lg)`, `box-shadow: var(--shadow-md)`, slight rotation on side cards (`rotate(-1.5deg)` / `rotate(1.5deg)`). Content **must look realistic**:
- Bar chart card: warm yellow bars (`--chart-bar`), month labels, metric tags
- Transaction list: company icon + name + dollar delta per row
- Line chart: highlighted tooltip on peak data point
- **Chart colors = `--chart-bar` (#E8D87A). Never use brand accent for charts.**

---

## Step 4 — Logo Strip

`Trusted by X,000+ companies` → horizontal marquee of grayscale logos (opacity 0.45, hover → 0.9).
- `animation: marquee 28s linear infinite` on duplicated track; pause on hover
- `overflow: hidden` wrapper; `1px solid var(--border)` top and bottom

---

## Step 5 — Feature Cards (3-up)

Centered serif H2 + subtext. Three equal cards below:
- Card: white, `border: 1px solid var(--border)`, `border-radius: var(--radius-lg)`, `padding: var(--s3)`, `box-shadow: var(--shadow-sm)`
- Top half: UI mockup; bottom: sans-serif H3 + body text
- Hover: border-color transitions to `--accent`, no lift

---

## Step 6 — Feature Tab Section

Background: `background-image: var(--bg-pattern)` (diagonal crosshatch).

Layout:
- Left-aligned serif H2
- Tab nav bar: 3 tabs with colored rounded-square icon boxes (28×28px, warm tint bg — orange/yellow/green, NOT the brand accent). Active tab: `background: var(--bg-subtle); box-shadow: var(--shadow-sm)`
- Below: 2-column — left panel (colored icon, serif sub-H3, description, green checkmark list, muted caption); right panel (product UI screenshot, `box-shadow: var(--shadow-float)`)
- Tab switch: fade transition `opacity 0 → 1` at 0.25s

---

## Step 7 — Pricing Section

Background: `background-image: var(--bg-pattern)`. Toggle: Monthly / Yearly (green pill toggle).

**ASYMMETRIC layout — critical detail:**
```
Basic Plan        | POPULAR (label above)  | Pro Plan
                  | ┌──────────────────┐   |
$29               | │  Standard Plan   │   | $99
[no card bg]      | │  $49             │   | [no card bg]
✓ features        | │  ✓ features      │   | ✓ features
                  | │                  │   |
"Choose Plan"     | │ [Green button]   │   | "Choose Plan"
(plain text)      | └──────────────────┘   | (plain text)
```

```css
.pricing-grid { display:grid; grid-template-columns:1fr 1fr 1fr; align-items:start; max-width:900px; margin:0 auto; }
.pricing-card--popular { background:var(--bg-subtle); border:1px solid var(--border);
  border-radius:var(--radius-lg); box-shadow:var(--shadow-md); padding:var(--s4); margin-top:-20px; }
.pricing-card--basic, .pricing-card--pro { background:transparent; padding:var(--s4); }
.popular-label { text-align:center; font-size:12px; font-weight:600; letter-spacing:0.08em;
  text-transform:uppercase; color:var(--text-muted); padding-bottom:var(--s3); border-bottom:1px solid var(--border); }
.pricing-price { font-family:var(--font-display); font-size:52px; font-weight:800; line-height:1; }
.btn-pricing-popular { width:100%; background:var(--accent); color:var(--accent-fg); border:none;
  border-radius:var(--radius-md); padding:12px; font-size:15px; font-weight:500; }
.btn-pricing-plain { background:none; border:none; padding:12px; color:var(--text-secondary);
  font-size:15px; width:100%; text-align:center; cursor:pointer; }
.check-item { display:flex; align-items:center; gap:10px; }
.check-icon { color:var(--accent); }
```

---

## Step 8 — Testimonials

Centered serif H2. Grid of 3 × 2 cards:

```css
.testimonials-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:1px; background:var(--border); }
.testimonial-card { background:var(--bg-muted); padding:var(--s4); } /* gray bg, NO border */
.testimonial-logo { margin-bottom:var(--s3); opacity:0.9; }          /* company logo at TOP */
.testimonial-quote { font-size:15px; line-height:1.65; color:var(--text-primary); margin-bottom:var(--s4); }
.testimonial-author { display:flex; align-items:center; gap:12px; }
.testimonial-avatar { width:44px; height:44px; border-radius:50%; object-fit:cover; }
.testimonial-name { font-size:14px; font-weight:600; }
.testimonial-role { font-size:13px; color:var(--text-muted); }
```

---

## Step 9 — Supporting Sections

**Stats Row:** 4-column grid, `border: 1px solid var(--border)`, `border-radius: var(--radius-lg)`. Cells divided by `border-right`. Numbers: `font-display`, 40px, weight 800. Animate from 0 on scroll.

**FAQ Accordion:** Items separated by `border-bottom: 1px solid var(--border)`. Question row: flex space-between. ChevronDown icon rotates 180° on open. Answer: `max-height: 0 → 400px` with ease transition.

**CTA Banner:** Dark bg (`--bg-dark`), centered serif H2, subtext, accent CTA button. Optional: decorative SVG shapes at corners at `opacity: 0.06`.

**Footer:** `bg-subtle`, `border-top`. 4-column grid: `2fr 1fr 1fr 1fr`. Links: 14px, `--text-muted`, hover → `--text-primary`. Bottom row: copyright + social icons.

---

## Step 10 — Micro-Animations

**Scroll reveal** (apply `.reveal` to section headings, cards — stagger with `transition-delay: 0/80/160ms`):
```css
.reveal { opacity:0; transform:translateY(20px); transition:opacity 0.55s ease, transform 0.55s ease; }
.reveal.visible { opacity:1; transform:translateY(0); }
```
```js
const io = new IntersectionObserver(es=>es.forEach(e=>e.isIntersecting&&e.target.classList.add('visible')),{threshold:0.1});
document.querySelectorAll('.reveal').forEach(el=>io.observe(el));
```

**Floating hero cards:**
```css
@keyframes float { 0%,100%{transform:translateY(0) rotate(var(--rot,0deg))} 50%{transform:translateY(-10px) rotate(var(--rot,0deg))} }
.hero-card { animation:float 5s ease-in-out infinite; }
.hero-card:nth-child(2){animation-delay:-1.8s} .hero-card:nth-child(3){animation-delay:-3.4s}
```

**Stat counter:** Animate numbers from 0 to target (ease-out-cubic, ~1400ms) when scrolled into view.

**Pricing toggle:** On switch, fade prices out (`opacity:0, translateY(6px)`) then update text and fade back in at 180ms delay.

**Buttons:** `transform: translateY(-2px)` + `box-shadow` on hover; back on active.

**Navbar:** `box-shadow` fades in when `scrollY > 40`.

---

## Step 11 — Icons & Output

**Icons — Lucide only. Never emoji.**
- HTML: `<script src="https://unpkg.com/lucide@latest/dist/umd/lucide.js"></script>` + `lucide.createIcons()`
- React: `import { Check, ArrowRight, Zap, ... } from 'lucide-react'`
- Common: `check-circle` (feature lists), `arrow-right` (CTAs), `chevron-down` (FAQ), `zap`, `layers`, `bar-chart-2`, `shield-check`, `users`
- Sizes: 16px inline / 20px default / 24px feature icons

**Output format:**
- HTML (default for full pages): CSS in `<style>`, JS in `<script>` at bottom
- React (.jsx): when explicitly requested; use `useState` for toggles/tabs
- Always produce **complete, working, no-TODO code**

---

## Step 12 — Anti-Patterns & Accent Presets

| ✅ DO | ❌ DON'T |
|---|---|
| Playfair Display for H1/H2 (serif) | Inter/Sora for headings |
| Green or industry-specific accent | Purple gradient on white |
| `--chart-bar` (#E8D87A) for data viz | Accent color on chart bars |
| Outer pricing plans: no card/no button | All 3 pricing cards identical |
| Testimonials: `--bg-muted` gray, no border | White bordered testimonials |
| Diagonal crosshatch on pricing/tab sections | No section visual differentiation |
| Dashed vertical lines as decoration | Overused gradients everywhere |
| Realistic UI in hero cards (real numbers) | Lorem ipsum / blurry screenshots |
| Company logo at TOP of testimonial card | Stars/rating at top |
| Lucide icons | Emoji |

**Accent presets by industry:**

| Industry | Accent |
|---|---|
| General SaaS / No-code | `#5EA832` Green |
| B2B Analytics / Enterprise | `#4F46E5` Indigo |
| Fintech / Revenue | `#10B981` Emerald |
| DevTools / APIs | `#0EA5E9` Sky blue |
| AI / Automation | `#8B5CF6` Violet |
| HR / People ops | `#F59E0B` Amber |
| Security / Monitoring | `#EF4444` Red |
| Marketing / CRO | `#EC4899` Pink |

Pair each accent with `--accent-light` = accent at ~10% opacity for badges/backgrounds.
