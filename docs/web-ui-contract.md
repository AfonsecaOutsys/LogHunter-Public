# LogHunter Web UI Contract

## 1. Purpose

This document is the single source of truth for all Web UI work in LogHunter.

The existing ALB options 1 (Download logs from S3), 2 (Top IPs + Top Full Paths), and 3 (IP Summary) are the **design authority**. Every rule in this contract was extracted directly from that working implementation.

As more options are ported from console to the web (IIS, Platform, AbuseIPDB, and remaining ALB options), they must follow this contract exactly. Consistency across the product is more important than any individual improvement.

**Do not redesign. Do not innovate on layout. Follow the patterns that already work.**

---

## 2. Core Principles

1. **Operational/support-tool feel** - This is a tool for incident investigation and log analysis, not a consumer product. Every pixel must earn its space.
2. **Strong visual hierarchy** - The user must instantly know what to look at, what to act on, and what is informational.
3. **Compact but readable forms** - Forms must be tight and operational. No oversized inputs, no excessive whitespace, no decorative spacing.
4. **High dark-mode readability** - Dark mode is the default. All color choices, contrast ratios, and surface treatments must be optimised for dark-mode-first viewing.
5. **Result-first practicality** - Results and status information are more important than the form once a job is running. The UI must reflect this.
6. **Clear distinction between action and passive data** - Buttons must look like buttons. Cards that are not clickable must not look clickable. Status pills must not look like buttons.
7. **Consistency over novelty** - If a pattern exists, reuse it. If it does not, generalise it and add it as shared.

---

## 3. Page Structure

Every option page follows this canonical order. Sections may be hidden/shown based on state, but the order must not change.

```
1. Hero section           - page title + one-line description
2. Two-column layout      - left: form panel | right: status panel
3. Results section        - full-width, below the two-column layout, hidden until complete
```

### 3.1 Hero Section

- Uses `.hero` > `.hero-grid` > `div` containing `h1` + `p`
- Title is the option name (e.g. "Download logs from S3", "Top IPs + top full paths", "IP Summary")
- Description is a single sentence explaining what the option does
- No action buttons in the hero. No badges. No stats.

### 3.2 Two-Column Layout

- Uses `.module-two-column` (CSS grid: `1.4fr` left, `0.6fr` right, gap `22px`)
- Collapses to single column at 1080px
- **Left column** (`.panel.form-panel`): form inputs and primary action button
- **Right column** (`.panel.panel-tight`): job status, progress, expandable details

### 3.3 Results Section

- Uses `.stack` container with `hidden` attribute, revealed on job completion
- Contains one or more `.panel` blocks with `.section-heading` (eyebrow + h2)
- Full width, not constrained to the two-column layout

---

## 4. Visual Hierarchy Rules

### What must stand out most
1. **Primary action button** - gradient background (`--accent` to `--accent-strong`), dark text, full pill shape
2. **Status pills** - the current state/phase of a running job
3. **Results headings** - eyebrow + h2 in section headings
4. **Error messages** - red-tinted inline error blocks

### How input areas differ from result areas
- **Input areas**: `.panel.form-panel` with `align-content: start`, standard 20px padding, 18px gap
- **Result areas**: `.panel` blocks in the results `.stack`, same surface treatment but with `.section-heading` headers using the `.eyebrow` pattern

### How action buttons differ from summary cards
- **Action buttons**: `.button-link.primary.button-like` - gradient fill, dark text, pill shape, cursor pointer, hover lift (`translateY(-1px)`)
- **Summary cards**: `.result-card` - passive surface, no cursor pointer, no hover transform, border only

### How clickable surfaces differ from passive information
- **Clickable**: cursor pointer, hover transform (`translateY(-1px)` or `-2px`), border-color transition to `--line-cool-strong`, shadow escalation to `--shadow-interactive`
- **Passive**: no cursor change, no transform, no hover effects, static border and shadow

### Text hierarchy
| Element | Class/Style | Purpose |
|---------|-------------|---------|
| Page title | `.hero h1` | clamp(2rem, 3vw, 3.4rem), weight 800 |
| Section title | `.panel h2` | 1.05rem, weight bold |
| Eyebrow | `.eyebrow` | 0.78rem, uppercase, letter-spacing 0.16em, `--accent` colour |
| Label | `.field label` / `.field-label` | 0.92rem, `--muted` colour, weight 600 |
| Body/description | `.page-copy` | `--muted` colour, max-width 70ch |
| Helper text | `.footer-note` | 0.92rem, `--muted` colour |
| Info label | `.info-label` | 0.78rem, uppercase, letter-spacing 0.12em |

---

## 5. Layout and Spacing Rules

### Card usage
- `.panel` is the primary container: 22px border-radius, 20px padding, 18px gap between children
- `.panel-tight` for the status column: 16px padding, 10px gap
- `.result-card` for individual result blocks: 22px padding, 22px border-radius, 12px gap
- All cards use the same surface treatment: `linear-gradient` overlay + `--bg-surface-passive`, border `--line-cool`, shadow `--shadow-soft`, `backdrop-filter: blur(16px)`

### Section separation
- `.stack` provides 26px gap between major sections, 22px top margin
- `.field-group` provides 18px top margin between form groups
- `.button-row` provides 10px top margin, 12px gap between buttons
- `.expandable-stack` provides 18px gap, 22px top margin

### Vertical rhythm
- Panel h2 to content: 12px (via margin-bottom on h2)
- Status block to message: 10px gap (panel-tight)
- Progress card internal: 14px gap
- Form grid gap: 18px
- Result summary gap: 18px

### Grouping of related controls
- Related form fields go inside a `.form-grid` (auto-fit grid, minmax 220px)
- Toggle buttons (config mode, log source, output mode) use `.button-row.source-action-row` with `.source-btn` children
- Checkboxes use `.choice-pill.choice-pill--flat`

### Padding expectations
- Page content: 26px (18px below 720px)
- Panels: 20px (16px for panel-tight)
- Cards: 22px
- Inputs: 12px vertical, 14px horizontal
- Buttons: 0 vertical, 18px horizontal (14px for compact)
- Status pills: 12px vertical, 14px horizontal

### Dense tables/results
- `.mini-table` for compact data: 0.88rem font, 6px/10px cell padding, bottom borders only
- `.result-lines` for ranked lists: flex, 12px gap, muted colour
- Tables must feel tight and scannable for incident investigation

### What must be avoided
- Excessive whitespace between form fields
- Oversized empty areas when no results exist
- Margins that break the vertical rhythm established above
- Inconsistent padding between similar containers

---

## 6. Controls and Forms

### Label placement
- Labels sit **above** inputs, inside a `.field` container (grid, 8px gap)
- Group labels (e.g. "Log source", "Configuration") use `.field-label` class above a `.button-row`

### Helper text
- Use `.footer-note` below the relevant control or group
- Keep helper text concise (one line preferred)
- Max-width for helper text: ~58ch (`.source-helper`)

### Validation message placement
- Inline error: `.inline-error` block at the top of the form panel, hidden by default
- Field-level: `.is-invalid` class on `.field` wrapper, `aria-invalid='true'` on the input
- Invalid label colour: `#ffb3b3`
- Invalid input border: `rgba(255, 120, 120, 0.72)` with tinted background

### Button sizing
| Type | Class | Min-height | Padding | Border-radius |
|------|-------|------------|---------|---------------|
| Primary | `.button-link.primary.button-like` | 44px | 0 18px | 999px (pill) |
| Secondary | `.button-link.button-like` | 44px | 0 18px | 999px (pill) |
| Compact | `.button-link.compact` | 32px | 0 14px | 6px |
| Source toggle | `.source-btn` | 30px | 0 12px | 6px |

### Radio/selector treatment
- Mode toggles (config mode, IP input mode, log source, output mode) use `.source-btn` buttons in a `.button-row.source-action-row`
- Active state: `.active` class adds accent border and tinted background
- These are NOT native radio inputs. They are buttons with JS-driven mutual exclusion.

### Grouping related inputs
- Wrap related fields in `.form-grid` (auto-fit columns, 220px minimum)
- Time pickers: date + hour + minute in a nested `.panel` > `.form-grid`
- Keep related controls visually grouped, do not spread across sections

### File/folder selection
- Button row with: Default folder | Select folder | Select files | Clear
- Selection summary displayed in `.source-chip` below the button row
- Hidden file inputs for browser uploads: `<input type="file" hidden>`
- Native dialogs via POST to server endpoints for local filesystem access

### What is not acceptable
- Oversized input fields that waste vertical space
- Giant toggle buttons or radio buttons
- Full-width buttons when compact is appropriate
- Controls that span the full panel width without reason

---

## 7. Run Lifecycle States

All option pages must implement the same state machine and visual treatment.

### States

| State | Status pill | Stage badge | Progress bar | Message | Primary button |
|-------|------------|-------------|--------------|---------|---------------|
| **Idle** | "idle" | "idle" | 0%, static | "Idle." or "Waiting for a scan to start." | Enabled |
| **Running** | "running" | Phase name (e.g. "scanning", "downloading", "building-excel") | Animated width% | Active progress description | Disabled |
| **Completed** | "completed" | "completed" | 100% | Completion summary | Re-enabled |
| **Failed** | "failed" | "failed" | Frozen at last % | Error message | Re-enabled |

### Visual communication

- **Status pills** (`.status-pill`): always visible in the right panel, show State + Phase + a context-specific count (Matches, IPs, etc.)
- **Progress card** (`.result-card.progress-card-compact`): contains progress label, stage badge (`.kicker`), summary text, progress bar, and footer meta (ETA, file counts)
- **Progress bar** (`.progress-track` > `.progress-fill`): 12px height, green gradient (`#22c55e` to `#86efac`), 180ms width transition
- **Error display**: `.inline-error` block shown at the top of the form panel with the error message
- **Export buttons**: disabled until job completes, then enabled with correct labels ("Open Excel", "Open report", "Open logs folder")

### Polling

- Poll interval: 1500-2000ms via `setInterval`
- Stop polling when `state !== 'running'`
- Restore running job state on page load via `/meta` endpoint

### Consistency requirement

Every new option page must implement the same status pill layout, progress card structure, and state transitions. Do not invent alternative progress indicators or status displays.

---

## 8. Results Presentation

### When to use each pattern

| Pattern | Use case | Example |
|---------|----------|---------|
| **Status pills** (`.status-pill`) | Key scalar values at a glance | Total hits, file count, first/last hit timestamps |
| **Mini tables** (`.mini-table`) | Compact key-value or ranked data | ELB response totals, top endpoints |
| **Result lines** (`.result-lines`) | Simple ranked lists | "#1 10.0.0.1 **1000** hits" |
| **Result cards** (`.result-card`) | Grouped result blocks | Per-IP breakdown card with multiple sub-tables |
| **Expandable panels** (`<details class="expandable-panel">`) | Optional detail that can be collapsed | Per-IP row counts, all-day progress, live output |
| **IP summary grid** (`.ip-summary-grid`) | Multi-card grid within a result | ELB totals + FE totals + mismatches + top endpoints |
| **Terminal panel** (`.terminal-panel`) | Raw log/command output | Live output stream |

### Result density
- Results must support incident/support investigation
- Prefer compact tables over large cards
- Do not add decorative spacing between result items
- Use `.mini-table` (0.88rem font, 6px padding) for tabular data, not full-sized tables
- Result cards should use 22px padding maximum

### Artifact/download links
- Export buttons use `.button-link.compact` (32px height, 6px radius)
- Place in `.export-row` (flex, 10px gap, vertically centred)
- Include export path as `.footer-note` next to the button
- Hide buttons until artifacts are available

### Summary cards (per-IP pattern)
- Use `<details class="expandable-panel" open>` for per-item expandable summaries
- Summary line: "IP - N hits"
- Body: `.status-block` with key stats as pills, then `.ip-summary-grid` with categorised `.result-card` blocks containing `.mini-table` tables

---

## 9. Dark Mode and Contrast Rules

### Current visual direction

Dark mode is the default and primary design target. All CSS uses custom properties from `:root`.

| Token | Dark value | Light value | Purpose |
|-------|-----------|-------------|---------|
| `--bg-base` | `#0a0f1d` | `#f4efe6` | Page background |
| `--bg-elevated` | `rgba(19, 27, 44, 0.84)` | `rgba(255, 252, 247, 0.82)` | Elevated surfaces |
| `--bg-surface-passive` | `rgba(20, 29, 46, 0.9)` | `rgba(255, 252, 247, 0.9)` | Non-interactive cards/panels |
| `--bg-surface-interactive` | `rgba(28, 40, 64, 0.98)` | `rgba(255, 254, 251, 0.98)` | Clickable surfaces |
| `--bg-input` | `rgba(14, 22, 38, 0.98)` | `rgba(255, 255, 255, 0.92)` | Form inputs |
| `--text` | `#e7edf7` | `#1e2430` | Primary text |
| `--muted` | `#acb9cc` | `#5e6572` | Secondary/label text |
| `--accent` | `#68d5ff` | `#1d6f5f` | Accent/brand colour |
| `--accent-strong` | `#8cf0d3` | `#114b43` | Strong accent |
| `--warm` | `#ffb86c` | `#d98943` | Warning/warm accent |
| `--line` | `rgba(148, 163, 184, 0.24)` | `rgba(30, 36, 48, 0.12)` | Default borders |
| `--line-cool` | `rgba(129, 172, 231, 0.38)` | `rgba(30, 36, 48, 0.15)` | Panel/card borders |
| `--line-cool-strong` | `rgba(125, 203, 255, 0.56)` | `rgba(29, 111, 95, 0.28)` | Hover/focus borders |

### Borders
- All panels, cards, and inputs use `--line-cool` as the default border
- Interactive hover escalates to `--line-cool-strong`
- Invalid fields use `rgba(255, 120, 120, 0.72)`

### Surfaces
- Passive surfaces: `--bg-surface-passive` with subtle `linear-gradient` overlay
- Interactive surfaces: `--bg-surface-interactive` with slightly brighter gradient
- All surfaces use `backdrop-filter: blur(16px)` for depth

### Readability under imperfect conditions
- Primary text `--text` against `--bg-surface-passive` provides strong contrast in both themes
- Labels use `--muted` which is intentionally lower contrast for de-emphasis
- Accent colours are high-chroma to remain visible on both dark and light surfaces

### Clickable vs non-clickable contrast
- Clickable elements get `--bg-surface-interactive` (brighter) and hover transforms
- Non-clickable elements get `--bg-surface-passive` (darker/neutral)
- Disabled elements get `opacity: 0.4` and `pointer-events: none`

### What must never happen in dark mode
- Pure white (`#ffffff`) text or backgrounds
- Borders that disappear against the background
- Accent colours used for large background areas (only for text, borders, small indicators)
- Low-contrast muted text on dark surfaces without sufficient opacity
- Hard-edged colour blocks without gradient softening

---

## 10. Reuse and Shared Components

### Mandatory reuse

The following shared assets must be used by all option pages:

| Asset | Path | Purpose |
|-------|------|---------|
| `site.css` | `LogHunter/Web/Assets/site.css` | All CSS custom properties, component classes, responsive rules |
| `site.js` | `LogHunter/Web/Assets/site.js` | Theme management, runtime health polling, shell initialisation |
| `WebShellPageBuilder` | `LogHunter/Web/Hosting/WebShellPageBuilder.cs` | Page shell template (topbar, navigation, footer) |
| `WebPageDefinition` | `LogHunter/Web/Hosting/` | Page metadata (path, parent, eyebrow, title, subtitle, description) |

### Per-option JavaScript

- Each module gets its own JS file (e.g. `alb.js`) loaded as an extra script
- JS uses IIFE pattern: `(function () { ... })()`
- State kept in closure variables
- DOM access via `byId(id)` helper
- All user content HTML-escaped via `escapeHtml()`

### Shared CSS classes that must be reused

These classes are defined in `site.css` and must not be duplicated or overridden per-feature:

`.hero`, `.panel`, `.panel-tight`, `.form-panel`, `.stack`, `.module-two-column`, `.field`, `.field-group`, `.field-label`, `.form-grid`, `.button-row`, `.button-link`, `.button-link.primary`, `.button-link.compact`, `.source-btn`, `.source-chip`, `.source-group`, `.choice-pill`, `.status-pill`, `.status-block`, `.progress-track`, `.progress-fill`, `.progress-card-compact`, `.result-card`, `.result-lines`, `.result-summary`, `.result-summary-body`, `.section-heading`, `.eyebrow`, `.expandable-panel`, `.expandable-body`, `.expandable-stack`, `.terminal-panel`, `.inline-error`, `.export-row`, `.mini-table`, `.footer-note`, `.page-copy`, `.info-label`, `.info-value`, `.kicker`

### Adding new patterns

If a new feature requires a pattern that does not exist:
1. Check if an existing class can be composed or extended
2. If not, add the new class to `site.css` as a general-purpose component
3. Name it descriptively (e.g. `.upload-progress-card`, not `.option7-card`)
4. Never add per-feature CSS that duplicates existing patterns

---

## 11. Forbidden Patterns

The following are strictly prohibited in any new web UI work:

| Forbidden pattern | Why |
|-------------------|-----|
| Oversized controls (inputs taller than 44px, buttons wider than necessary) | Wastes space, breaks compact operational feel |
| Giant radio buttons or toggle switches | Inconsistent with `.source-btn` toggle pattern |
| Inconsistent spacing between sections | Breaks vertical rhythm established by `.stack`, `.field-group`, `.button-row` |
| One-off page layouts that skip the hero + two-column + results structure | Breaks user expectations and navigation patterns |
| Decorative UI elements that reduce clarity (gradients on data, animations on results, icons for decoration) | This is a support tool, not a marketing page |
| Passive cards that look clickable (hover effects on non-interactive surfaces) | Confuses action hierarchy |
| Buttons that visually blend into non-actions (unstyled buttons, text-only actions without borders) | Users must instantly identify what they can click |
| Ad hoc result layouts that do not use `.result-card`, `.mini-table`, `.result-lines`, or `.expandable-panel` | Inconsistent result presentation across features |
| Inline styles for layout or colour (use CSS classes and custom properties) | Unmaintainable, breaks theme switching |
| Feature-specific CSS files (every feature gets one-off styling) | Leads to divergence; all shared styles belong in `site.css` |
| Non-standard fonts or font sizes not in the hierarchy table (Section 4) | Breaks typographic consistency |
| Using native `alert()`, `confirm()`, or `prompt()` dialogs | Use inline error/status patterns instead |
| Polling intervals faster than 1500ms or slower than 4000ms for job status | Matches established ALB patterns |
| Skipping HTML escaping for any user-controlled or server-provided content | XSS vulnerability |

---

## 12. API Contract Patterns

All web option APIs must follow the conventions established by ALB options 1-3.

### Endpoint naming
- `GET /api/{module}/{option}/meta` - Load initial state (defaults, saved configs, current running job)
- `POST /api/{module}/{option}/run` or `/start` - Start the job
- `GET /api/{module}/{option}/job` - Poll job status
- `POST /api/{module}/{option}/browse-folder` - Native folder picker
- `POST /api/{module}/{option}/browse-files` - Native file picker
- `POST /api/{module}/{option}/open-export` - Open result file in OS

### Job snapshot shape
Every job snapshot must include at minimum:
```
jobId, state, phase, message, error, currentStep, totalSteps
```

Additional fields are option-specific but must follow the existing naming conventions (camelCase, UTC timestamps as ISO 8601).

### Response format
- Success: HTTP 200 with JSON body
- Errors: HTTP 4xx/5xx with `{ "error": "message" }`

---

## 13. Implementation Checklist

Before marking any web UI feature as complete, verify:

- [ ] Page follows hero + two-column + results structure
- [ ] Left panel is `.panel.form-panel`, right panel is `.panel.panel-tight`
- [ ] All form controls use `.field`, `.field-group`, `.form-grid` classes
- [ ] Toggle buttons use `.source-btn` in `.button-row.source-action-row`
- [ ] Primary action uses `.button-link.primary.button-like`
- [ ] Status pills show State + Phase + context count
- [ ] Progress card uses `.result-card.progress-card-compact` with bar and meta
- [ ] All lifecycle states (idle, running, completed, failed) are handled
- [ ] Error messages use `.inline-error` block
- [ ] Results use `.section-heading` with `.eyebrow` pattern
- [ ] Result data uses `.mini-table`, `.result-lines`, `.result-card`, or `.expandable-panel`
- [ ] Export buttons use `.button-link.compact` in `.export-row`
- [ ] All user content is HTML-escaped
- [ ] Dark mode renders correctly (check all surfaces, borders, text)
- [ ] Light mode renders correctly
- [ ] Responsive layout works at 1080px and 720px breakpoints
- [ ] No inline styles used for layout or colour
- [ ] No new CSS classes that duplicate existing `site.css` patterns
- [ ] JS follows IIFE pattern with closure state
- [ ] Polling uses 1500-2000ms interval and stops on completion
- [ ] API endpoints follow `/api/{module}/{option}/{action}` naming

---

## Reference Files

These files define the current implementation and were used to create this contract:

| File | Role |
|------|------|
| `LogHunter/Web/Assets/site.css` | All CSS: custom properties, components, responsive rules (1452 lines) |
| `LogHunter/Web/Assets/site.js` | Shell JS: theme, runtime polling (116 lines) |
| `LogHunter/Web/Assets/alb.js` | ALB option JS: state management, polling, rendering (1672 lines) |
| `LogHunter/Web/Pages/AlbPageBuilder.cs` | ALB HTML generation: hero, forms, status, results (609 lines) |
| `LogHunter/Web/Api/AlbApi.cs` | ALB API endpoints: meta, run, job, browse, open |
| `LogHunter/Web/Hosting/WebShellPageBuilder.cs` | Shell template: topbar, nav, footer |
| `LogHunter/Web/Hosting/WebAppContext.cs` | Shared web context |
| `LogHunter/Web/Hosting/WebAppHost.cs` | HTTP listener and routing |
