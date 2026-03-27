# AGENTS

At the end of a coding session:

- Always push the current working branch to GitHub, provided it is not `main`.
- Never merge to `main`.
- Only merge into `main` when explicitly asked to do it.
- Only produce a Release build to `C:\espaces` when explicitly asked to do it.
- If asked to publish, produce the executable as `C:\espaces\LogHunter2.0.exe`.
- If asked to publish and `C:\espaces\LogHunter2.0.exe` is in use and cannot be replaced, publish the executable as `C:\espaces\LogHunter2.0-new.exe` instead.

## UI / UX Design Guardrails (LogHunter 2.0)

LogHunter is an operator-focused tool, not a marketing/product UI. All UI decisions must prioritize speed, clarity, and action over explanation.

### 1. Action-first UI

- Screens must prioritize doing over explaining.
- The primary UI element should be actions (cards, buttons, inputs), not descriptive text.
- Users should understand what to do within about 2 seconds, without reading paragraphs.

Do:
- Show workflows/actions immediately.

Avoid:
- Hero sections.
- Marketing-style introductions.
- Long explanatory text.

### 2. No roadmap or implementation-state language

The UI must not reflect development status.

Do NOT use:
- Available now.
- Coming soon / coming next.
- Preview.
- Planned.
- Migration status.

Instead:
- Present all workflows as part of the final tool.
- Handle incomplete features through behavior (for example, placeholder pages), not labels.

### 3. No Option 1 / Option 2 naming

Workflows must be named by what they do, not by position.

Do:
- Download ALB logs from S3.
- Top IPs for endpoint.
- IP summary.

Avoid:
- Option 1.
- Option 2.
- Generic or numbered labels.

### 4. Cards = primary interaction model

Workflow selection must be based on cards.

Rules:
- Each card represents a single workflow/action.
- The entire card must be clickable.
- Cards must be visually consistent.

### 5. Consistent interaction behavior

Interactive elements must behave consistently.

Enabled cards:
- Show hover feedback (border highlight, slight elevation, pointer cursor).
- Are fully clickable.

Do NOT:
- Hardcode visual importance for a single card.
- Treat one card as permanently special.

### 6. Do not encode disabled state visually

Avoid:
- Greyed-out cards.
- Reduced opacity to indicate not implemented.
- Disabled-looking UI elements.

Instead:
- Allow interaction.
- Handle incomplete features after click (for example, simple placeholder page).

### 7. Minimal copy, direct language

All text must be:
- Short.
- Direct.
- Action-oriented.

Avoid:
- Long descriptions.
- Repetitive explanations.
- Internal/dev terminology.

### 8. Layout hierarchy

- The first visible content should be actionable (cards, inputs, etc.).
- Minimize vertical space before primary actions.
- Avoid stacking multiple headers or sections above the main UI.

### 9. Internal mindset

Design decisions must assume:
- The user is technical.
- The user is time-constrained.
- The user prefers speed over guidance.

### Summary principle

If the user has to read before acting, the UI is too heavy.

Prefer:
click -> action -> result

Over:
read -> understand -> decide -> click
