# AGENTS

At the end of a coding session:

- Never create a commit unless the user explicitly asks for a commit.
- Never push the current working branch unless the user explicitly asks for a push.
- Never merge to `main`.
- Only merge into `main` when explicitly asked to do it.
- Only produce a Release build to `C:\espaces` when explicitly asked to do it.
- These rules must be treated as the expected behavior across branches so `AGENTS.md` stays aligned between branch lines unless the user explicitly changes it.

## Session Flow Rules

- When the user says `testmode on`, enable Test Mode for the current session.
- Test Mode stays active until the user says `testmode off`.
- In Test Mode, the session flow becomes: major fix -> build Release `.exe` according to the Release Publish Rules -> stop for user testing feedback.
- Test Mode does not authorize a commit, push, merge, or release publish unless the user explicitly asks for it.
- Outside Test Mode, do not assume commit, push, merge, or release publish steps unless the user explicitly asks for them.

## Release Publish Rules

- The executable naming and publish behavior must follow the current branch family.
- If the working branch is `main`, or a branch derived from `main`, the Release executable name is `LogHunter.exe`.
- If the working branch is `LogHunter-2.0`, or a branch derived from `LogHunter-2.0`, the Release executable name is `LogHunter2.0.exe`.
- Release publishes only happen when explicitly requested by the user.
- The publish flow itself must produce the correct final executable name for that branch line.
- Do NOT solve naming by publishing one executable and then copying or renaming it afterward.
- Do NOT leave two equivalent executables in `C:\espaces`.
- There must be exactly one final deliverable artifact in `C:\espaces` for the requested publish.
- If the target executable for the current branch line is in use and cannot be replaced, publish a single fallback artifact using the same branch line naming with a `-new` suffix:
  - `LogHunter-new.exe` for `main` / `main`-derived branches
  - `LogHunter2.0-new.exe` for `LogHunter-2.0` / `LogHunter-2.0`-derived branches

## Release Notes Workflow

- When a version is bumped or a release is prepared, update the main `README.md` release notes summary for the shipped version.
- Keep a detailed internal patch note file under `LogHunter/docs/patch-notes/` for the shipped version when the release contains material operator-facing changes.
- After shipping a patch or hotfix release, also add or update a carry-forward backnote for the next planned minor release under `LogHunter/docs/patch-notes/`.
- The backnote should capture what shipped in the patch release so it can be folded into the next minor-release notes without the user needing to restate it.
- Maintain these patch, hotfix, and carry-forward notes cumulatively so the next minor release line already has the shipped changes ready to fold in when the user decides to cut that version.
- Unless the user says otherwise, keep these backnotes internal-only and do not mirror them to `LogHunter-Public`.
- These release-note carry-forward rules should stay aligned across branches unless the user explicitly changes them.

## Public Release Flow (LogHunter-Public)

- The public repo remote is named `public` and points to `https://github.com/AfonsecaOutsys/LogHunter-Public.git`.
- Public releases only happen when the user explicitly asks for them.
- Before pushing to `public`, update `README.md` release notes for the new version. Exclude any Web UI references — the public release notes should only cover console-facing features and improvements.
- Push `main` branch and the version tag (e.g. `v1.6.0`) to the `public` remote.
- Create a GitHub release on the `public` remote using `gh release create` with the version tag.
- Attach the published Release executable (`LogHunter.exe` from `C:\espaces`) to the GitHub release when available.
- Do not mirror internal patch notes, backnotes, or web UI documentation to the public repo.

## Version Bump Rules

- When work from a feature/fix branch is merged into `main`, bump the shipped version on `main`.
- For these routine merges, default to a patch-version bump only:
  - `1.5.0.0` -> `1.5.0.1`
  - `1.5.0.1` -> `1.5.0.2`
  - `1.5.0.9` -> `1.5.0.10`
- Do not autonomously bump the minor version line.
- Minor-version changes such as `1.5` -> `1.6` or `1.6` -> `1.7` only happen when the user explicitly decides them.
- If the current version format needs interpretation, preserve the current minor line and increment only the rightmost shipped patch component unless the user says otherwise.

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
