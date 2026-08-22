# Security Audit Runbook — for Asi's projects

**For**: Claude Code sessions running on Asi's other machines (MacBook M4 Max etc.).
**Purpose**: A self-contained runbook to audit any of Asi's web/Next.js client projects (Bashier, gan-tair, hanna-engteacher, faran, eishoron, shwartz, YL-SPORT, code7, etc.) for the most common shippable security holes.
**Created**: 2026-05-23, distilled from two IG reels Asi sent + the IDOR ("listed from users") angle he asked me to cover explicitly.

---

## How to use this on another machine

1. Open Claude Code in the project directory you want to audit.
2. Paste this entire file into the chat, then say: *"Run this runbook on this project and give me a findings report."*
3. The Claude session should execute each `RUN` block and report **PASS / FAIL** for each step, with specific file:line references for any FAIL.
4. After the report, ask Claude to fix the FAIL items one-by-one. Commit between fixes.

---

## Audit checklist (5 steps, ~30–45 min per project)

### Step 1 — Dependency vulnerabilities (`npm audit`)

**Goal**: Catch known CVEs in installed packages.

**RUN**:
```bash
# In the project root:
npm audit --omit=dev          # production deps only
npm audit                      # everything
npm outdated                   # what's old
```

**Interpret**:
- **Critical / High** → must fix before shipping. Run `npm audit fix` first; if that fails, manually upgrade the package.
- **Moderate** → fix if exploitable in your usage path (look at the CWE description).
- **Low / Informational** → can ignore if the vulnerable code path is not reachable.

**Common gotchas**:
- `npm audit fix --force` can break the app — run tests after. Prefer manual upgrade for major-version bumps.
- If lockfile is `pnpm-lock.yaml` or `yarn.lock`, use `pnpm audit` / `yarn audit` instead.
- Next.js projects: pay extra attention to `next` itself, `@auth/*`, anything that touches server actions.

---

### Step 2 — Auth boundary tests (IDOR — the "listed from users" angle)

**Goal**: Verify that User A cannot read or modify User B's data by tweaking IDs.

This is the **single highest-value test** because IDOR (Insecure Direct Object Reference) is the most common and most damaging bug in CRUD apps. "Having a login page" is not the same as "having authorization."

**RUN (manual test, ~10 min per app)**:
1. Create two test users: `alice@test.com` and `bob@test.com`.
2. Log in as Alice. Create a resource (a record, an order, a profile, whatever the app owns). Note its ID — e.g., `/api/orders/42`.
3. Open Network tab in browser dev tools. Find the API call to fetch order 42. Note its URL.
4. **In another browser / incognito**, log in as Bob.
5. From Bob's session, directly request Alice's resource:
   - URL approach: paste `https://app.example.com/orders/42` in Bob's browser.
   - API approach: in Bob's dev console, run `fetch('/api/orders/42').then(r => r.json()).then(console.log)`.
6. **PASS** = Bob gets `403 Forbidden` or `404 Not Found`. **FAIL** = Bob sees Alice's data.

**RUN (automated grep)**:
```bash
# Find API routes that fetch by ID but don't check ownership
grep -rn "findUnique\|findFirst\|findOne" --include="*.ts" --include="*.js" -A 3 . | grep -i "where.*id" | grep -v "userId\|user_id\|ownerId\|owner_id"
```
Any match that doesn't filter by `userId`/`ownerId` is suspicious — it returns the record regardless of who's asking.

**Common patterns to look for in Next.js / API routes**:
- `prisma.order.findUnique({ where: { id } })` — **FAIL** unless followed by an ownership check.
- `prisma.order.findUnique({ where: { id, userId: session.user.id } })` — **PASS**.
- Server actions / route handlers that take `params.id` from the URL and look it up without filtering by session — **FAIL**.

**Mutation endpoints** are even worse — also test:
- `PATCH /api/orders/42` from Bob's session with a body change — does it succeed? If yes, **FAIL**.
- `DELETE /api/orders/42` from Bob's session — does it succeed? If yes, **FAIL**.

**Fix pattern**: every database read/write inside a route should be scoped by the current user's session — never trust an ID from the URL or body on its own.

---


### Step 2b — API response surface audit (overexposure + enumerable IDs + versioning)

**Goal**: Verify that endpoints return only what the client needs, do not leak sensitive/internal fields, and do not create brittle customer integrations. Source: IG reel `Da-xLx0GH9f` (2026-07-20, @mattmurphyai).

**Why this matters**: An attacker may not need to hack the database. If `/api/users/:id` returns email, phone, billing address, roles, internal DB IDs, and nested relationships, a single JSON response already leaked the data. Sequential IDs make enumeration easier, and unversioned API responses become customer contracts you can accidentally break.

**RUN (code review / grep targets)**:
```bash
# Find JSON-returning routes / handlers
grep -rn "NextResponse.json\|Response.json\|res.json\|return .*json" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" .

# Find common over-fetch patterns
grep -rn "select:.*true\|include:.*true\|findMany\|findUnique\|SELECT \*" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" .
```

**Review every match**:
- Is the route returning ORM/database objects directly? If yes, prefer an explicit DTO/serializer.
- Are fields like `email`, `phone`, `billingAddress`, `role`, `isAdmin`, `internalId`, `tenantId`, or nested relationships actually needed by this screen?
- Can User B change a URL/body ID and read User A's response? If yes, this is Step 2 IDOR → **CRITICAL**.
- Are public IDs sequential/guessable? Use opaque public IDs (UUID/ULID/CUID) **plus** authorization checks. Opaque IDs reduce guessing; they do not replace authz.
- Does any partner/customer integration depend on this JSON shape? If yes, add `/v1` and keep it stable before changing response fields.

**Fix pattern**: define a minimal response schema per endpoint, strip everything the client does not need, keep object-level authorization on every read/write, and version external/customer APIs from day one.


### Step 2c — Frontend trust boundary + abuse controls

**Goal**: Catch the AI/vibe-coded pattern where the UI *appears* to enforce rules, but the backend actually trusts the browser.

**Sources**: IG reels `DZhxVg2xu-u` and `DZySxo1AjkZ` (2026-07-26).

**RUN (grep + review)**:
```bash
# Find client-side role/permission/plan checks that might need server enforcement
grep -rEn "isAdmin|role|permission|can[A-Z]|plan|tier|price|discount|feature" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" .

# Find route handlers / server actions that accept JSON. Confirm each validates and authorizes server-side.
grep -rEn "await req\.json\(|NextResponse\.json|Response\.json|server action|use server" --include="*.ts" --include="*.tsx" .

# Find public env vars. NEXT_PUBLIC_* ships to the browser; only truly public values belong here.
grep -rEn "NEXT_PUBLIC_|PUBLIC_" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.env*" .
```

**Review every match**:
- Pricing, discounts, feature gates, role checks, permission checks, and access decisions must be enforced on the backend. Frontend checks are UX only.
- Client-side validation is not security. Validate again in route handlers/server actions with shared schemas where possible.
- Disabled buttons are not access control. Test direct `fetch()` calls against the endpoint.
- Production bundles must not expose private API keys, internal endpoints, admin URLs, service-role keys, or config objects.
- Paid/external API routes (OpenAI, Resend, Stripe, scraping, AI generation) need per-IP/user/API-key rate limits and an emergency IP/user block path.

**Fix pattern**: frontend asks; backend decides. Add server-side authz + validation, move business rules server-side, clamp inputs, rate-limit paid routes, and keep a fast incident lever for blocking abusive IPs/users.

---

### Step 3 — Secrets hygiene (env vars + Git history)

**Goal**: No secrets in code, no secrets in front-end bundles, no secrets in Git history.

**RUN**:
```bash
# 3a — Is .env tracked by Git? It shouldn't be.
git ls-files | grep -E "^\.env($|\.)"
# Expected output: EMPTY. Any .env file shown here is committed and likely exposed.

# 3b — Were secrets ever committed (even if .env is now gitignored)?
git log -p --all -S "API_KEY" --source -- "*.env*" 2>/dev/null | head -50
git log -p --all -S "SECRET" --source 2>/dev/null | head -50
git log -p --all -S "sk_live" --source 2>/dev/null | head -30   # Stripe live keys
git log -p --all -S "AKIA" --source 2>/dev/null | head -30      # AWS access keys
# Any output = a secret was once committed. Rotate it.

# 3c — Are secrets leaking into front-end via NEXT_PUBLIC_*?
grep -rn "NEXT_PUBLIC_" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" . | grep -i -E "SECRET|API_KEY|TOKEN|PASSWORD|PRIVATE"
# Anything matching = bug. NEXT_PUBLIC_* gets bundled into the browser. Move to server-only.

# 3d — Hardcoded secrets anywhere in code?
grep -rEn "(sk_live_|sk_test_|AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36})" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.json" .
# Stripe live, Stripe test, AWS access, GitHub PAT respectively. Should return nothing.
```

**Fix pattern**:
- Anything in `.env` should be server-side only.
- For Next.js, **only** prefix with `NEXT_PUBLIC_` if it's something safe to ship to a browser (e.g., a public Supabase anon key, an analytics ID). Service-role keys / private API keys → never.
- If a secret was ever committed → **rotate it today**. Removing from git history (e.g., `git filter-repo`) doesn't help — assume it's already scraped by bots indexing GitHub.

---

### Step 4 — One-command quality pass (Claude Code skills)

If the project is opened in Claude Code, two built-in commands cover most of what we did above plus more:

```
/security-review     # multi-agent security scan; reports findings + suggested fixes
/simplify            # cleanup pass; recommended on the side, not in same commit as security
```

**Workflow Asi follows**:
1. Commit a clean checkpoint before running these (so you can revert).
2. `/security-review` first — read the findings, ask Claude to fix the high-severity ones, commit.
3. `/simplify` second — separate commit for code cleanup.
4. **Both** of these run in cloud (paid). Use them for actual deliveries, not for every save.


### Step 5 — Vibe-coded app quality pass (accessibility + performance + UX)

**Goal**: Catch non-security issues that make an AI-built app inaccessible, legally risky, unfinished, or likely to collapse under real usage. Sources: IG reels `DaBJZy8ovVY` (2026-07-26) and `DbaxXyTgbRR` (2026-08-22, accessibility add-on).

**Review**:
- **Keyboard-only navigation**: every core flow must work with Tab/Shift+Tab, Enter, Space, Escape, and arrows where relevant. Focus must be visible; modals/menus must trap and release focus correctly.
- **Screen-reader semantics**: images, buttons, links, forms, navigation, headings, status/error messages, and modals need useful labels/structure. Prefer native HTML before ARIA; add `aria-label`/`aria-describedby` only where needed.
- **WCAG AA contrast**: normal text should be at least 4.5:1; large text/icons/key UI at least 3:1. Do not communicate state by color alone.
- Icon-only buttons need visible labels where practical, `aria-label`, keyboard focus, and hover/focus tooltips.
- Use optimistic UI only for safe high-confidence operations; never for payments/destructive work.
- Every list endpoint needs pagination/cursors and hard `limit` caps.
- Watch for N+1 database queries in pages/components/routes.
- Long operations should be async/background jobs with status, retries, and idempotency instead of one synchronous request.

**Report**: `issue | evidence file:line | severity | user/security impact | smallest fix`.

---

## Findings report format (for the auditing Claude)

When you (the auditing Claude session) finish, return a report like this:

```
Project: <name>
Date: <date>

Step 1 (npm audit):
  - Critical: 0 | High: 2 | Moderate: 5 | Low: 3
  - Critical/High details: [package@version → CVE → fix]
  - Recommendation: <e.g. "Run `npm audit fix`; manual upgrade needed for `lodash@4.17.10` → `4.17.21`.">

Step 2 (auth boundaries / IDOR):
  - Routes checked: <count>
  - Suspicious routes (no ownership filter): [file:line, file:line, ...]
  - Manual test result (User A → User B): PASS / FAIL / NOT TESTED (login flow blocked test)

Step 2b (API response surface):
  - JSON endpoints checked: <count>
  - Overexposed fields: [endpoint → field list]
  - Direct ORM responses: [file:line, ...]
  - Enumerable ID / versioning risk: NONE / FOUND (list)

Step 3 (secrets):
  - .env tracked: NO / YES (rotate immediately)
  - Past commits with secrets: NONE / FOUND (list)
  - NEXT_PUBLIC_* leaks: NONE / FOUND (list)
  - Hardcoded secrets: NONE / FOUND (list)

Step 4 (overall):
  - SHIP / DO NOT SHIP / SHIP AFTER FIXES (list)
  - Top 3 issues to fix before launch
```

---

## Bonus — Cloak Browser (for Asi's other Mac, separate topic)

**Context**: A new open-source tool Asi may want to evaluate. Not part of the security audit — listed here only because Asi asked me to include it so he can read it on the MacBook.

**What it is**: A custom Chromium build with 16 patches compiled into the source itself (not runtime patches like Playwright-stealth). Branded as **"Cloak Browser"**, dropped on GitHub recently.

**Why it's interesting for Asi specifically**:
- Drop-in replacement for Playwright — change one import, same scraping code works.
- Reportedly passes:
  - reCAPTCHA v3 with score 0.9 (human-equivalent).
  - Cloudflare Turnstile.
  - fingerprint.js.
  - 14/14 stealth tests on browserscan.net.
- Asi has hit Bitunix's 403-block and Binance's 418-ban via direct API. If REST is permanently closed off for some venues, a stealth headless browser is one route to re-open data collection (depth, klines, trades) without an API key.

**How to find it**:
- Search GitHub for `Cloak Browser` (case-insensitive).
- Verify before installing:
  1. Read the repo's README and the patch list under `patches/` to make sure nothing exotic is happening to your system.
  2. Look at star count, age, and contributors. If it's brand new with no track record, treat any binary download with caution — prefer building from source.
  3. Run it inside a Docker container or a VM the first few times to limit blast radius.
- License: check the repo. If it's GPL-derivative from Chromium, that's normal; commercial use may need attention.

**Verdict for Asi**: worth a 30-min exploration. Specifically useful if/when you want to retry scraping Bitunix L2 depth or Binance candles after an IP/API ban — REST may be blocked, but a real-Chrome user-agent rarely is. Don't put it in the live-trading critical path until you've stress-tested it for at least a week against the venue you actually want.

---

## Quick reminder of skills available in Claude Code

If the auditing session has these plugins enabled (Asi's setup as of 2026-05-23):
- `/security-review` — multi-agent security pass
- `/simplify` — code cleanup pass
- `/review` — PR review
- `/init` — initialize CLAUDE.md for a new repo

Use them. They're cheaper than thinking from scratch.
