# Website Costs and Delivery Roadmap

## Current decision

Do not make hosted scanning a prerequisite for the initial GPY Analytics / SecretLoop website. A static/local-first experience can provide strong onboarding at negligible GPY compute cost.

## Delivery stages

### W0 — Research pack

This folder. Parked separately from the active SecretLoop engineering roadmap.

### W1 — Strong static/local-first website

Target experience:

- GPY Analytics homepage;
- SecretLoop product page;
- interactive synthetic console;
- follow-along executable documentation;
- synthetic demo repository;
- CLI / VS Code / MCP onboarding;
- security center;
- evidence center;
- comparison page;
- changelog/public roadmap;
- pilot/design-partner funnel;
- about/contact/privacy/terms/security.txt;
- responsive/accessibility/performance/SEO/security review.

Previous planning estimate: approximately **65–75 focused engineering/content hours** for a strong enterprise-ready static/local-first V1, assuming heavy AI-assisted implementation but human review of security claims.

This is an estimate, not a commitment.

### W2 — Hosted public-repository scanner

Only after demand/budget justifies it.

Adds:

- public GitHub repo ingestion;
- isolated ephemeral workers;
- real scan event streaming;
- structured findings UI;
- resource/abuse controls;
- cleanup/retention controls;
- security/adversarial testing.

Previous planning estimate for the scanner backend itself: roughly **30–50+ hours**, with broader web-workbench integration pushing the total higher. Treat as discovery estimate until architecture is specified and benchmarked.

### W3 — Full web workbench

Potential:

- console + structured findings;
- history/archive/entropy controls;
- reports;
- P0/P1 identity/fan-out/investigation UI after those features ship;
- read-only MCP activity/evidence UI.

A richer site + hosted workbench was estimated in discussion at roughly **160–225 hours total** depending on scope. Do not treat this as an execution commitment.

### W4 — Account / hosted free tier

Only if hosted scanning exists.

Candidate model:

- account required for hosted scan convenience;
- no credit card for initial free allowance;
- candidate: three standard public-repo scans;
- after quota: unlimited local free path + request-more-access/scan-pack experiment + team pilot;
- do not build billing until users demonstrate post-quota demand.

### W5 — Paid hosted convenience

Potential scan packs/developer hosted plan only after evidence. Pricing must be based on actual compute cost, demand and willingness to pay; no pricing is locked in this research.

### W6 — Enterprise/private/on-prem

Future product work, customer-evidence gated. Prefer local processing and structured metadata over uploading raw private repositories.

## Cost-control principles for hosted scanning

- pay for current scale, architect for later scale;
- repository/file/history/archive/runtime/memory budgets;
- concurrency limits;
- rate limits;
- short-lived cache for identical public scans if safe;
- ephemeral storage;
- no LLM API call required for every anonymous visitor;
- deterministic/template explanation where possible;
- local CLI remains the unlimited free compute path.

## Initial recurring-cost target

Static/local-first website should aim for negligible hosting cost beyond the already-owned domain and any chosen email/hosting services.

A future light hosted scanner was discussed with an initial operating target of staying within a small monthly budget (for example around INR 5,000/month) until real usage justifies expansion. This is a budgeting goal, not a provider quote or guaranteed cost.

## Promotion gates

Website research does not interrupt SecretLoop P0/P1/P2. Promote a parked website capability only when one or more of these materially justify it:

- real user demand;
- enterprise/design-partner requirement;
- available budget;
- strong conversion evidence;
- implementation cost falls materially;
- strategic/security reason.

Security/correctness issues in the existing product may interrupt the roadmap; new website feature ideas should normally be recorded here and wait.
