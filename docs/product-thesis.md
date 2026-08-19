# Product thesis: from demo to company

This document records why Hindsight is a product and not just a hackathon
entry, who would pay for it, and what has to be true before anyone should.
It is deliberately honest about the counter-case; the project's whole
technical identity is refusing to overstate what it knows, and the business
argument is held to the same standard.

## The one-sentence position

Hindsight reconstructs, from the git history every organisation already
has, exactly which repositories resolved a compromised dependency at any
past instant - with lockfile-level evidence, a versioned record of what the
world knew when, and an explicit statement of what it cannot prove - so an
organisation can answer "were we affected?" defensibly without having been
a customer when it happened.

The two load-bearing words are **retroactive** (zero prior
instrumentation; the history is already in git) and **defensible** (the
output is an evidence artifact with a coverage statement, not a dashboard
chart).

## Why now

1. **The exposure window is hours; scanning is continuous-present.**
   chalk/debug (Sep 2025) was live for ~2 hours. The Axios compromise
   (Mar 2026) for ~3. The keyv/cacheable wave (Aug 4, 2026) went from first
   poisoned publish to npm takedowns in under three hours, and the wider
   campaign pushed 400+ packages in a morning. If a tool was not watching
   during the window, a current-state scan of today's tree answers a
   different question than "what did we resolve at 10:14 UTC that day."
   Only history answers that one.
2. **The knowledge itself is retroactive.** IOC lists grow for days after
   disclosure (Shai-Hulud went from ~180 to 500+ packages; keyv/cacheable
   counts ranged 400 to 2,200+ across seven vendors with no verified
   complete list). Any answer given on day 1 is stale by day 5, so old
   questions must be re-asked against newer knowledge. That is a two-axis
   problem - valid time crossed with what-was-known time - and it is the
   axis no incumbent models. It is also exactly what a bitemporal graph is.
3. **A regulatory clock now exists.** The EU Cyber Resilience Act's
   reporting regime goes live September 11, 2026: 24-hour early warning,
   72-hour notification, 14-day report, fines to EUR 15M or 2.5% of global
   turnover, and it applies to products shipped years ago. "Products
   shipped years ago" is a historical obligation by construction. The SEC's
   8-K amendment duty (update within four business days when new
   information changes the assessment) is the same bitemporal requirement
   in disguise.
4. **Practitioners already name the cost.** S&P Global's head of AppSec on
   Shai-Hulud: answering "are we affected?" across hundreds of applications
   "is easily a week of work. In the middle of an active incident, you
   don't have a week." Detection-and-escalation is the single largest
   breach cost line (~$1.6M average).

## Who buys it

- **Segment:** organisations with a filing obligation, not a hygiene
  preference - CRA-in-scope software manufacturers selling into the EU,
  US-listed companies, PCI-scoped platforms. Fintech, healthtech, and
  EU-market device/software vendors first.
- **Size:** 300-5,000 engineers, 200-3,000 repositories, npm-heavy (npm is
  ~80% of 2026 supply-chain IOCs, so npm-only is a defensible v1). Below
  ~200 repos, `git log -S` is genuinely good enough and free wins; above
  ~5,000 the platform team builds it in-house.
- **Champion:** the head of AppSec who personally wrote the last "are we
  affected" memo. Economic buyer: the CISO. It sells alongside the
  incumbent SCA (Socket/Snyk/Endor), never instead of it.

## How it prices

Not per seat (value is unrelated to developer count) and not per incident
(the incident is the moment the product should be free and instant).

1. **Land, free:** the one-shot retroactive scan. Point a read-scoped org
   token at Hindsight, name an incident, get the answer with coverage.
   This is the demo, the marketing asset, and the trust move in one.
2. **Core, subscription tiered on repositories:** continuous bitemporal
   capture, unlimited historical queries, re-run-on-new-IOCs. Anchored
   against incident-response retainers ($10K-150K/yr), not against
   $25/dev/mo SCA seats.
3. **Expand, compliance module:** CRA notification pack, 8-K amendment
   diffs, signed questionnaire attestations - sold to GRC on a different
   budget line. The honesty envelope is the premium feature here, because
   a regulator-facing artifact that states its own coverage is worth more
   than one that cannot.

## The three capabilities a paid pilot requires

1. **Zero-instrumentation historical ingest at org scale.** A read-scoped
   token, every repo's lockfile history walked, queryable in under an hour
   for ~1,000 repos. Without this the wedge does not exist. The current
   ingest does exactly this at small scale (5,386 edges/s on the
   eight-repo PoC corpus; 4,160 rows/s on the nine-repo demo dataset's
   RESOLVES phase); the open
   engineering question is HydraDB's per-relationship-type read ceiling
   (~1M edges), which the label-namespacing design addresses by sharding
   relationship types per dataset.
2. **Resolution fidelity.** `npm ci` makes the lockfile authoritative;
   `npm install` inside a caret range does not. Evidence must classify
   every repo-instant as lockfile-authoritative, resolution-ambiguous, or
   no-build-in-window - and must not treat valid provenance as clean,
   because the keyv wave shipped malware with valid SLSA attestations.
   This is the existing coverage taxonomy (answerable / truncated /
   unanswerable and proven-negative vs truncated-empty) extended one level
   down, made mechanical instead of prose.
3. **Versioned advisory knowledge plus an exportable evidence artifact.**
   Every answer stamped with which advisory set, from which sources, at
   which fetch time; re-running under a newer set yields a diff against
   the prior answer, not a silently different answer. In this repo the
   advisory set is the incident file: registry-verified publish
   timestamps, named sources, explicit notes for what could not be
   verified. The export packet (JSON plus human-readable finding) carries
   the query, the result, the coverage envelope, and the incident file's
   identity.

## The counter-case, stated plainly

- **Socket could ship this.** They hold per-repo scan history and $125M.
  The defence is not the date-picker; it is the bitemporal advisory axis
  and the resolution-ambiguity classification - engineering a buyer cannot
  evaluate in a demo, which cuts both ways.
- **The free workaround is good at p50.** A disciplined `npm ci` shop can
  grep lockfile history in an afternoon. The product's margin lives in the
  cases where the cheap answer is subtly wrong (floating ranges, tag
  repointing, registry unpublishes) and in the artifact, not the answer.
- **Episodic pain churns.** Teams feel this a few times a year. The
  subscription must be carried by the compliance artifact and the
  re-run-on-new-IOCs loop, or it will not renew.
- **Precision may not change remediation.** Standard guidance treats any
  system that installed a compromised package as fully compromised, so a
  finding often triggers total rotation regardless of nuance. The honest
  answer "unaffected, with proof, for 87% of repos; ambiguous for 13%"
  loses questionnaire deals to a vendor who just says "no exposure found."
  This is the deepest risk, and it is a bet that regulators and auditors -
  unlike questionnaires - reward stated coverage.

The net: pitched as a supply-chain security tool, this is a feature.
Pitched as forensic evidence infrastructure for a regulatory clock that
starts in weeks, it is a category with a timing advantage.

## What this repo already proves, and what it does not

Proven here: bitemporal as-of answers over real lockfile history (320/320
agreement with an independent git oracle), blast-radius reads at 5.9ms p50
for warm id-anchored queries at PoC scale (the first query against a
freshly restarted node is 568ms), truncation honesty end to end, two real
incidents as data
(chalk/debug Sep 2025; keyv/cacheable Aug 2026) with registry-verified
timestamps that survive npm's own takedowns.

Not proven here: org-scale ingest beyond nine repos, CI-run joins for
resolution-ambiguity classification, multi-ecosystem lockfiles, and the
advisory-diff loop. Those are the pilot roadmap, not the hackathon.

## Sources

Market sizing, funding, and incident facts summarized above draw from:
CISA alerts (Sep 2025 npm compromise; Apr 2026 Axios), Datadog Security
Labs' deduplicated Shai-Hulud IOC set, Wiz/Snyk/Socket/Chainguard/Expel
write-ups of the keyv/cacheable wave, Phoenix Security's 2026 supply-chain
campaign data, the ArmorCode interview with S&P Global's head of AppSec,
BSI and Mend on the EU CRA timeline, Morrison Foerster on SEC 8-K
guidance, OpenAI's TanStack disclosure (the template for the evidence
artifact), Socket/Chainguard/Aikido/Endor/Oligo funding disclosures, and
npm registry `time` maps queried directly for every timestamp in
`poc/incident-keyv-shai-hulud.json`.
