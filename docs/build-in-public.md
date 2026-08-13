# Build-in-public posts (Discord/X) — ready to publish

## Post 1 — announcement (use the organizers' template)

I'm building **Hindsight — a Blast Radius Time Machine** for Hack Hydra by @hydradb this week.

The idea: when npm's chalk/debug packages were compromised on Sept 8 2025, whether you were hit came down to a ~2-hour window — did any lockfile in your org resolve one of 24 malicious versions before takedown? Every tool on the market answers "what's vulnerable *now*". None can reconstruct what your org resolved *then*, and none can prove you were safe.

I'm using HydraDB to: store every dependency state your org has ever had as a bitemporal graph — repos, resolved package versions with valid-from/valid-to intervals, and maintainers as first-class nodes — so "who was exposed at 14:05 UTC?" and "which single maintainer account reaches the most of our repos?" are millisecond graph traversals instead of days of grep.

Shipping by Aug 20. Repo: github.com/kgarg2468/hydradb-oss-hack

---

## Post 2 — the engine contribution (strong "Best Use of HydraDB" signal)

Update on Hindsight for Hack Hydra: HydraDB's query API has a `read_epoch` field that was rejected at the route — historical reads weren't wired up.

So I wired them up. On a fork: `read_epoch` now maps to durable SlateDB checkpoints, plus a retention API (`POST/GET /v1/graphs/{graph}/cells/{cell}/retained-epochs`). A historical query returns the old state while head moves on, survives node restart and compaction churn, and fails loudly ("epoch N is not retained") instead of silently returning current state.

464 lib + 2 integration tests pass, clippy clean on all six CI feature sets.

Fork: github.com/kgarg2468/hydradb @ 258f787

---

## Post 3 — the counterintuitive demo moment

The best moment in the Hindsight demo isn't finding an exposed repo. It's **proving a negative**.

Scrub the timeline to 14:05 UTC on Sept 8 2025 and webpack shows clean — not "no results found", but *why*: its lockfile pinned chalk@5.6.0 four days and one hour before the first malicious publish, and wasn't touched for 102 days.

Grep can tell you a string isn't in a file today. It can't tell you what your org resolved during a two-hour window last September, across every repo, with the interval each version was held over.

That's what a bitemporal graph buys you.

---

## Notes
- Post 1 now; post 2 once the upstream PR decision is made; post 3 with a screen recording of the scrubber.
- Drop links in the Hack Hydra Discord after posting.
- Do NOT claim deployment/exposure beyond lockfile resolution — every public claim must carry the "resolved ≠ deployed" caveat that the product itself enforces.
