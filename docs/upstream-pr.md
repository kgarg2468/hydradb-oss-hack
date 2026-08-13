# Upstream PR to hydra-db/hydradb — ready to fire

The engine work lives on a public fork and is finished, tested and documented.
This file holds the PR body so opening it upstream is one command. Nothing here
is sent until someone runs it.

```bash
gh pr create \
  --repo hydra-db/hydradb \
  --head kgarg2468:experiment/historical-reads \
  --base main \
  --title "Historical reads: map read_epoch onto durable SlateDB checkpoints, plus a retention API" \
  --body-file docs/upstream-pr-body.md
```

## Before firing, check these three

1. **Rebase onto current upstream `main`.** The fork is at `258f787`; upstream
   moves. A PR that does not apply is worse than no PR.
2. **AGPL-3.0.** The engine changes are a derivative work of HydraDB and are
   licensed AGPL-3.0 on the fork. This repository's own Apache-2.0 licence
   covers Hindsight, not the fork. Do not mix them up in the PR description.
3. **Decide the framing.** This is offered as a working branch and a design
   proposal, not as something anyone is obliged to merge. Say so — a
   hackathon-week PR landing unannounced in a young project's queue reads
   better when it is explicit about that.

## Reviewer questions to expect

- **Why checkpoints rather than a new durable structure?** Because the SlateDB
  manifest is already the registry, so retained epochs survive restart with
  nothing new to persist, back up or corrupt.
- **What happens to GC?** SlateDB GC respects checkpoints, so a retained epoch
  holds its SSTs. That is the intended cost and it is why retention is explicit
  and opt-in rather than automatic.
- **What about the reader/writer split?** Retention is writer-gated
  (`421 not_cell_writer` on a reader). Multi-node retain is unexercised by
  tests — disclosed, not hidden.
- **Why no TTL?** Deliberately out of scope for this branch. `gc_retained_epochs`
  exists as a library function with no route; adding a policy is a separate
  design conversation about who owns retention lifetime.
