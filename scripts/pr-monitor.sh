#!/usr/bin/env bash
# PR loop monitor: waits for CI checks + Greptile review on a PR, then condenses
# everything into a prioritized action-item list using a cheap model (gpt-5.6-luna, medium)
# so the expensive orchestrator only spends tokens on the condensed result.
#
# Usage: scripts/pr-monitor.sh <pr-number> [timeout-minutes]
# Output: prints ACTION ITEMS markdown to stdout; also saved to /tmp/pr-<n>-action-items.md
set -uo pipefail

PR="${1:?usage: pr-monitor.sh <pr-number> [timeout-minutes]}"
TIMEOUT_MIN="${2:-25}"
DEADLINE=$(( $(date +%s) + TIMEOUT_MIN * 60 ))
GREPTILE_GRACE=$(( $(date +%s) + 8 * 60 ))  # stop waiting for greptile alone after 8 min

echo "[pr-monitor] watching PR #$PR (timeout ${TIMEOUT_MIN}m)" >&2

while :; do
  NOW=$(date +%s)
  PENDING=$(gh pr checks "$PR" --json state --jq '[.[] | select(.state=="PENDING" or .state=="QUEUED" or .state=="IN_PROGRESS")] | length' 2>/dev/null || echo 1)
  GREPTILE=$( { gh api "repos/{owner}/{repo}/pulls/$PR/reviews" --jq '[.[] | select(.user.login | test("greptile"; "i"))] | length' 2>/dev/null || echo 0; } )
  GREPTILE_IC=$( { gh api "repos/{owner}/{repo}/issues/$PR/comments" --jq '[.[] | select(.user.login | test("greptile"; "i"))] | length' 2>/dev/null || echo 0; } )
  TOTAL_GREPTILE=$(( GREPTILE + GREPTILE_IC ))

  if [ "$PENDING" -eq 0 ] && { [ "$TOTAL_GREPTILE" -gt 0 ] || [ "$NOW" -gt "$GREPTILE_GRACE" ]; }; then
    break
  fi
  if [ "$NOW" -gt "$DEADLINE" ]; then
    echo "[pr-monitor] timeout; proceeding with whatever is available" >&2
    break
  fi
  sleep 45
done

MAT="/tmp/pr-$PR-materials.md"
{
  echo "# PR #$PR review materials"
  echo "## CI check results"
  gh pr checks "$PR" --json name,state,link 2>/dev/null || echo "(no checks)"
  echo
  echo "## Failed CI logs (if any)"
  for RUN_ID in $(gh run list --branch "$(gh pr view "$PR" --json headRefName --jq .headRefName)" --json databaseId,conclusion --jq '.[] | select(.conclusion=="failure") | .databaseId' 2>/dev/null | head -3); do
    echo "### run $RUN_ID"
    gh run view "$RUN_ID" --log-failed 2>/dev/null | tail -150
  done
  echo
  echo "## Greptile review bodies"
  gh api "repos/{owner}/{repo}/pulls/$PR/reviews" --jq '.[] | select(.user.login | test("greptile"; "i")) | .body' 2>/dev/null
  echo
  echo "## Greptile inline comments (path:line + body)"
  gh api "repos/{owner}/{repo}/pulls/$PR/comments" --paginate --jq '.[] | select(.user.login | test("greptile"; "i")) | "- \(.path):\(.line // .original_line): \(.body)"' 2>/dev/null
  echo
  echo "## Greptile issue comments"
  gh api "repos/{owner}/{repo}/issues/$PR/comments" --jq '.[] | select(.user.login | test("greptile"; "i")) | .body' 2>/dev/null
} > "$MAT"

OUT="/tmp/pr-$PR-action-items.md"
codex exec -m gpt-5.6-luna -c model_reasoning_effort="medium" --sandbox read-only \
  "Read $MAT. Produce a prioritized ACTION ITEMS list in markdown for the PR author: 1) CI failures first (with the failing test/step and the likely fix), 2) Greptile findings worth acting on (dedupe, drop pure style nits unless trivial, keep file:line), 3) a 'safe to ignore' section listing dismissed suggestions with one-line reasons. If CI is green and Greptile has no substantive findings, say exactly 'READY TO MERGE' as the first line. Be terse." \
  < /dev/null > "$OUT" 2>/dev/null

if [ -s "$OUT" ]; then
  cat "$OUT"
else
  echo "[pr-monitor] luna summarization failed; raw materials at $MAT" >&2
  cat "$MAT"
fi
