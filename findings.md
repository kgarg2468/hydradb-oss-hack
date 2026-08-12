# Findings

## Hackathon (hackhydra.hydradb.com)
- Aug 12–20 2026, online, teams 1–4, $10k pool (Grand $5k / $3k / $1.5k / Best-use-of-HydraDB $500).
- Submission: Google Form + ≤3min demo video + public OSS-licensed GitHub repo. Deadline Aug 20 11:59pm PT. Commit history must start ≥Aug 12.
- HydraDB must do REAL core functionality. Judges: technical execution, HydraDB/graph-native use, product completeness+usability, result quality, originality. "Working, thoughtful products, not just benchmark scores."
- Discord: discord.gg/D8cGSa9H9. Form: forms.gle/WEwqEmmN7Bkp4HyJ6.

## Tracks
1. **Enterprise Context & Ontology** — ~500k noisy docs from 9 sources → queryable ontology. Entity resolution, contradiction resolution, multi-hop, abstention. Datasets: Enterprise RAG Bench, Salesforce HERB (HF).
2. **Repos/Dependencies/Code as Graphs** — 2A: supply-chain blast radius (npm/PyPI compromise → which internal services exposed, shared maintainers, typosquats). 2B: code graphs for IDE assistants (call chains, types, configs, tests — "graph traversal not semantic similarity").
3. **Memory & Context Retrieval** — agent memory across 30–40 sessions, 115k+ tokens/question; fact synthesis, chronology, overwrites, abstention. Datasets: LongMemEval, LongMemEval V2, BEAM.

## HydraDB — what it is
- Rust, AGPL-3.0, ~35 commits/31 stars (young project). "Fast graph database on object storage."
- **Architecture**: fully disaggregated. Data nodes (query+mutation, disposable NVMe cache) / async indexer workers (immutable traversal indexes via atomic object-store pointers) / S3 object storage as single source of truth (WALs, SSTs, leases, "CSC generations") built on **SlateDB**. Writer handoff via object-store CAS leases + writer epochs.
- **Query**: OpenCypher subset (reads+mutations, var-length paths, OPTIONAL MATCH, UNION, UNWIND, aggregation), GraphBLAS (SuiteSparse) traversal kernels, path procs algo.SPpaths/SSpaths/MSpaths.
- **Connectivity**: Neo4j Bolt 5.x compatible + HTTPS JSON/NDJSON API. Auth, deadlines, backpressure.
- **Consistency**: causal (default) vs strong (refresh from object store before pinning **snapshot**). Snapshot-consistent queries.
- Prometheus metrics, OTel tracing. Docker images ghcr.io/hydra-db/hydradb. Docs: architecture.md, DEVELOPMENT.md, Jepsen report, Quint formal model, correctness casebook.
- KEY LEVERAGE: object-store-native + snapshot/generation design + SlateDB (which supports checkpoints/clones) → potentially cheap zero-copy graph versioning/branching. Neo4j can't do this.

## HydraDB repo/architecture notes (full: .context/research/repo-capabilities.md)
- **TIME TRAVEL IS PLUMBED, GATED BY 3 `if`s**: `read_epoch` exists on HTTP body (src/client/http.rs:283), ClientQueryRequest (service.rs:503), `at_epoch()`. Rejected at service.rs:1253, service.rs:1383, shard/lifecycle.rs:745. Downstream (cursors, path procs, cache keys) already epoch-parameterized. HydraDB only uses DbReaderMode::ManagedCheckpoint; zero use of SlateDB named checkpoints/clones/restore. No branching/backup/PITR exposed.
- **CDC exists, no consumer API**: shard/xlog.rs — every topology mutation writes ordered xlog keys in same txn; idempotent replay; bounded range scan for "what changed in (A,B]". Needs only tail/subscribe API.
- **Branching primitives ready**: immutable content-addressed generations/<seq>-<sha256>.csc + CAS on tiny `current` pointer; graph_index_csc() loads ANY descriptor. Branch = second pointer over same objects.
- **Missing**: vector/ANN, full-text (only STARTS WITH), GDS algos (GraphBLAS linked though), triggers/UDFs, explicit txns, DDL/constraints, shortestPath, min/max, IN/CONTAINS/IS NULL, EXPLAIN. HTTP: 3 routes + 3 admin routes; Admin transport action defined but empty.
- **Strong**: dynamic multi-tenancy via base64 Bolt db names (unbounded tenants), per-namespace quotas, CAS writer leases + epoch fencing, cross-tenant-safe bookmarks, durable idempotency keys.
- ⇒ Hackathon leverage: small engine patches unlock time-travel queries + branches + CDC tail — features HydraDB would obviously want upstream, then a product demo on top.

## HydraDB the COMPANY (hydradb.com) — critical context
- Positioning: "The Brain Behind Your Company's AI" — context infrastructure for AI agents. Graph + vector hybrid. Tiered storage (mem cache → NVMe → object storage) w/ retention score (salience+recency+reuse).
- ALREADY claims: append-only ledger (timestamped edges, no overwrites), **"Git-style temporal versioning"** (recall what was true at any time), entity resolution across sessions, agent memory. LongMemEval-s 90.79% (Knowledge Update 97.43%, Temporal 90.97%), BEAM 1M 82%, FinanceBench 91.4%.
- Pricing: Free / $25 (2GB) / $399 (10GB) / Enterprise. Storage-based. Multi-tenancy in free tier.
- Use-case pages: Customer Support, Research Intelligence, AI Coding Assistants.
- ⇒ IMPLICATION: Track-3-style "agent memory layer" and "temporal recall" = their OWN core product. To be novel FOR THEM we need something they don't do: e.g. true branching/fork+merge+diff (recall ≠ branching), or a vertical product (supply-chain security graph, code graph) they'd sell as a new offering. Their use-case list lacks security entirely.

## SlateDB checkpoints/clones (verified from slatedb.io docs)
- Checkpoint = durable pinned reference to a manifest version; NO data copy (metadata only); GC respects it. Optional expiration/name. APIs: Db::create_checkpoint(), Admin::create_detached_checkpoint(), DbReader checkpoint modes.
- **Writable clones**: start from a checkpoint, write new data to own path while referencing source SSTs = copy-on-write branching at storage layer. ⇒ zero-copy graph branching is technically real; question is only whether HydraDB exposes it (repo agent to confirm).

## Competitive landscape / prior art
### Memory landscape (full: .context/research/memory-landscape.md)
White-space gaps ranked (novelty × value):
1. **Provenance as queryable graph** — no system traces where a memory came from, validity, downstream influence (explicit open problem in lit). Cypher-native fit.
2. **Verified/auditable forgetting w/ dependency cascade** — weakest competency across ALL systems (MemoryAgentBench); nobody cascades deletion to derived beliefs or proves erasure (GDPR angle).
3. **Branching/speculative memory** — no prior work joining versioned-graph infra with counterfactual branching. Nearest: Letta Context Repositories (Feb 2026, file-based).
4. **Deterministic replay ("why did it believe this?")** — blocked on immutable snapshot pinning, which nobody has… but HydraDB does.
5. Permissioned multi-agent shared memory (partially taken). 6. Confidence decay + abstention gating injection. 7. Non-LLM deterministic conflict resolution.
- **Strategic thesis:** incumbents treat memory as mutable state because history is expensive on their substrates. Object-store-native inverts it: history cheap, mutation derived. Gaps 1–4 = one coherent thesis.
- Reusable facts: GraphRAG/LightRAG/HippoRAG-1 LOSE 5–10 F1 vs dense retrieval on simple factual QA (HippoRAG 2 paper); LongMemEval abstention varies 56→93% by reader on frozen retrieval (SOTA claims often measure the reader).

### Code/supply-chain landscape (full: .context/research/codegraph-landscape.md)
- Core: ALL products (Socket, Endor, deps.dev, Dependabot, Snyk) build point-in-time, per-repo, package-level graphs. Nobody has org-wide + temporal + package+maintainer+symbol graph an agent can traverse.
- Ranked gaps: (1) **temporal "were we exposed on date X"** — chalk/debug Sept 8 2025 exposure depended on a 2.5-hour window and lockfile resolution timing; answered industry-wide with grep+spreadsheets; git stores historical lockfiles = free time series. (2) **Maintainer-trust graph** — avg npm pkg transitively trusts 40 maintainers; 391 maintainers touch >10k pkgs (USENIX 2019); no product exposes maintainer as queryable node; exact shape of chalk/debug (1 phished human, 2.6B weekly downloads), Shai-Hulud (worm along maintainer edges), xz. (3) Unified traversal service→lockfile→pkg→maintainer→CVE→symbol→call site; SCIP is a transmission format, consuming it is invited. (4) **MCP: give agent cypher() + schema**, not canned tools; existing ~6 MCP code-graph servers are single-repo/now-only. (5) Speculative upgrade simulation (BUMP dataset for eval). (6) Typosquat/slopsquat graph scoring (edit distance catches ~13% of AI-hallucinated names).
- Sourcegraph closed source Aug 2024 → OSS code-graph slot vacant.
- Agent recommends #1+#2+#4 as one demo.

### Branchable DBs + inspiration (full: .context/research/branching-and-inspiration.md)
- **⚠️ Omnigraph (omnigraph.dev, Modern Relay, Barcelona/SF, €2.5M seed Apr 2026, MIT, ~1.1k stars)**: versioned graph DB on S3, git-style branch/3-way merge, time travel, agents-branch-humans-merge, MCP server. Custom `.gq` language (no Cypher). ⇒ "git for graphs" ALONE is taken. Check if they're a sponsor/judge/entrant.
- Still open: standard-Cypher branching (TerminusDB post-mortem: "stacked novelty killed it"); **speculative Cypher / counterfactual execution** (research rich, products zero; Berkeley 2025: agent speculative exploration needs cheap fork/rollback); Datomic can't branch from the past — SlateDB checkpoints can.
- SlateDB reality: fork + read-only time travel ~free (manifest-only; WAL copied; nested clones shallow), BUT single-writer-per-path, flush-before-clone, checkpoint TTL, union can't merge WAL ⇒ **diff/merge must live at graph layer = our novelty**.
- Winning patterns: (1) ONE NUMBER said aloud; (2) live destructive drama undone on stage; (3) stand on a standard (Cypher/S3), never pitch "generally useful" (Dolt post-mortem).

## Inspiration: niche hackathon wins
(see branching-and-inspiration.md Thread B)

## Candidate ideas (draft v1 — pre-agent-reports)
1. **HydraFork** — zero-copy branchable knowledge graphs: fork/diff/merge graph branches for agent what-if reasoning, dev/test branches of prod context graphs. Neon-style killer feature. Risk: they already market "git-style recall" (though recall ≠ branch+merge); Rust engine work may be too heavy for 8 days unless done at app layer.
2. **Supply-chain blast radius + time machine (Track 2A)** — org-wide dependency graph in HydraDB + advisory feeds; answers: exposed now? exposed on date X? shared-maintainer risk? typosquat proximity? + speculative upgrade simulation (branch graph, apply upgrade, recompute exposure). HydraDB has NO security use case today ⇒ new sellable vertical. Demo: replay Sept 2025 npm attack wave (chalk/debug, Shai-Hulud) on synthetic org. Track framing literally says "graph traversal, not semantic similarity".
3. **Code graph MCP for IDE assistants (2B)** — crowded (Sourcegraph/SCIP etc.), weaker novelty.
4. **Track 1 ontology builder** — competes with their own company-brain product; heavy data eng.
5. **Epistemic memory (provenance/confidence/abstention)** — competes with their core memory product.
Leaning: #2, possibly with #1's branching as the what-if mechanism.

## Build-in-public (from Discord)
- Organizers encourage posting progress publicly (X etc.) with template: "I'm building [PROJECT] for Hack Hydra by @hydradb… The idea: … I'm using HydraDB to: … Shipping by Aug 20." Drop link in their server. Helps stand out + Best Use of HydraDB ($500).
- TODO after idea locked: draft post for user to publish.

## Debate outcomes (Fable position + Sol xhigh attack — both in .context/debate/)
- **CONVERGED: A wins; B, C, D killed.** Sol's scoped variant **A′ "Incident Replay"**: npm only; chalk/debug incident; ~100-repo fixture w/ real lockfile histories; explicit evidence states (RESOLVED from lockfiles ≠ BUILT ≠ DEPLOYED — never conflate); CURRENT maintainer-risk graph (don't fake historical publish perms); durable AS-OF reads; one timeline UI + impact graph + raw Cypher/MCP; NO PyPI/symbols/vectors/branch-merge/speculative-syntax.
- Positioning: "existing products answer what is vulnerable NOW; this reconstructs what was exposed THEN." Nearest OSS competitor: OpenSSF GUAC (attestation-centric, heavy, not snapshot-temporal, not agent-native). Cite Small World with High Risks (2019) as basis, don't claim concept novelty.
- HydraDB fit: upstream durable historical-query APIs + snapshot admin + CDC surface; reference product for a forensics vertical, NOT "HydraDB becomes Snyk".
- Sol's key technical attack: read_epoch = sequence/bookmark mechanism, NOT persistent historical snapshot; true time travel must survive compaction+restart; only 1 previous CSC generation retained by default; transaction-time ≠ validity-time (bitemporal).
- **Fable synthesis (final):** primary temporal mechanism = schema-level bitemporality (valid_from/valid_to on RESOLVES edges from lockfile git history) — zero engine risk, answers "resolved during window" in plain Cypher. Engine epoch/checkpoint historical reads = parallel experiment; if it works it's the Best-Use-of-HydraDB cherry + upstreamable PR, not the foundation.
- One number: measured p95 org-wide historical blast-radius query latency on 100-repo corpus.
- Demo: timeline scrub through Sept 8 2025 14:00 UTC window; exposure appears/disappears; pivot to maintainer reach.

### PoC gate (go/no-go, from debate)
1. Bitemporal correctness: ≥5 real repos' lockfile histories ingested; AS-OF Cypher result at time T == independent lockfile-parser oracle at T (100% on fixture).
2. Scale: 100k+ edges via batched UNWIND; measure throughput.
3. Blast-radius + maintainer-reach queries expressible in HydraDB's Cypher subset (no IN/CONTAINS/shortestPath/min/max!), correct, p95 measured.
4. Engine experiment: pin/query older epoch (read_epoch probe → checkpoint patch). Go/no-go for engine-PR cherry.
Fail 1 or 3 → kill A, revisit B. Fail 4 alone → ship schema-level only.

## PoC results
### Gate 4 — engine historical reads: **GO-WITH-CAVEATS** ✅
- Branch `experiment/historical-reads` in .context/hydradb (commits d57be4c, f79370d, local). Report: .context/research/engine-experiment.md.
- read_epoch IS a SlateDB sequence; epoch→state is a real durable 1:1 mapping via named checkpoints (`hydradb-epoch-<seq>`); manifest = registry (survives restart free). Snapshot installed into existing ACTIVE_STORAGE_SNAPSHOT task-local → all reads follow.
- Evidence: read_epoch=1→[2] vs head→[2,3]; survives close/reopen; survives 40 writes + 8→94 SSTs; after GC fails loudly ("epoch 1 is not retained"), never silently wrong.
- Optimizer already falls back to canonical adjacency when read_epoch≠current → CSC generation retention NOT needed. 540 LOC total (188 test). Build on this Mac fine (55s); 325/325 tests pass.
- Remaining gap for demo: no wire API to CREATE/retain an epoch — ~60 LOC on already-defined-but-unrouted QueryTransportAction::Admin.
- Mac build recipe: brew tap cleishm/neo4j for libcypher-parser; BINDGEN_EXTRA_CLANG_ARGS/LIBRARY_PATH exports per README.

### Gates 1–3 — data/bitemporal/oracle PoC: **ALL PASS** ✅ (full: poc/POC-RESULTS.md)
- Gate 1 AS-OF correctness: 128/128 full-set + 192/192 targeted vs independent git-based oracle, 0 mismatches; 98 distinct answer sets over time (query genuinely discriminates).
- Gate 2 ingest: 111,723 edges + 31,481 nodes in 20.8s = **5,386 edges/s** single-threaded; max UNWIND batch 1024 (admission control).
- Gate 3 blast radius: correct; **maintainer `qix` (the actually-phished account) reaches 8/8 repos through `debug` alone — 5.9ms p50**; sindresorhus = largest trust concentration (8 repos, 34 pkgs).
- Fixture: 8 real repos, 5,028 lockfile snapshots (2024-01→2025-12), npm v1/v2/v3 + yarn classic/berry parsers. All 24 malicious versions' publish timestamps verified against npm registry `time` map (wave 1 = 8min22s burst 13:12:10–13:20:31Z Sept 8 2025).
- **True negative finding (demo gold):** zero compromised versions in fixture — lockfile-pinned repos were never exposed; exposure required reinstall inside ~2h window. webpack regenerated its lockfile 69 min before first malicious publish; grafana missed by 2.1h. ⇒ product story: *prove* you weren't exposed (or were), with evidence — grep can't prove a negative org-wide.
- **Perf caveat / build requirement:** NO secondary property index — property-predicate entry scans (7,880ms p50); id-entry is 3.9ms (2,047× gap). App must own name→id map. Deletion unusable (~3 nodes/s, 30s server cap) — never delete, namespace labels instead (append-only fits product anyway). 17 subset limitations catalogued in POC-RESULTS §6. Multi-pattern joins WORK (3-pattern maintainer→pkg→version→repo join) — key positive.
- Flags: only cell-0 exists; blobless clones need `-c core.commitGraph=false` for concurrent lazy fetches.

## VERDICT: A′ VALIDATED — all 4 gates pass. Proceed to build.
