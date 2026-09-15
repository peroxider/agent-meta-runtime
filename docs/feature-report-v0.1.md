# Feature Report — agent-meta-runtime v0.1

Scope of this report: the **Runtime** deliverable only (this repository).
The Seed Harness is a separate distribution (`agent-meta-seed-harness`) and is
tracked by its own report; v0.1 Runtime ships no Seed code, fixtures, or
Conformance harness artifacts (see `docs/plans/v0.1/Runtime_09_Release_Closure.md`).

Release identity: `agent-meta-runtime` 0.0.1, wheel
`agent_meta_runtime-0.0.1-py3-none-any.whl`, sdist
`agent_meta_runtime-0.0.1.tar.gz`, artifacts under `dist/release/` with an
SBOM (`sbom-agent-meta-runtime.json`) and a signed-content
`release-manifest.json` produced by `scripts/build_release.py`.

## Implemented capability slices (Runtime v0.1)

- **Foundation (Step 00)** — package skeleton, canonical JSON/JCS encoding,
  stable error model, configuration with redaction, daemon lock, architecture
  lint (`scripts/arch_lint.py`): FR-MARCH-001..005, FR-MSEC-001..006,
  FR-MOS-001..007.
- **Store (Step 01)** — SQLite migration/initializer, content-addressed CAS,
  unit-of-work command execution, append-only Fact chain with doctor,
  artifact integrity: FR-MSTORE-001..010, FR-MFACT-001..006,
  FR-MINV-001..005, FR-MCAP-001..009.
- **Semantic Core (Step 02)** — UUIDv7 identity, canonical IDs/URIs, Task and
  Action lifecycle, Invocation, runtime views, context projection:
  FR-MID-001..009, FR-MTASK-001..007, FR-MSTATE-001..005,
  FR-MCTX-001..006, FR-MREF-001..006.
- **Authority & Composition (Step 03)** — authority grants, delegation
  containment, capability surfaces, composition revisions, frozen state:
  FR-MAUTH-001..008.
- **Execution (Step 04)** — Backend protocol, portable worker ledger, effect
  intents with validation and hashing, deadlines: FR-MEFFECT-001..006.
- **Control Plane (Step 05)** — transactional outbox, dedupe keys,
  dispatcher, reconciliation, recovery: FR-MOPS-001..005 (operations), and
  the outbox portion of FR-MRUN.
- **Interfaces (Step 06)** — SDK, local RPC server, CLI
  (`agent-meta --data-dir …`), readiness/serving views, cursor stability:
  FR-MAPI-001..008, FR-MRUN-001..009.
- **Harness Host (Step 07)** — Harness lifecycle on the Runtime side
  (install/get/list/activate/deactivate/uninstall), loop policy and budget
  enforcement, IPython Scratch adapter: FR-MRUN harness portion, FR-MCAP-008/009.
- **Evolution (Step 08)** — deterministic evaluator
  (`deterministic-evaluation/v1`), security AST scanner, experiment worlds,
  promotion/rollback/archive, compatibility validation:
  FR-MEVO-001..006, FR-MSPEC-001..005.
- **Operations (Step 09.1)** — sealed backup manifests, restore round-trip
  with quarantine, GC plan/sweep/purge with tombstones, upgrade preflight:
  FR-MOPS-001..005, FR-MSTORE-007..010.

Non-functional requirements NFR-M01..M54 carry named proofs under
`tests/trace/`; acceptance criteria AC-M01..M54 carry named proofs under
`tests/acceptance/`. The traceability verdict is enforced by
`scripts/traceability_check.py` (218-ID strict set equality, exit 0).

## Deferred and external scope (not part of the v0.1 Runtime verdict)

- FR-MSUC-001, FR-MSUC-002, FR-MSUC-003, FR-MSUC-004, FR-MSUC-005 —
  **Deferred-schema**: successor-schema work is specified but its schema
  surface lands in milestone M5; the named proof modules exist and pass, and
  the rows remain `SPECIFIED` in the traceability table.
- NFR-M14 — **Deferred-M5**: tied to the successor-schema milestone; proof
  module present, row remains `SPECIFIED`.
- AC-M10 and AC-M11 — **Deferred-M5**: explicitly deferred acceptance
  criteria for v0.1; their proof modules exist under `tests/acceptance/` and
  the traceability table keeps them at `SPECIFIED`. They are *not* part of
  the delivered v0.1 acceptance set.
- NFR-M48 — **External-Seed**: verified in the Seed Harness distribution
  (`external://agent-meta-seed-harness/tests/contract/test_nfr_m48.py`),
  excluded from the Runtime traceability verdict.
- AC-M17 and AC-M48 — **External-Seed**: acceptance coverage owned by the
  Seed Harness distribution
  (`external://agent-meta-seed-harness/tests/acceptance/test_ac_m17.py`,
  `external://agent-meta-seed-harness/tests/acceptance/test_ac_m48.py`),
  excluded from the Runtime traceability verdict.

## Known limitations (v0.1)

- Single-process writer per data directory (daemon lock); no multi-host
  replication.
- The deterministic evaluator trusts the evidence bundles it is given; it
  does not re-execute model calls (the experiment runner uses a fake model).
- Backup/restore and GC require an operator quiesce window; the store rejects
  writers with mismatched `application_id`/`user_version` instead of
  migrating automatically beyond the frozen v0.1 schema.
- The CLI is a thin, human-oriented surface over the local RPC; automation
  should target the SDK or the wire protocol.
