# Operator Runbook — agent-meta-runtime v0.1

Audience: operators deploying and maintaining a Runtime data directory.
All commands use the bundled CLI. Every invocation names the data directory
first; the CLI is the only supported human entry point — automation should
use the SDK or the local RPC wire protocol (`docs/spec`).

```console
agent-meta --data-dir /srv/amrt [--realm realm://main] [--actor principal://…] \
           [--output json|text] [--dry-run] <command> …
```

Stable exit codes (`EXIT_CODES` in `agent_meta_runtime.interfaces.cli.main`):

| Exit | Meaning |
|-----:|---------|
| 0 | success |
| 2 | invalid argument |
| 3 | authority denied |
| 4 | not found |
| 5 | revision/idempotency/already-exists conflict |
| 6 | readiness (feature unavailable, failed precondition, serving not ready, no serving composition) |
| 7 | temporary / retryable |
| 8 | integrity violation |
| 70 | internal error |

## 1. Bootstrap a data directory

```console
agent-meta --data-dir /srv/amrt init
agent-meta --data-dir /srv/amrt info
agent-meta --data-dir /srv/amrt doctor
```

`init` creates the SQLite store offline (no daemon needed), writes the frozen
`application_id`/`user_version`, and bootstraps `realm://main` at meta
revision 1. `doctor` verifies schema identity, trigger set, fact chain, and
CAS integrity; run it after any crash or suspected tamper. Exit 6 from
`doctor` means a precondition failed — do not write until resolved; exit 8
means an integrity violation (see §6).

## 2. Daily task flow

```console
agent-meta --data-dir /srv/amrt artifact put payload.json
agent-meta --data-dir /srv/amrt composition commit <body_artifact_id>
agent-meta --data-dir /srv/amrt task submit --input-artifact <artifact_id> [--budget '{"…"}']
agent-meta --data-dir /srv/amrt task wait <task_id> --timeout 60
agent-meta --data-dir /srv/amrt task get <task_id>
```

Serving readiness: task execution requires an active serving composition;
exit 6 (`NO_SERVING_COMPOSITION`) means commit and activate one first.
`task cancel <task_id> --reason …` for cooperative cancellation; late
completions after a terminal state are recorded but never reverse state
(proof: `tests/trace/test_nfr_m07.py`).

## 3. Harness lifecycle

```console
agent-meta --data-dir /srv/amrt harness validate <manifest_artifact>
agent-meta --data-dir /srv/amrt harness install --name NAME --version VER <manifest_artifact> <package_artifact>
agent-meta --data-dir /srv/amrt harness list [--status ACTIVE]
agent-meta --data-dir /srv/amrt harness inspect <harness_id>
agent-meta --data-dir /srv/amrt harness activate <harness_id> <body_artifact> \
    --expected-revision N --expected-serving M
agent-meta --data-dir /srv/amrt harness deactivate <harness_id>
agent-meta --data-dir /srv/amrt harness uninstall <harness_id>
```

Install is idempotent per (name, version); re-install of an identical package
succeeds without a new revision (proof: `tests/trace/test_fr_mrun_001.py`).
Activation uses optimistic serving/revision guards — exit 5 means another
operator moved the composition first; re-read with `view --revision` and retry.

## 4. Backup and restore (§41.47)

```console
agent-meta --data-dir /srv/amrt operations backup --destination /backups/2026-09-15
agent-meta --data-dir /srv/amrt operations get <operation_id>
agent-meta --data-dir /srv/amrt operations wait <operation_id> --timeout 60
```

The backup writes a sealed manifest (hash-chained, `runtime_version` and
`db_schema_version` bound). Restore is a Python entry point (deliberately not
exposed on the operator CLI, to prevent accidental in-place restores):

```python
from agent_meta_runtime.adapters.store.backup import restore_backup
restore_backup(source_dir=Path("/backups/2026-09-15"), data_dir=Path("/srv/amrt-restore"))
```

Rules:

- Quiesce writers during backup for a consistent meta revision; pass
  `--expected-meta-revision` to fail instead of racing (exit 5 on mismatch).
- Restore quarantines facts/artifacts whose hashes fail verification rather
  than aborting the whole restore; inspect the quarantine report before
  serving traffic (proofs: `tests/trace/test_fr_mops_003.py`,
  `tests/trace/test_fr_mstore_008.py`).
- Restores into a directory with a different schema identity are rejected.
- Upgrade preflight and apply are also Python entry points in the same
  module: `preflight_upgrade(conn, data_dir)` and `run_upgrade(conn, data_dir)`.

## 5. Garbage collection

```console
agent-meta --data-dir /srv/amrt operations gc-plan --expected-meta-revision N [--legal-hold <scope>]
agent-meta --data-dir /srv/amrt operations gc-apply --gc-plan-artifact <plan_artifact> --expected-meta-revision N
```

GC is plan-then-apply: the plan is itself an artifact (auditable), marks only
true orphans, and honors legal holds. Apply first tombstones, then sweeps to
trash; physical purge only after the retention window
(`tests/trace/test_fr_mops_004.py`, `test_fr_mops_005.py`,
`test_fr_mstore_009.py`, `test_fr_mstore_010.py`). Never delete store files
by hand — exit 8 from `doctor` afterwards is expected and means real damage.

## 6. Upgrade and integrity incidents

- **Upgrade preflight**: the store freezes `application_id = 0x414D5254`
  ("AMRT") and `user_version = 1`. On startup a writer with mismatched
  identity is rejected (`tests/trace/test_nfr_m54.py`). To upgrade,
  run `doctor` in the new version and follow its migration preflight output;
  never edit the store in place across schema versions.
- **Suspected tamper** (exit 8, or `doctor` reports fact-chain/CAS mismatch):
  stop writers, capture `doctor --output json` output, restore from the last
  sealed backup (§4), and quarantine-and-inspect. Tamper detection proofs:
  `tests/trace/test_fr_mfact_003.py`, `tests/trace/test_nfr_m05.py`,
  `tests/acceptance/test_ac_m04.py`.

## 7. Adversarial matrix → standing proofs

| Scenario | Behavior / guard | Proof module(s) |
|---|---|---|
| Process crash mid-command | UoW commit is atomic; journal replay on reopen; restart yields same revision | `tests/trace/test_fr_mrun_008.py`, `tests/trace/test_fr_mstate_002.py`, `tests/acceptance/test_ac_m29.py` |
| Concurrent/racing writers | Optimistic meta-revision guards; stale writes rejected | `tests/trace/test_fr_mstate_002.py`, `tests/trace/test_nfr_m15.py`, `tests/trace/test_nfr_m53.py` |
| Clock jump / NTP step | Deadlines/stamps use monotonic-stable µs; misalignment detected | `tests/trace/scenarios.py` (`clock_stability` scenario; not a v0.1 traceability ID) |
| Late result after terminal state | Recorded, never reverses terminal state | `tests/trace/test_nfr_m07.py`, `test_nfr_m24.py` |
| Low disk / partial write | Doctor detects CAS/hash mismatch; restore quarantines bad facts | `tests/trace/test_fr_mops_001.py`, `test_fr_mops_002.py`, `tests/acceptance/test_ac_m16.py` |
| Credential loss / authority abuse | Delegation containment, frozen permissions, hash-bound tokens | `tests/trace/test_fr_mauth_001.py`, `tests/acceptance/test_ac_m05.py`, `test_ac_m21.py`, `test_ac_m38.py` |
| Store tamper (fact/CAS) | Append-only triggers + hash chain detection | `tests/trace/test_fr_mfact_001.py`, `tests/trace/test_nfr_m04.py`, `tests/acceptance/test_ac_m12.py` |
| Cursor/session tampering | MAC'd cursor codec rejects forgery | `tests/acceptance/test_ac_m47.py`, `tests/trace/test_nfr_m47.py` |
| Secret leakage in logs/config | Redaction deterministic on load and render | `tests/trace/test_fr_msec_001.py`, `tests/trace/test_nfr_m16.py` |
| Outbox duplicate dispatch | Dedupe keys bound to (kind, realm, entity, transition, payload) | `tests/trace/test_fr_mrun_009.py`, `tests/trace/test_nfr_m23.py`, `test_nfr_m43.py` |
| Oversized/malformed frames | Wire codec caps and rejects | `tests/trace/test_fr_mos_001.py`, `tests/acceptance/test_ac_m22.py` |
| Accidental artifact deletion | DB triggers block DELETE/UPDATE on artifacts | `tests/trace/test_nfr_m05.py`, `tests/acceptance/test_ac_m15.py` |

## 8. Known limitations

See `docs/feature-report-v0.1.md` §Known limitations (single-writer lock,
evaluator trusts provided evidence, operator quiesce windows for backup/GC,
CLI is a thin surface over the wire protocol).
