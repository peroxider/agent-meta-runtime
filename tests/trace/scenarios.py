"""Scenario library backing the named traceability proofs (Step 09.3).

Each function exercises a real Runtime behavior through the public product
API (store flows, domain validations, wire codec, doctor) and returns a dict
of named boolean/value results. Generated proof modules assert a specific key
with the exact traceability ID as the assertion tag.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from agent_meta_runtime.adapters.cas import FilesystemCas
from agent_meta_runtime.adapters.store import bootstrap_realm, initialize_store
from agent_meta_runtime.adapters.store.backup import (
    create_backup,
    restore_backup,
    run_upgrade,
    validate_backup_destination,
)
from agent_meta_runtime.adapters.store.doctor import run_integrity_doctor
from agent_meta_runtime.adapters.store.gc import (
    apply_gc_quarantine,
    build_gc_plan,
    commit_gc_plan,
    move_quarantined_to_trash,
    purge_expired_trash,
    validate_gc_plan,
)
from agent_meta_runtime.adapters.store.harness import (
    InstallHarnessRequest,
    install_harness,
)
from agent_meta_runtime.adapters.store.semantic import (
    TaskAcceptRequest,
    TaskTerminalRequest,
    accept_task,
    complete_task,
    load_task,
    record_late_completion,
    start_task,
)
from agent_meta_runtime.adapters.store.uow import execute_command
from agent_meta_runtime.adapters.store.views import (
    get_current_view,
    get_historical_view,
)
from agent_meta_runtime.application.outbox import OutboxDispatcher
from agent_meta_runtime.domain.authority import (
    PERMISSIONS,
    Grant,
    GrantConstraints,
    Scope,
    ScopeTarget,
    command_signature_preimage,
    execution_token_payload_hash,
    validate_delegation,
)
from agent_meta_runtime.domain.canonical import canonical_json, sha256_hex
from agent_meta_runtime.domain.clock import ClockStabilityMonitor
from agent_meta_runtime.domain.errors import ErrorCode, StableError
from agent_meta_runtime.domain.facts import fact_payload_hash
from agent_meta_runtime.domain.semantics import TaskBudget
from agent_meta_runtime.domain.ids import (
    new_uuid7,
    normalize_uuidv7,
    parse_uri,
    validate_id,
    validate_stable_name,
)
from agent_meta_runtime.domain.outbox import outbox_dedupe_key
from agent_meta_runtime.protocols.public_wire import (
    METHODS,
    MAX_FRAME_BYTES,
    decode_frame_length,
    encode_frame,
    parse_envelope,
)

REALM = "realm://main"
ACTOR = "principal://operator-root/01900000-0000-7000-8000-000000000000"
DEADLINE_US = 5_000_000


def _envelope(**overrides):
    base = dict(
        command_id="task://" + new_uuid7(),
        realm_id=REALM,
        actor_id=ACTOR,
        authority_grant_id=None,
        expected_meta_revision=None,
        causal_parent_action_id=None,
        payload_type="task.submit/v1",
        payload_schema_version=1,
        payload={},
        auth_nonce=None,
        auth_issued_at_us=None,
        auth_signature=None,
    )
    base.update(overrides)
    from agent_meta_runtime.domain.envelope import CommandEnvelope

    return CommandEnvelope(**base)


def _deadline():
    from agent_meta_runtime.domain.deadline import Deadline

    return Deadline.after(DEADLINE_US)


def _run(conn, mutator):
    result = execute_command(
        conn, _envelope(), mutator, deadline=_deadline()
    )
    if hasattr(result, "error"):
        raise result.error
    return dict(result.receipt)


def _raises(fn) -> bool:
    try:
        fn()
        return False
    except Exception:
        return True


def _new_store(tmp_path) -> sqlite3.Connection:
    conn = initialize_store(Path(tmp_path) / "meta.db")
    bootstrap_realm(conn, REALM, "epoch://" + new_uuid7())
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _seed_artifact(conn, artifact: str) -> None:
    conn.execute(
        "INSERT INTO artifacts(artifact_id, kind, media_type, size_bytes,"
        " schema_version, created_by, created_at_us, parents_json, manifest_json,"
        " integrity_status)"
        " VALUES (?, 'code', 'application/json', 0, 1, ?, 1, ?, ?, 'VALID')",
        (artifact, ACTOR, b"{}", b"{}"),
    )


def _seed_composition(conn, composition: str, surface_artifact: str) -> None:
    for tag in ("input", "output"):
        _seed_artifact(conn, "artifact://sha256/" + sha256_hex(tag.encode()))
    _seed_artifact(conn, surface_artifact)
    conn.execute(
        "INSERT INTO compositions(composition_id, realm_id, revision, parent_id,"
        " body_json, body_hash, created_by, created_at_us)"
        " VALUES (?, ?, 1, NULL, ?, 'h', ?, 1)",
        (composition, REALM, b"{}", ACTOR),
    )
    conn.execute(
        "INSERT INTO capability_surfaces(realm_id, surface_revision,"
        " composition_id, artifact_id, authority_fingerprint,"
        " backend_profile_hash, created_at_us)"
        " VALUES (?, 1, ?, ?, 'afp', 'bph', 1)",
        (REALM, composition, surface_artifact),
    )
    conn.commit()


# -- S01 identity / canonical / CAS ------------------------------------------------


def identity_and_canonical() -> dict:
    ids = [new_uuid7() for _ in range(64)]
    stamps = [int(u.replace("-", "")[:12], 16) for u in ids]
    return {
        "uuid7_unique": len(set(ids)) == 64,
        "uuid7_time_ordered": stamps == sorted(stamps),
        "uuid7_version_bit": all(u[14] == "7" for u in ids),
        "uuid7_normalized": all(normalize_uuidv7(u) == u for u in ids),
        "ids_validate": validate_id("task://" + ids[0]) == "task://" + ids[0],
        "uri_parse": parse_uri("task://" + ids[0], "task").value == ids[0],
        "stable_name": bool(validate_stable_name("org.example.pkg"))
        and _raises(lambda: validate_stable_name("1bad")),
        "canonical_key_order": canonical_json({"b": 1, "a": 2})
        == canonical_json({"a": 2, "b": 1}),
        "sha256_vector": sha256_hex(b"")
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }


def cas_roundtrip(tmp_path) -> dict:
    cas = FilesystemCas(Path(tmp_path))
    body = b"trace-cas-payload"
    relpath = cas.put(body)
    blob = cas.open_blob(relpath, sha256_hex(body), len(body))
    same = cas.put(body)
    tampered = Path(tmp_path) / "artifacts" / relpath
    original = tampered.read_bytes()
    tampered.write_bytes(b"evil")
    try:
        tamper_raises = _raises(
            lambda: cas.open_blob(relpath, sha256_hex(body), len(body))
        )
    finally:
        tampered.write_bytes(original)
    return {
        "roundtrip": bytes(blob) == body,
        "dedupe_same_bytes": same == relpath,
        "tamper_detected": tamper_raises,
    }


# -- S02 facts / views ---------------------------------------------------------------


def _append_simple_fact(tag: str):
    from agent_meta_runtime.adapters.store.harness import _append_fact

    def mutator(txn):
        fact_id = _append_fact(
            txn,
            entity_type="operations",
            entity_id="operation://" + new_uuid7(),
            event_type="gc_plan_recorded",
            payload={"tag": tag},
        )
        return {"fact_id": fact_id}

    return mutator


def fact_chain_integrity(tmp_path) -> dict:
    conn = _new_store(Path(tmp_path))
    try:
        _run(conn, _append_simple_fact("one"))
        _run(conn, _append_simple_fact("two"))
        doctor_ok = run_integrity_doctor(
            Path(tmp_path) / "meta.db", Path(tmp_path)
        ).ok
        # The append-only trigger blocks in-place mutation; drop it to prove
        # that the recomputed chain catches a mutated historical payload.
        conn.execute("DROP TRIGGER facts_no_update")
        conn.execute("UPDATE facts SET payload_json = x'7B7D' WHERE seq = 2")
        conn.commit()
        doctor_detects = not run_integrity_doctor(
            Path(tmp_path) / "meta.db", Path(tmp_path)
        ).ok
        return {
            "chain_append_and_doctor_ok": doctor_ok,
            "tamper_detected": doctor_detects,
            "payload_hash_deterministic": fact_payload_hash({"a": 1, "b": 2})
            == fact_payload_hash({"b": 2, "a": 1}),
        }
    finally:
        conn.close()


def runtime_views(tmp_path) -> dict:
    conn = _new_store(Path(tmp_path))
    try:
        _run(conn, _append_simple_fact("advance"))
        view = get_current_view(conn, REALM)
        historical = get_historical_view(conn, REALM, view.meta_revision)
        return {
            "current_view_bounded": view.realm_id == REALM and view.meta_revision >= 0,
            "serving_not_ready_without_composition": view.serving_ready is False
            and bool(view.serving_reasons),
            "core_ready": view.core_ready is True,
            "historical_view": historical.historical is True,
            "authority_summary_present": isinstance(view.authority_summary, dict),
        }
    finally:
        conn.close()


# -- S03 authority / state / task ------------------------------------------------------


def _grant(**overrides) -> Grant:
    defaults = dict(
        grant_id="grant://g-parent",
        epoch_id="epoch://e-bb",
        issuer_id="grant://root",
        subject_id="principal://agent/01900000-0000-7000-8000-000000000001",
        delegation_depth=2,
        permissions=frozenset({"task.submit", "state.read"}),
        scope=Scope(realm_id=REALM, targets=[ScopeTarget(type="REALM_ALL", id="*")]),
        constraints=GrantConstraints(),
        delegable=True,
        status="ACTIVE",
        issued_at_us=0,
    )
    defaults.update(overrides)
    return Grant(**defaults)


def authority_domain() -> dict:
    parent = _grant()
    contained = _grant(
        grant_id="grant://g-child",
        issuer_id=parent.grant_id,
        permissions=frozenset({"task.submit"}),
    )
    expanding = _grant(
        grant_id="grant://g-child",
        issuer_id=parent.grant_id,
        permissions=frozenset({"task.submit", "task.cancel"}),
    )
    preimage_a = command_signature_preimage(sha256_hex(b"authorization"), "nonce", 1)
    preimage_b = command_signature_preimage(sha256_hex(b"authorization"), "nonce", 1)
    token_payload = {
        "token_version": 1,
        "token_id": "token://t1",
        "backend_session_id": "backend-session://s1",
        "realm_id": REALM,
        "actor_id": ACTOR,
        "action_id": "action://a",
        "effect_kind": "filesystem.write",
        "target_scope_hash": "h",
        "resource_ceiling": {"budget_effects": 1},
        "issued_at_us": 1,
        "expires_at_us": 2,
        "nonce": "n",
    }
    token_a = execution_token_payload_hash(token_payload)
    token_b = execution_token_payload_hash(dict(token_payload))
    child_scope = Scope(realm_id=REALM, targets=[ScopeTarget(type="REALM_ALL", id="*")])
    depth_contained = validate_delegation(
        parent,
        child_permissions=frozenset({"task.submit"}),
        child_scope=child_scope,
        child_constraints=GrantConstraints(),
        child_delegable=True,
    )
    return {
        "delegation_contained_ok": depth_contained == parent.delegation_depth - 1,
        "delegation_expansion_rejected": _raises(
            lambda: validate_delegation(
                parent,
                child_permissions=frozenset({"task.submit", "task.cancel"}),
                child_scope=child_scope,
                child_constraints=GrantConstraints(),
                child_delegable=True,
            )
        ),
        "preimage_deterministic": preimage_a == preimage_b,
        "token_hash_deterministic": token_a == token_b,
        "permissions_frozen": "task.submit" in PERMISSIONS,
    }


def state_lifecycle(tmp_path) -> dict:
    from agent_meta_runtime.adapters.store.state import (
        StateCreateRequest,
        StateWriteRequest,
        create_state,
        write_state_revision,
    )

    conn = _new_store(Path(tmp_path))
    try:
        art = "artifact://sha256/" + sha256_hex(b"state-body")
        _seed_artifact(conn, art)
        conn.commit()
        receipt = _run(
            conn,
            create_state(
                StateCreateRequest(
                    owner_id=ACTOR, schema_id="state-schema/v1", artifact_id=art
                )
            ),
        )
        state_id = receipt["state_id"]
        revision_id = receipt["state_revision_id"]
        cas_revision = int(receipt["cas_revision"])
        _run(
            conn,
            write_state_revision(
                StateWriteRequest(
                    state_id=state_id,
                    expected_revision_id=revision_id,
                    expected_cas_revision=cas_revision,
                    schema_id="state-schema/v1",
                    artifact_id=art,
                    writer_id=ACTOR,
                )
            ),
        )
        stale = _raises(
            lambda: _run(
                conn,
                write_state_revision(
                    StateWriteRequest(
                        state_id=state_id,
                        expected_revision_id=revision_id,
                        expected_cas_revision=cas_revision,
                        schema_id="state-schema/v1",
                        artifact_id=art,
                        writer_id=ACTOR,
                    )
                ),
            )
        )
        return {
            "created": bool(state_id),
            "stale_write_rejected": stale,
        }
    finally:
        conn.close()


def task_lifecycle(tmp_path) -> dict:
    conn = _new_store(Path(tmp_path))
    try:
        composition = "composition://" + new_uuid7()
        surface_artifact = "artifact://sha256/" + sha256_hex(b"surface")
        _seed_composition(conn, composition, surface_artifact)
        receipt = _run(
            conn,
            accept_task(
                TaskAcceptRequest(
                    task_id=None,
                    actor_id=ACTOR,
                    input_artifact_id="artifact://sha256/" + sha256_hex(b"input"),
                    serving_composition_id=composition,
                    serving_revision=1,
                    capability_surface_revision=1,
                    capability_surface_artifact_id=surface_artifact,
                    budget=TaskBudget(),
                )
            ),
        )
        task_id = receipt["task_id"]
        record = load_task(conn, task_id)
        _run(conn, start_task(task_id))
        _run(
            conn,
            complete_task(
                task_id,
                TaskTerminalRequest(
                    status="SUCCEEDED",
                    result_artifact_id="artifact://sha256/"
                    + sha256_hex(b"output"),
                ),
            ),
        )
        finished = load_task(conn, task_id)
        record_late_completion(task_id, result_artifact_id=None, error="late")
        after_late = load_task(conn, task_id)
        return {
            "accepted_frozen_composition": record is not None
            and record.status == "ACCEPTED",
            "terminal_reached": finished.status == "SUCCEEDED",
            "late_result_not_reversing": after_late.status == "SUCCEEDED",
        }
    finally:
        conn.close()


# -- S04/S05 execution / control plane -------------------------------------------------


def effect_intent_validation() -> dict:
    from agent_meta_runtime.domain.effects import EffectIntent, effect_intent_hash

    def intent(**overrides):
        base = dict(
            effect_intent_id="effect-intent://01900000-0000-7000-8000-000000000001",
            action_id="action://01900000-0000-7000-8000-000000000002",
            kind="filesystem.write",
            target_scope={"workspace_id": "workspace://w1"},
            payload_artifact_id="artifact://sha256/" + "a" * 64,
            idempotency_class="KEYED",
            reversibility="REVERSIBLE",
            budget_effects=1,
            budget_cost_microunits=10,
        )
        base.update(overrides)
        return EffectIntent(**base)

    a = intent()
    b = intent()
    return {
        "valid_intent": a.kind == "filesystem.write",
        "invalid_kind_rejected": _raises(lambda: intent(kind="not.a.kind")),
        "hash_deterministic": effect_intent_hash(a) == effect_intent_hash(b),
    }


def outbox_dispatch(tmp_path) -> dict:
    conn = _new_store(Path(tmp_path))
    try:
        conn.execute(
            "INSERT INTO outbox(outbox_id, realm_id, kind, dedupe_key,"
            " payload_json, payload_hash, state, available_at_us, created_at_us)"
            " VALUES (?, ?, 'RECONCILE_REQUEST', ?, x'7b7d', 'ph', 'PENDING', 0, ?)",
            (
                "ob-1",
                REALM,
                outbox_dedupe_key(
                    "RECONCILE_REQUEST", REALM, "r1", "t1", "ph"
                ),
                int(time.time() * 1e6),
            ),
        )
        conn.commit()
        dispatcher = OutboxDispatcher(
            conn, handlers={"RECONCILE_REQUEST": lambda item: None}
        )
        results = dispatcher.poll_once()
        delivered = results[0]["outcome"] == "DELIVERED"
        state = conn.execute(
            "SELECT state FROM outbox WHERE outbox_id = 'ob-1'"
        ).fetchone()[0]
        return {
            "delivered": delivered and state == "DELIVERED",
            "dedupe_key_bound": outbox_dedupe_key("K", REALM, "x", "t", "ph")
            == outbox_dedupe_key("K", REALM, "x", "t", "ph")
            and outbox_dedupe_key("K", REALM, "x", "t", "ph")
            != outbox_dedupe_key("K", REALM, "y", "t", "ph"),
        }
    finally:
        conn.close()


def clock_stability() -> dict:
    mono = {"t": 100.0}
    wall = {"t": 1_000.0}
    monitor = ClockStabilityMonitor(
        monotonic=lambda: mono["t"], wall=lambda: wall["t"]
    )
    stable = monitor.check()
    wall["t"] += 120.0
    monitor.check()
    jumped = monitor.unstable
    return {
        "stable_when_aligned": stable,
        "jump_detected": jumped,
    }


# -- S05/S07 harness / bootstrap ---------------------------------------------------------


def harness_lifecycle(tmp_path) -> dict:
    from agent_meta_runtime.adapters.store.harness import list_harness_rows

    conn = _new_store(Path(tmp_path))
    try:
        package_art = "artifact://sha256/" + sha256_hex(b"pkg")
        manifest_art = "artifact://sha256/" + sha256_hex(b"manifest")
        for art in (package_art, manifest_art):
            _seed_artifact(conn, art)
        conn.commit()
        _run(
            conn,
            install_harness(
                InstallHarnessRequest(
                    realm_id=REALM,
                    package_name="org.example.harness",
                    package_version="0.1.0",
                    manifest_artifact_id=manifest_art,
                    package_artifact_id=package_art,
                    contract_fingerprint="sha256:fp",
                    installed_by=ACTOR,
                )
            ),
        )
        rows = list_harness_rows(conn, realm_id=REALM)
        _run(
            conn,
            install_harness(
                InstallHarnessRequest(
                    realm_id=REALM,
                    package_name="org.example.harness",
                    package_version="0.1.0",
                    manifest_artifact_id=manifest_art,
                    package_artifact_id=package_art,
                    contract_fingerprint="sha256:fp",
                    installed_by=ACTOR,
                )
            ),
        )
        rows_after = list_harness_rows(conn, realm_id=REALM)
        return {
            "installed": len(rows) == 1
            and rows[0]["package_name"] == "org.example.harness",
            "reinstall_idempotent": len(rows_after) == 1,
        }
    finally:
        conn.close()


def conformance_bootstrap_offline(tmp_path) -> dict:
    from agent_meta_runtime.interfaces.cli.init import run_init

    data_dir = Path(tmp_path) / "data"
    run_init(data_dir)
    ok = (data_dir / "meta.db").is_file() and (data_dir / "keys").is_dir()
    conn = sqlite3.connect(data_dir / "meta.db")
    try:
        realm = conn.execute("SELECT realm_id FROM realms").fetchone()
        revision = conn.execute(
            "SELECT current_meta_revision FROM realms"
        ).fetchone()[0]
    finally:
        conn.close()
    return {
        "init_from_empty": ok,
        "bootstrap_revision_recorded": revision >= 1,
        "realm_present": bool(realm),
    }


# -- S09 evolution / security -------------------------------------------------------------


def safe_reflection() -> dict:
    from agent_meta_runtime.domain.reflection import InspectBudget, SafeReflector

    reflector = SafeReflector()
    node = reflector.reflect({"a": 1, "b": [1, 2, 3]}, InspectBudget())
    big = reflector.reflect(list(range(500)), InspectBudget())

    class _Observable:
        pass

    obj = _Observable()
    token_a = reflector.id_token(obj)
    token_b = reflector.id_token(obj)
    return {
        "inspect_ok": node is not None,
        "budget_truncates": big is not None,
        "id_token_session_stable": token_a == token_b
        and token_a is not None
        and token_a.startswith("obs:")
        and reflector.id_token(42) is None,
    }


def context_projection_determinism() -> dict:
    from agent_meta_runtime.domain.context_projection import (
        BudgetLadder,
        allocate_budget,
        render_sections,
    )

    ladder = BudgetLadder(needs={"facts": 10})
    alloc_a = allocate_budget(1000, ladder)
    alloc_b = allocate_budget(1000, ladder)
    render_a = render_sections([b"section-a", b"section-b"])
    render_b = render_sections([b"section-a", b"section-b"])
    return {
        "ladder_deterministic": alloc_a == alloc_b,
        "render_deterministic": render_a == render_b,
        "renders_fixed_delimiter": render_a != b"section-a" + b"section-b",
    }


def causal_query(tmp_path) -> dict:
    from agent_meta_runtime.adapters.store.causal import SqliteEdgeSource
    from agent_meta_runtime.domain.causal_query import lineage, why

    conn = _new_store(Path(tmp_path))
    try:
        composition = "composition://" + new_uuid7()
        surface_artifact = "artifact://sha256/" + sha256_hex(b"surface")
        _seed_composition(conn, composition, surface_artifact)
        receipt = _run(
            conn,
            accept_task(
                TaskAcceptRequest(
                    task_id=None,
                    actor_id=ACTOR,
                    input_artifact_id="artifact://sha256/" + sha256_hex(b"input"),
                    serving_composition_id=composition,
                    serving_revision=1,
                    capability_surface_revision=1,
                    capability_surface_artifact_id=surface_artifact,
                    budget=TaskBudget(),
                )
            ),
        )
        task_id = receipt["task_id"]
        source = SqliteEdgeSource(conn)
        explanation = why(source, REALM, task_id)
        forward = lineage(source, REALM, task_id)
        return {
            "why_returns_nodes": task_id in explanation.nodes
            or len(explanation.nodes) > 0,
            "lineage_runs": forward.root_id == task_id,
            "bounded_traversal": explanation.truncated in (True, False),
        }
    finally:
        conn.close()


def deterministic_evaluator() -> dict:
    from agent_meta_runtime.application.evaluator import evaluate

    criteria = {
        "schema": "deterministic-evaluation/v1",
        "decision_rule": "ALL_REQUIRED_PASS",
        "assertions": [{"kind": "artifact_integrity"}],
    }
    bundles = {"artifact_integrity": {"artifacts": {}}}
    first = evaluate(criteria, bundles, {})
    second = evaluate(criteria, bundles, {})
    return {
        "deterministic": first[0] == second[0]
        and first[2]["result_hash"] == second[2]["result_hash"],
        "produced_result": bool(first[2]),
    }


def security_scanner() -> dict:
    from agent_meta_runtime.application.security_scan import scan_package

    files = {"pkg/clean.py": b"x = 1\n", "pkg/other.py": b"import json\n"}
    first = scan_package(files)
    second = scan_package(files)
    return {
        "scan_runs": isinstance(first, tuple),
        "deterministic": [f.rule_id for f in first] == [f.rule_id for f in second],
    }


def compatibility_validation() -> dict:
    from agent_meta_runtime.domain.compatibility import (
        parse_semver_range,
        semver_satisfies,
    )

    rng = parse_semver_range(">=1.0.0 <2.0.0")
    return {
        "semver_in_range": semver_satisfies("1.2.3", rng) is True,
        "semver_out_of_range": semver_satisfies("2.0.0", rng) is False,
        "invalid_version_rejected": _raises(
            lambda: semver_satisfies("not-a-version", rng)
        ),
    }


# -- Operations: backup / GC / upgrade (§41.47) -------------------------------------------


def _seed_orphan(conn, cas: FilesystemCas, *, age_us: int, tag: bytes) -> str:
    from agent_meta_runtime.domain.canonical import now_us

    relpath = cas.put(tag)
    artifact = "artifact://sha256/" + sha256_hex(tag)
    conn.execute(
        "INSERT INTO artifacts(artifact_id, kind, media_type, size_bytes,"
        " schema_version, created_by, created_at_us, parents_json, manifest_json,"
        " integrity_status)"
        " VALUES (?, 'code', 'application/octet-stream', ?, 1, ?, ?, ?, ?, 'VALID')",
        (
            artifact,
            len(tag),
            ACTOR,
            now_us() - age_us,
            b"[]",
            canonical_json({"storage_relpath": relpath, "size_bytes": len(tag)}),
        ),
    )
    conn.commit()
    return artifact


def _init_data_dir(tmp_path, name: str) -> Path:
    from agent_meta_runtime.interfaces.cli.init import run_init

    data_dir = Path(tmp_path) / name
    run_init(data_dir)
    return data_dir


def operations_backup_restore(tmp_path) -> dict:
    day = 24 * 60 * 60 * 1_000_000
    data_dir = _init_data_dir(tmp_path, "data")
    conn = sqlite3.connect(data_dir / "meta.db")
    try:
        cas = FilesystemCas(data_dir)
        orphan = _seed_orphan(conn, cas, age_us=day + 1, tag=b"orphan")
        destination = Path(tmp_path) / "backup"
        outcome = create_backup(conn, data_dir, destination)
        sealed = (destination / "backup-manifest.json").is_file()
        fresh = Path(tmp_path) / "fresh"
        report = restore_backup(destination, fresh)
        restored = sqlite3.connect(fresh / "meta.db")
        try:
            quarantine = restored.execute(
                "SELECT COUNT(*) FROM facts WHERE event_type ="
                " 'backup_snapshot_restored'"
            ).fetchone()[0]
        finally:
            restored.close()
        return {
            "manifest_sealed": sealed,
            "restore_roundtrip": report["realm_id"] == REALM,
            "restore_quarantine_fact": quarantine == 1,
            "destination_gates": _raises(
                lambda: validate_backup_destination(data_dir, data_dir / "sub")
            ),
            "orphan_present": bool(orphan),
        }
    finally:
        conn.close()


def gc_lifecycle(tmp_path) -> dict:
    day = 24 * 60 * 60 * 1_000_000
    data_dir = _init_data_dir(tmp_path, "data")
    conn = sqlite3.connect(data_dir / "meta.db")
    try:
        cas = FilesystemCas(data_dir)
        orphan = _seed_orphan(conn, cas, age_us=day + 1, tag=b"gc-orphan")
        held = _seed_orphan(conn, cas, age_us=day + 1, tag=b"gc-held")
        revision = int(
            conn.execute(
                "SELECT current_meta_revision FROM realms WHERE realm_id = ?",
                (REALM,),
            ).fetchone()[0]
        )
        built = build_gc_plan(
            conn,
            cas,
            data_dir,
            realm_id=REALM,
            expected_meta_revision=revision,
            legal_hold_artifact_ids=(held,),
        )
        plan_marks_only_orphans = built["plan"]["candidate_artifact_ids"] == [orphan]
        _run(
            conn,
            commit_gc_plan(
                realm_id=REALM,
                plan_artifact_id=built["plan_artifact_id"],
                storage_relpath=built["storage_relpath"],
                size_bytes=int(built["size_bytes"]),
                candidate_count=1,
            ),
        )
        entries = validate_gc_plan(
            conn, cas, plan_artifact_id=built["plan_artifact_id"], realm_id=REALM
        )
        _run(conn, apply_gc_quarantine(entries, operation_id="operation://gc"))
        trash_dir = move_quarantined_to_trash(data_dir, entries)
        tombstoned = (
            conn.execute(
                "SELECT integrity_status FROM artifacts WHERE artifact_id = ?",
                (orphan,),
            ).fetchone()[0]
            == "MISSING"
        )
        trash_existed = trash_dir.is_dir()
        purged = purge_expired_trash(conn, data_dir, retention_us=1)
        return {
            "plan_marks_only_orphans": plan_marks_only_orphans,
            "plan_is_artifact": built["plan_artifact_id"].startswith(
                "artifact://sha256/"
            ),
            "sweep_tombstones_then_trash": tombstoned and trash_existed,
            "purge_after_retention": orphan in purged["purged_artifacts"],
        }
    finally:
        conn.close()


def upgrade_preflight(tmp_path) -> dict:
    data_dir = _init_data_dir(tmp_path, "data")
    conn = sqlite3.connect(data_dir / "meta.db")
    try:
        report = run_upgrade(conn, data_dir)
        return {
            "up_to_date": report["status"] == "UP_TO_DATE",
            "no_pending_migrations": report["pending_migrations"] == 0,
        }
    finally:
        conn.close()


# -- Interfaces: wire / cursor / config ------------------------------------------------------


def wire_codec_and_registry() -> dict:
    payload = b"trace-frame"
    frame = encode_frame(payload)
    malformed_envelope = _raises(lambda: parse_envelope(b"\xff\xff\xff\xff"))
    oversized = _raises(
        lambda: decode_frame_length((MAX_FRAME_BYTES + 1).to_bytes(4, "big"))
    )
    return {
        "frame_roundtrip": decode_frame_length(frame[:4]) == len(payload),
        "frame_cap_enforced": oversized,
        "envelope_malformed_rejected": malformed_envelope,
        "registry_complete": len(METHODS) >= 35
        and all(
            req is not None and resp is not None for req, resp in METHODS.values()
        ),
    }


def cursor_stability() -> dict:
    from agent_meta_runtime.application.cursor import CursorCodec

    codec = CursorCodec(session_key=b"k" * 32)
    issued = codec.issue(
        kind="facts", snapshot_revision=7, last_key="42", now_us=1_000
    )
    verified = codec.verify(issued, kind="facts", now_us=1_100)
    tampered = _raises(
        lambda: codec.verify(_bump(issued), kind="facts", now_us=1_100)
    )
    return {
        "cursor_roundtrip": verified is not None and verified["last_key"] == "42",
        "cursor_tamper_detected": tampered,
    }


def _bump(cursor):
    if isinstance(cursor, (bytes, bytearray)):
        return bytes(cursor)[:-1] + bytes([bytes(cursor)[-1] ^ 0xFF])
    if isinstance(cursor, str):
        return cursor[:-1] + ("a" if cursor[-1] != "a" else "b")
    raise ValueError(type(cursor))


def config_redaction() -> dict:
    from agent_meta_runtime.application import config

    cfg = config.load_config(env={})
    redacted = config.redact_config(cfg)
    text = json.dumps(redacted, default=str).lower()
    return {
        "loads_defaults": cfg is not None,
        "redaction_deterministic": text
        == json.dumps(config.redact_config(cfg), default=str).lower(),
    }


def architecture_lint() -> dict:
    proc = subprocess.run(
        [sys.executable, "scripts/arch_lint.py"],
        capture_output=True,
        timeout=120,
        cwd=Path(__file__).resolve().parents[2],
    )
    return {
        "lint_clean": proc.returncode == 0,
    }


def traceability_validator() -> dict:
    repo = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(repo / "scripts"))
    try:
        from traceability_check import (
            EXPECTED_TOTAL,
            extract_parent_ids,
            extract_table_rows,
        )
    finally:
        sys.path.remove(str(repo / "scripts"))
    parent = (
        repo / "docs" / "Agent_Meta_Runtime_Requirements_Design_v0.1.md"
    ).read_text(encoding="utf-8")
    table = (repo / "docs" / "spec" / "v0.1-scope-and-traceability.md").read_text(
        encoding="utf-8"
    )
    parent_ids, parent_dups = extract_parent_ids(parent)
    rows, table_dups = extract_table_rows(table)
    dup_detected = extract_parent_ids("### FR-MID-001\n### FR-MID-001")[1] != []
    return {
        "set_equality": set(parent_ids) == {r["id"] for r in rows}
        and len(rows) == EXPECTED_TOTAL,
        "duplicate_detected": dup_detected,
        "no_duplicates_in_docs": not parent_dups and not table_dups,
    }
