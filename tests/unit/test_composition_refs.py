"""Step 03 composition tests: immutable revisions, three-reference CAS,
ref history, concurrent-conflict semantics (§41.37, §41.38, §41.42.2)."""

from __future__ import annotations

import pytest

from agent_meta_runtime.adapters.store import (
    CompositionCreateRequest,
    SetDesiredRequest,
    SetRealizedRequest,
    SetServingRequest,
    create_composition,
    set_desired,
    set_realized,
    set_serving,
)
from agent_meta_runtime.domain.errors import ErrorCode, StableError

from conftest import ACTOR, execute_command_result, run_command

REALM = "realm://main"


def _body(realm=REALM, tag="default"):
    return {"schema": "composition/v1", "realm_id": realm, "tag": tag}


def test_composition_revisions_are_immutable(store):
    conn, realm, _tmp = store
    r1 = run_command(
        conn,
        create_composition(
            CompositionCreateRequest(realm_id=realm, body=_body(tag="v1"), created_by=ACTOR, revision=1)
        ),
    )
    composition_id = r1["composition_id"]
    r2 = run_command(
        conn,
        create_composition(
            CompositionCreateRequest(
                realm_id=realm,
                body=_body(tag="v2"),
                created_by=ACTOR,
                revision=2,
                parent_id=composition_id,
            )
        ),
    )
    assert r2["composition_id"] != composition_id
    assert r2["body_hash"] != r1["body_hash"]
    # Re-committing the same composition_id (or the same realm revision) is refused.
    dup = execute_command_result(
        conn,
        create_composition(
            CompositionCreateRequest(
                realm_id=realm,
                body=_body(tag="v3"),
                created_by=ACTOR,
                revision=3,
                composition_id=composition_id,
            )
        ),
    )
    assert dup.error is not None
    assert dup.error.code == "ALREADY_EXISTS"
    # Revision rows keep their original bodies and hashes.
    rows = conn.execute(
        "SELECT revision, body_hash, body_json FROM compositions"
        " WHERE composition_id IN (?, ?) ORDER BY revision",
        (composition_id, r2["composition_id"]),
    ).fetchall()
    assert [row[0] for row in rows] == [1, 2]
    assert bytes(rows[0][2]).decode("utf-8").find('"v1"') != -1
    assert bytes(rows[1][2]).decode("utf-8").find('"v2"') != -1
    assert rows[0][1] == r1["body_hash"]
    assert rows[1][1] == r2["body_hash"]
    # A body without the schema tag or with a foreign realm is invalid.
    with pytest.raises(StableError):
        create_composition(
            CompositionCreateRequest(realm_id=realm, body={"schema": "other"}, created_by=ACTOR)
        )
    with pytest.raises(StableError):
        create_composition(
            CompositionCreateRequest(
                realm_id=realm, body=_body(realm="realm://other"), created_by=ACTOR
            )
        )


def test_ref_cas_progression_and_history(store):
    conn, realm, _tmp = store
    run_command(
        conn,
        create_composition(
            CompositionCreateRequest(realm_id=realm, body=_body(), created_by=ACTOR, revision=1)
        ),
    )
    desired = run_command(
        conn, set_desired(SetDesiredRequest(realm_id=realm, revision=1, expected_cas=0))
    )
    assert desired == {"desired_revision": 1, "reconcile_status": "PENDING"}
    serving = run_command(
        conn, set_serving(SetServingRequest(realm_id=realm, revision=1, expected_cas=0))
    )
    assert serving == {"serving_revision": 1}
    realized = run_command(
        conn, set_realized(SetRealizedRequest(realm_id=realm, revision=1, expected_cas=0))
    )
    assert realized == {"realized_revision": 1, "reconcile_status": "READY"}
    row = conn.execute(
        "SELECT desired_revision, serving_revision, realized_revision,"
        " desired_cas, serving_cas, realized_cas, reconcile_status"
        " FROM composition_refs WHERE realm_id = ?",
        (realm,),
    ).fetchone()
    assert tuple(row) == (1, 1, 1, 1, 1, 1, "READY")
    # One history row per ref change, each bound to its fact.
    history = conn.execute(
        "SELECT desired_revision, serving_revision, realized_revision,"
        " reconcile_status, source_fact_id FROM composition_ref_history"
        " WHERE realm_id = ? ORDER BY meta_revision",
        (realm,),
    ).fetchall()
    assert len(history) == 3
    assert history[0][:4] == (1, 0, 0, "PENDING")
    assert history[1][:4] == (1, 1, 0, "APPLYING")
    assert history[2][:4] == (1, 1, 1, "READY")
    for row in history:
        fact = conn.execute(
            "SELECT event_type FROM facts WHERE fact_id = ?", (row[4],)
        ).fetchone()
        assert fact is not None
    events = {
        r[0]
        for r in conn.execute(
            "SELECT event_type FROM facts WHERE event_type IN"
            " ('reconcile_started','serving_switched','realization_completed')"
        ).fetchall()
    }
    assert events == {"reconcile_started", "serving_switched", "realization_completed"}


def test_stale_cas_never_overwrites(store):
    conn, realm, _tmp = store
    run_command(
        conn,
        create_composition(
            CompositionCreateRequest(realm_id=realm, body=_body(), created_by=ACTOR, revision=1)
        ),
    )
    run_command(
        conn,
        create_composition(
            CompositionCreateRequest(realm_id=realm, body=_body(tag="two"), created_by=ACTOR, revision=2)
        ),
    )
    run_command(
        conn, set_desired(SetDesiredRequest(realm_id=realm, revision=1, expected_cas=0))
    )
    # A concurrent planner still expects cas=0: rejected, nothing changes.
    stale = execute_command_result(
        conn, set_desired(SetDesiredRequest(realm_id=realm, revision=2, expected_cas=0))
    )
    assert stale.error is not None
    assert stale.error.code == "REVISION_CONFLICT"
    row = conn.execute(
        "SELECT desired_revision, desired_cas FROM composition_refs WHERE realm_id = ?",
        (realm,),
    ).fetchone()
    assert tuple(row) == (1, 1)
    # The winner proceeds with cas=1.
    run_command(
        conn, set_desired(SetDesiredRequest(realm_id=realm, revision=2, expected_cas=1))
    )
    row = conn.execute(
        "SELECT desired_revision, desired_cas FROM composition_refs WHERE realm_id = ?",
        (realm,),
    ).fetchone()
    assert tuple(row) == (2, 2)
    # History records only the committed changes (no rolled-back row).
    count = conn.execute(
        "SELECT COUNT(*) FROM composition_ref_history WHERE realm_id = ?", (realm,)
    ).fetchone()[0]
    assert count == 2


def test_set_desired_requires_committed_revision(store):
    conn, realm, _tmp = store
    missing = execute_command_result(
        conn, set_desired(SetDesiredRequest(realm_id=realm, revision=99, expected_cas=0))
    )
    assert missing.error is not None
    assert missing.error.code == "NOT_FOUND"
