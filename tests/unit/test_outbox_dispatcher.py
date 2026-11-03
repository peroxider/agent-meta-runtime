"""Step 05 control-plane tests: outbox dispatcher (§41.38, §41.59.4)."""

from __future__ import annotations

import hashlib
import asyncio
import time

import pytest

from agent_meta_runtime.adapters.store import initialize_store
from agent_meta_runtime.adapters.store.uow import bootstrap_realm
from agent_meta_runtime.application.outbox import DeliveryError, OutboxDispatcher
from agent_meta_runtime.domain.clock import ClockStabilityMonitor
from agent_meta_runtime.domain.ids import new_uuid7
from agent_meta_runtime.domain.errors import StableError, ErrorCode
from agent_meta_runtime.domain.outbox import outbox_dedupe_key

REALM = "realm://main"


@pytest.fixture()
def odb(tmp_path):
    conn = initialize_store(tmp_path / "meta.db")
    bootstrap_realm(conn, REALM, "epoch://" + new_uuid7())
    yield conn
    conn.close()


def _insert(conn, outbox_id, kind, dedupe, *, state="PENDING", created_us=None):
    conn.execute(
        "INSERT INTO outbox(outbox_id, realm_id, kind, dedupe_key, payload_json,"
        " payload_hash, state, available_at_us, created_at_us)"
        " VALUES (?, ?, ?, ?, x'7b7d', 'ph', ?, 0, ?)",
        (outbox_id, REALM, kind, dedupe, state, created_us or int(time.time() * 1e6)),
    )


def test_delivery_commits_terminal_state(odb):
    _insert(odb, "ob-1", "RECONCILE_REQUEST", "dk1")
    odb.commit()
    d = OutboxDispatcher(odb, handlers={"RECONCILE_REQUEST": lambda item: None})
    results = d.poll_once()
    assert results[0]["outcome"] == "DELIVERED"
    assert odb.execute("SELECT state FROM outbox WHERE outbox_id='ob-1'").fetchone()[0] == "DELIVERED"


def test_async_delivery_releases_transaction_and_cancel_abandons_lease(odb):
    _insert(odb, "async-1", "RECONCILE_REQUEST", "async-key")
    odb.commit()
    async def scenario():
        entered = asyncio.Event()
        async def waiting(item):
            assert not odb.in_transaction
            entered.set()
            await asyncio.Event().wait()
        dispatcher = OutboxDispatcher(odb, handlers={"RECONCILE_REQUEST": waiting})
        pending = asyncio.create_task(dispatcher.poll_once_async())
        await asyncio.wait_for(entered.wait(), 1)
        assert odb.execute("SELECT state FROM outbox WHERE outbox_id='async-1'").fetchone()[0] == "LEASED"
        with pytest.raises(StableError) as busy:
            await dispatcher.poll_once_async()
        assert busy.value.code == ErrorCode.ALREADY_RUNNING
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        assert not odb.in_transaction
        assert odb.execute("SELECT state,lease_owner FROM outbox WHERE outbox_id='async-1'").fetchone() == ("PENDING", None)
        async def success(item):
            assert not odb.in_transaction
        dispatcher._handlers["RECONCILE_REQUEST"] = success
        delivered = await dispatcher.poll_once_async()
        assert delivered[0]["outcome"] == "DELIVERED"
    asyncio.run(scenario())


def test_foreign_lease_recovery_resets_to_pending(odb):
    _insert(odb, "ob-2", "RECONCILE_REQUEST", "dk2", state="LEASED")
    odb.execute("UPDATE outbox SET lease_owner='dead-instance' WHERE outbox_id='ob-2'")
    odb.commit()
    d = OutboxDispatcher(odb, handlers={})
    assert d.recover_foreign_leases() == 1
    row = odb.execute("SELECT state, lease_owner FROM outbox WHERE outbox_id='ob-2'").fetchone()
    assert row == ("PENDING", None)


def test_retry_backoff_then_dead_letter_and_critical_signal(odb):
    wall = {"t": 2_000_000.0}
    mono = {"t": 1000.0}
    odb.execute(
        "INSERT INTO outbox(outbox_id, realm_id, kind, dedupe_key, payload_json,"
        " payload_hash, state, available_at_us, created_at_us)"
        " VALUES ('ob-3', ?, 'OPERATION_RUN', 'dk3', x'7b7d', 'ph3', 'PENDING', 0, ?)",
        (REALM, int(wall["t"] * 1e6)),
    )
    odb.commit()

    def flaky(item):
        raise DeliveryError("boom")

    d = OutboxDispatcher(
        odb, handlers={"OPERATION_RUN": flaky}, max_attempts=2,
        monotonic=lambda: mono["t"], wall=lambda: wall["t"],
    )
    states = []
    for _ in range(3):
        d.poll_once()
        states.append(
            odb.execute("SELECT state, attempts FROM outbox WHERE outbox_id='ob-3'").fetchone()
        )
        mono["t"] += 20.0
        wall["t"] += 20.0
    assert states[0][1] == 1 and states[0][0] == "PENDING"  # retry scheduled
    assert states[-1][0] == "DEAD_LETTER" and states[-1][1] == 3
    assert d.has_critical_dead_letters() is True  # OPERATION_RUN is critical


def test_clock_instability_blocks_new_leases_then_recovers(odb):
    mono = {"t": 100.0}
    wall = {"t": 1_000_000.0}
    clock = ClockStabilityMonitor(monotonic=lambda: mono["t"], wall=lambda: wall["t"])
    d = OutboxDispatcher(
        odb, handlers={}, clock=clock,
        monotonic=lambda: mono["t"], wall=lambda: wall["t"],
    )
    odb.execute(
        "INSERT INTO outbox(outbox_id, realm_id, kind, dedupe_key, payload_json,"
        " payload_hash, state, available_at_us, created_at_us)"
        " VALUES ('ob-4', ?, 'TERMINAL_ACK', 'dk4', x'7b7d', 'ph4', 'PENDING', 0, ?)",
        (REALM, int(wall["t"] * 1e6)),
    )
    odb.commit()
    mono["t"] += 100.0  # huge monotonic jump, tiny wall jump → unstable
    wall["t"] += 1.0
    assert clock.check() is False and clock.unstable
    assert d.poll_once() == []  # no new leases while unstable
    for _ in range(3):  # recovery streak: 3 stable checks 10s apart
        mono["t"] += 10.0
        wall["t"] += 10.0
        clock.check()
    assert clock.unstable is False
    results = d.poll_once()
    assert results and results[0]["outcome"] == "RETRY_SCHEDULED"  # no handler → retry


def test_missing_handler_schedules_retry(odb):
    _insert(odb, "ob-5", "EXECUTION_SUBMIT", "dk5")
    odb.commit()
    d = OutboxDispatcher(odb, handlers={})
    results = d.poll_once()
    assert results[0]["outcome"] == "RETRY_SCHEDULED"
    row = odb.execute("SELECT state, last_error_json FROM outbox WHERE outbox_id='ob-5'").fetchone()
    assert row[0] == "PENDING" and b"no handler" in bytes(row[1])


def test_dedupe_key_is_sha256_of_nul_joined_preimage():
    expected = hashlib.sha256(b"k\x00realm://main\x00e\x001\x00ph").hexdigest()
    assert outbox_dedupe_key("k", "realm://main", "e", "1", "ph") == expected
    assert outbox_dedupe_key("k", "realm://main", "e", "1", "ph") != outbox_dedupe_key(
        "k", "realm://main", "e", "2", "ph"
    )
