"""Asynchronous delivery of real installation/reconcile work."""

import asyncio
import json

from ..domain.errors import ErrorCode, StableError
from ..domain.probe import HealthProbeDescriptor
from .reconciler import reconcile_id, slot_request_id, topological_slots


async def restore_bound_snapshots(plans, *, instantiate, probe_runner, withdraw_health, complete_restore):
    """Rebind actual serving/frozen snapshots without changing desired refs.

    A failed desired candidate is never retried by this recovery path. Each
    old snapshot reruns validation, its real factory and actual PURE health.
    Unavailable historical packages stay unready; Task recovery decides their
    outcome separately rather than silently selecting the current version.
    """
    for plan in plans:
        passed = True
        rid = reconcile_id(plan["realm_id"], plan["revision"], plan["body_hash"])
        for step in topological_slots(plan["body"]):
            slot = step["slot"]
            try:
                instance = await instantiate({**step, "request_id": slot_request_id(rid, slot, "instantiate"),
                    "reconcile_id": rid, "composition_id": plan["composition_id"], "realm_id": plan["realm_id"], "desired_revision": plan["revision"]})
                report = await probe_runner.run_async(HealthProbeDescriptor.from_descriptor(step["health_probe"]),
                    slot=slot, criticality=step["criticality"], reconcile_id=rid, composition_id=plan["composition_id"],
                    instance_id=instance["instance_id"], descriptor_revision=step["descriptor_revision"])
                if not report.passed:
                    passed = False
                    withdraw_health(plan["composition_id"], slot)
            except Exception:
                passed = False
                withdraw_health(plan["composition_id"], slot)
        complete_restore(plan["composition_id"], passed)


class HostControl:
    def __init__(self, reconciler, *, read_refs, startup=None):
        self.reconciler, self.read_refs = reconciler, read_refs
        self.stopping = False
        self.failure = None
        self.startup = startup

    async def deliver(self, item):
        payload = item["payload"] if "payload" in item else json.loads(item["payload_json"])
        desired, status = self.read_refs()
        requested = payload.get("revision", payload.get("desired_revision"))
        if requested is not None and int(requested) != desired:
            return  # stale intent; the newer desired transition owns its delivery
        if status in ("FAILED", "UNKNOWN"):
            return  # requires an explicit recovery decision; never blind retry
        result = await self.reconciler.run_reconcile_async()
        if result.status == "DEGRADED":
            raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="Harness drain has not completed")

    async def run(self, dispatcher):
        delivery = None
        try:
            if self.startup is not None:
                await self.startup()
            while not self.stopping:
                dispatcher.renew_leases()
                if delivery is None or delivery.done():
                    if delivery is not None:
                        delivery.result()
                    delivery = asyncio.create_task(dispatcher.poll_once_async())
                await asyncio.sleep(.02)
        except asyncio.CancelledError:
            raise
        except Exception:
            self.failure = ErrorCode.INTERNAL
        finally:
            if delivery is not None:
                delivery.cancel()
                await asyncio.gather(delivery, return_exceptions=True)
            dispatcher.abandon_all()
