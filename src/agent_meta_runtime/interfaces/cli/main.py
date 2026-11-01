"""``agent-meta`` command line interface (§41.52).

Every subcommand answers over the local Public API (UDS); the CLI never
touches the store, CAS, outbox or backends directly (§41.26).
``--output json`` prints the machine envelope
``{"api_version", "ok", "result"|"error"}``; text output is a compact
human summary. Exit codes are stable: 0 success; 2 argument/schema;
3 Authority; 4 not found; 5 revision/idempotency conflict; 6 feature,
precondition or readiness; 7 temporary backend/resource/deadline;
8 integrity, data loss or key; 70 internal (§41.52). ``--dry-run``
performs full argument and readiness validation and prints the mutation
plan — without sending any command, so no store/CAS/outbox/backend side
effect occurs.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from ...domain.errors import ErrorCode, StableError
from ...protocols.public_wire import PUBLIC_API_MAJOR, PUBLIC_API_MINOR
from ..local_api.connection import LocalConnection
from ...sdk import AgentMetaClient, LocalTransport
from ...sdk import CommandAuthority, decode_command
from ...adapters.credentials import operator_signing_authority
from .init import run_init

__all__ = ["EXIT_CODES", "build_parser", "main", "run_cli"]

API_VERSION = f"{PUBLIC_API_MAJOR}.{PUBLIC_API_MINOR}"

_EXIT_ARGUMENTS = 2
_EXIT_AUTHORITY = 3
_EXIT_NOT_FOUND = 4
_EXIT_CONFLICT = 5
_EXIT_READINESS = 6
_EXIT_TEMPORARY = 7
_EXIT_INTEGRITY = 8
_EXIT_INTERNAL = 70

EXIT_CODES: dict[str, int] = {
    ErrorCode.INVALID_ARGUMENT: _EXIT_ARGUMENTS,
    ErrorCode.AUTHORITY_DENIED: _EXIT_AUTHORITY,
    ErrorCode.NOT_FOUND: _EXIT_NOT_FOUND,
    ErrorCode.REVISION_CONFLICT: _EXIT_CONFLICT,
    ErrorCode.IDEMPOTENCY_CONFLICT: _EXIT_CONFLICT,
    ErrorCode.ALREADY_EXISTS: _EXIT_CONFLICT,
    ErrorCode.FEATURE_UNAVAILABLE: _EXIT_READINESS,
    ErrorCode.FAILED_PRECONDITION: _EXIT_READINESS,
    ErrorCode.SERVING_NOT_READY: _EXIT_READINESS,
    ErrorCode.NO_SERVING_COMPOSITION: _EXIT_READINESS,
    ErrorCode.ALREADY_RUNNING: 12,
    ErrorCode.CONTRACT_INCOMPATIBLE: _EXIT_READINESS,
    ErrorCode.BACKEND_UNAVAILABLE: _EXIT_TEMPORARY,
    ErrorCode.RESOURCE_EXHAUSTED: _EXIT_TEMPORARY,
    ErrorCode.DEADLINE_EXCEEDED: _EXIT_TEMPORARY,
    ErrorCode.HANDLE_EXPIRED: _EXIT_TEMPORARY,
    ErrorCode.EXTERNAL_EFFECT_UNKNOWN: _EXIT_TEMPORARY,
    ErrorCode.INTEGRITY_ERROR: _EXIT_INTEGRITY,
    ErrorCode.DATA_LOSS: _EXIT_INTEGRITY,
    ErrorCode.KEY_UNAVAILABLE: _EXIT_INTEGRITY,
    ErrorCode.INVALID_RESULT: _EXIT_INTEGRITY,
    ErrorCode.COMPATIBILITY_UNKNOWN: _EXIT_INTEGRITY,
}


def _socket_path(data_dir: Path) -> Path:
    return Path(data_dir) / "run" / "agent-meta.sock"


async def _connect(args: argparse.Namespace) -> AgentMetaClient:
    connection = LocalConnection(_socket_path(args.data_dir))
    try:
        await connection.connect()
    except StableError:
        await connection.close()
        raise
    authority = None
    try:
        operator, signer = operator_signing_authority(args.data_dir, allow_insecure=args.insecure_dev_credential_file)
        if args.actor is None:
            args.actor = operator["actor_id"]
        if args.actor == operator["actor_id"]:
            authority = CommandAuthority(operator["actor_id"], operator["authority_grant_id"], signer)
    except StableError:
        if args.command in {"authority", "task", "artifact", "composition", "harness", "evolution", "operations", "stop"}:
            await connection.close()
            raise
    return AgentMetaClient(LocalTransport(connection), authority=authority)


def _emit_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, sort_keys=True), flush=True)


def _fail(args: argparse.Namespace, exc: StableError) -> int:
    if args.output == "json":
        _emit_json(
            {
                "api_version": API_VERSION,
                "ok": False,
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "details": dict(exc.details or {}),
                },
            }
        )
    else:
        print(f"error: {exc.code}: {exc.message}", file=sys.stderr)
    if args.command == "start":
        startup_codes = {ErrorCode.INVALID_ARGUMENT: 2, ErrorCode.INTEGRITY_ERROR: 3,
                         ErrorCode.DATA_LOSS: 3, ErrorCode.FAILED_PRECONDITION: 3,
                         ErrorCode.AUTHORITY_DENIED: 4, ErrorCode.KEY_UNAVAILABLE: 4,
                         ErrorCode.BACKEND_UNAVAILABLE: 5, ErrorCode.CONTRACT_INCOMPATIBLE: 5,
                         ErrorCode.ALREADY_RUNNING: 12}
        return startup_codes.get(exc.code, _EXIT_INTERNAL)
    return EXIT_CODES.get(exc.code, _EXIT_INTERNAL)


def _emit_result(args: argparse.Namespace, result: Any) -> int:
    if args.output == "json":
        _emit_json({"api_version": API_VERSION, "ok": True, "result": result})
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


#: Static dry-run declaration of the authority each mutation requires
#: (§41.52: plans must state required permissions/capabilities).
_REQUIRED_PERMISSIONS: dict[str, tuple[str, ...]] = {
    "authority.principal.create/v1": ("authority.grant",),
    "authority.delegate/v1": ("authority.delegate",),
    "authority.revoke/v1": ("authority.revoke",),
    "runtime.stop/v1": ("runtime.admin.stop",),
    "task.submit/v1": ("task.submit",),
    "task.cancel/v1": ("task.cancel",),
    "artifact.put/v1": ("artifact.put",),
    "composition.commit/v1": ("composition.commit",),
    "harness.install/v1": ("harness.install",),
    "harness.activate/v1": ("harness.activate",),
    "harness.configure-provider/v1": ("harness.activate",),
    "harness.deactivate/v1": ("harness.deactivate",),
    "harness.uninstall/v1": ("harness.uninstall",),
    "evolution.propose/v1": ("experiment.run",),
    "experiment.run/v1": ("experiment.run",),
    "candidate.promote/v1": ("composition.promote",),
    "composition.rollback/v1": ("composition.rollback",),
    "operations.backup/v1": ("operations.backup",),
    "operations.gc-plan/v1": ("operations.gc",),
    "operations.gc-apply/v1": ("operations.gc",),
}


def _plan(
    *, payload_type: str, payload: dict[str, Any], realm: str, actor: str
) -> dict[str, Any]:
    digest = hashlib.sha256(
        "\x00".join((payload_type, "1", json.dumps(payload, sort_keys=True))).encode()
    ).hexdigest()
    return {
        "payload_type": payload_type,
        "realm_id": realm,
        "actor_id": actor,
        "plan_hash": f"sha256:{digest}",
        "required_permissions": list(_REQUIRED_PERMISSIONS.get(payload_type, ())),
        "required_capabilities": [],
        "payload": payload,
    }


# -- subcommand implementations ---------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    """Local bootstrap; runs without a daemon connection (§41.57.1)."""

    report = run_init(args.data_dir, insecure_dev_credential_file=args.insecure_dev_credential_file)
    if report.feature_summary["credential_store"] == "INSECURE_TEST_ONLY":
        print("credential_store=INSECURE_TEST_ONLY: development fixture, not product security", file=sys.stderr)
    result = {
        "realm_id": report.realm_id,
        "epoch_id": report.epoch_id,
        "data_dir": report.data_dir,
        "core_ready": report.core_ready,
        "serving_ready": report.serving_ready,
        "reinitialized": report.reinitialized,
        "features": report.feature_summary,
    }
    if report.recovery_code is not None:
        result["recovery_code"] = report.recovery_code
    return _emit_result(args, result)


async def cmd_info(client: AgentMetaClient, args: argparse.Namespace) -> int:
    info = await client.get_info()
    return _emit_result(
        args,
        {
            "live": info.live,
            "instance_id": client.server_instance_id,
            "core_ready": info.core_ready,
            "serving_ready": info.serving_ready,
            "ready": info.core_ready,  # v1 alias equals core_ready (§41.52)
            "core_reasons": list(info.core_reasons),
            "serving_reasons": list(info.serving_reasons),
            "desired_revision": info.desired_revision,
            "serving_revision": info.serving_revision,
            "realized_revision": info.realized_revision,
        },
    )


async def cmd_start(args: argparse.Namespace) -> int:
    from ..daemon import RuntimeDaemon

    if args.dry_run:
        return _emit_result(args, {"dry_run": True, "data_dir": str(args.data_dir.resolve()),
                                  "foreground": True, "trusted_publishers": sorted(args.trusted_publisher)})
    daemon = RuntimeDaemon(args.data_dir, config_path=args.config,
        allow_insecure_credentials=args.insecure_dev_credential_file,
        trusted_publishers=args.trusted_publisher, execution_backend=args.execution_backend)
    try:
        status = await daemon.start()
        _emit_result(args, status)
        await daemon.wait()
    finally:
        await daemon.close()
    return _emit_result(args, {"state": "STOPPED", "instance_id": daemon.instance_id})


async def cmd_stop(client: AgentMetaClient, args: argparse.Namespace) -> int:
    if args.dry_run:
        return _dry_run(args, "runtime.stop/v1", {"instance_id": client.server_instance_id, "reason_code": args.reason})
    result = await client.stop_runtime(realm_id=args.realm, actor_id=args.actor, reason_code=args.reason)
    return _emit_result(args, {**dict(result.receipt), **dict(result.resource or {})})


async def cmd_view(client: AgentMetaClient, args: argparse.Namespace) -> int:
    return _emit_result(args, await client.get_view(args.revision))


async def cmd_doctor(client: AgentMetaClient, args: argparse.Namespace) -> int:
    return _emit_result(args, await client.doctor())


async def cmd_refs(client: AgentMetaClient, args: argparse.Namespace) -> int:
    return _emit_result(args, await client.get_refs())


def _authority_json(raw: str):
    def unique_fields(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate field")
            value[key] = item
        return value
    try:
        return json.loads(raw, object_pairs_hook=unique_fields)
    except (ValueError, TypeError) as exc:
        raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="Authority arguments require valid JSON with unique fields") from exc


async def cmd_authority(client: AgentMetaClient, args: argparse.Namespace) -> int:
    from ...domain.principal_contract import delegation_payload, principal_registration, revocation_payload

    if args.authority_command == "create-principal":
        payload = {"kind": args.kind, "public_key_hex": args.public_key_hex}
        if args.principal_id is not None:
            payload["principal_id"] = args.principal_id
        _, _, public_key = principal_registration(payload)
        if args.dry_run:
            return _dry_run(args, "authority.principal.create/v1", payload)
        result = await client.create_principal(realm_id=args.realm, actor_id=args.actor,
            kind=args.kind, public_key=public_key, principal_id=args.principal_id)
    elif args.authority_command == "delegate":
        payload = {"subject_id": args.subject, "permissions": sorted(set(args.permission)),
            "scope": _authority_json(args.scope), "constraints": _authority_json(args.constraints),
            "delegable": args.delegable}
        delegation_payload(payload, realm_id=args.realm)
        if args.dry_run:
            return _dry_run(args, "authority.delegate/v1", payload)
        result = await client.delegate_authority(realm_id=args.realm, actor_id=args.actor,
            subject_id=args.subject, permissions=payload["permissions"], scope=payload["scope"],
            constraints=payload["constraints"], delegable=args.delegable)
    else:
        payload = {"grant_id": args.grant_id, "reason_code": args.reason}
        revocation_payload(payload)
        if args.dry_run:
            return _dry_run(args, "authority.revoke/v1", payload)
        result = await client.revoke_authority(realm_id=args.realm, actor_id=args.actor,
            grant_id=args.grant_id, reason_code=args.reason)
    return _emit_result(args, {**dict(result.receipt), **dict(result.resource or {})})


async def cmd_task_submit(client: AgentMetaClient, args: argparse.Namespace) -> int:
    from ...domain.task_submission import parse_task_submission
    payload = {"input_artifact_id": args.input_artifact}
    if args.budget is not None:
        def unique_budget_fields(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate budget field")
                result[key] = value
            return result
        try:
            payload["budget"] = json.loads(args.budget, object_pairs_hook=unique_budget_fields)
        except (ValueError, TypeError) as exc:
            raise StableError(code=ErrorCode.INVALID_ARGUMENT, message="Task budget must be valid JSON with unique fields") from exc
    if args.deadline_at_us is not None:
        payload["deadline_at_us"] = args.deadline_at_us
    parse_task_submission(payload)
    if args.dry_run:
        info = await client.get_info()
        refs = await client.get_refs()
        return _emit_result(
            args,
            {
                "dry_run": True,
                "would_change": True,
                "serving_ready": info.serving_ready,
                "serving_revision": refs["serving_revision"],
                "plan": _plan(
                    payload_type="task.submit/v1",
                    payload=payload,
                    realm=args.realm,
                    actor=args.actor,
                ),
            },
        )
    handle = await client.submit_task(
        realm_id=args.realm,
        actor_id=args.actor,
        input_artifact_id=args.input_artifact,
        budget=payload.get("budget"),
        deadline_at_us=payload.get("deadline_at_us"),
    )
    return _emit_result(
        args,
        {
            "task_id": handle.task_id,
            "root_action_id": handle.root_action_id,
            "serving_revision": handle.serving_revision,
            "status": handle.status,
        },
    )


async def cmd_task_get(client: AgentMetaClient, args: argparse.Namespace) -> int:
    return _emit_result(args, await client.get_task(args.task_id))


async def cmd_task_execution(client: AgentMetaClient, args: argparse.Namespace) -> int:
    return _emit_result(args, await client.get_task_execution(args.task_id))


async def cmd_task_trace(client: AgentMetaClient, args: argparse.Namespace) -> int:
    return _emit_result(args, await client.get_task_trace(args.task_id))


async def cmd_task_wait(client: AgentMetaClient, args: argparse.Namespace) -> int:
    resource, terminal = await client.wait_task(args.task_id, timeout_s=args.timeout)
    return _emit_result(args, {**resource, "terminal": terminal})


async def cmd_task_cancel(client: AgentMetaClient, args: argparse.Namespace) -> int:
    payload = {"task_id": args.task_id, "reason_code": args.reason}
    if args.dry_run:
        return _emit_result(
            args,
            {
                "dry_run": True,
                "would_change": True,
                "plan": _plan(
                    payload_type="task.cancel/v1",
                    payload=payload,
                    realm=args.realm,
                    actor=args.actor,
                ),
            },
        )
    result = await client.cancel_task(
        realm_id=args.realm, actor_id=args.actor, task_id=args.task_id, reason_code=args.reason
    )
    return _emit_result(args, dict(result.receipt))


async def cmd_artifact_put(client: AgentMetaClient, args: argparse.Namespace) -> int:
    content = Path(args.file).read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    if args.dry_run:
        return _emit_result(
            args,
            {
                "dry_run": True,
                "would_change": True,
                "plan": _plan(
                    payload_type="artifact.put/v1",
                    payload={
                        "expected_sha256": digest,
                        "expected_size": len(content),
                        "kind": args.kind,
                        "media_type": args.media_type,
                    },
                    realm=args.realm,
                    actor=args.actor,
                ),
            },
        )
    resource = await client.put_artifact(
        realm_id=args.realm,
        actor_id=args.actor,
        content=content,
        kind=args.kind,
        media_type=args.media_type,
    )
    return _emit_result(args, resource)


async def cmd_artifact_get(client: AgentMetaClient, args: argparse.Namespace) -> int:
    return _emit_result(args, await client.get_artifact_manifest(args.artifact_id))


async def cmd_artifact_content(client: AgentMetaClient, args: argparse.Namespace) -> int:
    content = await client.get_artifact_content(args.artifact_id)
    return _emit_result(args, {"artifact_id": args.artifact_id, "size_bytes": len(content), "content_hex": content.hex()})


async def cmd_artifact_verify(client: AgentMetaClient, args: argparse.Namespace) -> int:
    ok, reason = await client.verify_artifact(args.artifact_id)
    return _emit_result(args, {"ok": ok, "reason_code": reason})


async def cmd_composition_validate(client: AgentMetaClient, args: argparse.Namespace) -> int:
    valid, issues = await client.validate_composition(args.body_artifact)
    return _emit_result(args, {"valid": valid, "issues": issues})


async def cmd_composition_commit(client: AgentMetaClient, args: argparse.Namespace) -> int:
    if args.dry_run:
        return _emit_result(
            args,
            {
                "dry_run": True,
                "would_change": True,
                "plan": _plan(
                    payload_type="composition.commit/v1",
                    payload={"composition_body_artifact_id": args.body_artifact},
                    realm=args.realm,
                    actor=args.actor,
                ),
            },
        )
    result = await client.commit_composition(
        realm_id=args.realm, actor_id=args.actor, body_artifact_id=args.body_artifact
    )
    return _emit_result(args, dict(result.receipt))


async def cmd_why(client: AgentMetaClient, args: argparse.Namespace) -> int:
    return _emit_result(args, await client.why(args.entity_id, max_depth=args.depth))


async def cmd_lineage(client: AgentMetaClient, args: argparse.Namespace) -> int:
    return _emit_result(
        args,
        await client.lineage(args.entity_id, direction=args.direction, limit=args.limit),
    )


async def cmd_harness(client: AgentMetaClient, args: argparse.Namespace) -> int:
    if args.harness_command == "validate":
        return _emit_result(args, await client.validate_harness_package(args.manifest_artifact))
    if args.harness_command == "install":
        result = await client.install_harness(
            realm_id=args.realm,
            actor_id=args.actor,
            package_name=args.name,
            package_version=args.version,
            manifest_artifact_id=args.manifest_artifact,
            package_artifact_id=args.package_artifact,
        )
        return _emit_result(args, {**dict(result.receipt), **dict(result.resource or {})})
    if args.harness_command == "list":
        return _emit_result(
            args, {"harnesses": await client.list_harnesses(status=args.status)}
        )
    if args.harness_command == "inspect":
        return _emit_result(args, await client.get_harness(args.harness_id))
    if args.harness_command == 'configure-provider':
        envelope=await client.prepare_harness_provider_configuration(realm_id=args.realm,actor_id=args.actor,
            harness_id=args.harness_id,capability_id=args.capability,profile_artifact_id=args.profile_artifact,
            credential_handle=args.credential_handle,enabled=not args.disable,
            expected_configuration_revision=args.expected_configuration_revision,expected_meta_revision=args.expected_meta_revision)
        validation=await client.validate_harness_provider_configuration(envelope)
        if args.dry_run:
            return _emit_result(args,{'dry_run':True,'would_change':True,**validation,'command_envelope_jcs':envelope})
        result=await client.execute_command('agent_meta.public.v1.Harness.ConfigureProvider',envelope)
        return _emit_result(args,{**dict(result.receipt),**dict(result.resource or {})})
    if args.harness_command == "activate":
        refs = await client.get_refs()
        if args.expected_revision is not None and refs["serving_revision"] != args.expected_revision:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message="serving revision does not match --expected-revision",
                details={"serving_revision": str(refs["serving_revision"])},
            )
        if args.expected_serving is not None and refs["serving_revision"] != args.expected_serving:
            raise StableError(
                code=ErrorCode.FAILED_PRECONDITION,
                message="serving revision does not match --expected-serving",
                details={"serving_revision": str(refs["serving_revision"])},
            )
        envelope_jcs = await client.prepare_harness_activation(
            realm_id=args.realm, actor_id=args.actor, harness_id=args.harness_id,
            composition_body_artifact_id=args.body_artifact,
            grant_requests=[json.loads(g) for g in args.grant] if args.grant else None,
            expected_serving_revision=refs["serving_revision"],
        )
        if args.dry_run:
            envelope = decode_command(envelope_jcs)
            return _emit_result(
                args,
                {
                    "dry_run": True,
                    "would_change": True,
                    "plan": dict(envelope.payload),
                    "expected_meta_revision": envelope.expected_meta_revision,
                    "required_permissions": sorted({"harness.activate", *({"authority.delegate"} if envelope.payload["grant_requests"] else set()),
                                                    *(item["permission"] for item in envelope.payload["grant_requests"])}),
                    "command_envelope_jcs": envelope_jcs,
                },
            )
        result = await client.execute_command("agent_meta.public.v1.Harness.Activate", envelope_jcs)
        return _emit_result(args, {**dict(result.receipt), **dict(result.resource or {})})
    if args.harness_command == "deactivate":
        if args.dry_run:
            return _emit_result(
                args,
                {
                    "dry_run": True,
                    "would_change": True,
                    "plan": _plan(
                        payload_type="harness.deactivate/v1",
                        payload={"harness_id": args.harness_id},
                        realm=args.realm,
                        actor=args.actor,
                    ),
                },
            )
        result = await client.deactivate_harness(
            realm_id=args.realm, actor_id=args.actor, harness_id=args.harness_id
        )
        return _emit_result(args, {**dict(result.receipt), **dict(result.resource or {})})
    # uninstall
    if args.dry_run:
        return _emit_result(
            args,
            {
                "dry_run": True,
                "would_change": True,
                "plan": _plan(
                    payload_type="harness.uninstall/v1",
                    payload={"harness_id": args.harness_id},
                    realm=args.realm,
                    actor=args.actor,
                ),
            },
        )
    result = await client.uninstall_harness(
        realm_id=args.realm, actor_id=args.actor, harness_id=args.harness_id
    )
    return _emit_result(args, {**dict(result.receipt), **dict(result.resource or {})})


def _dry_run(args: argparse.Namespace, payload_type: str, payload: dict[str, Any]) -> int:
    return _emit_result(
        args,
        {
            "dry_run": True,
            "would_change": True,
            "plan": _plan(
                payload_type=payload_type, payload=payload, realm=args.realm, actor=args.actor
            ),
        },
    )


def _expected_serving(args: argparse.Namespace, serving_revision: int) -> int:
    # Promote/Rollback CAS on the serving revision; default to the observed one.
    if args.expected_serving is not None:
        return args.expected_serving
    return serving_revision


async def cmd_evolution(client: AgentMetaClient, args: argparse.Namespace) -> int:
    if args.evolution_command == "propose":
        payload = {
            "hypothesis": args.hypothesis,
            "source_evidence_ids": list(args.evidence or []),
            "target_composition_id": args.target_composition,
        }
        if args.dry_run:
            return _dry_run(args, "evolution.propose/v1", payload)
        result = await client.propose(
            realm_id=args.realm,
            actor_id=args.actor,
            hypothesis=args.hypothesis,
            source_evidence_ids=args.evidence,
            target_composition_id=args.target_composition,
        )
        return _emit_result(args, {**dict(result.receipt), **dict(result.resource or {})})
    if args.evolution_command == "run":
        payload: dict[str, Any] = {
            "candidate_id": args.candidate,
            "baseline_id": args.baseline,
            "world_id": args.world,
            "criteria_artifact_id": args.criteria_artifact,
        }
        if args.budget:
            payload["budget"] = json.loads(args.budget)
        if args.dry_run:
            return _dry_run(args, "experiment.run/v1", payload)
        result = await client.run_experiment(
            realm_id=args.realm,
            actor_id=args.actor,
            candidate_id=args.candidate,
            baseline_id=args.baseline,
            world_id=args.world,
            criteria_artifact_id=args.criteria_artifact,
            budget=json.loads(args.budget) if args.budget else None,
        )
        return _emit_result(args, {**dict(result.receipt), **dict(result.resource or {})})
    if args.evolution_command == "get":
        return _emit_result(args, await client.get_experiment(args.experiment_id))
    if args.evolution_command == "wait":
        resource, terminal = await client.wait_experiment(
            args.experiment_id, timeout_s=args.timeout
        )
        return _emit_result(args, {**resource, "terminal": terminal})
    refs = await client.get_refs()
    expected = _expected_serving(args, int(refs["serving_revision"]))
    if args.evolution_command == "promote":
        payload = {
            "candidate_id": args.candidate,
            "evaluation_id": args.evaluation,
            "expected_serving_revision": expected,
        }
        if args.dry_run:
            return _dry_run(args, "candidate.promote/v1", payload)
        result = await client.promote_candidate(
            realm_id=args.realm,
            actor_id=args.actor,
            candidate_id=args.candidate,
            evaluation_id=args.evaluation,
            expected_serving_revision=expected,
        )
        return _emit_result(args, {**dict(result.receipt), **dict(result.resource or {})})
    # rollback
    state_revisions: dict[str, str] | None = None
    if args.state_revision:
        state_revisions = {}
        for entry in args.state_revision:
            state_id, separator, revision_id = entry.partition("=")
            if not separator or not state_id or not revision_id:
                raise StableError(
                    code=ErrorCode.INVALID_ARGUMENT,
                    message="--state-revision must be state_id=state_revision_id",
                )
            state_revisions[state_id] = revision_id
    payload = {
        "target_parent_id": args.target_parent,
        "expected_serving_revision": expected,
        "state_strategy": args.state_strategy,
        "reason_code": args.reason,
    }
    if state_revisions:
        payload["expected_state_revisions"] = state_revisions
    if args.dry_run:
        return _dry_run(args, "composition.rollback/v1", payload)
    result = await client.rollback_composition(
        realm_id=args.realm,
        actor_id=args.actor,
        target_parent_id=args.target_parent,
        expected_serving_revision=expected,
        state_strategy=args.state_strategy,
        expected_state_revisions=state_revisions,
        reason_code=args.reason,
    )
    return _emit_result(args, {**dict(result.receipt), **dict(result.resource or {})})


async def cmd_operations(client: AgentMetaClient, args: argparse.Namespace) -> int:
    if args.operations_command == "backup":
        payload: dict[str, Any] = {}
        if args.destination:
            payload["absolute_destination"] = args.destination
        if args.expected_meta_revision is not None:
            payload["expected_meta_revision"] = args.expected_meta_revision
        if args.dry_run:
            return _dry_run(args, "operations.backup/v1", payload)
        result = await client.backup(
            realm_id=args.realm,
            actor_id=args.actor,
            absolute_destination=args.destination,
            expected_meta_revision=args.expected_meta_revision,
        )
        return _emit_result(args, {**dict(result.receipt), **dict(result.resource or {})})
    if args.operations_command == "gc-plan":
        payload = {"expected_meta_revision": args.expected_meta_revision}
        if args.legal_hold:
            payload["legal_hold_artifact_ids"] = list(args.legal_hold)
        if args.dry_run:
            return _dry_run(args, "operations.gc-plan/v1", payload)
        result = await client.gc_plan(
            realm_id=args.realm,
            actor_id=args.actor,
            expected_meta_revision=args.expected_meta_revision,
            legal_hold_artifact_ids=args.legal_hold or (),
        )
        return _emit_result(args, {**dict(result.receipt), **dict(result.resource or {})})
    if args.operations_command == "gc-apply":
        payload = {
            "gc_plan_artifact_id": args.gc_plan_artifact,
            "expected_meta_revision": args.expected_meta_revision,
        }
        if args.dry_run:
            return _dry_run(args, "operations.gc-apply/v1", payload)
        result = await client.gc_apply(
            realm_id=args.realm,
            actor_id=args.actor,
            gc_plan_artifact_id=args.gc_plan_artifact,
            expected_meta_revision=args.expected_meta_revision,
        )
        return _emit_result(args, {**dict(result.receipt), **dict(result.resource or {})})
    if args.operations_command == "get":
        return _emit_result(args, await client.get_operation(args.operation_id))
    # wait
    return _emit_result(
        args, await client.wait_operation(args.operation_id, timeout_s=args.timeout)
    )


# -- parser -------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-meta", description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True, help="runtime data directory")
    parser.add_argument("--realm", default="realm://main")
    parser.add_argument(
        "--actor", default=None
    )
    parser.add_argument("--output", choices=("json", "text"), default="text")
    parser.add_argument("--insecure-dev-credential-file", action="store_true", help="explicitly allow fixture-only credential storage")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and print the plan; no command is sent",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init")
    init.add_argument("--insecure-dev-credential-file", action="store_true", default=argparse.SUPPRESS, help="explicit fixture-only credential storage; never a product security profile")
    init.set_defaults(func=cmd_init)
    sub.add_parser("info").set_defaults(func=cmd_info)
    start = sub.add_parser("start", help="run the local daemon in the foreground")
    start.add_argument("--config", type=Path, default=None)
    start.add_argument("--trusted-publisher", action="append", default=[], help="explicitly trusted publisher SHA-256 fingerprint")
    start.add_argument("--execution-backend", choices=("trusted_in_process", "in_memory"), default=None, help="select the Host execution backend; overrides execution.host_backend")
    start.set_defaults(func=cmd_start)
    stop = sub.add_parser("stop", help="request signed shutdown of the connected daemon instance")
    stop.add_argument("--reason", default="operator_stop")
    stop.set_defaults(func=cmd_stop)
    view = sub.add_parser("view")
    view.add_argument("--revision", type=int, default=None)
    view.set_defaults(func=cmd_view)
    sub.add_parser("doctor").set_defaults(func=cmd_doctor)
    sub.add_parser("refs").set_defaults(func=cmd_refs)

    authority = sub.add_parser("authority")
    authority_sub = authority.add_subparsers(dest="authority_command", required=True)
    principal = authority_sub.add_parser("create-principal")
    principal.add_argument("--kind", required=True, choices=("AGENT", "CAPABILITY", "PEER"))
    principal.add_argument("--public-key-hex", required=True, help="32 raw Ed25519 public bytes in lowercase hex")
    principal.add_argument("--principal-id", default=None)
    principal.set_defaults(func=cmd_authority)
    delegate = authority_sub.add_parser("delegate")
    delegate.add_argument("--subject", required=True)
    delegate.add_argument("--permission", action="append", required=True)
    delegate.add_argument("--scope", required=True, help="typed scope JSON in the current realm")
    delegate.add_argument("--constraints", default="{}", help="strict grant constraints JSON")
    delegate.add_argument("--delegable", action="store_true")
    delegate.set_defaults(func=cmd_authority)
    revoke = authority_sub.add_parser("revoke")
    revoke.add_argument("grant_id")
    revoke.add_argument("--reason", default="operator_revoke")
    revoke.set_defaults(func=cmd_authority)

    task = sub.add_parser("task")
    task_sub = task.add_subparsers(dest="task_command", required=True)
    submit = task_sub.add_parser("submit")
    submit.add_argument("--input-artifact", required=True)
    submit.add_argument("--budget", default=None, help="JSON object of TaskBudget fields")
    submit.add_argument("--deadline-at-us", type=int, default=None, help="absolute Unix microsecond deadline; zero is already expired")
    submit.set_defaults(func=cmd_task_submit)
    get = task_sub.add_parser("get")
    get.add_argument("task_id")
    get.set_defaults(func=cmd_task_get)
    execution = task_sub.add_parser("execution")
    execution.add_argument("task_id")
    execution.set_defaults(func=cmd_task_execution)
    trace = task_sub.add_parser("trace")
    trace.add_argument("task_id")
    trace.set_defaults(func=cmd_task_trace)
    wait = task_sub.add_parser("wait")
    wait.add_argument("task_id")
    wait.add_argument("--timeout", type=float, default=60.0)
    wait.set_defaults(func=cmd_task_wait)
    cancel = task_sub.add_parser("cancel")
    cancel.add_argument("task_id")
    cancel.add_argument("--reason", default="requested")
    cancel.set_defaults(func=cmd_task_cancel)

    artifact = sub.add_parser("artifact")
    art_sub = artifact.add_subparsers(dest="artifact_command", required=True)
    put = art_sub.add_parser("put")
    put.add_argument("file")
    put.add_argument("--kind", default="code")
    put.add_argument("--media-type", default="application/json")
    put.set_defaults(func=cmd_artifact_put)
    get_art = art_sub.add_parser("get")
    get_art.add_argument("artifact_id")
    get_art.set_defaults(func=cmd_artifact_get)
    content = art_sub.add_parser("content")
    content.add_argument("artifact_id")
    content.set_defaults(func=cmd_artifact_content)
    verify = art_sub.add_parser("verify")
    verify.add_argument("artifact_id")
    verify.set_defaults(func=cmd_artifact_verify)

    comp = sub.add_parser("composition")
    comp_sub = comp.add_subparsers(dest="composition_command", required=True)
    validate = comp_sub.add_parser("validate")
    validate.add_argument("body_artifact", help="composition body artifact id")
    validate.set_defaults(func=cmd_composition_validate)
    commit = comp_sub.add_parser("commit")
    commit.add_argument("body_artifact")
    commit.set_defaults(func=cmd_composition_commit)

    harness = sub.add_parser("harness")
    harness_sub = harness.add_subparsers(dest="harness_command", required=True)
    hvalidate = harness_sub.add_parser("validate")
    hvalidate.add_argument("manifest_artifact")
    hvalidate.set_defaults(func=cmd_harness)
    hinstall = harness_sub.add_parser("install")
    hinstall.add_argument("--name", required=True, help="package name")
    hinstall.add_argument("--version", required=True, help="package version")
    hinstall.add_argument("manifest_artifact")
    hinstall.add_argument("package_artifact")
    hinstall.set_defaults(func=cmd_harness)
    hlist = harness_sub.add_parser("list")
    hlist.add_argument("--status", default="")
    hlist.set_defaults(func=cmd_harness)
    hinspect = harness_sub.add_parser("inspect")
    hinspect.add_argument("harness_id")
    hinspect.set_defaults(func=cmd_harness)
    hconfigure=harness_sub.add_parser('configure-provider')
    hconfigure.add_argument('harness_id')
    hconfigure.add_argument('--capability',required=True)
    hconfigure.add_argument('--profile-artifact',required=True)
    hconfigure.add_argument('--credential-handle',required=True,help='opaque provider handle, never a token value')
    hconfigure.add_argument('--disable',action='store_true')
    hconfigure.add_argument('--expected-configuration-revision',type=int,default=None)
    hconfigure.add_argument('--expected-meta-revision',type=int,default=None)
    hconfigure.set_defaults(func=cmd_harness)
    hactivate = harness_sub.add_parser("activate")
    hactivate.add_argument("harness_id")
    hactivate.add_argument("body_artifact", help="composition body artifact id")
    hactivate.add_argument(
        "--grant",
        action="append",
        default=None,
        help='JSON grant request object, e.g. \'{"permission": "model.invoke"}\'',
    )
    hactivate.add_argument("--expected-revision", type=int, default=None)
    hactivate.add_argument("--expected-serving", type=int, default=None)
    hactivate.set_defaults(func=cmd_harness)
    hdeactivate = harness_sub.add_parser("deactivate")
    hdeactivate.add_argument("harness_id")
    hdeactivate.set_defaults(func=cmd_harness)
    huninstall = harness_sub.add_parser("uninstall")
    huninstall.add_argument("harness_id")
    huninstall.set_defaults(func=cmd_harness)

    evolution = sub.add_parser("evolution")
    evolution_sub = evolution.add_subparsers(dest="evolution_command", required=True)
    epropose = evolution_sub.add_parser("propose")
    epropose.add_argument("hypothesis")
    epropose.add_argument("--target-composition", required=True)
    epropose.add_argument("--evidence", action="append", default=None)
    epropose.set_defaults(func=cmd_evolution)
    erun = evolution_sub.add_parser("run")
    erun.add_argument("--candidate", required=True)
    erun.add_argument("--baseline", required=True)
    erun.add_argument("--world", required=True)
    erun.add_argument("--criteria-artifact", required=True)
    erun.add_argument("--budget", default=None, help="JSON object of TaskBudget fields")
    erun.set_defaults(func=cmd_evolution)
    eget = evolution_sub.add_parser("get")
    eget.add_argument("experiment_id")
    eget.set_defaults(func=cmd_evolution)
    ewait = evolution_sub.add_parser("wait")
    ewait.add_argument("experiment_id")
    ewait.add_argument("--timeout", type=float, default=60.0)
    ewait.set_defaults(func=cmd_evolution)
    epromote = evolution_sub.add_parser("promote")
    epromote.add_argument("--candidate", required=True)
    epromote.add_argument("--evaluation", required=True)
    epromote.add_argument(
        "--expected-serving",
        type=int,
        default=None,
        help="serving revision observed by the caller (default: current)",
    )
    epromote.set_defaults(func=cmd_evolution)
    erollback = evolution_sub.add_parser("rollback")
    erollback.add_argument("--target-parent", required=True)
    erollback.add_argument("--expected-serving", type=int, default=None)
    erollback.add_argument(
        "--state-strategy", choices=("KEEP_COMPATIBLE", "RESTORE_PARENT"),
        default="KEEP_COMPATIBLE",
    )
    erollback.add_argument(
        "--state-revision",
        action="append",
        default=None,
        metavar="STATE_ID=STATE_REVISION_ID",
        help="required with --state-strategy RESTORE_PARENT",
    )
    erollback.add_argument("--reason", default="operator_rollback")
    erollback.set_defaults(func=cmd_evolution)

    operations = sub.add_parser("operations")
    operations_sub = operations.add_subparsers(dest="operations_command", required=True)
    obackup = operations_sub.add_parser("backup")
    obackup.add_argument(
        "--destination", default=None, help="absolute backup destination directory"
    )
    obackup.add_argument("--expected-meta-revision", type=int, default=None)
    obackup.set_defaults(func=cmd_operations)
    ogcplan = operations_sub.add_parser("gc-plan")
    ogcplan.add_argument("--expected-meta-revision", type=int, required=True)
    ogcplan.add_argument("--legal-hold", action="append", default=None)
    ogcplan.set_defaults(func=cmd_operations)
    ogcapply = operations_sub.add_parser("gc-apply")
    ogcapply.add_argument("--gc-plan-artifact", required=True)
    ogcapply.add_argument("--expected-meta-revision", type=int, required=True)
    ogcapply.set_defaults(func=cmd_operations)
    oget = operations_sub.add_parser("get")
    oget.add_argument("operation_id")
    oget.set_defaults(func=cmd_operations)
    owait = operations_sub.add_parser("wait")
    owait.add_argument("operation_id")
    owait.add_argument("--timeout", type=float, default=60.0)
    owait.set_defaults(func=cmd_operations)

    why = sub.add_parser("why")
    why.add_argument("entity_id")
    why.add_argument("--depth", type=int, default=None)
    why.set_defaults(func=cmd_why)
    lineage = sub.add_parser("lineage")
    lineage.add_argument("entity_id")
    lineage.add_argument("--direction", choices=("UPSTREAM", "DOWNSTREAM"), default="DOWNSTREAM")
    lineage.add_argument("--limit", type=int, default=None)
    lineage.set_defaults(func=cmd_lineage)

    return parser


async def _run(args: argparse.Namespace) -> int:
    if getattr(args.func, "__name__", "") == "cmd_init":
        return cmd_init(args)  # init bootstraps locally; no daemon connection
    if args.func is cmd_start:
        return await cmd_start(args)
    client = await _connect(args)
    try:
        return await args.func(client, args)
    finally:
        await client.aclose()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return asyncio.run(_run(args))
    except StableError as exc:
        return _fail(args, exc)
    except KeyboardInterrupt:
        return _EXIT_INTERNAL


def run_cli() -> None:
    sys.exit(main())


if __name__ == "__main__":
    run_cli()
