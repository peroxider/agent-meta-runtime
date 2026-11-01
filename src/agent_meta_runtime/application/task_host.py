"""Bound trusted in-process Task execution; the external package owns the Loop.

All admission, authority, journal and terminal writes are delegated to a store
port. No transaction spans a package callback. Cancellation is cooperative in
this explicitly trusted profile; it is not process isolation or hard preemption.
"""

import asyncio
import json
import inspect
import secrets

from ..domain.canonical import canonical_json, sha256_hex
from ..domain.errors import ErrorCode, StableError
from ..domain.host_contract import (CapabilityInvocation, ContextProjection, InvocationResult, ModelInvocation,
    decode_model_response, encode_model_response, encode_terminal_result, part_to_value)
from ..domain.host_contract import ProviderRequestPlan, ProviderTerminalResponse
from ..domain.loop import ToolCallPart, terminal_result, tool_calls_in_order
from ..domain.host_schema import validate_host_value
from ..ports.host_execution import HostCallValue, PreparedProviderCall


def _invalid(message):
    return StableError(code=ErrorCode.INVALID_RESULT, message=message)


_SESSIONS = {}


def _session(token):
    session = _SESSIONS.get(token)
    if session is None:
        raise asyncio.CancelledError()
    return session


class _TaskFacade:
    """Only an opaque session capability crosses into the external package.

    No store, native adapter, command authority or provider object is a facade
    field. This is an API boundary within explicitly trusted Python execution,
    not a claim that Python introspection is an isolation mechanism.
    """
    __slots__ = ("__token",)

    def __init__(self, token):
        self.__token = token

    async def project_context(self, request):
        return await _session(self.__token).project_context(request)

    async def invoke_model(self, projection):
        return await _session(self.__token).invoke_model(projection)

    async def invoke_tool(self, call):
        return await _session(self.__token).invoke_tool(call)

    def check_cancelled(self):
        _session(self.__token).check_cancelled()


class TaskSession:
    __slots__ = ("_store", "_task", "_bound", "_ordinal", "_models", "_history", "_pending", "_calls", "_last", "_projections", "_busy", "_closed", "_workers", "_runner", "_providers")

    def __init__(self, store, task, bound, runner=None, providers=None):
        self._store, self._task, self._bound = store, task, bound
        self._runner = runner
        self._providers = providers
        self._ordinal, self._models = 0, 0
        self._history, self._pending, self._calls = [], [], set()
        self._last, self._projections, self._busy = None, {}, False
        self._closed, self._workers = False, set()

    def check_cancelled(self):
        if self._closed:
            raise asyncio.CancelledError()
        self._store.check(self._task.task_id)

    def _schema(self, operation, field, value):
        schema = json.loads(self._store.read_artifact(operation[field]))
        validate_host_value(schema, value)

    def _model_value(self, response, operation):
        raw = encode_model_response(response)
        self._schema(operation, "output_schema_artifact_id", json.loads(raw))
        usage = response.usage
        return HostCallValue(content=raw, usage={"input_tokens": usage.input_tokens if usage else None,
            "output_tokens": usage.output_tokens if usage else None, "cost_microunits": usage.cost_microunits if usage else None})

    @staticmethod
    def _provider_plan(provider, invocation):
        try:
            plan = provider.prepare(invocation)
            if inspect.iscoroutine(plan):
                plan.close()
            if type(plan) is not ProviderRequestPlan:
                raise ValueError("Provider plan callback returned an invalid value")
            return plan
        except (Exception, SystemExit):
            raise _invalid("Provider plan callback failed") from None

    def _provider_normalizer(self, provider, plan, operation):
        def normalize(terminal):
            try:
                if type(terminal) is not ProviderTerminalResponse or terminal.profile_artifact_id != plan.profile_artifact_id:
                    raise ValueError("Provider terminal profile differs")
                response = provider.normalize(terminal)
                if inspect.iscoroutine(response):
                    response.close()
                return self._model_value(response, operation)
            except (Exception, SystemExit):
                raise _invalid("Provider normalization callback failed") from None
        return normalize

    async def _activity(self, reserved, kind, capability, operation, content, execute):
        try:
            value = (await self._runner.invoke(task=self._task, invocation_id=reserved["invocation_id"],
                kind=kind, capability_id=capability, operation=operation, content=content, execute=execute)
                if self._runner else await execute())
        except Exception as exc:
            self._store.finish_invocation(reserved["invocation_id"],
                error=exc.code if isinstance(exc, StableError) else ErrorCode.INTERNAL)
            raise
        # A failed commit must propagate without a second terminal attempt.
        extra = {"backend_result": dict(value.backend_result)} if value.backend_result is not None else {}
        self._store.finish_invocation(reserved["invocation_id"], content=value.content,
            error=value.error_code, usage=dict(value.usage) if value.usage is not None else None, **extra)
        if value.raise_error:
            raise StableError(code=value.error_code, message="Host activity failed")
        return value

    async def close(self):
        self._closed = True
        children = self._workers - {asyncio.current_task()}
        for worker in children:
            worker.cancel()
        if children:
            await asyncio.gather(*children, return_exceptions=True)

    async def project_context(self, request):
        # Even a cached projection can synchronously commit a journal command.
        # Yield outside the transaction so repeated facade calls cannot starve
        # control-plane Hello, cancellation or other Task scheduling.
        await asyncio.sleep(0)
        self.check_cancelled()
        projection = self._store.save_projection(self._task, request)
        previous = self._projections.get(projection.manifest.projection_id)
        if previous is not None:
            if previous != projection:
                raise StableError(code=ErrorCode.INTEGRITY_ERROR, message="replayed Context projection identity changed")
            return previous
        self._projections[projection.manifest.projection_id] = projection
        return projection

    def _operation(self, name, *, model=False):
        matches = []
        surface = json.loads(self._task.capability_surface_content)
        names = {op["operation_id"] for op in surface["operations"]}
        for slot_name, slot in self._bound.composition["slots"].items():
            descriptor = self._bound.descriptors[(slot["capability_id"], slot["descriptor_revision"])]
            for operation in descriptor["operations"]:
                if operation["operation_id"] not in names:
                    continue
                if (model and slot_name == "model" and "model.invoke" in operation["effects"]) or (not model and operation["operation_id"] == name):
                    matches.append((descriptor["capability_id"], operation))
        if len(matches) != 1:
            raise StableError(code=ErrorCode.AUTHORITY_DENIED, message="operation is absent or ambiguous in the frozen Capability Surface")
        capability, operation = matches[0]
        effects = set(operation["effects"])
        if effects - ({"none", "model.invoke"} if model else {"none"}):
            raise StableError(code=ErrorCode.FEATURE_UNAVAILABLE, message="operation effects require an unavailable execution profile")
        if not model and operation["idempotency"] != "PURE":
            raise StableError(code=ErrorCode.FEATURE_UNAVAILABLE, message="this Host profile supports only PURE tools")
        return capability, operation

    async def invoke_model(self, projection):
        await asyncio.sleep(0)
        self.check_cancelled()
        if self._busy or self._pending:
            raise _invalid("model calls must follow serial completion of the preceding tool calls")
        if not isinstance(projection, ContextProjection) or self._projections.get(projection.manifest.projection_id) is not projection:
            raise _invalid("model requires a projection issued by this Task Host")
        capability, operation = self._operation(None, model=True)
        self._busy = True
        worker = asyncio.current_task()
        self._workers.add(worker)
        try:
            history = canonical_json(self._history)
            request_id = f"{self._task.task_id}/invocation/{self._ordinal}"
            content = canonical_json({"schema": "host-model-request/v1", "projection_id": projection.manifest.projection_id,
                "projection_identity_hash": projection.manifest.identity_hash(), "rendered_artifact_id": projection.rendered_artifact_id,
                "history": self._history, "model_ordinal": self._models})
            provider = getattr(self._bound.adapter, "provider", None)
            prepared = None
            if provider is not None:
                plan = self._provider_plan(provider, ModelInvocation(self._task, request_id, self._models, projection, history))
                value = json.loads(content)
                content = canonical_json({**value, "schema": "host-model-request/v2",
                    "provider_plan": {"profile_artifact_id": plan.profile_artifact_id, "body_sha256": sha256_hex(plan.body)}})
            self._schema(operation, "input_schema_artifact_id", json.loads(content))
            if provider is not None:
                if self._providers is None:
                    raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="controlled Provider execution is not configured; approved profile, exact tokenizer and pricing enforcement are required")
                prepared = self._providers.prepare(task=self._task, ordinal=self._ordinal, capability_id=capability,
                    operation=operation, plan=plan, projection=projection, normalize=self._provider_normalizer(provider, plan, operation))
                if type(prepared) is not PreparedProviderCall:
                    raise StableError(code=ErrorCode.INTERNAL, message="Provider preparation has no enforced reservation")
                self.check_cancelled()
            reserved = self._store.reserve(self._task, ordinal=self._ordinal, kind="MODEL", capability_id=capability,
                operation=operation, content=content, projection_id=projection.manifest.projection_id,
                **({"provider": prepared.reservation,
                    **({"provider_request":prepared.request} if prepared.reservation.configuration_fact_id is not None else {})}
                    if prepared is not None else {}))
            self._ordinal += 1
            request_id = f"{self._task.task_id}/invocation/{self._ordinal - 1}"
            if reserved["replay"]:
                if reserved["error"]:
                    raise StableError(code=reserved["error"], message="replayed model invocation failed")
                response = decode_model_response(self._store.read_artifact(reserved["output_artifact_id"]))
            elif prepared is not None:
                value = await self._providers.invoke(task=self._task, invocation_id=reserved["invocation_id"], prepared=prepared)
                if value.error_code:
                    raise StableError(code=value.error_code, message="controlled Provider invocation failed")
                response = decode_model_response(value.content)
            else:
                async def execute():
                    response = await self._bound.adapter.invoke_model(ModelInvocation(self._task, request_id, self._models, projection, history))
                    return self._model_value(response, operation)
                value = await self._activity(reserved, "MODEL", capability, operation, content, execute)
                if value.error_code:
                    raise StableError(code=value.error_code, message="model invocation failed")
                response = decode_model_response(value.content)
            self.check_cancelled()
            if provider is None and (response.usage is None or response.usage.cost_microunits != 0):
                raise StableError(code=ErrorCode.FEATURE_UNAVAILABLE, message="this Host profile requires an explicitly zero-cost provider result")
            self._models += 1
            calls = tool_calls_in_order(response)
            if any(call.call_id in self._calls for call in calls):
                raise _invalid("tool call IDs must be unique across the Task")
            self._calls.update(call.call_id for call in calls)
            self._pending = list(calls)
            self._history.append({"role": "model", "response": json.loads(encode_model_response(response))})
            self._last = response
            return response
        finally:
            self._busy = False
            self._workers.discard(worker)

    async def invoke_tool(self, call):
        await asyncio.sleep(0)
        self.check_cancelled()
        if self._busy or not isinstance(call, ToolCallPart) or not self._pending or call != self._pending[0]:
            raise _invalid("only the next normalized model tool call may be dispatched")
        capability, operation = self._operation(call.name)
        callback = self._bound.adapter.tools.get(call.name)
        if callback is None:
            raise StableError(code=ErrorCode.FEATURE_UNAVAILABLE, message="tool has no installed package binding")
        self._busy = True
        worker = asyncio.current_task()
        self._workers.add(worker)
        try:
            self._schema(operation, "input_schema_artifact_id", json.loads(call.arguments_json))
            content = canonical_json({"schema": "host-tool-request/v1", "call": part_to_value(call)})
            reserved = self._store.reserve(self._task, ordinal=self._ordinal, kind="CAPABILITY", capability_id=capability,
                operation=operation, content=content)
            self._ordinal += 1
            request_id = f"{self._task.task_id}/invocation/{self._ordinal - 1}"
            if reserved["replay"]:
                if reserved.get("raise_error"):
                    raise StableError(code=reserved["error"], message="replayed tool activity failed validation")
                result = InvocationResult(error_code=reserved["error"]) if reserved["error"] else InvocationResult(content=self._store.read_artifact(reserved["output_artifact_id"]))
            else:
                async def execute():
                    result = await callback(CapabilityInvocation(self._task, request_id, call))
                    if not isinstance(result, InvocationResult):
                        raise _invalid("tool returned an invalid normalized result")
                    if result.content is not None:
                        self._schema(operation, "output_schema_artifact_id", json.loads(result.content))
                    return HostCallValue(content=result.content, error_code=result.error_code)
                value = await self._activity(reserved, "CAPABILITY", capability, operation, content, execute)
                result = InvocationResult(content=value.content, error_code=value.error_code)
            self.check_cancelled()
            self._pending.pop(0)
            self._history.append({"role": "tool", "call_id": call.call_id, "error_code": result.error_code,
                "content_hex": result.content.hex() if result.content is not None else None})
            if result.error_code and json.loads(self._task.loop_policy_content)["stop_on_tool_error"]:
                raise StableError(code=result.error_code, message="tool failed under stop-on-error policy")
            return result
        finally:
            self._busy = False
            self._workers.discard(worker)

    def validate_terminal(self, result):
        self.check_cancelled()
        if self._busy or self._pending or self._last is None:
            raise _invalid("Task terminal requires a completed terminal model response")
        raw = encode_terminal_result(result)
        if raw != encode_terminal_result(terminal_result(self._last)):
            raise _invalid("Task terminal differs from the complete normalized model response")
        return raw


class TaskHost:
    def __init__(self, store, catalog, runner=None, providers=None):
        self.store, self.catalog = store, catalog
        self.runner = runner
        self.providers = providers
        self.stopping, self.failure = False, None
        self._active = {}
        self._abort_status = {}

    async def _execute(self, task_id, composition_id):
        session = None
        token = secrets.token_hex(32)
        try:
            if self.store.interrupted(task_id):
                self.store.finish_task(task_id, "FAILED_RECOVERY", error=ErrorCode.EXTERNAL_EFFECT_UNKNOWN)
                return
            self.store.start(task_id)
            try:
                task = self.store.envelope(task_id, self.catalog.binding(composition_id))
            except StableError as exc:
                self.store.finish_task(task_id, "FAILED_RECOVERY", error=exc.code)
                return
            session = TaskSession(self.store, task, self.catalog.binding(composition_id), self.runner, self.providers)
            _SESSIONS[token] = session
            result = await self.catalog.binding(composition_id).adapter.run_task(task, _TaskFacade(token))
            self.store.finish_task(task_id, "SUCCEEDED", content=session.validate_terminal(result))
        except asyncio.CancelledError:
            if not self.stopping:
                status = self._abort_status.pop(task_id, "CANCELLED")
                error = ErrorCode.EXTERNAL_EFFECT_UNKNOWN if self.store.interrupted(task_id) else ErrorCode.DEADLINE_EXCEEDED if status == "TIMED_OUT" else None
                self.store.finish_task(task_id, status, error=error)
        except StableError as exc:
            status = "TIMED_OUT" if exc.code == ErrorCode.DEADLINE_EXCEEDED else "FAILED_RECOVERY" if exc.code == ErrorCode.EXTERNAL_EFFECT_UNKNOWN else "FAILED"
            self.store.finish_task(task_id, status, error=exc.code)
        except Exception:
            self.store.finish_task(task_id, "FAILED", error=ErrorCode.INTERNAL)
        finally:
            _SESSIONS.pop(token, None)
            if session is not None:
                await session.close()

    async def run(self):
        try:
            while not self.stopping:
                for task_id, composition_id in self.store.candidates():
                    if task_id not in self._active:
                        if self.store.interrupted(task_id):
                            self.store.finish_task(task_id, "FAILED_RECOVERY", error=ErrorCode.EXTERNAL_EFFECT_UNKNOWN)
                            continue
                        if self.catalog.recovery_failed(composition_id):
                            self.store.finish_task(task_id, "FAILED_RECOVERY", error=ErrorCode.CONTRACT_INCOMPATIBLE)
                            continue
                        try:
                            self.store.check(task_id)
                        except asyncio.CancelledError:
                            self.store.finish_task(task_id, "CANCELLED")
                            continue
                        except StableError as exc:
                            self.store.finish_task(task_id, "TIMED_OUT", error=exc.code)
                            continue
                    if task_id not in self._active and len(self._active) < 16 and self.catalog.healthy_for(composition_id):
                        self._active[task_id] = asyncio.create_task(self._execute(task_id, composition_id))
                for task_id, worker in tuple(self._active.items()):
                    if worker.done():
                        worker.result()
                        del self._active[task_id]
                    else:
                        try:
                            self.store.check(task_id)
                        except asyncio.CancelledError:
                            self._abort_status[task_id] = "CANCELLED"
                            worker.cancel()
                        except StableError as exc:
                            self._abort_status[task_id] = "TIMED_OUT" if exc.code == ErrorCode.DEADLINE_EXCEEDED else "CANCELLED"
                            worker.cancel()
                await asyncio.sleep(.01)
        except asyncio.CancelledError:
            raise
        except Exception:
            self.failure = ErrorCode.INTERNAL
        finally:
            self.stopping = True
            for worker in self._active.values():
                worker.cancel()
            await asyncio.gather(*self._active.values(), return_exceptions=True)
            self._active.clear()
