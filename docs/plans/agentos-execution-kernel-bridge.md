# AgentOS Execution Kernel Bridge — 8 RPC 逐字段映射方案

> 状态：PROPOSED（设计文档，未进入任何版本的实施计划）
> 日期：2026-11-03
> 下游（provider 侧）：`agent_meta.execution_backend.v1`（本仓库，冻结合同：
> `proto/agent_meta/execution_backend/v1/execution_backend.proto`，§41.27 / §41.41）
> 上游（substrate 侧）：`agentos.kernel.v1`（agentos-execution-kernel 仓库，冻结 ABI：
> `proto/agentos/kernel/v1/service.proto`，gRPC over UDS）
> 前置结论：v0.1 只交付 `AgentOSFakeProvider` contract gate（Runtime_04 步骤 7），
> 本文档是 production provider 的映射设计，不修改 v0.1 计划与冻结合同。

## 0. 桥的位置与总体决策

```
meta-runtime (Harness loop)
  └─ execution_port (BackendContract, agent_meta.execution_backend.v1)
       └─ [新增] AgentOSProvider  ← 本方案要实现的桥（进程内 Python，同 FakeProvider 位置）
            └─ agentos-execution-kernel Python SDK (gRPC over UDS, agentos.kernel.v1)
                 └─ agentos-kerneld
```

三个总体决策：

1. **会话是桥内对象**。kernel 没有会话（session）概念，`BackendSession` /
   `session_id` 完全由桥维护；kernel 连接是长连 gRPC/UDS，`Hello` 在桥启动或
   首次 Negotiate 时调用一次。
2. **kernel 侧命名全部确定性派生**，让 Submit 天然幂等：
   `realm_name = "meta-" + sha256(realm_id)[:16]`；
   `process_name = realm_name + "-host"`（每 realm 一个长驻宿主进程，
   `ActivitySpec.process_name` 为必填）；
   `activity_name = "act-" + request_id`（request_id 是 UUIDv7；UUIDv4 约束只
   适用于 kernel `RequestMeta.request_id`，桥为每个 kernel 调用自行生成
   UUIDv4 并在账本里记录映射）。
3. **`ExecutionHandle.opaque_handle` 编码 kernel 的 `ObjectRef`**：JCS JSON
   `{"name":…, "generation":…, "revision":…}`。`incarnation` 直接取
   `ref.generation`——kernel 重启恢复后 generation 前进，恰好对应本合同
   "句柄换 incarnation" 的语义。

## 1. 预备映射表（贯穿 8 个 RPC）

### 1.1 状态词表：kernel `ActivityState` → backend `status` 字符串

| kernel ActivityState | backend ExecutionResult.status / ExecutionSnapshot.status |
|---|---|
| NEW / READY / RUNNING / BLOCKED / SUSPENDED | `RUNNING` |
| CANCELLING / KILLING | `CANCELLING` |
| COMPLETED | `COMPLETED` |
| FAILED | `FAILED` |
| CANCELLED | `CANCELLED` |
| TIMED_OUT | `TIMED_OUT` |
| KILLED | `FAILED`（error_jcs 注明 killed） |

### 1.2 错误映射：kernel `KernelErrorCode` → 本仓库 `ErrorCode`（含 retryable）

| KernelErrorCode | meta ErrorCode | retryable |
|---|---|---|
| INVALID_ARGUMENT | INVALID_ARGUMENT | false |
| NOT_FOUND | HANDLE_EXPIRED（句柄解码出的 name 查无此对象时）／NOT_FOUND（其余） | false |
| ALREADY_EXISTS | IDEMPOTENCY_CONFLICT（activity_name 相同但 payload_hash 不同）／ALREADY_EXISTS（相同且 hash 相同 → 幂等成功路径） | false |
| INVALID_STATE | FAILED_PRECONDITION | false |
| PERMISSION_DENIED | AUTHORITY_DENIED | false |
| RESOURCE_EXHAUSTED / ADMISSION_REJECTED | RESOURCE_EXHAUSTED | true |
| DEADLINE_EXCEEDED | DEADLINE_EXCEEDED | true |
| 连接层失败 | BACKEND_UNAVAILABLE | true |
| 其余 / 未识别 | INTERNAL | false |

`RpcError.details_jcs` 携带 kernel `KernelError` 的 JCS 原文；
`correlation_id` 回填本仓库侧 `request_id`。

### 1.3 通用字段

| backend 字段 | kernel 对应 | 说明 |
|---|---|---|
| `RpcEnvelope.request_id`（UUIDv7） | `RequestMeta.request_id`（**必须是 UUIDv4**） | 桥生成新 UUIDv4，账本记 `uuid7 ↔ uuid4` |
| `deadline_at_us` | `RequestMeta.deadline`（google.protobuf.Timestamp） | 0 → 不设置 |
| `trace`（仅 traceparent/tracestate） | `RequestMeta.trace_context` | 键集合一致，直传 |
| `authority_token` | **不上 kernel** | enforcement-only：桥先验签，再以 token 内 principal 作为 `claimed_principal_name` 发出 kernel 调用；kernel 侧授权走它自己的 Grant 体系。token 任何情况下不进 kernel 调用、不进日志（§41.27 redaction 条款） |

## 2. 逐 RPC 映射

### 2.1 Negotiate

`ClientHello` → `Hello` +（一次性）`GetKernelStatus`

| ClientHello 字段 | kernel 调用/字段 | BackendSession 回填 |
|---|---|---|
| `supported[]`（VersionRange） | `HelloRequest.supported_abi_versions = ["v1"]`（任一 range.major==1 即声明） | `protocol_major=1, protocol_minor=selected`（从 `selected_abi_version` 解析） |
| `required_features` / `optional_features` | `HelloRequest.requested_features`（直传） | 与 `enabled_features` 求交后写 `features_jcs`（JCS 数组）；required 未被满足 → 直接抛 `CONTRACT_INCOMPATIBLE`，不建会话 |
| `client_instance_id` | 无对应 | 仅入桥账本 |

`BackendSession` 其余字段：`profile` — kernel 提供 realm 隔离 + 监督重启 →
**`"MANAGED"`**（上游启用 `k5.cluster` 时可声明 `"DISTRIBUTED"`，v1 桥先只做
MANAGED，守住 §41.48.4 profile 诚实性）；
`backend_id = "backend://agentos-kernel/" + kernel_instance_id`；
`session_id` 桥生成 UUIDv7；`features_jcs` 来自 `HelloResponse.enabled_features`
+ `GetKernelStatus` 能力开关；`limits_jcs` 来自 `GetKernelStatus` 资源清单的
JCS；`established_at_us = server_time_us`。

### 2.2 Submit

`ExecutionRequest` → `CreateRealm`（懒）→ `SpawnProcess`（懒）→ `SubmitActivity`

| ExecutionRequest 字段 | kernel 对应 |
|---|---|
| `session_id` | 无 kernel 对应；桥校验会话有效 |
| `realm_id` | `ActivitySpec.realm_name = "meta-" + sha256(realm_id)[:16]`；不存在则 `CreateRealm{requested_name, adapter_kind:"linux", minimum_isolation:NAMESPACE}`（每 realm_id 懒创建一次） |
| `request_id` | 不进 kernel；派生 `activity_name = "act-" + request_id` 作为幂等键 |
| `operation_kind` | `OpaquePayload.schema_ref = "urn:agentos:schema:exec:<operation_kind>:v1"` |
| `payload_jcs` | `OpaquePayload{content_type:"application/jcs+json", data:payload_jcs}` → `ActivitySpec.payload` |
| `payload_hash` | kernel 无字段；桥账本记录，幂等冲突判定用（见 1.2） |
| `idempotency_class` / `dedupe_scope` / `reversibility` | kernel 无字段；桥账本按 `(dedupe_scope, request_id)` 去重 |
| `requested_retention_us` | kernel 无字段；由 AcknowledgeTerminal 的桥内账本承担（见 2.7） |
| `deadline_at_us` | `ActivitySpec.hard_deadline`（Timestamp）+ `RequestMeta.deadline` 双写 |
| `authority_token` | 见 1.3：不上 kernel |
| —（新增） | `ActivitySpec.process_name = realm_name + "-host"`（首次 Submit 前 `SpawnProcess`：`ExecutionMode: MULTIPLEXED_SERVICE`、`CompletionKind: PROCESS_EXIT`、`RestartPolicy: ALWAYS`） |

返回 `SubmitActivityResponse.activity` → `ExecutionHandle`：

| ActivityRecord | ExecutionHandle |
|---|---|
| `ref`（name/generation/revision） | `opaque_handle` = JCS(ref)；`incarnation = ref.generation` |
| — | `backend_id` / `session_id` / `request_id` 按会话与请求回填 |
| `hard_deadline` | `expires_at_us` |

### 2.3 Await

`ExecutionHandle` + `deadline_at_us` → `WaitActivity{activity_name, expected_generation}`

- `opaque_handle` 解码出 `name/generation` → `activity_name` /
  `expected_generation`（generation 不匹配 → kernel 报错 → 按 1.2 映射
  `HANDLE_EXPIRED`）。
- `deadline_at_us` → `RequestMeta.deadline`。kernel `DEADLINE_EXCEEDED` 时
  **不报错**，返回 `ExecutionResult{status:"RUNNING", effect_state_unknown:false}`
  （状态可继续通过 Inspect 观察；外部效应确定性未知不成立）。
- 终态时 `ActivityRecord.result`（`ActivityResult`）→ `ExecutionResult`：

| ActivityResult | ExecutionResult |
|---|---|
| `payload`（OpaquePayload） | 桥把 `payload.data` 注册进本仓库 CAS → `result_artifact_id`；`result_hash = sha256(payload.data)`（hex） |
| `usage`（UsageSnapshot） | `usage_jcs` = UsageSnapshot 的 JCS |
| `error`（KernelError） | `error_jcs` = `{"code":映射后 meta code, "kernel_code":…, "message":…}` 的 JCS；无 error 则 oneof 走 `result_artifact_id` |
| `completed_at` | `completed_at_us` |
| `terminal_state` / `completion_kind` / `exit_code` | 折入 `status`（1.1 表）；`exit_code` 并入 `usage_jcs` |
| — | `effect_state_unknown = false`（仅 kernel 实例重启且 reconcile 判定状态丢失时置 true） |

### 2.4 Cancel

`CancelRequest{handle, mode, deadline_at_us}` →
`CancelActivity{activity_name, expected_generation, expected_revision, reason}`

- handle 解码 → 三个 expected 字段（kernel 的 CAS 乐观并发正好用上）。
- `mode`：`"GRACEFUL"` → `CancelActivity`（kernel 内部走 CANCELLING→KILLING
  阶梯）；`"KILL"` → 先 `CancelActivity`，若在 `deadline` 内未到终态再升级
  `KillProcess`（宿主进程级，最后手段）。
- `CancelReport{status}` ← 操作后的 `ActivityRecord.state`（映射同 1.1）；
  `terminal_confirmed` = 已达终态（未达则 false，调用方用 Await/Inspect 收尾）；
  `details_jcs` = `OperationRecord` 的 JCS。

### 2.5 Inspect

`ExecutionHandle` → `InspectActivity{activity_name}`

| ActivityRecord | ExecutionSnapshot |
|---|---|
| `ref` | `handle`（重新编码，generation/revision 取当前值） |
| `state` | `status`（1.1 表） |
| `result`（仅终态存在） | `terminal`（同 2.3 的 ExecutionResult 构造） |
| —（运行中无 usage） | `usage_jcs = ""` |
| — | `observed_at_us` = `ResponseMeta.server_time` |

已知缺口：kernel 不经终态不暴露活动级 usage（UsageSnapshot 只在
ActivityResult 里）；v1 桥如实留空，不做推测。

### 2.6 Reconcile

`ReconcileRequest{session_id, realm_id, known[]}` →
`GetSnapshot{scope: ObjectScope{kind:"activity"}}`（按 realm 过滤，翻页取全）

对每个 `KnownBinding`：

1. 解码 `handle.opaque_handle` → `activity_name`；
2. 在 snapshot.activities 中查找：
   - **找到且终态** → `ReconciledBinding{known, status, terminal}`
     （ExecutionResult 构造同 2.3；`result_hash` 重算并与账本比对，
     不一致 → `INTEGRITY_ERROR`）；
   - **找到且非终态** → `renewed_handle`：用当前 `ref` 重编码
     （kernel 恢复后 generation 前进 → 新 incarnation）；
   - **找不到** → `OrphanWorkload{handle, request_id, payload_hash,
     recommended_action:"resubmit"}`（kernel 无该 activity 记录：从未落库
     或已过保留）。
3. `observed_at_us` ← `ResponseMeta.server_time`。

### 2.7 AcknowledgeTerminal

`TerminalAck{session_id, request_id, result_hash}` → **kernel 无对应 RPC**
（kernel 的 activity 记录无调用方确认式 GC）。

桥内账本处理：校验 `result_hash` 与账本记录一致（不一致 →
`INTEGRITY_ERROR`）；标记 acked；`AckReport{status:"ACKED",
retained_until_us}` = 账本保留策略（桥配置，如 now + requested_retention_us）。
kernel 侧记录任其留在 SQLite 快照里，不删除——这是诚实映射，不伪造 kernel 能力。

### 2.8 CloseSession

`BackendSession` → `CloseReport`。**kernel 无对应**：桥仅标记会话关闭；
合同明确 "closing is advisory, in-flight work is not cancelled"，与 kernel
语义天然一致（活动继续跑，后续 Reconcile 仍可按 handle 找回）。
`CloseReport{status:"CLOSED", session_id, closed_at_us}`。

## 3. 缺口与风险清单

| # | 缺口 | 处置 |
|---|---|---|
| 1 | kernel `RequestMeta.request_id` 强制 UUIDv4 | 桥生成 v4，账本记 v7↔v4 映射；Facts 引用一律用本仓库侧 v7 |
| 2 | `idempotency_class` / `dedupe_scope` / `reversibility` / `payload_hash` kernel 无字段 | 桥账本承担（FakeProvider 已有同型 ledger，可复用结构） |
| 3 | `authority_token` per-request 语义 vs kernel 的 principal/Grant 模型 | 桥验签后映射 principal；token 永不透传（满足 redaction 条款） |
| 4 | 运行中活动无 usage 观测 | v1 留空；后续可接 `WatchSnapshot`（仅观测，非权威，符合上游 §35.8） |
| 5 | `requested_retention_us` / AcknowledgeTerminal 无 kernel 对应 | 桥账本承担；不伪造 kernel GC |
| 6 | 每次 Submit 懒建 realm+process 的竞态 | realm/process 用确定性名 + `ALREADY_EXISTS` 容忍重试，与 Submit 幂等路径同构 |

## 4. 落地形态

唯一需要本仓库新增的代码是 `src/agent_meta_runtime/adapters/execution_agentos/`
下的真 provider：复用 `AgentOSClient` 所在的帧协议位置，把 dispatch 从进程内
FakeProvider 换成 gRPC/UDS 调用 + 本文档的翻译层，并配套 contract gate 测试
（与 FakeProvider 同一套 8-RPC 会话断言，外加对 `agentos-kerneld` 的集成冒烟，
后者标记为需要本机 kernel 守护进程的 External 证据，不改变 Runtime 发布结论）。

**落地状态（2026-11-03）**：已实现——`mapping.py`（§1 映射表）、
`kernel_transport.py`（gRPC/UDS 传输缝）、`provider.py`（`AgentOSProvider`，
§2 全部 8 RPC + 桥账本复用 `PortableRequestLedger`）；kernel ABI 按上游
commit 原样 vendor 到 `protocols/_kernel_v1/`（`scripts/generate_protos.py`
生成）。契约门禁：`tests/unit/test_agentos_provider.py`（in-process fake
kernel，同一套 8-RPC 会话断言）；External 冒烟：
`tests/integration/test_agentos_kerneld_smoke.py`（需 `AGENTOS_KERNEL_ENDPOINT`
与 `agentos` extra，缺省跳过）。
