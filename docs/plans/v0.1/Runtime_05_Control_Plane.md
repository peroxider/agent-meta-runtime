# Runtime Step 05 — Control Plane

> 状态：PLANNED  
> 前置：Step 04 VERIFIED  
> 规范定位：§41.15、§41.17、§41.31、§41.38、§41.47、§41.51、§41.59

## 目标

实现transactional outbox、Reconciler、health probe、原子serving切换和确定性恢复。

## 实施顺序

1. 实现outbox lease owner/generation、stable dedupe、retry/dead-letter和clock rollback保护。
2. 实现desired→plan→instantiate/migrate/probe→serving/realized的Reconciler状态机。
3. 所有外部调用移出Meta Store write transaction，并用短事务提交结果。
4. 实现required/preferred health probe、pre-serving routing隔离和重复response处理。
5. 实现State migration与Composition cutover的单terminal transaction。
6. 实现daemon restart inspect/reconcile、orphan quarantine和UNKNOWN处置。
7. 实现core/serving readiness Facts、backpressure和operator recovery计划。

## 交付物

- outbox dispatcher、Reconciler、probe runner和recovery coordinator。
- crash-point/fault-injection fixtures、readiness reason registry。
- refs/state/history原子切换测试。

## 验证与退出门禁

- 每个外部请求可重放但只被当前lease owner结算。
- 失败切换保留旧serving；成功切换不出现混合Composition/State schema。
- revision 0无Harness时可稳定`core_ready=true/serving_ready=false`。
- FR-MSTORE-005/006、FR-MOPS-004/005、FR-MRUN-009及AC-M16/M20/M23/M33/M46/M53通过后进入Step 06。
