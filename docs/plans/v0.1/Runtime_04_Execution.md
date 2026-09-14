# Runtime Step 04 — Execution

> 状态：PLANNED  
> 前置：Step 03 VERIFIED  
> 规范定位：§37、§41.27、§41.32、§41.36、§41.41、§41.45、§41.48

## 目标

在语言中立Execution Backend Contract之上提供InMemory和Portable执行，并以EffectIntent约束外部副作用。

## 实施顺序

1. 冻结Backend v1 protobuf、field numbers、feature negotiation和错误映射。
2. 实现InMemory contract backend及可注入durable fake state。
3. 实现Portable request ledger、PREPARED/CLAIMED/RUNNING/TERMINAL/UNKNOWN状态机。
4. 实现worker目录、create-new claim、PID/start identity/nonce和process-tree取消。
5. 实现workspace/最小environment、Linux process group与Windows Job Object。
6. 实现EffectIntent reservation、dedupe、settlement和unknown fail-closed。
7. 实现AgentOS client和fake provider contract gate，不实现production AgentOS daemon。

## 交付物

- Backend proto/client、InMemory/Portable adapters。
- portable.db migration、worker launcher、inspect/reconcile/cancel。
- Effect schema和delivery/recovery fixtures。

## 验证与退出门禁

- 同一request/hash幂等，hash冲突失败，旧owner不能terminal commit。
- crash、重复delivery和cancel不会产生第二个不可幂等effect。
- Backend feature不足返回`FEATURE_UNAVAILABLE`，不伪造隔离能力。
- FR-MOS、FR-MEFFECT、FR-MSEC-002及AC-M09A/M09B/M22/M30/M34/M39/M43通过后进入Step 05。
