# Runtime Step 02 — Semantic Core

> 状态：PLANNED  
> 前置：Step 01 VERIFIED  
> 规范定位：§41.4～41.12、§41.25、§41.35、§41.44

## 目标

建立不依赖具体Harness策略的Identity、Task、Action、Invocation、Context和RuntimeView语义核心。

## 范围与顺序

1. 实现Realm、Epoch、Principal和稳定semantic ID。
2. 实现Task durable状态机、terminal不可逆、deadline/cancel和冻结snapshot字段。
3. 实现Action/Invocation因果关系、attempt、input/output Artifact和terminal提交。
4. 实现Fact catalog、causal edge projection、why/lineage查询。
5. 实现revision-consistent RuntimeView与historical read。
6. 实现deterministic Context projection：先redact、再rank/budget，并记录provenance。
7. 实现safe reflection budget，禁止触发用户descriptor、property、iterator或`repr`。

## 交付物

- Domain DTO/state machine和application use cases。
- Task/Action/Invocation/Context/Reflection schema。
- RuntimeView、why、lineage projection与golden fixtures。

## 验证与退出门禁

- 重启、重复command和迟到terminal结果不破坏Task终态。
- 同一snapshot/context输入产生相同projection Artifact。
- RuntimeView明确返回meta revision、Fact boundary及core/serving readiness。
- FR-MFACT、FR-MTASK、FR-MINV、FR-MCTX、FR-MREF-001～004/006以及AC-M02/M03/M12/M26/M31/M32/M36/M37通过后进入Step 03。
