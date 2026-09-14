# Runtime Step 09 — Release Closure

> 状态：PLANNED  
> 前置：Step 00～08 VERIFIED  
> 规范定位：§41.33～41.40、§41.47、§41.55、§41.58～41.60、§43～46

## 目标

把全部局部能力闭合为可重复构建、升级、恢复和审计的Runtime v0.1发行物。

## 实施顺序

1. 实现backup/restore、相邻migration upgrade、retention/GC plan与apply。
2. 冻结Runtime builtin AMPAK/lock、schema/proto golden和release manifest。
3. 生成wheel/sdist、SBOM、provenance、dependency hashes和artifact signatures。
4. 在Linux/Windows执行空目录、network deny、无Seed的完整E2E。
5. 执行crash、race、clock jump、low disk、credential loss和tamper矩阵。
6. 运行traceability checker，收集每个Required named proof与evidence hash。
7. 验证Deferred和External-Seed没有被宣传为Runtime implemented。
8. 完成operator runbook、known limitations和feature report。

## 发布门禁

- 规范和traceability的218个ID集合严格相等且每个恰好一次。
- 全部207个Runtime `Required` row通过；Deferred保持显式，External-Seed不参与结论。
- Runtime可在Seed仓库不存在时完成init revision 0、Conformance生命周期、Task、restart、backup/restore和upgrade。
- wheel/RECORD/SBOM无Conformance fixture、Seed module、Seed distribution或checkout path。
- SQLite/Portable DDL、Fact chain、Artifact hashes、Authority和恢复检查全部通过。

满足所有门禁后才可把Runtime v0.1标为release candidate；外部Seed的发布由其S03计划独立决定。
