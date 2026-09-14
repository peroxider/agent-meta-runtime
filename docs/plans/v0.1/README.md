# Agent Meta-Runtime v0.1 分步实施计划

> 规范基线：[`../../Agent_Meta_Runtime_Requirements_Design_v0.1.md`](../../Agent_Meta_Runtime_Requirements_Design_v0.1.md)
> 需求追踪：[`../../spec/v0.1-scope-and-traceability.md`](../../spec/v0.1-scope-and-traceability.md)
> 状态：PLANNED

本目录把编码工作拆成短小、可独立验收的步骤。主规范继续作为唯一的字段、DDL、协议、状态机和FR/NFR/AC定义来源；步骤文档只规定实施顺序、交付物和退出门禁，不复制完整规范正文。发生冲突时以实现交接文档规定的权威顺序为准。

## 文档约束

- 一个步骤只产生一个可审查的能力增量，目标不超过120行；超过160行必须继续拆分子步骤。
- 每一步必须列出输入、范围、交付物、验证和退出条件。
- `Required`证据只能来自Runtime仓库；`External-Seed`证据不得改变Runtime发布结论。
- 步骤完成只表示局部门禁通过，v0.1完成仍以Step 09和完整traceability为准。
- Seed Harness文档全部位于`seed-harness/`，文件名必须以`Seed_Harness_`开头，以便整体复制到外部项目。

## Runtime 步骤

| 顺序 | 计划 | 主要产物 | 前置 |
|---:|---|---|---|
| 00 | [Foundation](Runtime_00_Foundation.md) | 工程骨架、编码规则、架构lint | 无 |
| 01 | [Store](Runtime_01_Store.md) | SQLite、CAS、Fact chain、UoW | 00 |
| 02 | [Semantic Core](Runtime_02_Semantic_Core.md) | Identity、Task、Action、View、Context | 01 |
| 03 | [Authority & Composition](Runtime_03_Authority_Composition.md) | Grant、Capability、Composition、State | 02 |
| 04 | [Execution](Runtime_04_Execution.md) | Backend协议、Portable worker、Effect | 03 |
| 05 | [Control Plane](Runtime_05_Control_Plane.md) | Outbox、Reconciler、恢复和切换 | 04 |
| 06 | [Interfaces](Runtime_06_Interfaces.md) | SDK、local RPC、CLI、readiness | 05 |
| 07 | [Harness Host & Scratch](Runtime_07_Harness_Host_Scratch.md) | Harness生命周期、Conformance、IPython | 06 |
| 08 | [Evolution](Runtime_08_Evolution.md) | Experiment、Evidence、Promotion | 07 |
| 09 | [Release Closure](Runtime_09_Release_Closure.md) | 跨平台发布、备份升级、完整证据 | 08 |

默认依赖链为`00 → 01 → 02 → 03 → 04 → 05 → 06 → 07 → 08 → 09`。实现可以并行准备schema、fixture和文档，但不得在前一步退出门禁失败时宣称后一步可发布。

## 外部 Seed Harness 步骤

这些计划描述另一个项目的工作，不是本仓库产品实现范围：

| 顺序 | 计划 | 主要产物 |
|---:|---|---|
| S00 | [项目引导](seed-harness/Seed_Harness_00_Project_Bootstrap.md) | 独立仓库、包名和单向依赖 |
| S01 | [Package Contract](seed-harness/Seed_Harness_01_Package_Contract.md) | AMPAK、manifest、grant和Composition模板 |
| S02 | [Loop、Context、Provider](seed-harness/Seed_Harness_02_Loop_Context_Provider.md) | Seed行为实现与确定性fixture |
| S03 | [集成与发布](seed-harness/Seed_Harness_03_Integration_Release.md) | Runtime兼容矩阵、AC-M17/M48、独立发布 |

Seed步骤只依赖已发布的Runtime公共SDK/Contract或显式CI输入，不读取Runtime私有源码路径。Runtime CI不得反向执行这些步骤。

## 变更规则

新增工作先判断属于哪个步骤；跨三个以上步骤的契约变更先修改主规范和ADR，再同步受影响步骤。完成状态使用`PLANNED → IN_PROGRESS → VERIFIED`，只有链接到traceability中命名证据后才允许标记`VERIFIED`。
