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

开发入口见[Seed开发交接](seed-harness/Seed_Harness_Development_Guide.md)，逐步骤证明见[Seed追踪计划](seed-harness/Seed_Harness_Traceability.md)。两者随本目录整体复制，引用的测试路径都属于未来Seed仓库，当前仍为PLANNED。

| 顺序 | 计划 | 主要产物 |
|---:|---|---|
| S00 | [项目引导](seed-harness/Seed_Harness_00_Project_Bootstrap.md) | 独立仓库、包名和单向依赖 |
| S01 | [Package Contract](seed-harness/Seed_Harness_01_Package_Contract.md) | AMPAK、manifest、grant和Composition模板 |
| S01A | [Public Contract / Host Integration](seed-harness/Seed_Harness_01A_Public_Host_Contract.md) | 管理RPC/执行Host SPI映射、Runtime依赖台账、独立包加载与恢复证明 |
| S02 | [Loop、Context、Provider](seed-harness/Seed_Harness_02_Loop_Context_Provider.md) | Seed行为实现与确定性fixture |
| S03 | [集成与发布](seed-harness/Seed_Harness_03_Integration_Release.md) | Runtime兼容矩阵、AC-M17/M48、独立发布 |
| S04 | [Real Model Providers](seed-harness/Seed_Harness_04_Real_Model_Providers.md) | Provider profile、真实adapter、credential handle、R2 replay |
| S05 | [First Capability Toolset](seed-harness/Seed_Harness_05_Capability_Toolset.md) | 首批工具Capability、schema校验、redaction |
| S06 | [Conversation Session Model](seed-harness/Seed_Harness_06_Conversation_Sessions.md) | 会话=Managed State、消息→Task、Context预算 |
| S07 | [Evolution Capability](seed-harness/Seed_Harness_07_Evolution_Capability.md) | Proposal/ChangeSet生成、隔离实验、自迭代闭环、按S03流程发布 |
| S08 | [Tool/Skill Artifact Evolution](seed-harness/Seed_Harness_08_Tool_Skill_Evolution.md) | 工具/skill制品自改进（REPLACE_ARTIFACT白名单）、事件驱动有界触发、可选真实模型metric |
| S09 | [Harness Code Self-Evolution](seed-harness/Seed_Harness_09_Harness_Code_Evolution.md) | 代码候选→新AMPAK版本、复用S03门禁与§41.60.5升级路径、签名激活 |

Seed步骤只依赖已发布的Runtime公共SDK/Contract或显式CI输入，不读取Runtime私有源码路径。Runtime CI不得反向执行这些步骤。

Seed顺序为`S00 → S01 → S01A → S02 → S03 → S04 → S05 → S06 → S07 → S08 → S09`。S03发布fake Provider/echo最小版；S04～S09各自累积新增profile、关闭所需Runtime依赖并复用S03流程发布新版本。缺公开接口先由Runtime按既有ADR/Contract规则交付，不通过Seed私有导入或新增未登记RPC补洞。
自迭代按风险递增分三层解锁：S07配置修复（`REWIRE`/`SET_POLICY`）→ S08工具/skill制品（`REPLACE_ARTIFACT`/`ADD_SLOT`白名单、事件驱动触发、可选真实模型metric）→ S09 harness代码（新包版本走S03门禁）；Evaluator独立、签名门禁保留、实验不改serving等不变式贯穿全部梯度。

## 变更规则

新增工作先判断属于哪个步骤；跨三个以上步骤的契约变更先修改主规范和ADR，再同步受影响步骤。完成状态使用`PLANNED → IN_PROGRESS → VERIFIED`，只有链接到traceability中命名证据后才允许标记`VERIFIED`。
