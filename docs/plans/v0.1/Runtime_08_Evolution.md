# Runtime Step 08 — Evolution Baseline

> 状态：PLANNED  
> 前置：Step 07 VERIFIED  
> 规范定位：§41.18～41.23、§41.43、§41.59.2～41.59.3

## 目标

实现确定性、可审计、失败不污染current serving的Evolution baseline；不实现自主搜索或Root succession。

## 实施顺序

1. 实现Proposal、ChangeSet、Candidate、World、Experiment、Evidence、Evaluation DTO与持久化。
2. 从baseline clone实验State，禁止写production state id。
3. 实现deterministic criteria/assertions、fake model和budget。
4. 根据trust class选择Portable或Managed placement，权限不足fail closed。
5. 执行Artifact/security/compatibility/health/evidence gate。
6. Promotion只提交新desired Composition，由Reconciler完成serving切换。
7. Rollback创建可追踪的新transition，不改写旧revision或隐式回退State。

## 交付物

- evolution schemas/use cases、deterministic evaluator和world fixtures。
- experiment isolation、promotion/rollback和negative security tests。
- Evidence/causal graph与release feature report输入。

## 验证与退出门禁

- Candidate失败不会改变current serving、Root或production State。
- 相同World/criteria/input产生相同decision和Evidence hash。
- Promotion/rollback完整记录actor、authority、evidence和父revision。
- FR-MEVO、NFR-M08/M13及AC-M06/M18/M42通过后进入Step 09。
