# Runtime Step 03 — Authority and Composition

> 状态：PLANNED  
> 前置：Step 02 VERIFIED  
> 规范定位：§41.16、§41.24、§41.28、§41.31、§41.37、§41.42、§41.49、§41.59.1/3

## 目标

实现显式Authority、Capability Surface、版本化Composition和Managed State，使策略可替换但不能绕过核心不变量。

## 实施顺序

1. 实现Ed25519 Root bootstrap、Principal、Grant定义/history/counter及scope匹配。
2. 在Task接纳与每次effect前重新授权，缓存键包含完整authority/backend/surface状态。
3. 实现Capability descriptor、contract compatibility、trust class和placement validation。
4. 实现immutable Composition revision及desired/serving/realized三引用CAS。
5. 实现Managed State immutable revision、mutable ref、task snapshot和MVCC冲突。
6. 实现State migration plan、schema validation、未绑定结果和回滚策略。
7. 生成确定性的CompatibilityReport和Capability Surface Artifact。

## 交付物

- Authority、Capability、Composition、State schema/API。
- permission registry、compatibility solver和surface builder。
- delegation/revocation race、state write/migration race测试。

## 验证与退出门禁

- 无隐式Root bypass，Grant revoke/expire/use耗尽立即影响新调用。
- Composition/State历史不可改；并发CAS冲突不自动覆盖。
- policy capability可被删除/替换且历史仍解析到旧Artifact。
- FR-MAUTH、FR-MCAP、FR-MSTATE及AC-M05/M21/M25/M29/M38/M53相关证据通过后进入Step 04。
