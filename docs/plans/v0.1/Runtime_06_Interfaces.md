# Runtime Step 06 — Interfaces

> 状态：PLANNED  
> 前置：Step 05 VERIFIED  
> 规范定位：§41.13～41.14、§41.26、§41.39、§41.41、§41.46、§41.51～41.52

## 目标

只通过稳定公共边界暴露Runtime能力，为外部Harness和operator提供SDK、local RPC与CLI。

## 实施顺序

1. 实现4-byte big-endian framing和Public API v1 protobuf registry。
2. Linux/macOS使用UDS、Windows使用Named Pipe，并验证同OS user peer identity。
3. 实现`agent_meta_runtime.sdk`，禁止导出repository/UoW/adapter/private protobuf对象。
4. 实现CommandEnvelope、MutationReceipt、Operation和统一错误映射。
5. 实现Get/List/Why/Lineage snapshot cursor与分页认证。
6. 实现Artifact chunk upload、verify和过期staging语义。
7. 实现CLI JSON输出、exit code、dry-run、doctor和Runtime.GetInfo双readiness。

## 交付物

- Public proto、server/client、SDK和`agent-meta`CLI。
- peer-auth、pagination、upload、dry-run和redaction tests。
- version compatibility/golden wire fixtures。

## 验证与退出门禁

- Public API不泄漏private Python类型，未知required semantic按major失败。
- 篡改/过期/跨query cursor失败，dry-run没有DB/CAS/outbox/Backend副作用。
- `ready`兼容字段恒等于`core_ready`，Task只在`serving_ready`接纳。
- FR-MAPI、FR-MOPS-001～003及AC-M41/M44/M47通过后进入Step 07。
