# Runtime Step 00 — Foundation

> 状态：PLANNED  
> 规范定位：§41.0～41.5、§41.29、§41.39、§41.50

## 目标

建立后续步骤共同依赖的工程、类型和架构边界，不实现业务策略或外部Seed。

## 输入与范围

- 输入：v0.1-r11主规范、ADR-001～030、Python命名决定。
- 包含：`agent_meta_runtime`骨架、CPython 3.12、asyncio、配置、clock/ID、canonical encoding、错误模型、daemon lock、architecture lint。
- 不包含：数据库业务表、Backend执行、Harness实现、外部Provider。

## 实施顺序

1. 建立`domain/application/ports/adapters/interfaces/sdk/protocols`包与import规则。
2. 实现UUIDv7、UTC microseconds、SHA-256、JCS/AMPAK1基础工具及golden vectors。
3. 冻结稳定错误码、结果类型、deadline和取消原语。
4. 实现配置加载、fingerprint、data-dir解析和single-writer daemon lock。
5. 配置import-linter与AST规则，禁止Runtime引用`agent_meta_seed_harness`、`seed_harness`和private反向依赖。
6. 建立schema/protobuf生成与版本检查框架，但不提交未审查生成物为唯一协议源。

## 交付物

- `pyproject.toml`、包骨架、`architecture.toml`。
- canonical encoding/ID/clock库及跨平台golden。
- error/config/lock contract tests。
- wheel content与import graph检查。

## 验证与退出门禁

- Linux/Windows安装wheel后可import `agent_meta_runtime`且不需要Seed checkout、distribution或network。
- canonical vectors逐字节一致，非法路径/浮点/时间/ID fail closed。
- 架构负例能拦截Domain→Adapter和Runtime→Seed import。
- 相关FR-MARCH、NFR-M01/M12/M17/M22/M29/M35/M36/M42/M45及AC-M27/M45基础证据通过后进入Step 01。
