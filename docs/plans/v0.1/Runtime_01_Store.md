# Runtime Step 01 — Store

> 状态：PLANNED  
> 前置：Step 00 VERIFIED  
> 规范定位：§41.6～41.7、§41.29、§41.34～41.35、§41.47

## 目标

实现可审计、可恢复的SQLite Meta Store、filesystem CAS和单命令事务边界。

## 范围

- authoritative SQLite STRICT migration与connection profile。
- filesystem CAS、AMPAK1、Artifact manifest/blob/encryption分离。
- Unit of Work、CommandEnvelope幂等claim、meta revision、Fact hash chain和checkpoint。
- integrity doctor、staging清理和最小backup dependency记录。
- 本步骤不调用Backend或用户代码。

## 实施顺序

1. 把§41.34 DDL固化为只增量migration并校验checksum/application id。
2. 实现短`BEGIN IMMEDIATE`写事务、deferred read snapshot和busy deadline。
3. 实现CAS staging→hash verify→atomic publish，拒绝symlink/path traversal。
4. 实现plain/encrypted blob映射、credential handle和key不可用语义。
5. 实现Command幂等、连续meta revision与同事务Fact/outbox写入接口。
6. 实现per-Realm Fact chain、checkpoint重算和tamper doctor。

## 交付物

- migrations、repository/UoW ports、CAS adapter。
- Artifact/Fact/checkpoint schema与golden。
- migration、crash point、FK/trigger、hash tamper和concurrency tests。

## 验证与退出门禁

- 主DDL与migration等价，全部FK和immutable trigger有效。
- kill发生在CAS/DB各边界后均不会出现committed row指向缺失bytes。
- 修改、删除、交换任意旧Fact会使doctor报告`INTEGRITY_ERROR`。
- FR-MID、FR-MSTORE-001/003/004/007～010、FR-MFACT-001/002/006及AC-M04/M14/M15/M28/M35/M52通过后进入Step 02。
