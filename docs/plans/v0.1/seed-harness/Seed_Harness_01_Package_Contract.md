# Seed Harness Step S01 — Package Contract

> 归属：外部项目  
> 状态：PLANNED  
> 前置：S00 VERIFIED  
> Runtime规范定位：§41.24、§41.37、§41.42、§41.60.2～41.60.5

## 目标

把Seed实现构建成Runtime可验证但无需import的AMPAK与Harness manifest。

## 实施顺序

1. 定义稳定`package_name`和SemVer，不复用已卸载的同Realm name/version。
2. 构建AMPAK1，固定依赖锁、entrypoint、path canonicalization和provenance。
3. 生成`harness-package/v1` manifest、publisher/signature Artifact。
4. 提供Capability descriptors、单package Composition模板和loop policy Artifact。
5. 提供最小scoped grant requests，不请求Root/private credential权限。
6. 声明Public/Harness/Capability contract range和Backend required/preferred features。
7. 用Runtime public SDK执行Validate golden与negative fixtures。

## 退出门禁

- 相同源码/lock在支持平台产生相同逻辑package内容和可验证hash。
- 未知字段、签名错误、contract无交集、越权grant和不支持placement全部fail closed。
- Install不执行Seed代码、不创建Grant/Composition/Task或Backend request。
