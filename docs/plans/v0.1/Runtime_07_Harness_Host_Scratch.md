# Runtime Step 07 — Harness Host and Scratch

> 状态：PLANNED  
> 前置：Step 06 VERIFIED  
> 规范定位：§40、§41.24、§41.36、§41.44、§41.53～41.54、§41.57、§41.60

## 目标

交付通用Harness Host、外部package生命周期和Scratch能力，同时证明Runtime对Seed项目零反向依赖。

## 实施顺序

1. 实现无Harness的core bootstrap、revision 0和初始Root/Service grants。
2. 实现Harness manifest/schema/signature/contract range与`ValidatePackage`纯查询。
3. 实现Install/Get/List/Activate/Deactivate/Uninstall及installation history。
4. 把grant、desired切换、health probe、旧Harness drain和失败回滚接入Reconciler。
5. 实现Harness Loop typed DTO、budget/effect enforcement和terminal Model response contract。
6. 建立test-only Conformance Harness/Provider；断言其不进入wheel/sdist/SBOM。
7. 实现IPython isolated kernel、session binding、safe inspect和source-only promotion。

## 交付物

- `schemas/harness/v1`、public SDK方法和Harness CLI。
- Harness installation表/历史/Fact和生命周期测试。
- `tests/fixtures/conformance_harness`及wheel-content negative test。
- IPython Scratch adapter与restart/export tests。

## 验证与退出门禁

- 删除Seed checkout、阻断network后Runtime仍build/install/init/start/doctor/backup。
- 两个不同fixture只经公共API依次完成完整生命周期，失败保持旧serving。
- Runtime source/import graph/metadata不含Seed产品module或dependency。
- FR-MRUN、FR-MREF-005、FR-MARCH-006、NFR-M51/M54及AC-M07/M08/M13/M19/M49/M51/M54通过后进入Step 08；AC-M17/M48留给外部Seed。
