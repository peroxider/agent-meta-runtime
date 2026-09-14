# Seed Harness Step S03 — Integration and Release

> 归属：外部项目  
> 状态：PLANNED  
> 前置：S00～S02 VERIFIED  
> Runtime规范定位：§41.53、§41.58、§41.60.6、§45 AC-M17/M48

## 目标

在Seed仓库独立证明与声明Runtime版本的兼容性，并独立发布Seed distribution与AMPAK。

## 实施顺序

1. 对每个声明支持的Runtime minor pin公开wheel、SDK和contract golden。
2. 执行SDK compile、manifest validate、Install/Activate/Task/Deactivate/Uninstall全链路。
3. 覆盖Runtime restart、旧serving保留、health失败、grant deny和残留引用。
4. 执行AC-M17的Seed Loop E2E及AC-M48的确定性/文本无副作用矩阵。
5. 生成Seed自己的SBOM、provenance、compatibility report和release notes。
6. 发布distribution与签名AMPAK；不得修改Runtime wheel、schema或release manifest。

## 发布门禁

- AC-M17、AC-M48和NFR-M48在Seed CI中通过。
- 支持矩阵只列实际通过的Runtime版本和Backend feature profile。
- Seed安装、升级、停用和卸载全部使用公共SDK/local RPC。
- Seed CI失败只阻塞Seed发布，不改变Runtime release conclusion。
