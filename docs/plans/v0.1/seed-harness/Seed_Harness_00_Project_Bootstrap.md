# Seed Harness Step S00 — Project Bootstrap

> 归属：外部项目  
> 状态：PLANNED  
> Runtime规范定位：§1.3、§40、§41.60.1

## 目标

在独立路径建立Seed项目，并从第一天保持依赖方向只有Seed → Runtime public SDK/Contract。

## 固定命名

- repository/distribution：`agent-meta-seed-harness`
- Python import：`agent_meta_seed_harness`
- 推荐本地checkout：Runtime同级`../agent-meta-seed-harness`，仅作为开发提示。
- Runtime依赖：显式pin的`agent-meta-runtime`公开版本或CI wheel。

## 实施顺序

1. 建立独立Git仓库、`pyproject.toml`、source/tests/docs目录和版本策略。
2. 只允许import `agent_meta_runtime.sdk`、公开DTO与生成的公共协议包。
3. 增加lint，禁止import Runtime adapters/application/repository/UoW/private module。
4. CI通过显式artifact/version输入取得Runtime，不读取相对checkout路径。
5. 建立独立changelog、SBOM、provenance和release workflow。

## 退出门禁

- Seed可在任意目录build/test，移动checkout不改变ArtifactId或manifest。
- Runtime仓库/网络不可用时，已pin依赖的Seed构建行为明确；Seed失败不回写Runtime发布状态。
- package metadata与import namespace分别使用连字符和下划线命名。
