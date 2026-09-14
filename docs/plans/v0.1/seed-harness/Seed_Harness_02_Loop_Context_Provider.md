# Seed Harness Step S02 — Loop, Context and Provider

> 归属：外部项目  
> 状态：PLANNED  
> 前置：S01 VERIFIED  
> Runtime规范定位：§40.2、§41.11、§41.36、§41.44.4、§41.53

## 目标

实现最小但有用的Seed行为：Model、Task/Event、Loop、Context和tool dispatch policy，不把策略放回Runtime。

## 实施顺序

1. 实现terminal-only Model Provider adapter并规范化usage、finish reason、rate limit和tool calls。
2. 实现deterministic Context selection，先redact再排序/budget并保留provenance。
3. 实现bounded Loop，读取manifest loop policy并受Runtime hard ceiling约束。
4. 纯文本输出只形成content Artifact；只有typed `tool_calls`进入公共dispatch DTO。
5. tool calls按响应顺序串行，重复call id、未知kind和schema错误fail closed。
6. 实现fake provider场景：text、LENGTH、单/多tool、空响应、错误finish、budget exhaustion。
7. 记录Action/Invocation/Fact因果链，不保存provider-native object为协议状态。

## 退出门禁

- 相同provider terminal response、snapshot和budget产生相同状态序列与内容ArtifactId。
- 文本中的JSON/shell/tool形似指令不会触发Capability或Backend effect。
- Provider重试只发生在可证明未接纳且policy允许的幂等场景。
- 满足外部NFR-M48的确定性要求。
