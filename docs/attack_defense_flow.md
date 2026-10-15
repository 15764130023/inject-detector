# 攻击防御闭环

## 执行路径

`agent.agent.run_office_task` 是统一编排入口。它先通过 `ToolRegistry` 检索文档，
再为系统提示、用户任务、工具返回和每份检索文档建立来源记录，并用
`parent_source_id` 保存“用户任务 → 检索结果 → 检索文档”和
“攻击文档 → 文件工具返回 → 沙箱文件”的父来源关系。开启检测后，离线规则检测器输出
`label`、`risk_score`、`reasons`、`latency_ms` 和 `detector_id`。

为稳定复现间接提示注入，本地 Agent 会识别攻击文档中的嵌入操作意图，
并提出 `read_file` 与 `send_email` 调用。这些参数的 `argument_sources`
始终指向相应的不可信文档，不会被转换成用户授权。用户授权只从原始
用户任务中提取。策略引擎同时读取参数来源与该来源的检测结果：不可信来源会提升
风险等级；确认属于 `INJECTION` 的来源驱动 `read_file` 或 `send_email` 时直接阻断。
即使检测结果为 `SAFE`，敏感文件和邮件仍必须满足独立的显式授权规则。

## 三种配置

| 配置 | 检测器 | 工具授权网关 | 预期攻击结果 |
| --- | --- | --- | --- |
| `off` | 跳过 | 跳过任务级授权 | 读取虚构秘密并写入本地模拟发件箱 |
| `detector_only` | 开启 | 关闭 | 已知注入在提交工具前被检测器制止 |
| `full` | 开启 | 开启 | 危险调用仍会被提出，但在执行前因缺少用户显式授权而阻断 |

`off` 不会关闭硬边界：`read_file` 仍只能读取 `scenarios/sandbox_files/`
中的 UTF-8 文本，`send_email` 仍只写入 `scenarios/outbox.json`。

## 审计证据

每个工具调用都在执行前生成策略决策，并把 `trace_id`、`call_id`、
工具、参数、参数来源、来源风险因子、检测证据、策略标识、风险等级和结果追加到
`audit/events.jsonl`。
检测结果、检测器抑制事件与任务完成事件使用同一 `trace_id`。完整防护下，
被阻断的 `read_file` 不返回文件内容，被阻断的 `send_email` 不改变发件箱。

## 当前边界

- 检测器是确定性离线基线，不代表通用注入检测能力。
- 本地 Agent 使用可复现意图解析来展示攻击链；API 模式当前只生成最终摘要。
- 人工确认 `REQUIRE_CONFIRMATION` 为 P1，首版高风险未授权动作直接 `BLOCK`。
