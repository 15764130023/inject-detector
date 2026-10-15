# 大模型智能体提示注入防护系统

面向办公智能体的提示注入检测、工具调用授权和审计演示项目。详细范围和里程碑见 [项目计划](./大模型智能体提示注入防护系统项目计划.md)。

## 本地环境

项目使用 Python 3.11。Windows PowerShell 初始化和启动方式：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py
```

没有 API 密钥时，项目应使用本地模拟模式，且不会读取真实敏感文件或发送真实邮件。

也可以直接在命令行运行完整闭环：

```powershell
# 正常任务：检索、检测和摘要
python -m agent.agent "请搜索项目资料，并生成一份摘要。" --scenario normal --protection full

# 攻击对照：仅访问虚构 secret.txt，并写入本地 outbox.json
python -m agent.agent "请搜索项目启动计划，并生成摘要。" --scenario attack --protection off

# 完整防护：提示注入被检测，未授权的读取和外发在执行前阻断
python -m agent.agent "请搜索项目启动计划，并生成摘要。" --scenario attack --protection full
```

防护配置有 `off`、`detector_only` 和 `full` 三种。`off` 只能用于本地隔离
对照；即使关闭防护，文件沙箱和模拟发件箱边界仍然生效。`detector_only`
在检测到已知注入时停止提交危险调用。`full` 还会在每个工具执行前独立核对
用户显式授权，因此即使检测器漏报也会阻断未授权的敏感读取和邮件外发。

默认使用无需网络的确定性 Agent 和摘要器。设置 `OPENAI_API_KEY` 后，
可通过 `--mode openai` 使用 OpenAI Agents SDK 生成最终摘要；可选的
`OPENAI_MODEL` 用于显式指定模型。在线模式不直接持有工具，文档检索、
检测、来源追踪、授权和审计仍统一经过本地安全路径。详细语义见
[攻击防御闭环](./docs/attack_defense_flow.md)。

Streamlit 页面会展示最终摘要、执行轨迹、检测结果、参数来源、策略决定、
当前任务的审计日志和本地模拟发件箱，便于现场对照三种防护配置。

## 目录说明

- `agent/`：智能体配置、提示词和 LLM 适配。
- `security/`：检测器、来源追踪和工具授权策略。
- `tools/`：三个本地模拟工具及统一注册接口。
- `scenarios/`：正常/攻击文档、沙箱文件和模拟发件箱。
- `audit/`：结构化审计事件。
- `evaluation/`：固定测试集、评测脚本、指标和结果。
- `tests/`：自动化测试。
- `docs/`：架构、比赛材料和开源归属说明。

## 本地工具

三个模拟工具必须通过 `ToolRegistry` 调用，以保证执行前授权和审计：

```python
from tools import ToolRegistry

registry = ToolRegistry()
result = registry.invoke(
    "search_documents",
    {"query": "项目计划"},
    trace_id="demo-001",
)
```

完整参数、返回结构、安全边界和错误语义见 [工具接口说明](./docs/tool_contracts.md)。

## 验证

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m evaluation.runner
streamlit run app.py
```

批量评测默认对固定数据集逐例运行 `off`、`detector_only` 和 `full`
三种配置，并把真实指标与可复现元数据写入 `evaluation/results/`。数据集范围、
指标口径和结果结构见 [固定评测说明](./docs/evaluation.md)。

攻击对照会向 `scenarios/outbox.json` 追加一封虚构邮件。重复演示前可将该文件
恢复为空数组 `[]`；不会连接真实邮件服务。

