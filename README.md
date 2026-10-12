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

## 目录说明

- `agent/`：智能体配置、提示词和 LLM 适配。
- `security/`：检测器、来源追踪和工具授权策略。
- `tools/`：三个本地模拟工具及统一注册接口。
- `scenarios/`：正常/攻击文档、沙箱文件和模拟发件箱。
- `audit/`：结构化审计事件。
- `evaluation/`：固定测试集、评测脚本、指标和结果。
- `tests/`：自动化测试。
- `docs/`：架构、比赛材料和开源归属说明。

