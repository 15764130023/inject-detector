# 本地模拟工具接口

首版工具只操作 `scenarios/` 内的模拟数据。业务调用统一经过 `ToolRegistry.invoke()`，由注册层补充 `trace_id`、`call_id`、参数来源和来源检测结果，在执行前完成策略判断并写入 JSONL 审计事件。

`argument_sources` 按参数记录 `source_id`、`source_type`、`trusted` 和可选的
`parent_source_id`。模型无法确定单一直接来源时，还会记录
`attribution=mixed_or_unknown` 与 `candidate_source_ids`；候选来源只用于审计说明，
不会被策略当作已经确认的注入来源。参数确实包含先前工具返回的完整内容时，
`source_id` 指向对应的 `tool_result:<call_id>`。`detection_results` 按
`source_id` 提供检测标签与分数。
策略决定会回传 `risk_factors`、`source_ids`、`max_detection_label` 和
`max_detection_score`，用于解释来源如何影响最终决定。

## 统一结果

成功结果：

```json
{"ok": true, "tool": "search_documents", "data": {}, "meta": {}}
```

失败或阻断结果：

```json
{
  "ok": false,
  "tool": "send_email",
  "error": {"code": "TOOL_BLOCKED", "message": "用户未明确授权向该地址发送邮件。"},
  "meta": {}
}
```

`meta` 包含调用与追踪编号，以及本次调用前的策略决定。工具业务参数中不接受这些内部字段。

## `search_documents`

```python
registry.invoke("search_documents", {"query": "项目计划"})
```

- 搜索 `scenarios/normal/` 和 `scenarios/attacks/` 下的 UTF-8 `.txt`、`.md` 文档。
- 使用不依赖模型的中英文关键词计分，固定最多返回五篇完整文档。
- 每篇文档包含稳定来源编号、标题、场景相对路径、完整内容和匹配分数。
- 所有检索内容均设置 `trusted: false`；正常内容不因此被判定为恶意，但不能授予高风险工具权限。

## `read_file`

```python
registry.invoke(
    "read_file",
    {"path": "secret.txt"},
    user_authorization={"files": ["secret.txt"]},
)
```

- 只接受相对于 `scenarios/sandbox_files/` 的安全路径。
- 拒绝绝对路径、目录穿越、符号链接越界、目录、缺失文件、非 UTF-8 内容和超过 256 KiB 的文件。
- `security/rules.yaml` 的 `sandbox.sensitive_files` 显式列出敏感路径。
- 开启防护后，敏感文件必须同时出现在用户授权的 `files` 中。
- 参数来自不可信来源时提升为高风险；来源已确认为注入时，在读取前直接阻断。

## `send_email`

```python
registry.invoke(
    "send_email",
    {"to": "teacher@example.com", "subject": "项目摘要", "body": "摘要正文"},
    user_authorization={"email_recipients": ["teacher@example.com"]},
)
```

- 每次仅接受一个收件人、一个非空主题和非空正文。
- 主题最长 200 字符，正文最长 10,000 字符。
- 开启防护后，收件地址必须与用户明确授权地址一致。
- 来源已确认为注入时，即使地址碰巧在授权集合中也不会执行该次文档驱动调用。
- 工具不访问网络，只向 `scenarios/outbox.json` 原子追加 `sent_simulated` 记录。

## 防护开关

`protection_enabled=False` 仅用于本地攻击对照。此时跳过任务级授权，但路径沙箱、参数校验、文件大小限制和本地模拟邮件限制始终有效。开启防护时，被阻断的读取不会返回文件内容，被阻断的邮件不会改变发件箱。
