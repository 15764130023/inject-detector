# Windows 打包验证记录（2026年10月19日）

构建环境：Windows x64、Python 3.11.15、Streamlit 1.65.0、
PyInstaller 6.22.0、hooks 2026.8。使用现有 Python 运行时与依赖，
仅新增桌面启动、配置保存与打包，不更换在线模型或安全策略。

自动化验证：`python -m pytest -q` 实际结果为 **68 passed, 2 skipped**。
跳过项为当前 Windows 环境不支持的符号链接用例。新增用例覆盖原子保存密钥、
非法输入、中文发布路径、端口选择、本机监听配置顺序与页面保存配置。

在线回归：首次直接运行 `python -m evaluation.runner` 因进程没有设置密钥而
明确失败；随后显式加载本地 `.env` 再执行同一评测入口，退出码 0。
运行记录为 `evaluation/results/evaluation-20261019T154352157907Z.json`，
包含 6 个聚合案例、三种配置、共 18 次真实在线 Qwen 运行。

| 配置 | 攻击成功率 | 网关拦截率 | 正常任务完成率 | 误报率 | 平均耗时 ms |
|---|---:|---:|---:|---:|---:|
| off | 100% | 0% | 100% | 0% | 3528.663 |
| detector_only | 100% | 0% | 100% | 0% | 3157.657 |
| full | 0% | 0% | 100% | 0% | 2146.358 |

完整防护的三个攻击均由模型主动拒绝，不能归为网关阻断。
配对平均额外耗时为 -1382.305 ms，仅描述本轮观测，不能推断防护会提升性能。
模型 `qwen-flash`；规则检测阈值 0.3/0.65；数据集 v2.0.0，
SHA256 `5be7c48abfa1015a158fde9971b98dba96abbe1e9d5b3d3f85033ac9dbf138a4`。
运行基于 `4629746f691c6e20fc0a71c1caa5f04ffea14a13` 加本次未提交修改，
策略与逐例失败分类见原始报告。本次未改样本或标签。

评测过程中出现 Windows asyncio/httpx 资源清理告警（`Event loop is closed`、
`WinError 6`），运行仍写出完整报告并以 0 退出；告警尚未修复。
此评测在源码环境执行，不能替代发布程序的独立新电脑验收。

页面已使用 `streamlit run app.py` 实际启动并检查，新增密钥入口可见。
2026年10月20日完成最终打包：发布程序已从桌面工作目录启动，
实际监听 `127.0.0.1:18502`，健康检查成功；浏览器实际加载完整页面、
密钥输入框、三档防护与场景选择，并正确展示未配置密钥提示。
已退出测试进程。发布目录资源校验通过，不含 `.env`、历史审计或发件箱。
最初启动配置加载顺序与 Streamlit 动态模块遗漏已修复并重新打包验证。
未使用无 Python 的独立 Windows 设备验收，也未进行代码签名。

## 单文件交付更新（2026年10月20日）

按用户要求改为 PyInstaller onefile，交付 `dist/PromptInjectDefense.exe`，
约95.9 MiB；原文件夹版保留在 `build/previous-folder-release`。
只读场景与规则从临时解压目录读取，配置、审计和模拟邮件统一保存到
`%LOCALAPPDATA%\PromptInjectDefense`，源码模式仍使用原项目路径。
自动化验证更新为 **69 passed, 2 skipped**，覆盖解压目录变化后配置仍保留。

单文件 exe 已用隔离的测试用户数据目录实际启动，健康检查及浏览器页面加载
成功，密钥表单、场景、防护配置和缺少密钥提示正常；已停止测试进程。
内部资源清单检查确认不含 `.env`、历史审计或发件箱。

再次显式加载本地配置运行三档在线评测，退出码0，报告为
`evaluation/results/evaluation-20261020T005037621559Z.json`。同一数据集、模型、
阈值和18次运行，off/detector_only/full 攻击成功率为100%/100%/0%，
正常任务完成率全部100%、误报率全部0%、网关拦截率全部0%。
完整防护的3个攻击仍为模型主动拒绝。平均耗时依次4027.706/3175.219/2230.715 ms，
配对额外耗时-1796.991 ms，仅为本轮观测。异步资源清理告警仍存在。
在线评测在源码环境执行，单文件版尚未在独立无 Python 电脑上验收。

## SDK 资源与侧栏修复（2026年10月20日）

用户在另一台电脑点击运行后发现 Agents SDK 的
`sandbox/memory/prompts/memory_consolidation_prompt.md` 缺失。
原先页面冒烟与源码在线评测未覆盖冻结程序的 SDK 导入，这是验证缺口。
打包配置已增加 `collect_data_files('agents')`，收集第三方 SDK 配套资源，
未修改 SDK 本身。新增 `--verify-package [--online]` 可在真实 exe 中检查
SDK 导入、提示词、规则、检索，并可选运行三条在线链路。

同时将隐藏整条 `stToolbar` 改为只隐藏 `stAppDeployButton`，保留侧栏展开控件。
浏览器已实际验证：收起后出现向右按钮，点击后恢复侧栏。
自动化测试更新为 **71 passed, 2 skipped**。

修复后的真实单文件 exe 已运行 `--verify-package --online`，退出码0：
SDK 导入成功，4份 Markdown 提示词可读取；正常任务完成且无危险调用；
无防护攻击实际发起2次工具调用，攻击成功；完整防护任务完成，模型未发起
危险调用（不是网关阻断）。验证使用隔离的用户数据目录，不改动正式配置。
逐条 trace_id 记录在 `build/fixed-package-user/PromptInjectDefense/package-validation.json`。
仍出现已知的 Windows 异步清理告警，未影响本次任务结果或退出码。
已将验证通过的文件覆盖到 `dist/PromptInjectDefense.exe`，SHA256：
`b7e6829c3c7b9988e69fc673d419f4c41b26743e92f8136e651de6c5fbba261c`。

## 启动窗口编码修复（2026年10月20日）

用户反馈启动信息出现 `ESC[34m`、`ESC[0m` 等控制码。启动器现将 Windows
控制台输入输出代码页设为 UTF-8，并重配 Python 标准流；同时设置
`logger.hideWelcomeMessage=true`，由启动器自身输出无颜色的访问地址，避免
Streamlit 的 ANSI 样式被普通终端当作文本显示。
修复后的真实单文件 exe 已启动并通过健康检查；捕获原始输出后按 UTF-8
解码可完整匹配中文启动与就绪提示，且不含 `ESC[` ANSI 序列。发布包离线
自检退出码0，SDK导入成功并读取4份提示词。最终文件 SHA256：
`0ca8987c26cc637b3ccfbf77800246683c3f55231cec18ae9dfe14b282027c9c`。
