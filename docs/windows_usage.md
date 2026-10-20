# Windows 免安装版使用说明

适用于 Windows 10/11 x64。只需复制 `PromptInjectDefense.exe`，双击后
稍等片刻浏览器会打开本地页面；无需安装 Python 或携带依赖文件夹。
启动时自动解压依赖到 Windows 临时目录，首次启动可能稍慢。

第一次在左侧“在线模型密钥”填写百炼 API 密钥并保存。密钥以明文保存在本机
`%LOCALAPPDATA%\PromptInjectDefense\.env` 中，请保管该文件。
也可通过环境变量配置；默认模型为 `qwen-flash`。源码模式仍读取项目 `.env`。
保存只代表配置写入成功，运行任务时才验证服务是否可用。

执行任务需要联网访问百炼，可能产生模型费用；无密钥、网络或服务不可用会
明确报错，不会生成伪造评测结果。所有读取和模拟邮件仅作用于随附虚构场景。
首次运行 `detector_only` 或 `full` 还需要联网下载固定 revision 的 LLM Guard
PromptInjection 模型；下载后使用本机 Hugging Face 缓存。模型下载或缓存失败会明确
报告 `DETECTOR_UNAVAILABLE`，不会用规则结果冒充模型扫描成功。

启动窗口显示本地访问地址；浏览器没有自动打开时可手动访问。关闭启动窗口
或按 Ctrl+C 停止服务；只关闭浏览器不会停止程序。同一用户只运行一个实例。
启动窗口使用 UTF-8 纯文本输出，不包含终端颜色控制码。

审计写入 `%LOCALAPPDATA%\PromptInjectDefense\audit\events.jsonl`，模拟邮件
写入 `%LOCALAPPDATA%\PromptInjectDefense\scenarios\outbox.json`。重启后保留。
发布文件不含历史审计、邮件或真实密钥，exe 旁边不生成配置文件夹。

用户数据目录无写入权限时，需要修复其权限。启动失败时保留窗口中的错误
信息用于排查。此版本未进行代码签名，也未在所有 Windows 设备上验证。

构建后可运行 `PromptInjectDefense.exe --verify-package` 检查 SDK 提示词资源、
SDK 导入、规则和场景检索；加 `--online` 会真实调用在线模型，回归正常任务、
无防护攻击与完整防护攻击，并写入本机 `package-validation.json` 与审计。
在线检查需要密钥，可能产生模型费用，模型是否接受攻击如实记录。
