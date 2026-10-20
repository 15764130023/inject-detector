# PyInstaller 构建配置。显式白名单，禁止复制本地密钥和运行历史。
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, copy_metadata, collect_submodules

root = Path(SPECPATH)
datas = [(str(root / 'app.py'), '.'), (str(root / '.env.example'), '.'),
         (str(root / '.streamlit/config.toml'), '.streamlit'),
         (str(root / 'security/rules.yaml'), 'security'),
         (str(root / 'docs/windows_usage.md'), '.')]
for folder in ('normal', 'attacks', 'sandbox_files'):
    datas.append((str(root / 'scenarios' / folder), 'scenarios/' + folder))
datas += collect_data_files('streamlit')
# Agents SDK 在 import 时读取 sandbox/memory/prompts/*.md，必须连同代码打包。
datas += collect_data_files('agents')
datas += copy_metadata('streamlit') + copy_metadata('openai-agents', recursive=True)
datas += copy_metadata('llm-guard', recursive=True)

a = Analysis(['desktop_launcher.py'], pathex=[str(root)], binaries=[], datas=datas,
             hiddenimports=['agent.agent', 'audit.logger', 'tools.registry', 'desktop_config'] + collect_submodules('agents') + collect_submodules('streamlit') + collect_submodules('llm_guard'),
             hookspath=[], runtime_hooks=[], excludes=['pytest', 'IPython', 'matplotlib', 'tkinter'])
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name='PromptInjectDefense',
          debug=False, strip=False, upx=False, console=True)
