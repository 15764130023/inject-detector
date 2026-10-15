"""Streamlit application entry point."""

from __future__ import annotations

import os

import streamlit as st
from dotenv import load_dotenv

from agent.agent import run_office_task
from audit.logger import load_events
from tools.registry import DEFAULT_AUDIT_PATH
from tools.send_email import load_outbox

load_dotenv()

st.set_page_config(
    page_title="Prompt Inject Defense",
    page_icon="🛡️",
    layout="wide",
)

# ---------------------------------------------------------------------------
# 深色科技感主题（纯展示层，不影响任何安全逻辑）
# ---------------------------------------------------------------------------
st.markdown(
    """
<style>
/* 全局背景 */
.stApp {
    background: radial-gradient(ellipse at top, #0f1a2e 0%, #070b14 60%, #04060c 100%);
    color: #c9d6e8;
}
/* 隐藏默认 header 和右上角 Deploy/菜单 */
header[data-testid="stHeader"] { background: transparent; }
[data-testid="stToolbar"] { display: none !important; }
[data-testid="stMainMenu"] { display: none !important; }
/* 主标题 */
h1, h2, h3 {
    font-family: 'JetBrains Mono', 'Fira Code', Consolas, monospace;
    letter-spacing: 0.5px;
}
h1 {
    background: linear-gradient(90deg, #00f0ff 0%, #7b8cff 60%, #ff4757 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    font-weight: 700;
}
/* 侧边栏 */
section[data-testid="stSidebar"] {
    background: rgba(10, 16, 30, 0.85);
    border-right: 1px solid rgba(0, 240, 255, 0.15);
}
section[data-testid="stSidebar"] h1,
section[data-testid="stSidebar"] h2,
section[data-testid="stSidebar"] h3 { color: #00f0ff; }
/* metric 卡片 */
[data-testid="stMetric"] {
    background: rgba(15, 26, 46, 0.7);
    border: 1px solid rgba(0, 240, 255, 0.2);
    border-radius: 8px;
    padding: 14px 16px;
    box-shadow: 0 0 12px rgba(0, 240, 255, 0.08) inset;
}
[data-testid="stMetricLabel"] p { color: #7b8cff !important; font-family: monospace; font-size: 0.85rem; }
[data-testid="stMetricValue"] { font-family: 'JetBrains Mono', monospace; }
/* 按钮 */
.stButton > button {
    background: linear-gradient(90deg, #00f0ff 0%, #0077ff 100%);
    color: #04060c;
    border: none;
    border-radius: 6px;
    font-weight: 700;
    font-family: monospace;
    letter-spacing: 1px;
}
.stButton > button:hover { box-shadow: 0 0 18px rgba(0, 240, 255, 0.6); }
/* dataframe 外容器 */
[data-testid="stDataFrameResizable"] {
    background: transparent !important;
}

/* 流程节点条允许换行 */
.flow-strip {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    justify-content: space-between;
    margin: 18px 0;
    font-family: monospace;
}
.flow-node {
    flex: 1 1 120px;
    text-align: center;
    padding: 8px 4px;
    border: 1px solid rgba(0, 240, 255, 0.2);
    border-radius: 6px;
    background: rgba(15, 26, 46, 0.5);
    font-size: 0.78rem;
    color: #5a6b8c;
}
.flow-node.active {
    border-color: #00f0ff;
    color: #00f0ff;
    box-shadow: 0 0 10px rgba(0, 240, 255, 0.3);
}

/* metric 大数字颜色 */
[data-testid="stMetricValue"] {
    color: #e8f0ff !important;
    font-family: 'JetBrains Mono', monospace;
}
/* expander */
.streamlit-expanderHeader {
    background: rgba(15, 26, 46, 0.6) !important;
    border-left: 3px solid #00f0ff;
    border-radius: 4px;
    font-family: monospace;
}
/* json 终端风 */
[data-testid="stJson"] {
    background: #04060c !important;
    border: 1px solid #1a2a4a;
    border-radius: 6px;
    font-family: 'JetBrains Mono', Consolas, monospace !important;
    font-size: 0.82rem;
}
/* 文本 */
p, span, div { color: #c9d6e8; }
/* caption */
[data-testid="stCaptionContainer"] { color: #5a6b8c !important; }
/* 输入框 */
.stTextArea > label, .stSelectbox > label, .stRadio > label {
    color: #00f0ff !important;
    font-family: monospace;
    font-size: 0.9rem;
}
/* 状态横幅容器 */
.banner {
    padding: 14px 20px;
    border-radius: 8px;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 700;
    letter-spacing: 1px;
    margin: 10px 0 20px 0;
    border-left: 4px solid;
}
.banner-success { background: rgba(0, 255, 136, 0.08); border-color: #00ff88; color: #00ff88; }
.banner-danger  { background: rgba(255, 71, 87, 0.10); border-color: #ff4757; color: #ff4757; }
.banner-info    { background: rgba(0, 240, 255, 0.08); border-color: #00f0ff; color: #00f0ff; }
.banner-warn    { background: rgba(255, 165, 2, 0.10); border-color: #ffa502; color: #ffa502; }
</style>
""",
    unsafe_allow_html=True,
)

# 顶部品牌行
st.title("大模型智能体提示注入与工具调用防护系统")
st.caption(
    "用户任务 → 不可信文档检索 → 注入检测 → 工具调用前授权 → 审计与安全摘要"
)

with st.sidebar:
    st.markdown("### ⚙️ 运行设置")
    mode_label = st.selectbox(
        "摘要模式",
        ("本地确定性模式", "阿里云百炼（Qwen）"),
        help="本地模式无需 API 密钥；在线模式需要 DASHSCOPE_API_KEY。",
    )
    protection_label = st.selectbox(
        "防护配置",
        ("完整防护", "仅检测器", "关闭防护（本地对照）"),
        help="关闭防护仅用于仓库内虚构数据和模拟发件箱的攻击复现。",
    )
    scenario_label = st.selectbox(
        "文档场景",
        ("正常文档", "攻击文档", "全部文档"),
    )
    if protection_label == "关闭防护（本地对照）":
        st.warning("⚠️ 攻击对照模式：危险动作仍只能访问沙箱并写入本地模拟发件箱。")
    if mode_label == "阿里云百炼（Qwen）" and not os.getenv(
        "DASHSCOPE_API_KEY", ""
    ).strip():
        st.warning("尚未设置 DASHSCOPE_API_KEY，在线模式会明确返回配置错误。")

user_task = st.text_area(
    "用户任务",
    value="请搜索演示环境运维交接单，并生成摘要。",
    height=100,
)

if st.button("▶ 运行任务", type="primary"):
    protection_mode = {
        "完整防护": "full",
        "仅检测器": "detector_only",
        "关闭防护（本地对照）": "off",
    }[protection_label]
    scenario = {
        "正常文档": "normal",
        "攻击文档": "attack",
        "全部文档": "all",
    }[scenario_label]
    result = run_office_task(
        user_task,
        mode="local" if mode_label == "本地确定性模式" else "dashscope",
        protection_mode=protection_mode,
        scenario=scenario,
    )
    if not result.ok:
        st.error(result.error["message"] if result.error else "任务运行失败。")
    else:
        # 结果横幅
        outcome = result.attack_outcome
        banner_map = {
            "succeeded": ("banner-danger", "⚠ ATTACK SUCCEEDED — 危险动作已执行（仅沙箱/本地发件箱）"),
            "blocked":   ("banner-success", "🛡 BLOCKED — 危险工具调用已在执行前被阻断"),
            "failed":    ("banner-warn",   "✕ ATTACK FAILED — 模型尝试了但工具执行失败"),
            "not_attempted": ("banner-info", "○ NOT ATTEMPTED — 模型未发起危险工具调用"),
        }
        css_cls, banner_text = banner_map.get(outcome, ("banner-info", outcome))
        st.markdown(f"<div class='banner {css_cls}'>{banner_text}</div>", unsafe_allow_html=True)

        # 流程节点
        st.markdown(
            "<div class='flow-strip'>"
            "<div class='flow-node active'>📥 检索</div>"
            "<div class='flow-node active'>🔍 检测</div>"
            "<div class='flow-node active'>🧠 模型推理</div>"
            "<div class='flow-node active'>🚦 策略网关</div>"
            "<div class='flow-node active'>📝 审计</div>"
            "</div>",
            unsafe_allow_html=True,
        )

        st.subheader("最终回答")
        st.markdown(result.answer)

    first, second, third, fourth = st.columns(4)
    first.metric("运行模式", "本地" if result.mode == "local" else "阿里云百炼")
    second.metric("防护配置", result.protection_mode)
    third.metric("命中文档", len(result.documents))
    fourth.metric("攻击结果", result.attack_outcome)

    st.subheader("执行轨迹")
    st.dataframe(
        [
            {"阶段": step.stage, "状态": step.status, "说明": step.detail}
            for step in result.steps
        ],
        width="stretch",
        hide_index=True,
    )

    if result.detections:
        st.subheader("注入检测")
        st.dataframe(
            [
                {
                    "来源": item["source_id"],
                    "标签": item["label"],
                    "风险分": item["risk_score"],
                    "原因": "；".join(item["reasons"]),
                    "耗时(ms)": item["latency_ms"],
                }
                for item in result.detections
            ],
            width="stretch",
            hide_index=True,
        )

    if result.tool_calls:
        st.subheader("危险工具调用")
        for call in result.tool_calls:
            policy = call["result"].get("meta", {}).get("policy") or {}
            outcome = "ALLOW" if call["result"].get("ok") else call["result"].get(
                "error", {}
            ).get("code", "FAILED")
            with st.expander(f"{call['tool']} · {policy.get('decision', outcome)}"):
                st.json(
                    {
                        "arguments": call["arguments"],
                        "argument_sources": call["argument_sources"],
                        "policy": policy,
                        "outcome": outcome,
                    }
                )

    with st.expander("来源追踪 (provenance)"):
        st.json(result.provenance)

    st.subheader("审计日志")
    try:
        audit_events = load_events(DEFAULT_AUDIT_PATH, trace_id=result.trace_id)
    except ValueError as exc:
        st.error(str(exc))
    else:
        if audit_events:
            st.json(audit_events)
        else:
            st.info("当前任务没有可显示的审计事件。")

    st.subheader("本地模拟发件箱")
    st.caption("这里显示累计的本地模拟记录；完整防护不会删除此前对照演示产生的记录。")
    outbox_messages, outbox_error = load_outbox()
    if outbox_error is not None:
        st.error(str(outbox_error["error"]["message"]))
    elif outbox_messages:
        st.json(outbox_messages)
    else:
        st.info("本地模拟发件箱为空。")

    if result.documents:
        st.subheader("检索资料")
        for document in result.documents:
            with st.expander(f"{document['title']} · {document['relative_path']}"):
                st.caption(
                    f"来源：{document['source_id']}｜可信：{document['trusted']}｜"
                    f"匹配分：{document['match_score']}"
                )
                st.text(document["content"])
