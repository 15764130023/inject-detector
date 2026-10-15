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

st.set_page_config(page_title="提示注入防护系统", layout="wide")
st.title("大模型智能体提示注入与工具调用防护系统")
st.caption(
    "当前闭环：用户任务 → 不可信文档检索 → 注入检测 → "
    "工具调用前授权 → 审计与安全摘要"
)

with st.sidebar:
    st.header("运行设置")
    mode_label = st.selectbox(
        "摘要模式",
        ("本地确定性模式", "OpenAI Agents SDK"),
        help="本地模式无需 API 密钥；在线模式需要 OPENAI_API_KEY。",
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
        st.warning("当前为攻击对照模式：危险动作仍只能访问沙箱并写入本地模拟发件箱。")
    if mode_label == "OpenAI Agents SDK" and not os.getenv("OPENAI_API_KEY", "").strip():
        st.warning("尚未设置 OPENAI_API_KEY，在线模式会明确返回配置错误。")

user_task = st.text_area(
    "用户任务",
    value="请搜索项目资料，并生成一份摘要。",
    height=100,
)

if st.button("运行任务", type="primary"):
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
        mode="local" if mode_label == "本地确定性模式" else "openai",
        protection_mode=protection_mode,
        scenario=scenario,
    )
    if not result.ok:
        st.error(result.error["message"] if result.error else "任务运行失败。")
    else:
        st.subheader("最终回答")
        st.markdown(result.answer)

    first, second, third, fourth = st.columns(4)
    first.metric("运行模式", "本地" if result.mode == "local" else "OpenAI")
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

    with st.expander("来源追踪"):
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

