"""Streamlit app (spec 5.6): uv run streamlit run src/cve_copilot/app.py

Scan tab: upload or paste a requirements.txt and see the findings. Chat tab: ask questions,
with the scan as context; every answer shows its sources and a trace. The sidebar shows the
data date and the model. Logic lives in ui.py, scanner and rag; this file only draws.
"""
import streamlit as st

from cve_copilot import ui
from cve_copilot.config import Settings
from cve_copilot.llm.retry import LLMUnavailable
from cve_copilot.rag import pipeline
from cve_copilot.scanner import scan
from cve_copilot.scanner.requirements import decode_requirements

EXAMPLE = "django==3.2.0\nrequests==2.19.0\npillow==9.0.0\nflask==2.2.2\npyyaml==5.3\n"

st.set_page_config(page_title="CVE Copilot", page_icon="🛡️", layout="wide")
settings = Settings.from_env()
state = st.session_state
state.setdefault("report", None)
state.setdefault("messages", [])   # {"role", "text", "sources", "trace"}

# --- Sidebar: which data, which model -------------------------------------------------------
with st.sidebar:
    st.title("🛡️ CVE Copilot")
    st.caption("Python dependency vulnerabilities, explained with sources.")
    target = ui.pick_target(settings)
    if target is None:
        st.error("No vulnerability database yet. Build one:\n\n"
                 "`uv run python -m cve_copilot.ingest --pull-release`\n\n"
                 "or `uv run python -m cve_copilot.ingest --target live`")
        st.stop()
    db_dir = settings.db_dir(target)
    info = ui.manifest(db_dir) or {}
    st.markdown(f"**Data:** {target}, built {info.get('built_at', 'unknown')[:10]}")
    st.caption(f"{info.get('advisories', '?')} advisories · {info.get('kev', '?')} KEV entries")
    st.markdown(f"**Model:** {settings.llm} `{settings.ollama_model}`"
                if settings.llm == "ollama" else f"**Model:** {settings.llm}")
    problem = ui.ollama_status(settings)
    if problem:
        st.warning(problem + "\n\nScanning still works; chat needs the model.")
    if st.button("Reload data", help="After a nightly pull swapped the data folder"):
        ui.reload_data()
        st.rerun()
    if st.button("Clear chat"):
        state.messages = []
        st.rerun()

scan_tab, chat_tab = st.tabs(["Scan requirements", "Chat"])

# --- Scan tab -------------------------------------------------------------------------------
with scan_tab:
    st.subheader("Scan a requirements.txt")
    st.caption("Only pinned lines (`name==version`) are checked. Facts come from code, not the AI.")
    upload = st.file_uploader("Upload requirements.txt", type=["txt", "in"])
    pasted = st.text_area("…or paste it here", height=140, key="pasted",
                          placeholder="django==3.2.0\nrequests==2.19.0")
    left, right = st.columns([1, 5])
    run = left.button("Scan", type="primary")
    example = right.button("Try an example")
    if run or example:
        text = EXAMPLE if example else (
            decode_requirements(upload.getvalue()) if upload else pasted)
        if text.strip():
            state.report = scan(text, db_dir / "cve.db")
        else:
            st.info("Upload a file or paste some requirements first.")

    report = state.report
    if report is not None:
        n, pkgs = len(report.findings), len(report.upgrades)
        a, b, c = st.columns(3)
        a.metric("Pinned packages checked", len(report.checked))
        b.metric("Findings", n)
        c.metric("Packages to upgrade", pkgs)
        if report.findings:
            st.dataframe(ui.finding_rows(report), hide_index=True, width="stretch",
                         column_config={
                             "Advisory": st.column_config.LinkColumn(
                                 display_text=r"https://osv\.dev/vulnerability/(.*)"),
                             "CVSS": st.column_config.NumberColumn(format="%.1f")})
            st.markdown("**Suggested upgrades**")
            st.code("\n".join(ui.upgrade_lines(report)), language=None)
            st.caption("KEV = on CISA's list of bugs attackers are actively using: fix first. "
                       "MALWARE = the package itself is malicious: remove it.")
        elif report.checked:
            st.success("No known vulnerabilities in the pinned packages.")
        for title, notes in (("Not checked (not pinned)", report.not_pinned),
                             ("Skipped", report.skipped)):
            if notes:
                with st.expander(f"{title}: {len(notes)}"):
                    st.markdown("\n".join(f"- line {x.line_no}: `{x.line}` ({x.reason})"
                                          for x in notes))
        st.info("Ask about these results in the **Chat** tab.")

# --- Chat tab -------------------------------------------------------------------------------
def show(message: dict) -> None:
    with st.chat_message(message["role"]):
        st.markdown(message["text"])
        if message.get("sources"):
            with st.expander(f"Sources ({len(message['sources'])})"):
                st.markdown("\n".join(message["sources"]))
        if message.get("trace"):
            with st.expander("Show trace"):
                st.code(message["trace"], language=None)


with chat_tab:
    if state.report is not None:
        st.caption(f"Using your scan as context: {len(state.report.findings)} findings.")
    else:
        st.caption("Ask about a CVE, a package, or a kind of bug. Scan a file first to ask "
                   "about your own project.")
    for message in state.messages:
        show(message)
    question = st.chat_input("e.g. Which of my packages should I fix first?")
    if question:
        state.messages.append({"role": "user", "text": question})
        show(state.messages[-1])
        try:
            with st.spinner("Searching advisories and checking the answer…"):
                result = pipeline.answer(question, db_dir, report=state.report, settings=settings)
            reply = {"role": "assistant", "text": result.text,
                     "sources": ui.source_lines(result.sources),
                     "trace": ui.trace_text(result.trace) if result.trace else None}
        except LLMUnavailable as e:
            reply = {"role": "assistant", "text": f"⚠️ The model is not reachable. {e}"}
        state.messages.append(reply)
        show(reply)
