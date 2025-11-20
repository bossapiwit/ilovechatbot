import streamlit as st
import os
import json
from dotenv import load_dotenv
from graph import build_graph

# Load environment variables
load_dotenv()

# Page Config
st.set_page_config(
    page_title="OWASP 2025 Threat Intel Bot (LangGraph)",
    page_icon="🛡️",
    layout="wide"
)

# Title
st.title("🛡️ OWASP Top 10:2025 (RC) + LangGraph DAG")
st.markdown("""
**Architecture**: LangGraph DAG (Directed Acyclic Graph)
**Features**: NVD Integration, OPA Policy Checks, Automated Playbooks
""")

# Sidebar
with st.sidebar:
    st.header("Settings")
    model_name = st.selectbox("Select Ollama Model", ["llama3.1", "llama3", "mistral", "gemma"], index=0)

# Chat History
if "messages" not in st.session_state:
    st.session_state.messages = [{"role": "assistant", "content": "Describe a vulnerability (e.g., 'log4j remote code execution') and I'll check OWASP and NVD."}]

for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# Initialize Graph
app_workflow = build_graph()

# Input Handling
if prompt := st.chat_input("Describe a threat..."):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        with st.spinner("Running Security DAG..."):
            try:
                # Initial State
                initial_state = {
                    "input": prompt,
                    "model_name": model_name,
                    "category": "",
                    "potential_categories": [],
                    "confidence": 0.0,
                    "keywords": [],
                    "nvd_results": "",
                    "analysis": "",
                    "mitigation": "",
                    "cve_references": [],
                    "playbook_code": "",
                    "opa_passed": False,
                    "opa_reasons": [],
                    "clarifying_questions": []
                }
                
                # Invoke Graph
                final_state = app_workflow.invoke(initial_state)
                
                # Render Results based on State
                confidence = final_state.get("confidence", 0.0)
                
                if confidence < 0.65:
                    st.warning(f"⚠️ Low Confidence ({confidence:.2f})")
                    st.markdown("**Clarifying Questions:**")
                    for q in final_state.get("clarifying_questions", []):
                        st.markdown(f"- {q}")
                    st.session_state.messages.append({"role": "assistant", "content": "I need clarification."})
                
                else:
                    # Display Analysis
                    category = final_state.get("category")
                    impact = final_state.get("impact_level", "Unknown")
                    cvss = final_state.get("cvss_score", "N/A")
                    
                    st.info(f"Detected: **{category}**")
                    
                    col1, col2, col3 = st.columns(3)
                    col1.metric("Confidence", f"{confidence:.2f}")
                    col2.metric("Impact Level", impact)
                    col3.metric("Est. CVSS Score", cvss)
                    
                    response_md = f"""
### 🛡️ Threat Analysis
{final_state.get('analysis')}

### 🏛️ Related CWEs
"""
                    # Format CWEs
                    for ref in final_state.get('cwe_references', []):
                        if isinstance(ref, dict):
                            response_md += f"- **{ref.get('id', 'Unknown')}**: {ref.get('description', '')}\n"
                        else:
                            response_md += f"- {ref}\n"

                    response_md += f"""
### 🛠️ Mitigation
{final_state.get('mitigation')}
"""
                    st.markdown(response_md)
                    
                    # Display Playbook & OPA
                    st.markdown("### 🤖 Automated Playbook")
                    code = final_state.get("playbook_code")
                    passed = final_state.get("opa_passed")
                    reasons = final_state.get("opa_reasons")
                    
                    if passed:
                        st.success("✅ OPA Policy Check: PASSED")
                        st.code(code, language="python")
                        
                        # Execution Logs
                        with st.expander("🚀 View Execution Logs", expanded=True):
                            logs = final_state.get("execution_logs", [])
                            for log in logs:
                                if "[SUCCESS]" in log:
                                    st.success(log)
                                elif "[ERROR]" in log:
                                    st.error(log)
                                else:
                                    st.text(log)

                        full_response = response_md + f"\n\n**Playbook**:\n```python\n{code}\n```"
                    else:
                        st.error("⛔ OPA Policy Check: BLOCKED")
                        st.markdown("**Reasons:**")
                        for r in reasons:
                            st.markdown(f"- {r}")
                        st.markdown("**Blocked Code:**")
                        st.code(code, language="python")
                        full_response = response_md + f"\n\n**Playbook BLOCKED**: {reasons}"

                    st.session_state.messages.append({"role": "assistant", "content": full_response})

            except Exception as e:
                st.error(f"Error executing graph: {e}")
