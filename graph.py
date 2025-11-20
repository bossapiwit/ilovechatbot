from typing import TypedDict, List, Annotated
from langgraph.graph import StateGraph, END
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from langchain_ollama import ChatOllama
from pydantic import BaseModel, Field

from owasp_data import OWASP_2025_CONTEXT
from nvd_tool import nvd_cve_lookup
from playbook_gen import generate_remediation_code
from opa_check import check_opa_policy

from mock_executor import mock_execute_playbook

# --- State Definition ---
class AgentState(TypedDict):
    input: str
    model_name: str
    category: str
    potential_categories: List[str]
    confidence: float
    keywords: List[str]
    nvd_results: str
    analysis: str
    mitigation: str
    cwe_references: List[dict]
    impact_level: str
    cvss_score: str
    playbook_code: str
    opa_passed: bool
    opa_reasons: List[str]
    clarifying_questions: List[str]
    execution_logs: List[str]

# --- Models for Parsing ---
class ClassificationOutput(BaseModel):
    category: str = Field(description="Primary OWASP category")
    potential_categories: List[str] = Field(description="List of potential categories")
    confidence: float
    keywords: List[str]
    reasoning: str
    clarifying_questions: List[str]

class AnalysisOutput(BaseModel):
    analysis: str
    mitigation: str
    cwe_references: List[dict] = Field(description="List of related CWEs (e.g., [{'id': 'CWE-79', 'description': 'XSS'}])")
    impact_level: str = Field(description="High, Medium, or Low")
    cvss_score: str = Field(description="Estimated CVSS Base Score (e.g., '7.5 (High)')")

# --- Nodes ---

def classify_node(state: AgentState):
    """Classifies the input and extracts keywords."""
    llm = ChatOllama(model=state["model_name"], temperature=0, format="json")
    parser = JsonOutputParser(pydantic_object=ClassificationOutput)
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", """Analyze the security threat carefully.
        
        INSTRUCTIONS:
        1. Analyze the input to identify distinct security failures.
        2. Map each REAL failure to an OWASP category.
        3. If ONLY ONE failure is present, list only that one.
        4. If MULTIPLE distinct failures are explicitly described, list all of them.
        
        CONTEXT: {owasp_context}
        OUTPUT JSON: {{ "category": "Primary Category", "potential_categories": ["A07"], "confidence": 0.0, "keywords": [], "reasoning": "...", "clarifying_questions": [] }}"""),
        ("user", "{input}")
    ])
    
    chain = prompt | llm | parser
    result = chain.invoke({"input": state["input"], "owasp_context": OWASP_2025_CONTEXT})
    
    return {
        "category": result.get("category"),
        "potential_categories": result.get("potential_categories", []),
        "confidence": result.get("confidence", 0.0),
        "keywords": result.get("keywords", []),
        "clarifying_questions": result.get("clarifying_questions", [])
    }

def nvd_lookup_node(state: AgentState):
    """Queries NVD for keywords."""
    keywords = state.get("keywords", [])
    if not keywords:
        return {"nvd_results": "No keywords to search."}
    
    # For simplicity in this version, search the first keyword
    # In a full DAG, we could map this to parallel searches
    res = nvd_cve_lookup.invoke(keywords[0])
    return {"nvd_results": res}

def analysis_node(state: AgentState):
    """Generates final analysis and mitigation."""
    llm = ChatOllama(model=state["model_name"], temperature=0, format="json")
    parser = JsonOutputParser(pydantic_object=AnalysisOutput)
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are a Threat Intel Analyst. Provide a detailed report based on the OFFICIAL OWASP Top 10:2025 (Release Candidate).
        Reference: https://owasp.org/Top10/2025/0x00_2025-Introduction/
        
        INSTRUCTIONS:
        1. Start by listing ALL detected categories from the 'Potential Categories' list.
        2. Provide a DETAILED analysis for EACH detected category, including:
           - **Mechanism**: How the attack works.
           - **Root Cause**: What specific control failed.
           - **OWASP Mapping**: Why it fits this 2025 category.
        3. Determine the IMPACT LEVEL based on the inherent severity of the identified CWE (Common Weakness Enumeration).
           - Example: CWE-79 (XSS) -> Medium Impact.
           - Example: CWE-89 (SQLi) -> High/Critical Impact.
        4. Estimate the CVSS Score based on the typical severity of this CWE type (if exact NVD match is missing).
        
        OWASP CONTEXT: {owasp_context}
        OUTPUT JSON: {{ 
            "analysis": "### Incident Breakdown\n**1. Primary Issue (Axx)**: ...\n   - Mechanism: ...\n   - Root Cause: ...\n\n**2. Secondary Issue (Ayy)**: ...", 
            "mitigation": "1. Fix Axx by...\n2. Fix Ayy by...", 
            "cwe_references": [{{ "id": "CWE-...", "description": "..." }}],
            "impact_level": "High/Medium/Low",
            "cvss_score": "9.8 (Source: NVD/CWE Estimate)"
        }}"""),
        ("user", """User Input: {input}
        Detected Category: {category}
        Potential Categories: {potential_categories}
        NVD Data: {nvd_results}""")
    ])
    
    chain = prompt | llm | parser
    res = chain.invoke({
        "input": state["input"], 
        "owasp_context": OWASP_2025_CONTEXT,
        "category": state["category"],
        "potential_categories": state.get("potential_categories", []),
        "nvd_results": state["nvd_results"]
    })
    
    return {
        "analysis": res.get("analysis"),
        "mitigation": res.get("mitigation"),
        "cwe_references": res.get("cwe_references", []),
        "impact_level": res.get("impact_level", "Unknown"),
        "cvss_score": res.get("cvss_score", "N/A")
    }

def playbook_gen_node(state: AgentState):
    """Generates the remediation code."""
    llm = ChatOllama(model=state["model_name"], temperature=0)
    
    # We reuse the existing function logic but need to pass the LLM
    code = generate_remediation_code(
        llm, 
        state["category"], 
        state["analysis"], 
        state["mitigation"]
    )
    return {"playbook_code": code}

def opa_check_node(state: AgentState):
    """Validates the code with OPA."""
    code = state.get("playbook_code", "")
    passed, reasons = check_opa_policy(code)
    return {"opa_passed": passed, "opa_reasons": reasons}

def execute_node(state: AgentState):
    """Mocks the execution if OPA passed."""
    if state.get("opa_passed"):
        result = mock_execute_playbook(state.get("playbook_code"), state.get("impact_level"))
        return {"execution_logs": result["logs"]}
    return {"execution_logs": ["Execution skipped due to OPA block."]}

# --- Conditional Logic ---
def should_continue(state: AgentState):
    """Decides whether to proceed to analysis or ask for clarification."""
    if state["confidence"] < 0.65:
        return "ask_clarification"
    return "analyze"

# --- Graph Construction ---
def build_graph():
    workflow = StateGraph(AgentState)
    
    workflow.add_node("classify", classify_node)
    workflow.add_node("nvd_lookup", nvd_lookup_node)
    workflow.add_node("analyze", analysis_node)
    workflow.add_node("generate_playbook", playbook_gen_node)
    workflow.add_node("opa_check", opa_check_node)
    workflow.add_node("execute", execute_node)
    
    workflow.set_entry_point("classify")
    
    workflow.add_conditional_edges(
        "classify",
        should_continue,
        {
            "ask_clarification": END, # Stop here, app will handle UI
            "analyze": "nvd_lookup"
        }
    )
    
    workflow.add_edge("nvd_lookup", "analyze")
    workflow.add_edge("analyze", "generate_playbook")
    workflow.add_edge("generate_playbook", "opa_check")
    workflow.add_edge("opa_check", "execute")
    workflow.add_edge("execute", END)
    
    return workflow.compile()

