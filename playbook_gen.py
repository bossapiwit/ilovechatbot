from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

def generate_remediation_code(llm, category, analysis, mitigation):
    """
    Generates a specific, executable script to mitigate the identified threat.
    """
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are a Security Engineer enforcing COMPANY POLICY.
        
        **COMPANY POLICY FOR AUTOMATION:**
        1. **HIGH/CRITICAL IMPACT** (e.g., shutting down servers, blocking entire subnets, deleting data):
           - **DO NOT** generate code to execute the action.
           - **INSTEAD**, generate a Python script to **send an ALERT EMAIL** to `admin@gmail.com` requesting approval.
           - The script should log the incident and exit.
        
        2. **LOW/MEDIUM IMPACT** (e.g., adding a specific WAF rule, scanning for versions, checking configs):
           - Generate the actual remediation script (Python, Bash, or ModSecurity).
        
        **Output format**: Just the code block, no markdown explanations outside the block.

        **OWASP 2025 AUTOMATION STRATEGIES:**
        - **A01 (Access Control)**: Generate middleware/decorators for role checks.
        - **A02 (Misconfig)**: Scripts to check/disable default accounts or ports.
        - **A03 (Supply Chain)**: 'pip audit', 'npm audit', or dependency check scripts.
        - **A04 (Crypto)**: Scripts to scan for weak hashing (MD5/SHA1) or hardcoded keys.
        - **A05 (Injection)**: Parameterized query examples or ModSecurity WAF rules.
        - **A06 (Insecure Design)**: Rate limiting scripts (e.g., Token Bucket).
        - **A07 (Auth Failures)**: Password strength checkers or MFA enforcement snippets.
        - **A08 (Integrity)**: Checksum verification scripts (SHA-256).
        - **A09 (Logging)**: Config scripts to enable JSON structured logging.
        - **A10 (Exceptional)**: Global error handler wrappers to prevent stack trace leakage.
        """),
        ("user", f"""
        **Threat Category**: {category}
        **Analysis**: {analysis}
        **Recommended Mitigation**: {mitigation}
        
        Assess the IMPACT level (High/Critical vs Low/Medium) based on the mitigation risks.
        Generate the appropriate script adhering strictly to the COMPANY POLICY.
        """)
    ])
    
    chain = prompt | llm | StrOutputParser()
    return chain.invoke({})

