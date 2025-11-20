import time
import random

def mock_execute_playbook(script_content: str, impact_level: str):
    """
    Simulates the execution of a Python/Bash playbook.
    Returns a dictionary with status and mock logs.
    """
    print(f"--- MOCK EXECUTION START (Impact: {impact_level}) ---")
    
    # Simulate processing time
    time.sleep(1.5)
    
    logs = []
    logs.append("[INFO] Initializing execution environment...")
    logs.append("[INFO] Validating script syntax... OK")
    logs.append(f"[INFO] Impact Assessment: {impact_level}")
    
    if "admin@gmail.com" in script_content:
        logs.append("[INFO] Detected approval request logic.")
        logs.append("[INFO] Sending email to admin@gmail.com via SMTP...")
        time.sleep(0.5)
        logs.append("[SUCCESS] Approval request sent. Ticket #INC-992 created.")
        return {"status": "success", "logs": logs}
    
    if "pip" in script_content:
        logs.append("[EXEC] Running package manager audit...")
        time.sleep(1.0)
        logs.append("[OUTPUT] Requirement already satisfied: requests in /usr/local/lib/python3.9")
        logs.append("[SUCCESS] Audit complete. No critical vulnerabilities found.")
        return {"status": "success", "logs": logs}

    if "WAF" in script_content or "ModSecurity" in script_content:
        logs.append("[EXEC] Deploying WAF rule to /etc/nginx/modsec/...")
        time.sleep(0.8)
        logs.append("[INFO] Reloading Nginx service...")
        logs.append("[SUCCESS] WAF rule active. Blocked 0 requests so far.")
        return {"status": "success", "logs": logs}

    # Generic Success Fallback
    logs.append("[EXEC] Running remediation script...")
    logs.append("[INFO] Applying configuration changes...")
    logs.append("[SUCCESS] Script finished with exit code 0.")
    
    return {"status": "success", "logs": logs}

