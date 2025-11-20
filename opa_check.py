import subprocess
import json
import os

def check_opa_policy(script_content, impact_level="Low"):
    """
    Runs the local opa.exe against the policy.rego to validate the script.
    """
    
    # Create input.json for OPA
    input_data = {
        "input": {
            "script": script_content,
            "impact": impact_level
        }
    }
    
    # Save temp input file
    with open("opa_input.json", "w") as f:
        json.dump(input_data, f)
        
    try:
        # Use absolute path for opa.exe
        current_dir = os.path.dirname(os.path.abspath(__file__))
        opa_path = os.path.join(current_dir, "opa.exe")
        
        if not os.path.exists(opa_path):
            return False, [f"opa.exe not found at: {opa_path}"]

        # Run OPA eval
        # opa eval -i opa_input.json -d policy.rego "data.playbook.security.allow"
        result = subprocess.run(
            [opa_path, "eval", "-i", "opa_input.json", "-d", "policy.rego", "data.playbook.security"],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            return False, f"OPA execution failed: {result.stderr}"
            
        output = json.loads(result.stdout)
        
        # Parse OPA output
        # Expected structure: {"result": [{"expressions": [{"value": {"allow": false, "deny": ["msg"]}}]}]}
        decision = output.get("result", [])[0].get("expressions", [])[0].get("value", {})
        
        allowed = decision.get("allow", False)
        reasons = decision.get("deny", [])
        
        return allowed, reasons
        
    except Exception as e:
        return False, [str(e)]
    finally:
        # Cleanup
        if os.path.exists("opa_input.json"):
            os.remove("opa_input.json")

