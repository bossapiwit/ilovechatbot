package playbook.security

import future.keywords.contains
import future.keywords.if
import future.keywords.in

default allow = false

# 1. Allow by default if no deny rules match
allow if {
    count(deny) == 0
}

# --- GENERAL SAFETY ---

# Deny destructive commands
deny[msg] if {
    dangerous_keywords := ["rm -rf", "DROP TABLE", "DELETE FROM", "mkfs", "dd if=", ":(){ :|:& };:", "shutdown", "format c:"]
    some keyword in dangerous_keywords
    contains(input.script, keyword)
    msg := sprintf("Destructive command detected: %v", [keyword])
}

# Deny usage of hardcoded secrets (basic pattern matching)
deny["Potential hardcoded secret detected"] if {
    # Matches patterns like 'password = "..."' or 'api_key = "..."'
    regex.match("(?i)(password|secret|api_key)\\s*=\\s*['\"][^'\"]+['\"]", input.script)
}

# --- IMPACT CONTROL ---

# High impact scripts MUST send an email to admin
deny["High/Critical impact scripts must require admin approval via email"] if {
    input.impact in ["High", "Critical"]
    not contains(input.script, "admin@gmail.com")
}

# --- OWASP SPECIFIC CHECKS ---

# A01/A07: Protect system auth files
deny["Modification of system authentication files is forbidden"] if {
    file_patterns := ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "C:\\Windows\\System32"]
    some pattern in file_patterns
    contains(input.script, pattern)
}

# A03: Supply Chain - Block potentially unsafe external downloads (e.g. curl | bash)
deny["Unsafe pipe-to-shell execution detected"] if {
    regex.match("curl.*\\|.*(bash|sh|python)", input.script)
    not contains(input.script, "admin@gmail.com") # Allow if it's just an alert email ABOUT this command
}

# A05: Injection - Warn against raw SQL execution (simple check)
deny["Potential SQL Injection risk: Raw SQL execution detected"] if {
    contains(input.script, "execute(") 
    contains(input.script, "%") # Basic formatted string indicator in SQL context
    not contains(input.script, "?") # Missing placeholder often indicates unsafe query
}
