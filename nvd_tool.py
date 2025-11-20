import requests
from langchain_core.tools import tool

@tool
def nvd_cve_lookup(keyword: str) -> str:
    """
    Queries the National Vulnerability Database (NVD) for CVEs related to a keyword.
    Useful for finding real-world examples of vulnerabilities (e.g., 'log4j', 'sql injection').
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 3
    }
    
    try:
        # Increased timeout to 30 seconds due to slow NVD API
        response = requests.get(base_url, params=params, timeout=30)
        if response.status_code != 200:
            return f"Error contacting NVD API: {response.status_code}"
        
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            return f"No CVEs found for keyword: {keyword}"
        
        results = []
        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            descriptions = cve.get("descriptions", [])
            desc_text = descriptions[0].get("value") if descriptions else "No description"
            
            # Extract CVSS Score
            metrics = cve.get("metrics", {})
            score = "N/A"
            severity = "N/A"
            
            # Priority: V3.1 > V3.0 > V2
            cvss_data = None
            if "cvssMetricV31" in metrics:
                metric = metrics["cvssMetricV31"][0]
                cvss_data = metric.get("cvssData", {})
                severity = metric.get("baseSeverity", "N/A") # Severity is often outside cvssData in V3
            elif "cvssMetricV30" in metrics:
                metric = metrics["cvssMetricV30"][0]
                cvss_data = metric.get("cvssData", {})
                severity = metric.get("baseSeverity", "N/A")
            elif "cvssMetricV2" in metrics:
                metric = metrics["cvssMetricV2"][0]
                cvss_data = metric.get("cvssData", {})
                severity = metric.get("baseSeverity", "N/A") # V2 stores severity differently sometimes
                
            if cvss_data:
                score = cvss_data.get("baseScore", "N/A")
                if severity == "N/A": # Fallback if severity wasn't found above
                    severity = cvss_data.get("baseSeverity", "N/A")

            # Extract CWEs
            weaknesses = cve.get("weaknesses", [])
            cwes = []
            for w in weaknesses:
                desc = w.get("description", [])
                if desc:
                    cwes.append(desc[0].get("value", "Unknown"))
            
            cwe_str = ", ".join(cwes) if cwes else "No CWE mapped"

            results.append(f"ID: {cve_id}\nCWEs: {cwe_str}\nScore: {score} ({severity})\nDescription: {desc_text[:200]}...")
            
        return "\n\n".join(results)
        
    except Exception as e:
        return f"Exception during NVD lookup: {e}"

