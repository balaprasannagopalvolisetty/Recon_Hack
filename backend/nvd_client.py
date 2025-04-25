import requests
import time
from typing import List, Dict, Any, Optional
import logging
from datetime import datetime

logger = logging.getLogger("recon-ai.nvd")

class NVDClient:
    """Client for interacting with the NVD (National Vulnerability Database) API"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.delay = 6 if not api_key else 0.6  # Rate limiting - 10 requests/minute without API key, 100 requests/minute with API key
        self.last_request_time = 0
    
    def _respect_rate_limit(self):
        """Ensure we don't exceed rate limits"""
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        
        if time_since_last_request < self.delay:
            time.sleep(self.delay - time_since_last_request)
        
        self.last_request_time = time.time()
    
    def search_cves(self, 
                   keyword: Optional[str] = None,
                   cpe_name: Optional[str] = None,
                   cvss_v3_severity: Optional[str] = None,
                   limit: int = 20) -> List[Dict[str, Any]]:
        """
        Search for CVEs based on various criteria
        
        Args:
            keyword: Keyword to search in CVE descriptions
            cpe_name: CPE name to search for vulnerabilities (e.g., 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*')
            cvss_v3_severity: Filter by CVSS v3 severity (LOW, MEDIUM, HIGH, CRITICAL)
            limit: Maximum number of results to return
            
        Returns:
            List of CVE data dictionaries
        """
        self._respect_rate_limit()
        
        params = {
            "resultsPerPage": min(limit, 50)  # Max 50 per request
        }
        
        if keyword:
            params["keywordSearch"] = keyword
            
        if cpe_name:
            params["cpeName"] = cpe_name
            
        if cvss_v3_severity:
            params["cvssV3Severity"] = cvss_v3_severity
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        try:
            response = requests.get(self.base_url, params=params, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return data.get("vulnerabilities", [])
            else:
                logger.error(f"Error searching CVEs: {response.status_code} - {response.text}")
                return []
        except Exception as e:
            logger.error(f"Exception searching CVEs: {e}")
            return []
    
    def get_cves_for_software(self, software_name: str, version: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get CVEs for a specific software and optionally version
        
        Args:
            software_name: Name of the software (e.g., 'apache', 'nginx', 'wordpress')
            version: Optional version string
            
        Returns:
            List of CVE data dictionaries
        """
        keyword = software_name
        if version:
            keyword = f"{software_name} {version}"
            
        return self.search_cves(keyword=keyword)
    
    def format_cves(self, cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format CVE data into a simpler structure"""
        formatted_cves = []
        
        for vuln in cves:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id")
            
            if not cve_id:
                continue
                
            # Get descriptions
            descriptions = cve.get("descriptions", [])
            description = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "No description available")
            
            # Get metrics
            metrics = cve.get("metrics", {})
            cvss_v3 = metrics.get("cvssMetricV31", [{}])[0] if "cvssMetricV31" in metrics else \
                      metrics.get("cvssMetricV30", [{}])[0] if "cvssMetricV30" in metrics else {}
            
            cvss_data = cvss_v3.get("cvssData", {})
            base_score = cvss_data.get("baseScore")
            severity = cvss_v3.get("baseSeverity", "UNKNOWN")
            
            # Get references
            references = cve.get("references", [])
            urls = [ref.get("url") for ref in references if "url" in ref]
            
            # Get published and modified dates
            published = cve.get("published")
            last_modified = cve.get("lastModified")
            
            formatted_cve = {
                "id": cve_id,
                "description": description,
                "severity": severity,
                "score": base_score,
                "published": published,
                "last_modified": last_modified,
                "url": urls[0] if urls else f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "references": urls
            }
            
            formatted_cves.append(formatted_cve)
            
        return formatted_cves

# Create a singleton instance
nvd = NVDClient()
