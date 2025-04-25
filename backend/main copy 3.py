from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import List, Optional, Dict, Any
import httpx
import os
import json
import time
import asyncio
import dns.resolver
import socket
import ssl
import subprocess
import re
import uuid
from datetime import datetime
import ollama
import shodan
import requests
from urllib.parse import urlparse
import whois
import geoip2.database
import cryptography.x509
import cryptography.hazmat.backends
from bs4 import BeautifulSoup
import base64
import hashlib
import concurrent.futures
import tldextract
import urllib3
import certifi

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI(title="ReconAI API", description="Backend API for the ReconAI web reconnaissance tool")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load environment variables
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
NVD_API_KEY = os.getenv("NVD_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Initialize API clients
shodan_api = shodan.Shodan(SHODAN_API_KEY) if SHODAN_API_KEY else None

# Database (using JSON files for simplicity)
SCANS_DB = "data/scans.json"
FEEDBACK_DB = "data/feedback.json"
TRAINING_DB = "data/training_data.json"
BREACH_DB = "data/breach_data.json"

# Ensure data directory exists
os.makedirs("data", exist_ok=True)

# Initialize database files if they don't exist
for db_file in [SCANS_DB, FEEDBACK_DB, TRAINING_DB, BREACH_DB]:
    if not os.path.exists(db_file):
        with open(db_file, "w") as f:
            json.dump([], f)

# Download GeoIP database if not exists
GEOIP_DB = "data/GeoLite2-City.mmdb"
if not os.path.exists(GEOIP_DB):
    # In a real implementation, you would download the GeoIP database
    # For now, we'll just create a placeholder
    with open(GEOIP_DB, "wb") as f:
        f.write(b"placeholder")

# Models
class ScanRequest(BaseModel):
    url: str
    modules: List[str]

class FeedbackRequest(BaseModel):
    scan_id: str
    module: str
    finding_id: str
    is_true_positive: bool
    comment: Optional[str] = None

class AnalysisRequest(BaseModel):
    scan_id: Optional[str] = None
    query: str
    model: Optional[str] = "ALIENTELLIGENCE/predictivethreatdetection"
    scanResult: Optional[Dict[str, Any]] = None

class ScanResult(BaseModel):
    scan_id: str
    domain: str
    timestamp: str
    status: str
    modules: Dict[str, Any]

# Helper functions
def normalize_url(url: str) -> str:
    """Normalize URL by adding http:// if protocol is missing."""
    if not url.startswith(("http://", "https://")):
        return f"http://{url}"
    return url

def get_domain_from_url(url: str) -> str:
    """Extract domain from URL."""
    parsed_url = urlparse(normalize_url(url))
    return parsed_url.netloc

def get_base_domain(url: str) -> str:
    """Extract base domain from URL."""
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}"

async def save_scan_result(scan_result: dict):
    """Save scan result to database."""
    try:
        with open(SCANS_DB, "r") as f:
            scans = json.load(f)
        
        # Find and replace existing scan with same ID, or append new scan
        for i, scan in enumerate(scans):
            if scan.get("scan_id") == scan_result.get("scan_id"):
                scans[i] = scan_result
                break
        else:
            scans.append(scan_result)
        
        with open(SCANS_DB, "w") as f:
            json.dump(scans, f, indent=2)
    except Exception as e:
        print(f"Error saving scan result: {e}")

async def get_scan_by_id(scan_id: str) -> Optional[dict]:
    """Get scan result by ID."""
    try:
        with open(SCANS_DB, "r") as f:
            scans = json.load(f)
        
        for scan in scans:
            if scan.get("scan_id") == scan_id:
                return scan
        
        return None
    except Exception as e:
        print(f"Error getting scan: {e}")
        return None

async def save_feedback(feedback: dict):
    """Save user feedback to database."""
    try:
        with open(FEEDBACK_DB, "r") as f:
            feedbacks = json.load(f)
        
        feedbacks.append(feedback)
        
        with open(FEEDBACK_DB, "w") as f:
            json.dump(feedbacks, f, indent=2)
    except Exception as e:
        print(f"Error saving feedback: {e}")

async def save_training_data(training_data: dict):
    """Save training data for model improvement."""
    try:
        with open(TRAINING_DB, "r") as f:
            training_dataset = json.load(f)
        
        training_dataset.append(training_data)
        
        with open(TRAINING_DB, "w") as f:
            json.dump(training_dataset, f, indent=2)
    except Exception as e:
        print(f"Error saving training data: {e}")

# Scanning modules
async def scan_domain_dns(url: str) -> dict:
    """Scan domain and DNS information."""
    domain = get_domain_from_url(url)
    base_domain = get_base_domain(url)
    
    result = {
        "domain": domain,
        "base_domain": base_domain,
        "ip": None,
        "location": None,
        "hosting": None,
        "dns": {
            "a": [],
            "aaaa": [],
            "mx": [],
            "ns": [],
            "txt": [],
            "cname": [],
            "soa": [],
        },
        "whois": {},
        "ssl": {
            "grade": None,
            "validUntil": None,
            "issuer": None,
            "subject": None,
            "sans": [],
            "version": None,
        },
        "certificates": [],
    }
    
    # Get IP address
    try:
        ip = socket.gethostbyname(domain)
        result["ip"] = ip
        
        # Get location and hosting info from Shodan
        if shodan_api:
            try:
                host_info = shodan_api.host(ip)
                result["location"] = f"{host_info.get('city', '')}, {host_info.get('country_name', '')}"
                result["hosting"] = host_info.get('org', 'Unknown')
            except Exception as e:
                print(f"Error getting Shodan info: {e}")
        
        # Fallback to GeoIP if Shodan fails
        if not result["location"] and os.path.exists(GEOIP_DB) and os.path.getsize(GEOIP_DB) > 100:
            try:
                with geoip2.database.Reader(GEOIP_DB) as reader:
                    response = reader.city(ip)
                    result["location"] = f"{response.city.name}, {response.country.name}"
            except Exception as e:
                print(f"Error getting GeoIP info: {e}")
    except Exception as e:
        print(f"Error getting IP: {e}")
    
    # Get DNS records
    for record_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            result["dns"][record_type.lower()] = [str(rdata) for rdata in answers]
        except Exception as e:
            print(f"Error getting {record_type} records: {e}")
    
    # Get WHOIS info
    try:
        w = whois.whois(domain)
        result["whois"] = {
            "registrar": w.registrar,
            "created": str(w.creation_date[0]) if isinstance(w.creation_date, list) else str(w.creation_date),
            "expires": str(w.expiration_date[0]) if isinstance(w.expiration_date, list) else str(w.expiration_date),
            "updated": str(w.updated_date[0]) if isinstance(w.updated_date, list) else str(w.updated_date),
            "name_servers": w.name_servers,
            "status": w.status,
            "emails": w.emails,
            "dnssec": w.dnssec,
            "name": w.name,
            "org": w.org,
            "address": w.address,
            "city": w.city,
            "state": w.state,
            "zipcode": w.zipcode,
            "country": w.country,
        }
    except Exception as e:
        print(f"Error getting WHOIS info: {e}")
        
        # Fallback to command-line whois
        try:
            whois_cmd = subprocess.run(["whois", domain], capture_output=True, text=True)
            whois_output = whois_cmd.stdout
            
            # Extract basic WHOIS info with regex
            registrar_match = re.search(r"Registrar:\s*(.+)", whois_output)
            created_match = re.search(r"Creation Date:\s*(.+)", whois_output)
            expires_match = re.search(r"Registry Expiry Date:\s*(.+)", whois_output)
            
            result["whois"] = {
                "registrar": registrar_match.group(1).strip() if registrar_match else "Unknown",
                "created": created_match.group(1).strip() if created_match else "Unknown",
                "expires": expires_match.group(1).strip() if expires_match else "Unknown",
            }
        except Exception as e:
            print(f"Error getting command-line WHOIS info: {e}")
    
    # Get SSL/TLS info
    try:
        hostname = domain
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Get certificate expiration
                expire_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                result["ssl"]["validUntil"] = expire_date.strftime("%Y-%m-%d")
                
                # Get issuer
                issuer = dict(x[0] for x in cert["issuer"])
                result["ssl"]["issuer"] = issuer.get("organizationName", "Unknown")
                
                # Get subject
                subject = dict(x[0] for x in cert["subject"])
                result["ssl"]["subject"] = subject.get("commonName", "Unknown")
                
                # Get SANs
                if "subjectAltName" in cert:
                    result["ssl"]["sans"] = [x[1] for x in cert["subjectAltName"] if x[0] == "DNS"]
                
                # Get protocol version
                version = ssock.version()
                result["ssl"]["version"] = version
                
                # Assign a grade based on protocol version
                if version == "TLSv1.3":
                    result["ssl"]["grade"] = "A"
                elif version == "TLSv1.2":
                    result["ssl"]["grade"] = "B"
                else:
                    result["ssl"]["grade"] = "C"
    except Exception as e:
        print(f"Error getting SSL/TLS info: {e}")
    
    # Get certificate transparency logs from crt.sh
    try:
        response = requests.get(f"https://crt.sh/?q={domain}&output=json")
        if response.status_code == 200:
            certs = response.json()
            unique_certs = {}
            
            for cert in certs:
                cert_id = cert.get("id")
                if cert_id and cert_id not in unique_certs:
                    unique_certs[cert_id] = {
                        "id": cert_id,
                        "issuer": cert.get("issuer_name", "Unknown"),
                        "subject": cert.get("name_value", "Unknown"),
                        "not_before": cert.get("not_before", "Unknown"),
                        "not_after": cert.get("not_after", "Unknown"),
                    }
            
            result["certificates"] = list(unique_certs.values())[:10]  # Limit to 10 certificates
    except Exception as e:
        print(f"Error getting certificate transparency logs: {e}")
    
    return result

async def scan_tech_stack(url: str) -> dict:
    """Scan website technology stack."""
    result = {
        "webServer": None,
        "cms": None,
        "frameworks": [],
        "languages": [],
        "libraries": [],
        "analytics": [],
        "cdn": [],
        "os": None,
        "database": None,
        "versions": {},
    }
    
    try:
        async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
            response = await client.get(url, timeout=10.0)
            
            # Check server header
            server = response.headers.get("Server")
            if server:
                result["webServer"] = server
            
            # Check for X-Powered-By header
            powered_by = response.headers.get("X-Powered-By")
            if powered_by:
                if "PHP" in powered_by:
                    result["languages"].append("PHP")
                    php_version = re.search(r"PHP/([0-9.]+)", powered_by)
                    if php_version:
                        result["versions"]["php"] = php_version.group(1)
                elif "ASP.NET" in powered_by:
                    result["languages"].append("ASP.NET")
                    aspnet_version = re.search(r"ASP\.NET ([0-9.]+)", powered_by)
                    if aspnet_version:
                        result["versions"]["aspnet"] = aspnet_version.group(1)
            
            # Check for common frameworks and technologies in response body
            html = response.text.lower()
            
            # Check for languages
            if "php" in html or ".php" in html:
                if "PHP" not in result["languages"]:
                    result["languages"].append("PHP")
            if "ruby" in html or "rails" in html:
                result["languages"].append("Ruby")
            if "python" in html or "django" in html or "flask" in html:
                result["languages"].append("Python")
            if "node" in html or "nodejs" in html or "express" in html:
                result["languages"].append("Node.js")
            if "java" in html or "jsp" in html or "servlet" in html:
                result["languages"].append("Java")
            
            # Check for frameworks
            if "jquery" in html:
                result["frameworks"].append("jQuery")
                jquery_version = re.search(r"jquery[^0-9]*([0-9.]+)", html)
                if jquery_version:
                    result["versions"]["jquery"] = jquery_version.group(1)
            if "react" in html or "reactjs" in html:
                result["frameworks"].append("React")
            if "vue" in html or "vuejs" in html:
                result["frameworks"].append("Vue.js")
            if "angular" in html:
                result["frameworks"].append("Angular")
            if "bootstrap" in html:
                result["frameworks"].append("Bootstrap")
                bootstrap_version = re.search(r"bootstrap[^0-9]*([0-9.]+)", html)
                if bootstrap_version:
                    result["versions"]["bootstrap"] = bootstrap_version.group(1)
            if "laravel" in html:
                result["frameworks"].append("Laravel")
            if "django" in html:
                result["frameworks"].append("Django")
            if "flask" in html:
                result["frameworks"].append("Flask")
            if "express" in html:
                result["frameworks"].append("Express.js")
            if "spring" in html:
                result["frameworks"].append("Spring")
            
            # Check for analytics
            if "google-analytics.com" in html or "googletagmanager" in html:
                result["analytics"].append("Google Analytics")
            if "hotjar" in html:
                result["analytics"].append("Hotjar")
            if "matomo" in html or "piwik" in html:
                result["analytics"].append("Matomo")
            if "segment" in html:
                result["analytics"].append("Segment")
            if "mixpanel" in html:
                result["analytics"].append("Mixpanel")
            
            # Check for CDNs
            if "cloudflare" in html or "cloudflare" in str(response.headers):
                result["cdn"].append("Cloudflare")
            if "akamai" in html or "akamai" in str(response.headers):
                result["cdn"].append("Akamai")
            if "fastly" in html or "fastly" in str(response.headers):
                result["cdn"].append("Fastly")
            if "cloudfront" in html or "cloudfront" in str(response.headers):
                result["cdn"].append("CloudFront")
            if "jsdelivr" in html:
                result["cdn"].append("jsDelivr")
            if "unpkg" in html:
                result["cdn"].append("unpkg")
            
            # Check for CMS
            if "wordpress" in html:
                result["cms"] = "WordPress"
                wp_version = re.search(r"wp-content/themes/[^/]+/style.css\?ver=([0-9.]+)", html)
                if wp_version:
                    result["versions"]["wordpress"] = wp_version.group(1)
            elif "drupal" in html:
                result["cms"] = "Drupal"
                drupal_version = re.search(r"drupal.+?([0-9.]+)", html)
                if drupal_version:
                    result["versions"]["drupal"] = drupal_version.group(1)
            elif "joomla" in html:
                result["cms"] = "Joomla"
            elif "magento" in html:
                result["cms"] = "Magento"
            elif "shopify" in html:
                result["cms"] = "Shopify"
            elif "wix" in html:
                result["cms"] = "Wix"
            
            # Check for databases
            if "mysql" in html:
                result["database"] = "MySQL"
            elif "postgresql" in html or "postgres" in html:
                result["database"] = "PostgreSQL"
            elif "mongodb" in html:
                result["database"] = "MongoDB"
            elif "sqlite" in html:
                result["database"] = "SQLite"
            elif "oracle" in html:
                result["database"] = "Oracle"
            elif "sql server" in html or "sqlserver" in html:
                result["database"] = "SQL Server"
            
            # Check for OS
            if "ubuntu" in html or "debian" in html:
                result["os"] = "Linux (Debian/Ubuntu)"
            elif "centos" in html or "fedora" in html or "rhel" in html:
                result["os"] = "Linux (RHEL/CentOS/Fedora)"
            elif "windows" in html:
                result["os"] = "Windows"
            
            # Parse meta tags for more information
            soup = BeautifulSoup(response.text, "html.parser")
            meta_generator = soup.find("meta", attrs={"name": "generator"})
            if meta_generator and meta_generator.get("content"):
                generator = meta_generator.get("content").lower()
                if "wordpress" in generator:
                    result["cms"] = "WordPress"
                    wp_version = re.search(r"wordpress ([0-9.]+)", generator)
                    if wp_version:
                        result["versions"]["wordpress"] = wp_version.group(1)
                elif "drupal" in generator:
                    result["cms"] = "Drupal"
                    drupal_version = re.search(r"drupal ([0-9.]+)", generator)
                    if drupal_version:
                        result["versions"]["drupal"] = drupal_version.group(1)
                elif "joomla" in generator:
                    result["cms"] = "Joomla"
                    joomla_version = re.search(r"joomla! ([0-9.]+)", generator)
                    if joomla_version:
                        result["versions"]["joomla"] = joomla_version.group(1)
    except Exception as e:
        print(f"Error scanning technology: {e}")
    
    return result

async def scan_ports_network(domain: str) -> dict:
    """Scan network configuration, open ports, and topology."""
    result = {
        "openPorts": [],
        "services": {},
        "topology": {
            "hops": [],
            "route": [],
        },
        "firewalls": [],
    }
    
    # Scan common ports
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
    
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result_code = sock.connect_ex((domain, port))
            if result_code == 0:
                result["openPorts"].append(port)
                
                # Get service name
                try:
                    service_name = socket.getservbyport(port)
                except:
                    service_name = "Unknown"
                
                result["services"][str(port)] = service_name
            sock.close()
        except Exception:
            pass
    
    # Check for firewalls
    try:
        async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
            response = await client.get(f"http://{domain}", timeout=10.0)
            
            if "cloudflare" in str(response.headers).lower():
                result["firewalls"].append("Cloudflare WAF")
            if "sucuri" in str(response.headers).lower():
                result["firewalls"].append("Sucuri WAF")
            if "incapsula" in str(response.headers).lower():
                result["firewalls"].append("Imperva/Incapsula WAF")
            if "akamai" in str(response.headers).lower():
                result["firewalls"].append("Akamai WAF")
            if "f5" in str(response.headers).lower() or "big-ip" in str(response.headers).lower():
                result["firewalls"].append("F5 BIG-IP")
            if "fortinet" in str(response.headers).lower() or "fortigate" in str(response.headers).lower():
                result["firewalls"].append("Fortinet FortiGate")
    except Exception as e:
        print(f"Error checking firewalls: {e}")
    
    # Get network topology using traceroute
    try:
        traceroute_cmd = subprocess.run(["traceroute", "-m", "15", domain], capture_output=True, text=True)
        traceroute_output = traceroute_cmd.stdout
        
        # Parse traceroute output
        lines = traceroute_output.strip().split("\n")[1:]  # Skip the first line (header)
        for i, line in enumerate(lines):
            hop_match = re.search(r"^\s*(\d+)\s+([^\s]+)", line)
            if hop_match:
                hop_num = int(hop_match.group(1))
                hop_host = hop_match.group(2)
                
                if hop_host != "*":
                    result["topology"]["hops"].append({
                        "hop": hop_num,
                        "host": hop_host,
                    })
                    result["topology"]["route"].append(hop_host)
    except Exception as e:
        print(f"Error getting network topology: {e}")
    
    # Get additional network information from Shodan if available
    if shodan_api and result["openPorts"]:
        try:
            ip = socket.gethostbyname(domain)
            host_info = shodan_api.host(ip)
            
            # Add additional open ports from Shodan
            for item in host_info.get("data", []):
                port = item.get("port")
                if port and port not in result["openPorts"]:
                    result["openPorts"].append(port)
                    result["services"][str(port)] = item.get("_shodan", {}).get("module", "Unknown")
        except Exception as e:
            print(f"Error getting Shodan network info: {e}")
    
    return result

async def scan_files_directories(url: str) -> dict:
    """Scan for files, directories, and their sensitivity levels."""
    result = {
        "directories": [],
        "files": [],
        "sensitiveFiles": [],
        "backups": [],
        "extensions": {},
        "sensitivityMap": {
            "high": [],
            "medium": [],
            "low": [],
        },
    }
    
    # Common directories to check
    common_dirs = [
        "/admin", "/wp-admin", "/administrator", "/login", "/wp-content",
        "/images", "/img", "/css", "/js", "/api", "/uploads", "/backup",
        "/include", "/includes", "/temp", "/tmp", "/assets", "/static",
        "/config", "/settings", "/database", "/db", "/logs", "/log",
        "/private", "/secret", "/hidden", "/old", "/test", "/dev",
        "/staging", "/beta", "/alpha", "/production", "/prod",
        "/wp-includes", "/wp-content/plugins", "/wp-content/themes",
    ]
    
    # Common files to check
    common_files = [
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/.well-known/security.txt", "/readme.html", "/readme.txt", "/changelog.txt",
        "/license.txt", "/.env", "/.git/HEAD", "/wp-config.php", "/config.php",
        "/phpinfo.php", "/info.php", "/server-status", "/.htaccess",
        "/web.config", "/package.json", "/composer.json", "/Gemfile",
        "/requirements.txt", "/yarn.lock", "/package-lock.json",
        "/Dockerfile", "/docker-compose.yml", "/.dockerignore",
        "/.gitignore", "/.npmrc", "/.yarnrc", "/.npmignore",
        "/humans.txt", "/ads.txt", "/app.js", "/main.js",
        "/index.php", "/index.html", "/default.aspx", "/home.html",
        "/login.php", "/register.php", "/signup.php", "/forgot-password.php",
        "/reset-password.php", "/admin.php", "/administrator.php",
        "/wp-login.php", "/xmlrpc.php", "/api.php", "/api/v1",
    ]
    
    # Common backup files
    backup_files = [
        "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql",
        "/database.sql", "/1.sql", "/dump.sql", "/website.sql",
        "/temp.sql", "/site.tar.gz", "/site.zip", "/site.bak",
        "/backup.bak", "/backup.old", "/old.zip", "/new.zip",
        "/www.zip", "/public_html.zip", "/public_html.tar.gz",
        "/web.zip", "/web.tar.gz", "/src.zip", "/source.zip",
        "/production.zip", "/prod.zip", "/staging.zip", "/dev.zip",
        "/website-backup.zip", "/sql-backup.zip", "/db-backup.sql",
    ]
    
    # Sensitivity levels for file extensions
    sensitivity_levels = {
        "high": [".env", ".pem", ".key", ".cert", ".p12", ".pfx", ".sql", ".db", ".sqlite", ".config", ".ini", ".log", ".htpasswd", ".htaccess", ".git"],
        "medium": [".php", ".asp", ".aspx", ".jsp", ".py", ".rb", ".js", ".json", ".xml", ".yml", ".yaml", ".toml", ".conf", ".md", ".txt"],
        "low": [".html", ".htm", ".css", ".scss", ".less", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".eot"],
    }
    
    async with httpx.AsyncClient(follow_redirects=False, verify=False) as client:
        # Check directories
        for directory in common_dirs:
            try:
                response = await client.head(f"{url}{directory}", timeout=5.0)
                if response.status_code < 404:
                    result["directories"].append(directory)
            except Exception:
                pass
        
        # Check files
        for file in common_files:
            try:
                response = await client.head(f"{url}{file}", timeout=5.0)
                if response.status_code < 404:
                    result["files"].append(file)
                    
                    # Check file extension for sensitivity
                    ext = os.path.splitext(file)[1].lower()
                    if ext:
                        if ext not in result["extensions"]:
                            result["extensions"][ext] = 0
                        result["extensions"][ext] += 1
                        
                        # Determine sensitivity level
                        if any(ext.endswith(sensitive_ext) for sensitive_ext in sensitivity_levels["high"]):
                            result["sensitivityMap"]["high"].append(file)
                            result["sensitiveFiles"].append({"file": file, "level": "high"})
                        elif any(ext.endswith(sensitive_ext) for sensitive_ext in sensitivity_levels["medium"]):
                            result["sensitivityMap"]["medium"].append(file)
                            result["sensitiveFiles"].append({"file": file, "level": "medium"})
                        elif any(ext.endswith(sensitive_ext) for sensitive_ext in sensitivity_levels["low"]):
                            result["sensitivityMap"]["low"].append(file)
                            result["sensitiveFiles"].append({"file": file, "level": "low"})
            except Exception:
                pass
        
        # Check backup files
        for backup in backup_files:
            try:
                response = await client.head(f"{url}{backup}", timeout=5.0)
                if response.status_code < 404:
                    result["backups"].append(backup)
                    result["sensitiveFiles"].append({"file": backup, "level": "high"})
                    result["sensitivityMap"]["high"].append(backup)
            except Exception:
                pass
    
    # Crawl the website to find more files and directories
    try:
        async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
            response = await client.get(url, timeout=10.0)
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Find all links
            for link in soup.find_all(["a", "link", "script", "img"]):
                href = link.get("href") or link.get("src")
                if href and not href.startswith(("http://", "https://", "//", "mailto:", "tel:")):
                    # Normalize path
                    path = href.split("?")[0].split("#")[0]
                    
                    if path.endswith("/"):
                        # It's a directory
                        if path not in result["directories"]:
                            result["directories"].append(path)
                    else:
                        # It's a file
                        if path not in result["files"]:
                            result["files"].append(path)
                            
                            # Check file extension for sensitivity
                            ext = os.path.splitext(path)[1].lower()
                            if ext:
                                if ext not in result["extensions"]:
                                    result["extensions"][ext] = 0
                                result["extensions"][ext] += 1
                                
                                # Determine sensitivity level
                                if any(ext.endswith(sensitive_ext) for sensitive_ext in sensitivity_levels["high"]):
                                    result["sensitivityMap"]["high"].append(path)
                                    result["sensitiveFiles"].append({"file": path, "level": "high"})
                                elif any(ext.endswith(sensitive_ext) for sensitive_ext in sensitivity_levels["medium"]):
                                    result["sensitivityMap"]["medium"].append(path)
                                    result["sensitiveFiles"].append({"file": path, "level": "medium"})
                                elif any(ext.endswith(sensitive_ext) for sensitive_ext in sensitivity_levels["low"]):
                                    result["sensitivityMap"]["low"].append(path)
                                    result["sensitiveFiles"].append({"file": path, "level": "low"})
    except Exception as e:
        print(f"Error crawling website: {e}")
    
    return result

async def scan_api_endpoints(url: str) -> dict:
    """Scan for API endpoints and configurations."""
    result = {
        "endpoints": [],
        "authentication": "Unknown",
        "cors": "Unknown",
        "methods": {},
        "parameters": {},
        "responses": {},
        "swagger": None,
        "graphql": None,
    }
    
    # Common API paths to check
    api_paths = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/rest", "/graphql", "/graphiql", "/swagger",
        "/swagger-ui", "/swagger-ui.html", "/api-docs",
        "/openapi.json", "/swagger.json", "/api/swagger",
        "/api/docs", "/docs", "/redoc", "/api/redoc",
        "/wp-json", "/wp-json/wp/v2", "/jsonrpc",
        "/api/users", "/api/products", "/api/orders",
        "/api/customers", "/api/auth", "/api/login",
        "/api/register", "/api/reset-password",
        "/api/search", "/api/data", "/api/config",
        "/api/settings", "/api/admin", "/api/public",
    ]
    
    async with httpx.AsyncClient(follow_redirects=False, verify=False) as client:
        # Check API paths
        for path in api_paths:
            try:
                response = await client.head(f"{url}{path}", timeout=5.0)
                if response.status_code < 404:
                    result["endpoints"].append(path)
                    
                    # Check allowed methods
                    try:
                        options_response = await client.options(f"{url}{path}", timeout=5.0)
                        allowed_methods = options_response.headers.get("Allow") or options_response.headers.get("Access-Control-Allow-Methods")
                        if allowed_methods:
                            result["methods"][path] = allowed_methods.split(", ")
                    except Exception:
                        pass
            except Exception:
                pass
        
        # Check for Swagger/OpenAPI documentation
        swagger_paths = [
            "/swagger.json", "/swagger.yaml", "/api-docs.json",
            "/openapi.json", "/openapi.yaml", "/swagger-ui.html",
            "/api/swagger", "/api/docs", "/docs", "/redoc",
        ]
        
        for swagger_path in swagger_paths:
            try:
                response = await client.get(f"{url}{swagger_path}", timeout=5.0)
                if response.status_code == 200:
                    content_type = response.headers.get("Content-Type", "")
                    if "json" in content_type or "yaml" in content_type or "html" in content_type:
                        result["swagger"] = swagger_path
                        
                        # If it's JSON, try to parse the API documentation
                        if "json" in content_type:
                            try:
                                api_docs = response.json()
                                
                                # Extract endpoints from Swagger/OpenAPI
                                if "paths" in api_docs:
                                    for path, methods in api_docs["paths"].items():
                                        if path not in result["endpoints"]:
                                            result["endpoints"].append(path)
                                        
                                        # Extract methods
                                        path_methods = []
                                        for method in methods:
                                            if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]:
                                                path_methods.append(method.upper())
                                        
                                        if path_methods:
                                            result["methods"][path] = path_methods
                                        
                                        # Extract parameters
                                        for method, details in methods.items():
                                            if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                                                if "parameters" in details:
                                                    if path not in result["parameters"]:
                                                        result["parameters"][path] = {}
                                                    
                                                    if method.upper() not in result["parameters"][path]:
                                                        result["parameters"][path][method.upper()] = []
                                                    
                                                    for param in details["parameters"]:
                                                        result["parameters"][path][method.upper()].append({
                                                            "name": param.get("name"),
                                                            "in": param.get("in"),
                                                            "required": param.get("required", False),
                                                            "type": param.get("schema", {}).get("type") if "schema" in param else param.get("type"),
                                                        })
                                                
                                                # Extract responses
                                                if "responses" in details:
                                                    if path not in result["responses"]:
                                                        result["responses"][path] = {}
                                                    
                                                    if method.upper() not in result["responses"][path]:
                                                        result["responses"][path][method.upper()] = {}
                                                    
                                                    for status_code, response_details in details["responses"].items():
                                                        result["responses"][path][method.upper()][status_code] = {
                                                            "description": response_details.get("description"),
                                                        }
                            except Exception as e:
                                print(f"Error parsing API documentation: {e}")
                        
                        break
            except Exception:
                pass
        
        # Check for GraphQL endpoint
        graphql_paths = ["/graphql", "/api/graphql", "/gql", "/api/gql"]
        
        for graphql_path in graphql_paths:
            try:
                # Try introspection query
                introspection_query = {
                    "query": """
                    {
                        __schema {
                            queryType {
                                name
                            }
                            mutationType {
                                name
                            }
                            subscriptionType {
                                name
                            }
                            types {
                                kind
                                name
                                description
                            }
                        }
                    }
                    """
                }
                
                response = await client.post(f"{url}{graphql_path}", json=introspection_query, timeout=5.0)
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if "data" in data and "__schema" in data["data"]:
                            result["graphql"] = {
                                "endpoint": graphql_path,
                                "types": len(data["data"]["__schema"]["types"]),
                                "queryType": data["data"]["__schema"]["queryType"]["name"] if data["data"]["__schema"]["queryType"] else None,
                                "mutationType": data["data"]["__schema"]["mutationType"]["name"] if data["data"]["__schema"]["mutationType"] else None,
                                "subscriptionType": data["data"]["__schema"]["subscriptionType"]["name"] if data["data"]["__schema"]["subscriptionType"] else None,
                            }
                            
                            # Add to endpoints
                            if graphql_path not in result["endpoints"]:
                                result["endpoints"].append(graphql_path)
                            
                            break
                    except Exception:
                        pass
            except Exception:
                pass
        
        # Check CORS configuration
        try:
            headers = {"Origin": "https://evil.com"}
            response = await client.options(url, headers=headers, timeout=5.0)
            
            cors_header = response.headers.get("Access-Control-Allow-Origin")
            if cors_header:
                if cors_header == "*":
                    result["cors"] = "permissive"
                elif cors_header == "https://evil.com":
                    result["cors"] = "misconfigured"
                else:
                    result["cors"] = "restrictive"
            
            # Check authentication headers
            auth_headers = response.headers.get("WWW-Authenticate")
            if auth_headers:
                if "basic" in auth_headers.lower():
                    result["authentication"] = "Basic Auth"
                elif "bearer" in auth_headers.lower():
                    result["authentication"] = "Bearer Token"
                elif "digest" in auth_headers.lower():
                    result["authentication"] = "Digest Auth"
                else:
                    result["authentication"] = "Custom"
            
            # Check for common authentication patterns in response
            if "jwt" in str(response.headers).lower() or "token" in str(response.headers).lower():
                result["authentication"] = "JWT"
            elif "oauth" in str(response.headers).lower():
                result["authentication"] = "OAuth"
        except Exception as e:
            print(f"Error checking API configuration: {e}")
    
    # Crawl the website to find more API endpoints
    try:
        async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
            response = await client.get(url, timeout=10.0)
            
            # Look for API endpoints in JavaScript files
            soup = BeautifulSoup(response.text, "html.parser")
            script_tags = soup.find_all("script")
            
            for script in script_tags:
                src = script.get("src")
                if src:
                    # External script
                    if not src.startswith(("http://", "https://", "//")):
                        src = f"{url}/{src}"
                    elif src.startswith("//"):
                        src = f"https:{src}"
                    
                    try:
                        js_response = await client.get(src, timeout=5.0)
                        js_content = js_response.text
                        
                        # Look for API endpoints
                        api_patterns = [
                            r'"/api/[^"]+?"',
                            r"'/api/[^']+?'",
                            r'"/v1/[^"]+?"',
                            r"'/v1/[^']+?'",
                            r'"/v2/[^"]+?"',
                            r"'/v2/[^']+?'",
                            r'"/rest/[^"]+?"',
                            r"'/rest/[^']+?'",
                            r'"/graphql[^"]*?"',
                            r"'/graphql[^']*?'",
                        ]
                        
                        for pattern in api_patterns:
                            matches = re.findall(pattern, js_content)
                            for match in matches:
                                endpoint = match.strip("'\"")
                                if endpoint not in result["endpoints"]:
                                    result["endpoints"].append(endpoint)
                    except Exception:
                        pass
                else:
                    # Inline script
                    js_content = script.string
                    if js_content:
                        # Look for API endpoints
                        api_patterns = [
                            r'"/api/[^"]+?"',
                            r"'/api/[^']+?'",
                            r'"/v1/[^"]+?"',
                            r"'/v1/[^']+?'",
                            r'"/v2/[^"]+?"',
                            r"'/v2/[^']+?'",
                            r'"/rest/[^"]+?"',
                            r"'/rest/[^']+?'",
                            r'"/graphql[^"]*?"',
                            r"'/graphql[^']*?'",
                        ]
                        
                        for pattern in api_patterns:
                            matches = re.findall(pattern, js_content)
                            for match in matches:
                                endpoint = match.strip("'\"")
                                if endpoint not in result["endpoints"]:
                                    result["endpoints"].append(endpoint)
    except Exception as e:
        print(f"Error finding API endpoints in JavaScript: {e}")
    
    return result

async def scan_js_analysis(url: str) -> dict:
    """Scan JavaScript files for endpoints, secrets, and sensitive data."""
    result = {
        "files": [],
        "libraries": [],
        "secrets": [],
        "endpoints": [],
        "sensitiveData": [],
        "comments": [],
        "dependencies": {},
    }
    
    # Patterns for detecting secrets and sensitive data
    secret_patterns = [
        (r'apikey\s*[=:]\s*["\']([^"\']+)["\']', "API Key"),
        (r'api_key\s*[=:]\s*["\']([^"\']+)["\']', "API Key"),
        (r'api[-_]?token\s*[=:]\s*["\']([^"\']+)["\']', "API Token"),
        (r'access[-_]?token\s*[=:]\s*["\']([^"\']+)["\']', "Access Token"),
        (r'auth[-_]?token\s*[=:]\s*["\']([^"\']+)["\']', "Auth Token"),
        (r'client[-_]?secret\s*[=:]\s*["\']([^"\']+)["\']', "Client Secret"),
        (r'secret\s*[=:]\s*["\']([^"\']+)["\']', "Secret"),
        (r'password\s*[=:]\s*["\']([^"\']+)["\']', "Password"),
        (r'passwd\s*[=:]\s*["\']([^"\']+)["\']', "Password"),
        (r'pass\s*[=:]\s*["\']([^"\']+)["\']', "Password"),
        (r'pwd\s*[=:]\s*["\']([^"\']+)["\']', "Password"),
        (r'username\s*[=:]\s*["\']([^"\']+)["\']', "Username"),
        (r'user\s*[=:]\s*["\']([^"\']+)["\']', "Username"),
        (r'login\s*[=:]\s*["\']([^"\']+)["\']', "Login"),
        (r'email\s*[=:]\s*["\']([^"\']+)["\']', "Email"),
        (r'private[-_]?key\s*[=:]\s*["\']([^"\']+)["\']', "Private Key"),
        (r'aws[-_]?access[-_]?key[-_]?id\s*[=:]\s*["\']([^"\']+)["\']', "AWS Access Key"),
        (r'aws[-_]?secret[-_]?access[-_]?key\s*[=:]\s*["\']([^"\']+)["\']', "AWS Secret Key"),
        (r'firebase[-_]?api[-_]?key\s*[=:]\s*["\']([^"\']+)["\']', "Firebase API Key"),
        (r'google[-_]?api[-_]?key\s*[=:]\s*["\']([^"\']+)["\']', "Google API Key"),
        (r'github[-_]?token\s*[=:]\s*["\']([^"\']+)["\']', "GitHub Token"),
        (r'slack[-_]?token\s*[=:]\s*["\']([^"\']+)["\']', "Slack Token"),
        (r'slack[-_]?webhook\s*[=:]\s*["\']([^"\']+)["\']', "Slack Webhook"),
        (r'twitter[-_]?api[-_]?key\s*[=:]\s*["\']([^"\']+)["\']', "Twitter API Key"),
        (r'facebook[-_]?api[-_]?key\s*[=:]\s*["\']([^"\']+)["\']', "Facebook API Key"),
        (r'paypal[-_]?client[-_]?id\s*[=:]\s*["\']([^"\']+)["\']', "PayPal Client ID"),
        (r'stripe[-_]?api[-_]?key\s*[=:]\s*["\']([^"\']+)["\']', "Stripe API Key"),
        (r'mongodb[-_]?uri\s*[=:]\s*["\']([^"\']+)["\']', "MongoDB URI"),
        (r'database[-_]?url\s*[=:]\s*["\']([^"\']+)["\']', "Database URL"),
        (r'jdbc[-_]?url\s*[=:]\s*["\']([^"\']+)["\']', "JDBC URL"),
        (r'db[-_]?password\s*[=:]\s*["\']([^"\']+)["\']', "Database Password"),
        (r'db[-_]?username\s*[=:]\s*["\']([^"\']+)["\']', "Database Username"),
        (r'redis[-_]?url\s*[=:]\s*["\']([^"\']+)["\']', "Redis URL"),
    ]
    
    # Patterns for detecting API endpoints
    api_patterns = [
        r'"/api/[^"]+?"',
        r"'/api/[^']+?'",
        r'"/v1/[^"]+?"',
        r"'/v1/[^']+?'",
        r'"/v2/[^"]+?"',
        r"'/v2/[^']+?'",
        r'"/rest/[^"]+?"',
        r"'/rest/[^']+?'",
        r'"/graphql[^"]*?"',
        r"'/graphql[^']*?'",
        r'"https://api\.[^"]+?"',
        r"'https://api\.[^']+?'",
    ]
    
    try:
        async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
            response = await client.get(url, timeout=10.0)
            html = response.text
            
            # Find JavaScript files
            js_files = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', html)
            
            for js_file in js_files:
                # Normalize URL
                if js_file.startswith("//"):
                    js_file = f"https:{js_file}"
                elif js_file.startswith("/"):
                    js_file = f"{url}{js_file}"
                elif not js_file.startswith(("http://", "https://")):
                    js_file = f"{url}/{js_file}"
                
                js_filename = js_file.split("/")[-1]
                result["files"].append(js_filename)
                
                # Analyze JS file content
                try:
                    js_response = await client.get(js_file, timeout=5.0)
                    js_content = js_response.text
                    
                    # Check for libraries
                    if "jquery" in js_content.lower():
                        version_match = re.search(r'jquery[^0-9]*([0-9.]+)', js_content.lower())
                        if version_match:
                            lib = f"jQuery {version_match.group(1)}"
                            if lib not in result["libraries"]:
                                result["libraries"].append(lib)
                        else:
                            if "jQuery" not in result["libraries"]:
                                result["libraries"].append("jQuery")
                    
                    if "react" in js_content.lower() and "reactdom" in js_content.lower():
                        version_match = re.search(r'react[^0-9]*([0-9.]+)', js_content.lower())
                        if version_match:
                            lib = f"React {version_match.group(1)}"
                            if lib not in result["libraries"]:
                                result["libraries"].append(lib)
                        else:
                            if "React" not in result["libraries"]:
                                result["libraries"].append("React")
                    
                    if "angular" in js_content.lower():
                        version_match = re.search(r'angular[^0-9]*([0-9.]+)', js_content.lower())
                        if version_match:
                            lib = f"Angular {version_match.group(1)}"
                            if lib not in result["libraries"]:
                                result["libraries"].append(lib)
                        else:
                            if "Angular" not in result["libraries"]:
                                result["libraries"].append("Angular")
                    
                    if "vue" in js_content.lower():
                        version_match = re.search(r'vue[^0-9]*([0-9.]+)', js_content.lower())
                        if version_match:
                            lib = f"Vue.js {version_match.group(1)}"
                            if lib not in result["libraries"]:
                                result["libraries"].append(lib)
                        else:
                            if "Vue.js" not in result["libraries"]:
                                result["libraries"].append("Vue.js")
                    
                    # Check for API endpoints
                    for pattern in api_patterns:
                        matches = re.findall(pattern, js_content)
                        for match in matches:
                            endpoint = match.strip('\'"')
                            if endpoint not in result["endpoints"]:
                                result["endpoints"].append(endpoint)
                    
                    # Check for potential secrets
                    for pattern, secret_type in secret_patterns:
                        matches = re.findall(pattern, js_content, re.IGNORECASE)
                        for match in matches:
                            if len(match) > 8:  # Only consider strings that might be secrets
                                secret = {
                                    "type": secret_type,
                                    "file": js_filename,
                                    "value": f"{match[:3]}...{match[-3:]}",  # Mask the actual value
                                    "line": None,  # We don't have line numbers in this implementation
                                }
                                
                                # Check if this secret is already in the list
                                if not any(s["type"] == secret["type"] and s["file"] == secret["file"] and s["value"] == secret["value"] for s in result["secrets"]):
                                    result["secrets"].append(secret)
                    
                    # Extract comments
                    comments = re.findall(r'/\*\*(.*?)\*/', js_content, re.DOTALL)
                    comments.extend(re.findall(r'//(.*)$', js_content, re.MULTILINE))
                    
                    for comment in comments:
                        comment_text = comment.strip()
                        if len(comment_text) > 10 and "license" not in comment_text.lower() and "copyright" not in comment_text.lower():
                            if comment_text not in result["comments"]:
                                result["comments"].append(comment_text)
                    
                    # Check for package dependencies
                    require_matches = re.findall(r'require$$["\']([^"\']+)["\']$$', js_content)
                    import_matches = re.findall(r'from\s+["\']([^"\']+)["\']', js_content)
                    
                    for module in require_matches + import_matches:
                        if module.startswith(".") or module.startswith("/"):
                            continue  # Skip relative imports
                        
                        # Extract the package name (before any path or version)
                        package = module.split("/")[0]
                        
                        if package not in result["dependencies"]:
                            result["dependencies"][package] = 1
                        else:
                            result["dependencies"][package] += 1
                except Exception as e:
                    print(f"Error analyzing JS file {js_file}: {e}")
            
            # Check inline scripts
            inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL)
            
            for i, script in enumerate(inline_scripts):
                script_name = f"inline-script-{i+1}"
                
                # Check for API endpoints
                for pattern in api_patterns:
                    matches = re.findall(pattern, script)
                    for match in matches:
                        endpoint = match.strip('\'"')
                        if endpoint not in result["endpoints"]:
                            result["endpoints"].append(endpoint)
                
                # Check for potential secrets
                for pattern, secret_type in secret_patterns:
                    matches = re.findall(pattern, script, re.IGNORECASE)
                    for match in matches:
                        if len(match) > 8:  # Only consider strings that might be secrets
                            secret = {
                                "type": secret_type,
                                "file": script_name,
                                "value": f"{match[:3]}...{match[-3:]}",  # Mask the actual value
                                "line": None,  # We don't have line numbers in this implementation
                            }
                            
                            # Check if this secret is already in the list
                            if not any(s["type"] == secret["type"] and s["file"] == secret["file"] and s["value"] == secret["value"] for s in result["secrets"]):
                                result["secrets"].append(secret)
    except Exception as e:
        print(f"Error scanning JavaScript: {e}")
    
    return result

async def scan_cloud_security(url: str) -> dict:
    """Scan for cloud resources and misconfigurations."""
    domain = get_domain_from_url(url)
    base_domain = get_base_domain(url)
    
    result = {
        "s3Buckets": [],
        "azureBlobs": [],
        "googleStorage": [],
        "cloudfront": [],
        "firebaseApps": [],
        "misconfigurations": [],
        "exposed": False,
    }
    
    # Check for common cloud storage patterns
    cloud_patterns = [
        (f"https://{domain}.s3.amazonaws.com", "s3Buckets", "Amazon S3"),
        (f"https://{base_domain}.s3.amazonaws.com", "s3Buckets", "Amazon S3"),
        (f"https://s3.amazonaws.com/{domain}", "s3Buckets", "Amazon S3"),
        (f"https://s3.amazonaws.com/{base_domain}", "s3Buckets", "Amazon S3"),
        (f"https://{domain}.blob.core.windows.net", "azureBlobs", "Azure Blob Storage"),
        (f"https://{base_domain}.blob.core.windows.net", "azureBlobs", "Azure Blob Storage"),
        (f"https://storage.googleapis.com/{domain}", "googleStorage", "Google Cloud Storage"),
        (f"https://storage.googleapis.com/{base_domain}", "googleStorage", "Google Cloud Storage"),
        (f"https://{domain}.firebaseio.com", "firebaseApps", "Firebase"),
        (f"https://{base_domain}.firebaseio.com", "firebaseApps", "Firebase"),
        (f"https://{domain}.web.app", "firebaseApps", "Firebase Hosting"),
        (f"https://{base_domain}.web.app", "firebaseApps", "Firebase Hosting"),
    ]
    
    async with httpx.AsyncClient(verify=False) as client:
        for url_pattern, bucket_type, service_name in cloud_patterns:
            try:
                response = await client.head(url_pattern, timeout=5.0)
                if response.status_code < 404:
                    result[bucket_type].append({
                        "url": url_pattern,
                        "service": service_name,
                        "public": response.status_code == 200,
                    })
                    
                    # Check if bucket is publicly accessible
                    if response.status_code == 200:
                        result["exposed"] = True
                        result["misconfigurations"].append({
                            "type": "Public Access",
                            "service": service_name,
                            "url": url_pattern,
                            "severity": "High",
                            "description": f"The {service_name} resource at {url_pattern} is publicly accessible.",
                        })
            except Exception:
                pass
    
    # Check for AWS S3 bucket misconfiguration by trying to list objects
    for bucket in result["s3Buckets"]:
        try:
            list_url = bucket["url"] + "?list-type=2"
            response = await client.get(list_url, timeout=5.0)
            
            if response.status_code == 200 and "<ListBucketResult" in response.text:
                result["misconfigurations"].append({
                    "type": "List Objects",
                    "service": "Amazon S3",
                    "url": list_url,
                    "severity": "High",
                    "description": f"The S3 bucket at {bucket['url']} allows listing of objects.",
                })
        except Exception:
            pass
    
    # Check for Firebase Database misconfiguration
    for firebase_app in result["firebaseApps"]:
        if "firebaseio.com" in firebase_app["url"]:
            try:
                json_url = firebase_app["url"] + ".json"
                response = await client.get(json_url, timeout=5.0)
                
                if response.status_code == 200:
                    result["misconfigurations"].append({
                        "type": "Public Database",
                        "service": "Firebase",
                        "url": json_url,
                        "severity": "Critical",
                        "description": f"The Firebase database at {firebase_app['url']} is publicly accessible without authentication.",
                    })
            except Exception:
                pass
    
    # Check for CloudFront distributions
    try:
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(url, timeout=5.0)
            
            # Check for CloudFront in headers
            if "cloudfront" in str(response.headers).lower():
                cloudfront_domain = response.headers.get("X-Amz-Cf-Id") or response.headers.get("Via")
                if cloudfront_domain:
                    result["cloudfront"].append({
                        "domain": cloudfront_domain,
                        "origin": url,
                    })
    except Exception as e:
        print(f"Error checking CloudFront: {e}")
    
    # Check for cloud credentials in HTML and JavaScript
    try:
        async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
            response = await client.get(url, timeout=10.0)
            html = response.text
            
            # Check for AWS credentials
            aws_key_pattern = r'AKIA[0-9A-Z]{16}'
            aws_keys = re.findall(aws_key_pattern, html)
            
            for key in aws_keys:
                result["misconfigurations"].append({
                    "type": "Exposed Credentials",
                    "service": "AWS",
                    "severity": "Critical",
                    "description": f"AWS Access Key ID ({key[:4]}...{key[-4:]}) found in page source.",
                })
            
            # Check for Google API keys
            google_key_pattern = r'AIza[0-9A-Za-z\-_]{35}'
            google_keys = re.findall(google_key_pattern, html)
            
            for key in google_keys:
                result["misconfigurations"].append({
                    "type": "Exposed Credentials",
                    "service": "Google Cloud",
                    "severity": "Critical",
                    "description": f"Google API Key ({key[:4]}...{key[-4:]}) found in page source.",
                })
            
            # Check for Firebase config
            firebase_config_pattern = r'firebaseConfig\s*=\s*{[^}]+}'
            firebase_configs = re.findall(firebase_config_pattern, html)
            
            for config in firebase_configs:
                result["misconfigurations"].append({
                    "type": "Exposed Configuration",
                    "service": "Firebase",
                    "severity": "High",
                    "description": "Firebase configuration object found in page source.",
                })
    except Exception as e:
        print(f"Error checking for cloud credentials: {e}")
    
    return result

async def scan_vulnerabilities(url: str) -> dict:
    """Scan for vulnerabilities and security issues."""
    domain = get_domain_from_url(url)
    
    result = {
        "vulnerabilities": [],
        "cves": [],
        "misconfigurations": [],
        "riskScore": "Low",
        "securityIssues": [],
    }
    
    # Check for common security issues
    security_checks = [
        {
            "name": "SSL/TLS",
            "description": "Check for SSL/TLS configuration issues",
            "severity": "High",
        },
        {
            "name": "Security Headers",
            "description": "Check for missing security headers",
            "severity": "Medium",
        },
        {
            "name": "Open Ports",
            "description": "Check for unnecessary open ports",
            "severity": "Medium",
        },
        {
            "name": "Information Disclosure",
            "description": "Check for information disclosure in HTTP headers and responses",
            "severity": "Medium",
        },
        {
            "name": "Injection Vulnerabilities",
            "description": "Check for SQL, XSS, and other injection vulnerabilities",
            "severity": "High",
        },
        {
            "name": "CSRF",
            "description": "Check for Cross-Site Request Forgery vulnerabilities",
            "severity": "Medium",
        },
        {
            "name": "Outdated Software",
            "description": "Check for outdated software versions with known vulnerabilities",
            "severity": "High",
        },
    ]
    
    # Check SSL/TLS configuration
    try:
        hostname = domain
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get protocol version
                version = ssock.version()
                
                # Check for weak SSL/TLS versions
                if version in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                    result["vulnerabilities"].append({
                        "name": "Weak SSL/TLS Version",
                        "description": f"The server is using {version}, which is considered insecure.",
                        "severity": "High",
                        "remediation": "Upgrade to TLSv1.2 or TLSv1.3.",
                    })
                
                # Get cipher suite
                cipher = ssock.cipher()
                if cipher:
                    cipher_name = cipher[0]
                    
                    # Check for weak ciphers
                    weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL"]
                    for weak in weak_ciphers:
                        if weak in cipher_name:
                            result["vulnerabilities"].append({
                                "name": "Weak Cipher Suite",
                                "description": f"The server is using a weak cipher suite: {cipher_name}",
                                "severity": "High",
                                "remediation": "Configure the server to use strong cipher suites.",
                            })
    except Exception as e:
        print(f"Error checking SSL/TLS: {e}")
        
        # If we can't connect via HTTPS, it might be a vulnerability
        result["vulnerabilities"].append({
            "name": "Missing HTTPS",
            "description": "The server does not support HTTPS or has an invalid SSL certificate.",
            "severity": "Critical",
            "remediation": "Implement HTTPS with a valid SSL certificate.",
        })
    
    # Check security headers
    try:
        async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
            response = await client.get(url, timeout=10.0)
            
            security_headers = {
                "Content-Security-Policy": "Missing Content Security Policy header",
                "X-XSS-Protection": "Missing XSS Protection header",
                "X-Frame-Options": "Missing Clickjacking Protection header",
                "X-Content-Type-Options": "Missing MIME-type sniffing protection header",
                "Strict-Transport-Security": "Missing HTTP Strict Transport Security header",
                "Referrer-Policy": "Missing Referrer Policy header",
                "Permissions-Policy": "Missing Permissions Policy header",
            }
            
            for header, description in security_headers.items():
                if header not in response.headers:
                    result["vulnerabilities"].append({
                        "name": f"Missing {header}",
                        "description": description,
                        "severity": "Medium",
                        "remediation": f"Add the {header} header to HTTP responses.",
                    })
    except Exception as e:
        print(f"Error checking security headers: {e}")
    
    # Check for information disclosure
    try:
        async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
            response = await client.get(url, timeout=10.0)
            
            # Check for server information disclosure
            if "Server" in response.headers:
                server = response.headers["Server"]
                if len(server) > 5:  # More than just "nginx" or "apache"
                    result["vulnerabilities"].append({
                        "name": "Server Information Disclosure",
                        "description": f"The server is disclosing its software and version: {server}",
                        "severity": "Low",
                        "remediation": "Configure the server to hide detailed version information.",
                    })
            
            # Check for X-Powered-By header
            if "X-Powered-By" in response.headers:
                powered_by = response.headers["X-Powered-By"]
                result["vulnerabilities"].append({
                    "name": "Technology Information Disclosure",
                    "description": f"The server is disclosing its technology stack: {powered_by}",
                    "severity": "Low",
                    "remediation": "Remove the X-Powered-By header from HTTP responses.",
                })
    except Exception as e:
        print(f"Error checking information disclosure: {e}")
    
    # Check for known vulnerabilities using NVD API
    if NVD_API_KEY:
        try:
            headers = {"apiKey": NVD_API_KEY}
            response = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": domain},
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                for vuln in vulnerabilities[:10]:  # Limit to 10 vulnerabilities
                    cve_data = vuln.get("cve", {})
                    cve_id = cve_data.get("id", "Unknown")
                    
                    # Get description
                    descriptions = cve_data.get("descriptions", [])
                    description = "No description available"
                    for desc in descriptions:
                        if desc.get("lang") == "en":
                            description = desc.get("value", "No description available")
                            break
                    
                    # Get severity
                    metrics = cve_data.get("metrics", {})
                    cvss_data = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                    severity = cvss_data.get("baseSeverity", "Unknown")
                    
                    result["cves"].append({
                        "id": cve_id,
                        "description": description,
                        "severity": severity,
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    })
                    
                    result["vulnerabilities"].append({
                        "name": f"Known Vulnerability: {cve_id}",
                        "description": description,
                        "severity": severity,
                        "remediation": "Refer to the CVE details for remediation steps.",
                    })
        except Exception as e:
            print(f"Error checking NVD: {e}")
    
    # Check for common web vulnerabilities
    try:
        # Check for XSS vulnerability
        xss_payloads = [
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            '"><script>alert(1)</script>',
            '\'><script>alert(1)</script>',
        ]
        
        for payload in xss_payloads:
            try:
                test_url = f"{url}?q={payload}"
                async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
                    response = await client.get(test_url, timeout=5.0)
                    
                    if payload in response.text:
                        result["vulnerabilities"].append({
                            "name": "Potential XSS Vulnerability",
                            "description": "The application may be vulnerable to Cross-Site Scripting (XSS) attacks.",
                            "severity": "High",
                            "remediation": "Implement proper input validation and output encoding.",
                        })
                        break
            except Exception:
                pass
        
        # Check for SQL injection vulnerability
        sql_payloads = [
            "' OR '1'='1",
            "1' OR '1'='1",
            "1 OR 1=1",
            "' OR 1=1--",
        ]
        
        for payload in sql_payloads:
            try:
                test_url = f"{url}?id={payload}"
                async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
                    response = await client.get(test_url, timeout=5.0)
                    
                    # Check for SQL error messages
                    sql_errors = [
                        "SQL syntax",
                        "mysql_fetch",
                        "ORA-",
                        "PostgreSQL",
                        "SQLite",
                        "SQL Server",
                        "syntax error",
                        "unclosed quotation mark",
                    ]
                    
                    for error in response.text:
                        if error in response.text:
                            result["vulnerabilities"].append({
                                "name": "Potential SQL Injection Vulnerability",
                                "description": "The application may be vulnerable to SQL Injection attacks.",
                                "severity": "Critical",
                                "remediation": "Use parameterized queries or prepared statements.",
                            })
                            break
            except Exception:
                pass
    except Exception as e:
        print(f"Error checking web vulnerabilities: {e}")
    
    # Calculate risk score based on vulnerabilities
    high_count = sum(1 for v in result["vulnerabilities"] if v["severity"] in ["Critical", "High"])
    medium_count = sum(1 for v in result["vulnerabilities"] if v["severity"] == "Medium")
    
    if high_count > 2:
        result["riskScore"] = "Critical"
    elif high_count > 0:
        result["riskScore"] = "High"
    elif medium_count > 2:
        result["riskScore"] = "Medium"
    else:
        result["riskScore"] = "Low"
    
    # Add security issues summary
    for check in security_checks:
        matching_vulns = [v for v in result["vulnerabilities"] if check["name"] in v["name"]]
        
        if matching_vulns:
            status = "Vulnerable"
            details = ", ".join(v["name"] for v in matching_vulns)
        else:
            status = "Secure"
            details = "No issues found"
        
        result["securityIssues"].append({
            "name": check["name"],
            "description": check["description"],
            "severity": check["severity"],
            "status": status,
            "details": details,
        })
    
    return result

async def scan_email_credentials(domain: str) -> dict:
    """Scan for leaked emails, credentials, and breach information."""
    result = {
        "emails": [],
        "breaches": [],
        "credentials": [],
        "pastBreaches": [],
        "exposedData": {},
        "articles": [],
    }
    
    # Extract base domain
    base_domain = get_base_domain(domain)
    
    # Check for emails on the website
    try:
        async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
            response = await client.get(f"http://{domain}", timeout=10.0)
            html = response.text
            
            # Find email addresses
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            emails = re.findall(email_pattern, html)
            
            # Filter emails belonging to the domain
            domain_emails = [email for email in emails if base_domain in email]
            other_emails = [email for email in emails if base_domain not in email]
            
            # Add unique emails
            for email in domain_emails:
                if email not in result["emails"]:
                    result["emails"].append(email)
            
            # Add a limited number of other emails
            for email in other_emails[:5]:
                if email not in result["emails"]:
                    result["emails"].append(email)
    except Exception as e:
        print(f"Error finding emails on website: {e}")
    
    # Check for breaches using VirusTotal API
    if VT_API_KEY:
        try:
            headers = {"x-apikey": VT_API_KEY}
            response = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{base_domain}",
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                
                # Check for malicious reports
                last_analysis_stats = attributes.get("last_analysis_stats", {})
                malicious = last_analysis_stats.get("malicious", 0)
                
                if malicious > 0:
                    result["breaches"].append({
                        "source": "VirusTotal",
                        "description": f"Domain reported as malicious by {malicious} security vendors",
                        "date": datetime.now().strftime("%Y-%m-%d"),
                    })
        except Exception as e:
            print(f"Error checking VirusTotal: {e}")
    
    # Check for past breaches (simulated)
    # In a real implementation, this would use a service like Have I Been Pwned or a breach database
    try:
        # Load breach data from JSON file
        with open(BREACH_DB, "r") as f:
            breach_data = json.load(f)
        
        # Check if domain is in breach data
        domain_breaches = [breach for breach in breach_data if base_domain.lower() in breach.get("domain", "").lower()]
        
        for breach in domain_breaches:
            result["pastBreaches"].append({
                "name": breach.get("name", "Unknown Breach"),
                "date": breach.get("date", "Unknown"),
                "description": breach.get("description", "No details available"),
                "data_classes": breach.get("data_classes", []),
                "source": breach.get("source", "Breach Database"),
            })
            
            # Add exposed data types
            for data_class in breach.get("data_classes", []):
                if data_class not in result["exposedData"]:
                    result["exposedData"][data_class] = 0
                result["exposedData"][data_class] += 1
    except Exception as e:
        print(f"Error checking breach database: {e}")
        
        # If breach database is not available, add some simulated data
        # This is just for demonstration purposes
        if not result["pastBreaches"]:
            # Check if the domain is a well-known company
            well_known_domains = {
                "equifax.com": {
                    "name": "Equifax Data Breach",
                    "date": "2017-09-07",
                    "description": "Equifax, one of the three major consumer credit reporting agencies, announced a data breach that exposed personal information of 147 million people.",
                    "data_classes": ["Names", "Social Security Numbers", "Birth Dates", "Addresses", "Driver's License Numbers"],
                    "source": "Public Records",
                },
                "yahoo.com": {
                    "name": "Yahoo Data Breach",
                    "date": "2016-12-14",
                    "description": "Yahoo announced a data breach that occurred in 2013, affecting all 3 billion user accounts.",
                    "data_classes": ["Names", "Email Addresses", "Telephone Numbers", "Dates of Birth", "Hashed Passwords", "Security Questions and Answers"],
                    "source": "Public Records",
                },
                "linkedin.com": {
                    "name": "LinkedIn Data Breach",
                    "date": "2012-06-05",
                    "description": "LinkedIn suffered a data breach that exposed the passwords of approximately 6.5 million users.",
                    "data_classes": ["Email Addresses", "Passwords"],
                    "source": "Public Records",
                },
            }
            
            if base_domain in well_known_domains:
                breach = well_known_domains[base_domain]
                result["pastBreaches"].append(breach)
                
                # Add exposed data types
                for data_class in breach["data_classes"]:
                    if data_class not in result["exposedData"]:
                        result["exposedData"][data_class] = 0
                    result["exposedData"][data_class] += 1
    
    # Search for news articles about breaches
    try:
        search_query = f"{base_domain} data breach OR security incident OR hack OR leaked"
        search_url = f"https://news.google.com/rss/search?q={search_query}"
        
        response = requests.get(search_url, timeout=10.0)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "xml")
            items = soup.find_all("item")
            
            for item in items[:5]:  # Limit to 5 articles
                title = item.find("title").text
                link = item.find("link").text
                pub_date = item.find("pubDate").text
                
                result["articles"].append({
                    "title": title,
                    "url": link,
                    "date": pub_date,
                })
    except Exception as e:
        print(f"Error searching for news articles: {e}")
    
    return result

# Routes
@app.post("/api/scan", response_model=dict)
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new scan for the specified URL."""
    url = normalize_url(scan_request.url)
    domain = get_domain_from_url(url)
    
    scan_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()
    
    # Initialize scan result
    scan_result = {
        "scan_id": scan_id,
        "domain": domain,
        "url": url,
        "timestamp": timestamp,
        "status": "scanning",
        "modules": {},
    }
    
    # Save initial scan result
    await save_scan_result(scan_result)
    
    # Start scanning in background
    background_tasks.add_task(perform_scan, scan_id, url, domain, scan_request.modules)
    
    return {
        "scan_id": scan_id,
        "domain": domain,
        "timestamp": timestamp,
        "status": "scanning",
    }

async def perform_scan(scan_id: str, url: str, domain: str, modules: List[str]):
    """Perform the actual scanning in background."""
    scan_result = await get_scan_by_id(scan_id)
    if not scan_result:
        return
    
    try:
        # Run selected modules
        for module in modules:
            if module == "domain_dns":
                scan_result["modules"]["domain_dns"] = await scan_domain_dns(url)
            elif module == "tech_stack":
                scan_result["modules"]["tech_stack"] = await scan_tech_stack(url)
            elif module == "ports_network":
                scan_result["modules"]["ports_network"] = await scan_ports_network(domain)
            elif module == "files_directories":
                scan_result["modules"]["files_directories"] = await scan_files_directories(url)
            elif module == "api_endpoints":
                scan_result["modules"]["api_endpoints"] = await scan_api_endpoints(url)
            elif module == "js_analysis":
                scan_result["modules"]["js_analysis"] = await scan_js_analysis(url)
            elif module == "cloud_security":
                scan_result["modules"]["cloud_security"] = await scan_cloud_security(url)
            elif module == "vulnerabilities":
                scan_result["modules"]["vulnerabilities"] = await scan_vulnerabilities(url)
            elif module == "email_credentials":
                scan_result["modules"]["email_credentials"] = await scan_email_credentials(domain)
            
            # Update scan result after each module
            scan_result["status"] = "scanning"
            await save_scan_result(scan_result)
        
        # Update scan status
        scan_result["status"] = "complete"
    except Exception as e:
        print(f"Error during scan: {e}")
        scan_result["status"] = "error"
        scan_result["error"] = str(e)
    
    # Save final scan result
    await save_scan_result(scan_result)

@app.get("/api/scan/{scan_id}", response_model=dict)
async def get_scan(scan_id: str):
    """Get scan result by ID."""
    scan_result = await get_scan_by_id(scan_id)
    if not scan_result:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan_result

@app.post("/api/feedback", response_model=dict)
async def submit_feedback(feedback_request: FeedbackRequest):
    """Submit feedback for a scan finding."""
    scan_result = await get_scan_by_id(feedback_request.scan_id)
    if not scan_result:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    feedback = {
        "feedback_id": str(uuid.uuid4()),
        "scan_id": feedback_request.scan_id,
        "module": feedback_request.module,
        "finding_id": feedback_request.finding_id,
        "is_true_positive": feedback_request.is_true_positive,
        "comment": feedback_request.comment,
        "timestamp": datetime.now().isoformat(),
    }
    
    # Save feedback
    await save_feedback(feedback)
    
    # Prepare training data for model improvement
    training_data = {
        "scan_data": scan_result,
        "feedback": feedback,
        "timestamp": datetime.now().isoformat(),
    }
    
    # Save training data
    await save_training_data(training_data)
    
    return {"status": "success", "message": "Feedback submitted successfully"}

@app.post("/api/analyze", response_model=dict)
async def analyze_scan(analysis_request: AnalysisRequest):
    """Analyze scan results using LLM."""
    scan_result = None
    
    if analysis_request.scan_id:
        scan_result = await get_scan_by_id(analysis_request.scan_id)
        if not scan_result:
            raise HTTPException(status_code=404, detail="Scan not found")
    elif analysis_request.scanResult:
        scan_result = analysis_request.scanResult
    
    try:
        # Prepare the prompt
        if scan_result:
            prompt = f"""
            You are a cybersecurity expert analyzing web reconnaissance results.
            The scan was performed on the domain: {scan_result.get('domain', 'unknown')}
            
            Here's a summary of the scan results:
            {json.dumps(scan_result, indent=2)[:2000]}...
            
            User query: {analysis_request.query}
            
            Provide a detailed analysis based on the scan results and the user's query.
            Focus on security implications, potential vulnerabilities, and recommendations.
            Be concise but thorough.
            """
        else:
            prompt = f"""
            You are a cybersecurity expert specializing in web security, penetration testing, and threat analysis.
            
            User query: {analysis_request.query}
            
            Provide a detailed security analysis based on the user's query.
            Focus on security implications, potential vulnerabilities, and recommendations.
            Be concise but thorough.
            """
        
        # Call Ollama API
        try:
            # Try to use the specified model or fall back to default
            model_name = analysis_request.model or "ALIENTELLIGENCE/predictivethreatdetection"
            
            # Check if model exists, if not, try to pull it
            try:
                models = ollama.list()
                model_exists = any(model.get('name') == model_name for model in models.get('models', []))
                
                if not model_exists:
                    print(f"Model {model_name} not found, attempting to pull...")
                    ollama.pull(model_name)
            except Exception as e:
                print(f"Error checking/pulling model: {e}")
                # Fall back to a default model that should exist
                model_name = "llama3"
            
            response = ollama.chat(
                model=model_name,
                messages=[{"role": "user", "content": prompt}]
            )
            
            analysis = response['message']['content']
            
            # Save this interaction for model training
            training_data = {
                "type": "analysis",
                "scan_id": analysis_request.scan_id,
                "query": analysis_request.query,
                "response": analysis,
                "timestamp": datetime.now().isoformat(),
            }
            
            await save_training_data(training_data)
            
            return {"analysis": analysis}
        except Exception as e:
            print(f"Error with Ollama: {e}")
            # Try with OpenAI if available
            if OPENAI_API_KEY:
                try:
                    from openai import OpenAI
                    client = OpenAI(api_key=OPENAI_API_KEY)
                    
                    response = client.chat.completions.create(
                        model="gpt-4o",
                        messages=[
                            {"role": "system", "content": "You are a cybersecurity expert specializing in web security."},
                            {"role": "user", "content": prompt}
                        ]
                    )
                    
                    analysis = response.choices[0].message.content
                    return {"analysis": analysis}
                except Exception as openai_error:
                    print(f"Error with OpenAI fallback: {openai_error}")
                    raise HTTPException(status_code=500, detail=f"Failed to generate analysis: {str(e)}")
            else:
                raise HTTPException(status_code=500, detail=f"Failed to generate analysis: {str(e)}")
    except Exception as e:
        print(f"Error during analysis: {e}")
        
        # Return a generic error message
        return {
            "analysis": f"Analysis failed due to an error. Please try again later or contact support. Error: {str(e)}"
        }

@app.post("/api/train", response_model=dict)
async def train_model():
    """Train the custom LLM model with collected feedback data."""
    try:
        # Load training data
        with open(TRAINING_DB, "r") as f:
            training_data = json.load(f)
        
        if not training_data:
            return {"status": "error", "message": "No training data available"}
        
        # In a real implementation, this would call Ollama's API to fine-tune the model
        # For now, we'll just simulate the training process
        
        return {
            "status": "success",
            "message": f"Model training initiated with {len(training_data)} data points",
            "training_id": str(uuid.uuid4())
        }
    except Exception as e:
        print(f"Error training model: {e}")
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
