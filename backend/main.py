from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Header, Form, Security, Request
from fastapi.security import APIKeyHeader, HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, HttpUrl
from typing import List, Optional, Dict, Any, Set
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
import shodan
import requests
from urllib.parse import urlparse, urljoin
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
import secrets
from .config import settings
from .ollama_client import ollama
import logging
import ipaddress
from .nvd_client import nvd
from .pdf_generator import pdf_generator

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(settings.DATA_DIR, "recon.log"))
    ]
)
logger = logging.getLogger("recon-ai")

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI(title="ReconAI API", description="Backend API for the ReconAI web reconnaissance tool")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security schemes
security = HTTPBasic()
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Database paths
SCANS_DB = os.path.join(settings.DATA_DIR, "scans.json")
FEEDBACK_DB = os.path.join(settings.DATA_DIR, "feedback.json")
TRAINING_DB = os.path.join(settings.DATA_DIR, "training_data.json")
BREACH_DB = os.path.join(settings.DATA_DIR, "breach_data.json")
USERS_DB = os.path.join(settings.DATA_DIR, "users.json")
MODELS_DB = os.path.join(settings.DATA_DIR, "models.json")

# Ensure data directory exists
os.makedirs(settings.DATA_DIR, exist_ok=True)

# Create data directories if they don't exist
os.makedirs(os.path.join(settings.DATA_DIR, "reports"), exist_ok=True)

# Mount static files directory for reports
app.mount("/reports", StaticFiles(directory=os.path.join(settings.DATA_DIR, "reports")), name="reports")

# Initialize database files if they don't exist
for db_file in [SCANS_DB, FEEDBACK_DB, TRAINING_DB, BREACH_DB, USERS_DB, MODELS_DB]:
    if not os.path.exists(db_file):
        with open(db_file, "w") as f:
            if db_file == USERS_DB:
                # Initialize with default admin user
                json.dump([{
                    "username": settings.ADMIN_USERNAME,
                    "password_hash": hashlib.sha256(settings.ADMIN_PASSWORD.encode()).hexdigest(),
                    "role": "admin",
                    "created_at": datetime.now().isoformat()
                }], f)
            elif db_file == MODELS_DB:
                # Initialize with default model
                json.dump([{
                    "name": settings.DEFAULT_LLM_MODEL,
                    "description": "Default predictive threat detection model",
                    "created_at": datetime.now().isoformat(),
                    "status": "active"
                }], f)
            else:
                json.dump([], f)

# Download GeoIP database if not exists
GEOIP_DB = os.path.join(settings.DATA_DIR, "GeoLite2-City.mmdb")
if not os.path.exists(GEOIP_DB):
    logger.info("GeoIP database not found. Please download it manually.")

# Initialize API clients
shodan_api = None
if settings.SHODAN_API_KEY:
    try:
        shodan_api = shodan.Shodan(settings.SHODAN_API_KEY)
    except Exception as e:
        logger.error(f"Failed to initialize Shodan API: {e}")

# Models
class ScanRequest(BaseModel):
    url: str
    modules: List[str]
    use_llm: Optional[bool] = True

class FeedbackRequest(BaseModel):
    scan_id: str
    module: str
    finding_id: str
    is_true_positive: bool
    comment: Optional[str] = None

class AnalysisRequest(BaseModel):
    scan_id: Optional[str] = None
    query: str
    model: Optional[str] = None
    scanResult: Optional[Dict[str, Any]] = None
    use_llm: Optional[bool] = True

class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "user"

class UserLogin(BaseModel):
    username: str
    password: str

class ModelTrainRequest(BaseModel):
    name: str
    description: str
    base_model: str = "llama3"
    training_data_ids: Optional[List[str]] = None
    system_prompt: Optional[str] = None
    verification_code: str

# Security functions
def verify_admin(credentials: HTTPBasicCredentials = Depends(security)):
    with open(USERS_DB, "r") as f:
        users = json.load(f)
    
    user = next((u for u in users if u["username"] == credentials.username), None)
    
    if not user or user["password_hash"] != hashlib.sha256(credentials.password.encode()).hexdigest():
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    if user["role"] != "admin":
        raise HTTPException(
            status_code=403,
            detail="Not authorized",
        )
    
    return user

def verify_api_key(api_key: str = Security(api_key_header)):
    if not api_key or api_key != settings.API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
        )
    return api_key

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
        logger.error(f"Error saving scan result: {e}")

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
        logger.error(f"Error getting scan: {e}")
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
        logger.error(f"Error saving feedback: {e}")

async def save_training_data(training_data: dict):
    """Save training data for model improvement."""
    try:
        with open(TRAINING_DB, "r") as f:
            training_dataset = json.load(f)
        
        # Add unique ID to training data
        if "id" not in training_data:
            training_data["id"] = str(uuid.uuid4())
        
        training_dataset.append(training_data)
        
        with open(TRAINING_DB, "w") as f:
            json.dump(training_dataset, f, indent=2)
            
        return training_data["id"]
    except Exception as e:
        logger.error(f"Error saving training data: {e}")
        return None

async def get_training_data(data_id: str = None):
    """Get training data by ID or all if no ID provided."""
    try:
        with open(TRAINING_DB, "r") as f:
            training_dataset = json.load(f)
        
        if data_id:
            return next((data for data in training_dataset if data.get("id") == data_id), None)
        else:
            return training_dataset
    except Exception as e:
        logger.error(f"Error getting training data: {e}")
        return [] if not data_id else None

async def save_model_info(model_info: dict):
    """Save model information to database."""
    try:
        with open(MODELS_DB, "r") as f:
            models = json.load(f)
        
        # Find and replace existing model with same name, or append new model
        for i, model in enumerate(models):
            if model.get("name") == model_info.get("name"):
                models[i] = model_info
                break
        else:
            models.append(model_info)
        
        with open(MODELS_DB, "w") as f:
            json.dump(models, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving model info: {e}")

async def get_models():
    """Get all models."""
    try:
        with open(MODELS_DB, "r") as f:
            models = json.load(f)
        return models
    except Exception as e:
        logger.error(f"Error getting models: {e}")
        return []

def generate_verification_code():
    """Generate a verification code for sensitive operations."""
    return secrets.token_hex(3).upper()  # 6-character hex code

# Scanning functions
async def scan_domain_dns(url: str) -> dict:
    """Scan domain and DNS information."""
    domain = get_domain_from_url(url)
    base_domain = get_base_domain(url)
    result = {
        "domain": domain,
        "ip": None,
        "location": None,
        "hosting": None,
        "whois": {},
        "dns": {},
        "ssl": None,
        "certificates": []
    }
    
    # Get IP address
    try:
        ip = socket.gethostbyname(domain)
        result["ip"] = ip
        
        # Get location using GeoIP
        if os.path.exists(GEOIP_DB):
            try:
                with geoip2.database.Reader(GEOIP_DB) as reader:
                    response = reader.city(ip)
                    result["location"] = f"{response.city.name}, {response.country.name}" if response.city.name else response.country.name
            except Exception as e:
                logger.error(f"Error getting location: {e}")
    except Exception as e:
        logger.error(f"Error resolving domain: {e}")
    
    # Get WHOIS information
    try:
        w = whois.whois(domain)
        result["whois"] = {
            "registrar": w.registrar,
            "created": w.creation_date[0].isoformat() if isinstance(w.creation_date, list) else w.creation_date.isoformat() if w.creation_date else None,
            "expires": w.expiration_date[0].isoformat() if isinstance(w.expiration_date, list) else w.expiration_date.isoformat() if w.expiration_date else None,
            "updated": w.updated_date[0].isoformat() if isinstance(w.updated_date, list) else w.updated_date.isoformat() if w.updated_date else None,
        }
    except Exception as e:
        logger.error(f"Error getting WHOIS: {e}")
    
    # Get DNS records
    dns_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    result["dns"] = {}
    
    for dns_type in dns_types:
        try:
            answers = dns.resolver.resolve(domain, dns_type)
            result["dns"][dns_type] = [str(answer) for answer in answers]
        except Exception as e:
            logger.debug(f"No {dns_type} records found: {e}")
    
    # Get SSL/TLS information
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Parse certificate
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                
                result["ssl"] = {
                    "issuer": issuer.get('organizationName', issuer.get('commonName')),
                    "subject": subject.get('commonName'),
                    "validUntil": cert['notAfter'],
                    "version": cert['version'],
                    "sans": cert.get('subjectAltName', []),
                    "grade": "A"  # Simplified grade
                }
                
                # Add to certificates list
                result["certificates"].append({
                    "issuer": issuer.get('organizationName', issuer.get('commonName')),
                    "subject": subject.get('commonName'),
                    "not_before": cert['notBefore'],
                    "not_after": cert['notAfter']
                })
    except Exception as e:
        logger.error(f"Error getting SSL info: {e}")
    
    # Get hosting information using Shodan if available
    if shodan_api and result["ip"]:
        try:
            host_info = shodan_api.host(result["ip"])
            result["hosting"] = host_info.get('org', 'Unknown')
        except Exception as e:
            logger.error(f"Error getting hosting info from Shodan: {e}")
    
    return result

async def scan_tech_stack(url: str) -> dict:
    """Scan technology stack of the website."""
    normalized_url = normalize_url(url)
    result = {
        "webServer": None,
        "cms": None,
        "database": None,
        "os": None,
        "cdn": [],
        "analytics": [],
        "languages": [],
        "frameworks": [],
        "libraries": [],
        "versions": {}
    }
    
    try:
        # Make HTTP request
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(normalized_url, headers=headers, timeout=10, verify=False)
        
        # Check headers for server information
        if 'Server' in response.headers:
            result["webServer"] = response.headers['Server']
        
        # Check headers for technology clues
        for header, value in response.headers.items():
            # Check for CDN
            if header.lower() in ['x-cdn', 'x-powered-by-cdn']:
                result["cdn"].append(value)
            elif 'cloudflare' in header.lower() or 'cloudflare' in value.lower():
                if 'Cloudflare' not in result["cdn"]:
                    result["cdn"].append('Cloudflare')
            elif 'akamai' in header.lower() or 'akamai' in value.lower():
                if 'Akamai' not in result["cdn"]:
                    result["cdn"].append('Akamai')
            elif 'fastly' in header.lower() or 'fastly' in value.lower():
                if 'Fastly' not in result["cdn"]:
                    result["cdn"].append('Fastly')
            
            # Check for technologies
            if header.lower() == 'x-powered-by':
                if 'php' in value.lower():
                    result["languages"].append('PHP')
                    if 'php/' in value.lower():
                        version = re.search(r'php/([0-9.]+)', value.lower())
                        if version:
                            result["versions"]["PHP"] = version.group(1)
                elif 'asp.net' in value.lower():
                    result["languages"].append('ASP.NET')
                    result["frameworks"].append('ASP.NET')
        
        # Parse HTML for technology clues
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check for CMS
        if soup.select('meta[name="generator"]'):
            generator = soup.select_one('meta[name="generator"]')['content']
            if 'wordpress' in generator.lower():
                result["cms"] = 'WordPress'
                if re.search(r'wordpress ([0-9.]+)', generator.lower()):
                    result["versions"]["WordPress"] = re.search(r'wordpress ([0-9.]+)', generator.lower()).group(1)
            elif 'drupal' in generator.lower():
                result["cms"] = 'Drupal'
            elif 'joomla' in generator.lower():
                result["cms"] = 'Joomla'
        
        # Check for WordPress
        if soup.select('link[rel="https://api.w.org/"]') or soup.select('meta[name="generator"][content*="WordPress"]'):
            result["cms"] = 'WordPress'
        
        # Check for JavaScript frameworks
        scripts = soup.find_all('script')
        for script in scripts:
            # Check src attribute
            if script.has_attr('src'):
                src = script['src'].lower()
                if 'jquery' in src:
                    if 'jQuery' not in result["libraries"]:
                        result["libraries"].append('jQuery')
                    # Try to extract version
                    version_match = re.search(r'jquery-([0-9.]+)', src)
                    if version_match:
                        result["versions"]["jQuery"] = version_match.group(1)
                elif 'react' in src:
                    if 'React' not in result["frameworks"]:
                        result["frameworks"].append('React')
                elif 'angular' in src:
                    if 'Angular' not in result["frameworks"]:
                        result["frameworks"].append('Angular')
                elif 'vue' in src:
                    if 'Vue.js' not in result["frameworks"]:
                        result["frameworks"].append('Vue.js')
            
            # Check content for framework clues
            if script.string:
                content = script.string.lower()
                if 'react' in content and 'React' not in result["frameworks"]:
                    result["frameworks"].append('React')
                if 'angular' in content and 'Angular' not in result["frameworks"]:
                    result["frameworks"].append('Angular')
                if 'vue' in content and 'Vue.js' not in result["frameworks"]:
                    result["frameworks"].append('Vue.js')
        
        # Check for analytics
        if soup.select('script[src*="google-analytics.com"]') or soup.select('script[src*="analytics.google.com"]'):
            result["analytics"].append('Google Analytics')
        if soup.select('script[src*="googletagmanager.com"]'):
            result["analytics"].append('Google Tag Manager')
        
        # Check for languages based on file extensions
        links = soup.find_all('a', href=True)
        extensions = set()
        for link in links:
            href = link['href']
            if '.' in href:
                ext = href.split('.')[-1].lower()
                if ext in ['php', 'aspx', 'jsp', 'rb', 'py']:
                    extensions.add(ext)
        
        for ext in extensions:
            if ext == 'php' and 'PHP' not in result["languages"]:
                result["languages"].append('PHP')
            elif ext == 'aspx' and 'ASP.NET' not in result["languages"]:
                result["languages"].append('ASP.NET')
            elif ext == 'jsp' and 'Java' not in result["languages"]:
                result["languages"].append('Java')
            elif ext == 'rb' and 'Ruby' not in result["languages"]:
                result["languages"].append('Ruby')
            elif ext == 'py' and 'Python' not in result["languages"]:
                result["languages"].append('Python')
        
        # Check for CSS frameworks
        stylesheets = soup.find_all('link', rel='stylesheet')
        for stylesheet in stylesheets:
            if stylesheet.has_attr('href'):
                href = stylesheet['href'].lower()
                if 'bootstrap' in href and 'Bootstrap' not in result["frameworks"]:
                    result["frameworks"].append('Bootstrap')
                elif 'tailwind' in href and 'Tailwind CSS' not in result["frameworks"]:
                    result["frameworks"].append('Tailwind CSS')
        
        # Check inline styles for framework clues
        if soup.select('[class*="bootstrap"]'):
            if 'Bootstrap' not in result["frameworks"]:
                result["frameworks"].append('Bootstrap')
        if soup.select('[class*="tailwind"]') or soup.select('[class*="tw-"]'):
            if 'Tailwind CSS' not in result["frameworks"]:
                result["frameworks"].append('Tailwind CSS')
        
    except Exception as e:
        logger.error(f"Error scanning tech stack: {e}")
    
    return result

async def scan_ports_network(domain: str) -> dict:
    """Scan open ports and network information."""
    result = {
        "openPorts": [],
        "services": {},
        "firewalls": [],
        "topology": {
            "hops": []
        }
    }
    
    # Common ports to scan
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
    
    # Get IP address
    try:
        ip = socket.gethostbyname(domain)
        
        # Scan ports
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                conn_result = sock.connect_ex((ip, port))
                if conn_result == 0:
                    result["openPorts"].append(port)
                    
                    # Try to identify service
                    service_name = "Unknown"
                    try:
                        service_name = socket.getservbyport(port)
                    except:
                        # Fallback to common service names
                        service_map = {
                            21: "FTP",
                            22: "SSH",
                            23: "Telnet",
                            25: "SMTP",
                            53: "DNS",
                            80: "HTTP",
                            110: "POP3",
                            143: "IMAP",
                            443: "HTTPS",
                            465: "SMTPS",
                            587: "Submission",
                            993: "IMAPS",
                            995: "POP3S",
                            3306: "MySQL",
                            3389: "RDP",
                            5432: "PostgreSQL",
                            8080: "HTTP-Proxy",
                            8443: "HTTPS-Alt"
                        }
                        service_name = service_map.get(port, "Unknown")
                    
                    result["services"][port] = service_name
                sock.close()
            except Exception as e:
                logger.error(f"Error scanning port {port}: {e}")
        
        # Check for firewalls using Shodan if available
        if shodan_api:
            try:
                host_info = shodan_api.host(ip)
                
                # Check for WAF signatures in banners
                for item in host_info.get('data', []):
                    banner = item.get('data', '')
                    if isinstance(banner, str):
                        if 'cloudflare' in banner.lower() and 'Cloudflare' not in result["firewalls"]:
                            result["firewalls"].append('Cloudflare')
                        elif 'incapsula' in banner.lower() and 'Incapsula' not in result["firewalls"]:
                            result["firewalls"].append('Incapsula')
                        elif 'akamai' in banner.lower() and 'Akamai' not in result["firewalls"]:
                            result["firewalls"].append('Akamai')
                        elif 'f5' in banner.lower() and 'F5 WAF' not in result["firewalls"]:
                            result["firewalls"].append('F5 WAF')
                        elif 'imperva' in banner.lower() and 'Imperva' not in result["firewalls"]:
                            result["firewalls"].append('Imperva')
            except Exception as e:
                logger.error(f"Error checking firewalls with Shodan: {e}")
        
        # Perform traceroute (simplified)
        try:
            if os.name == 'posix':  # Linux/Mac
                output = subprocess.check_output(['traceroute', '-m', '10', domain], stderr=subprocess.STDOUT, timeout=10)
                lines = output.decode('utf-8').split('\n')
                
                for i, line in enumerate(lines[1:], 1):  # Skip the first line (header)
                    if line.strip():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            hop_ip = parts[1]
                            if hop_ip != '*':
                                result["topology"]["hops"].append({
                                    "hop": i,
                                    "host": hop_ip
                                })
            elif os.name == 'nt':  # Windows
                output = subprocess.check_output(['tracert', '-h', '10', domain], stderr=subprocess.STDOUT, timeout=10)
                lines = output.decode('utf-8').split('\n')
                
                for line in lines[4:]:  # Skip the first few lines (header)
                    if line.strip():
                        parts = line.strip().split()
                        if len(parts) >= 8:
                            hop_num = parts[0]
                            hop_ip = parts[8] if parts[8] != '*' else None
                            if hop_ip:
                                result["topology"]["hops"].append({
                                    "hop": int(hop_num),
                                    "host": hop_ip
                                })
        except Exception as e:
            logger.error(f"Error performing traceroute: {e}")
    
    except Exception as e:
        logger.error(f"Error scanning ports and network: {e}")
    
    return result

async def scan_files_directories(url: str) -> dict:
    """Scan for files and directories."""
    normalized_url = normalize_url(url)
    result = {
        "files": [],
        "directories": [],
        "sensitiveFiles": [],
        "backups": [],
        "extensions": {}
    }
    
    # Common directories to check
    common_dirs = [
        "admin", "administrator", "backup", "backups", "config", "dashboard", 
        "db", "debug", "default", "dev", "files", "home", "images", "img", 
        "install", "log", "login", "logs", "old", "panel", "private", "root", 
        "secure", "security", "setup", "site", "staging", "temp", "test", "tmp", 
        "upload", "uploads", "user", "users", "web", "wp-admin", "wp-content"
    ]
    
    # Common sensitive files to check  "user", "users", "web", "wp-admin", "wp-content"
   
    # Common sensitive files to check
    sensitive_files = [
        ".git/HEAD", ".env", ".htaccess", "robots.txt", "sitemap.xml", 
        "config.php", "wp-config.php", "configuration.php", "config.js", 
        "database.yml", "settings.py", "web.config", "phpinfo.php", 
        "info.php", "test.php", "server-status", "server-info", 
        "crossdomain.xml", "clientaccesspolicy.xml", "composer.json", 
        "package.json", "Dockerfile", "docker-compose.yml", "Jenkinsfile"
    ]
    
    # Common backup file extensions
    backup_extensions = [".bak", ".backup", ".old", ".orig", ".tmp", ".temp", ".swp", ".save", ".~ ", "._"]
    
    # Create a session for requests
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    })
    
    # Check directories
    for directory in common_dirs:
        try:
            dir_url = f"{normalized_url.rstrip('/')}/{directory}/"
            response = session.head(dir_url, timeout=5, allow_redirects=True, verify=False)
            
            if response.status_code == 200 or response.status_code == 403:  # 403 often means the directory exists but is forbidden
                result["directories"].append(directory)
        except Exception as e:
            logger.debug(f"Error checking directory {directory}: {e}")
    
    # Check sensitive files
    for file in sensitive_files:
        try:
            file_url = f"{normalized_url.rstrip('/')}/{file}"
            response = session.head(file_url, timeout=5, allow_redirects=True, verify=False)
            
            if response.status_code == 200:
                # Determine sensitivity level based on file type
                level = "medium"
                if file in [".env", "wp-config.php", "config.php", "database.yml", ".git/HEAD"]:
                    level = "high"
                elif file in ["phpinfo.php", "info.php", "test.php"]:
                    level = "medium"
                else:
                    level = "low"
                
                result["sensitiveFiles"].append({
                    "file": file,
                    "level": level
                })
                result["files"].append(file)
        except Exception as e:
            logger.debug(f"Error checking file {file}: {e}")
    
    # Check for backup files
    # First, get a list of discovered files from the initial page
    try:
        response = session.get(normalized_url, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract all links
        links = soup.find_all('a', href=True)
        discovered_files = set()
        
        for link in links:
            href = link['href']
            if '/' not in href or href.rfind('/') < href.rfind('.'):  # Likely a file, not a directory
                if '.' in href:
                    file_name = href.split('/')[-1]
                    discovered_files.add(file_name)
                    
                    # Track extensions
                    ext = file_name.split('.')[-1].lower()
                    if ext in result["extensions"]:
                        result["extensions"][ext] += 1
                    else:
                        result["extensions"][ext] = 1
        
        # Check for backup versions of discovered files
        for file_name in discovered_files:
            name, ext = os.path.splitext(file_name)
            
            for backup_ext in backup_extensions:
                backup_file = f"{name}{backup_ext}"
                try:
                    backup_url = f"{normalized_url.rstrip('/')}/{backup_file}"
                    response = session.head(backup_url, timeout=5, allow_redirects=True, verify=False)
                    
                    if response.status_code == 200:
                        result["backups"].append(backup_file)
                        result["files"].append(backup_file)
                except Exception as e:
                    logger.debug(f"Error checking backup file {backup_file}: {e}")
   
    except Exception as e:
       logger.error(f"Error scanning for files and directories: {e}")
   
    return result

async def scan_api_endpoints(url: str) -> dict:
   """Scan for API endpoints."""
   normalized_url = normalize_url(url)
   result = {
       "endpoints": [],
       "methods": {},
       "authentication": "Unknown",
       "cors": "Unknown",
       "swagger": False,
       "graphql": None
   }
   
   # Common API paths to check
   api_paths = [
       "api", "api/v1", "api/v2", "api/v3", "rest", "graphql", "query", 
       "service", "services", "wp-json", "wp-json/wp/v2", "api/rest", 
       "api/json", "json", "jsonrpc", "api/graphql", "v1", "v2"
   ]
   
   # Common API endpoint patterns
   endpoint_patterns = [
       "users", "posts", "comments", "products", "orders", "categories", 
       "tags", "items", "data", "auth", "login", "register", "search", 
       "upload", "download", "settings", "config", "admin", "public"
   ]
   
   # Create a session for requests
   session = requests.Session()
   session.headers.update({
       "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
   })
   
   # Check for API base paths
   for path in api_paths:
       try:
           api_url = f"{normalized_url.rstrip('/')}/{path}"
           response = session.get(api_url, timeout=5, verify=False)
           
           # Check if it looks like an API endpoint
           content_type = response.headers.get('Content-Type', '')
           if ('application/json' in content_type or 
               'application/xml' in content_type or 
               'application/graphql' in content_type):
               
               result["endpoints"].append(f"/{path}")
               
               # Check for CORS headers
               if 'Access-Control-Allow-Origin' in response.headers:
                   cors_value = response.headers['Access-Control-Allow-Origin']
                   if cors_value == '*':
                       result["cors"] = "permissive"
                   else:
                       result["cors"] = "restricted"
               
               # Check for authentication headers
               if 'WWW-Authenticate' in response.headers:
                   result["authentication"] = response.headers['WWW-Authenticate']
               elif response.status_code == 401:
                   result["authentication"] = "Required"
               
               # Check for allowed methods
               if 'Allow' in response.headers:
                   methods = [m.strip() for m in response.headers['Allow'].split(',')]
                   result["methods"][f"/{path}"] = methods
               else:
                   # Try OPTIONS request to determine allowed methods
                   try:
                       options_response = session.options(api_url, timeout=5, verify=False)
                       if 'Allow' in options_response.headers:
                           methods = [m.strip() for m in options_response.headers['Allow'].split(',')]
                           result["methods"][f"/{path}"] = methods
                       elif 'Access-Control-Allow-Methods' in options_response.headers:
                           methods = [m.strip() for m in options_response.headers['Access-Control-Allow-Methods'].split(',')]
                           result["methods"][f"/{path}"] = methods
                   except Exception as e:
                       logger.debug(f"Error checking OPTIONS for {path}: {e}")
               
               # Check for sub-endpoints
               for endpoint in endpoint_patterns:
                   try:
                       endpoint_url = f"{api_url}/{endpoint}"
                       endpoint_response = session.get(endpoint_url, timeout=5, verify=False)
                       
                       if (endpoint_response.status_code in [200, 401, 403] and 
                           ('application/json' in endpoint_response.headers.get('Content-Type', '') or 
                            'application/xml' in endpoint_response.headers.get('Content-Type', ''))):
                           
                           result["endpoints"].append(f"/{path}/{endpoint}")
                   except Exception as e:
                       logger.debug(f"Error checking endpoint {endpoint}: {e}")
       
       except Exception as e:
           logger.debug(f"Error checking API path {path}: {e}")
   
   # Check for Swagger/OpenAPI documentation
   swagger_paths = [
       "swagger", "swagger-ui", "swagger-ui.html", "api-docs", "swagger/index.html",
       "swagger/ui/index", "api/swagger", "api/swagger-ui.html", "docs", "api/docs"
   ]
   
   for path in swagger_paths:
       try:
           swagger_url = f"{normalized_url.rstrip('/')}/{path}"
           response = session.get(swagger_url, timeout=5, verify=False)
           
           if response.status_code == 200:
               if ('swagger' in response.text.lower() or 
                   'openapi' in response.text.lower() or 
                   'api documentation' in response.text.lower()):
                   
                   result["swagger"] = True
                   break
       except Exception as e:
           logger.debug(f"Error checking Swagger path {path}: {e}")
   
   # Check for GraphQL endpoint
   graphql_paths = ["graphql", "api/graphql", "query", "api/query"]
   
   for path in graphql_paths:
       try:
           graphql_url = f"{normalized_url.rstrip('/')}/{path}"
           
           # Try introspection query
           introspection_query = """
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
                 name
                 kind
               }
             }
           }
           """
           
           response = session.post(
               graphql_url, 
               json={"query": introspection_query},
               timeout=5,
               verify=False
           )
           
           if response.status_code == 200:
               try:
                   data = response.json()
                   if '__schema' in data.get('data', {}):
                       schema = data['data']['__schema']
                       result["graphql"] = {
                           "endpoint": f"/{path}",
                           "types": len(schema.get('types', [])),
                           "queryType": schema.get('queryType', {}).get('name'),
                           "mutationType": schema.get('mutationType', {}).get('name') if schema.get('mutationType') else None,
                           "subscriptionType": schema.get('subscriptionType', {}).get('name') if schema.get('subscriptionType') else None
                       }
                       break
               except Exception as e:
                   logger.debug(f"Error parsing GraphQL response: {e}")
       
       except Exception as e:
           logger.debug(f"Error checking GraphQL path {path}: {e}")
   
   return result

async def scan_js_analysis(url: str) -> dict:
   """Analyze JavaScript files for potential security issues."""
   normalized_url = normalize_url(url)
   result = {
       "files": [],
       "libraries": [],
       "secrets": [],
       "endpoints": [],
       "comments": [],
       "dependencies": {}
   }
   
   # Create a session for requests
   session = requests.Session()
   session.headers.update({
       "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
   })
   
   # Regular expressions for finding sensitive information
   secret_patterns = {
       "API Key": r'(?:api|access)(?:_|-)(?:key|token)["\']?\s*(?::|=|:=|\s=\s)\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
       "AWS Key": r'(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
       "Private Key": r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
       "Firebase URL": r'https://[a-z0-9-]+\.firebaseio\.com',
       "Password": r'(?:password|passwd|pwd)["\']?\s*(?::|=|:=|\s=\s)\s*["\']([^"\']{4,})["\']',
       "Secret": r'(?:secret|token)["\']?\s*(?::|=|:=|\s=\s)\s*["\']([a-zA-Z0-9_\-]{10,})["\']'
   }
   
   # Regular expressions for finding API endpoints
   endpoint_pattern = r'(?:"|\'|\`)(?:/[a-zA-Z0-9_\-/]+/(?:api|rest|graphql|v[0-9]+)/[a-zA-Z0-9_\-/]+)(?:"|\'|\`)'
   
   # Regular expressions for finding dependencies
   dependency_patterns = {
       "import": r'import\s+(?:{[^}]+}|[a-zA-Z0-9_\-]+)\s+from\s+["\']([a-zA-Z0-9_\-@/]+)["\']',
       "require": r'require\s*\(\s*["\']([a-zA-Z0-9_\-@/]+)["\']',
       "define": r'define\s*\(\s*\[[^\]]*["\']([a-zA-Z0-9_\-@/]+)["\']'
   }
   
   # Get the main page to find JavaScript files
   try:
       response = session.get(normalized_url, timeout=10, verify=False)
       soup = BeautifulSoup(response.text, 'html.parser')
       
       # Find all script tags with src attribute
       scripts = soup.find_all('script', src=True)
       
       for script in scripts:
           src = script['src']
           
           # Normalize the URL
           if src.startswith('//'):
               script_url = f"https:{src}"
           elif src.startswith('/'):
               script_url = f"{normalized_url.rstrip('/')}{src}"
           elif src.startswith('http'):
               script_url = src
           else:
               script_url = f"{normalized_url.rstrip('/')}/{src}"
           
           # Extract the filename
           filename = src.split('/')[-1]
           
           # Add to the list of files
           if filename not in result["files"]:
               result["files"].append(filename)
           
           # Identify libraries
           lower_src = src.lower()
           if 'jquery' in lower_src and 'jQuery' not in result["libraries"]:
               result["libraries"].append('jQuery')
           elif 'angular' in lower_src and 'Angular' not in result["libraries"]:
               result["libraries"].append('Angular')
           elif 'react' in lower_src and 'React' not in result["libraries"]:
               result["libraries"].append('React')
           elif 'vue' in lower_src and 'Vue.js' not in result["libraries"]:
               result["libraries"].append('Vue.js')
           elif 'bootstrap' in lower_src and 'Bootstrap' not in result["libraries"]:
               result["libraries"].append('Bootstrap')
           
           # Download and analyze the JavaScript file
           try:
               js_response = session.get(script_url, timeout=10, verify=False)
               
               if js_response.status_code == 200:
                   js_content = js_response.text
                   
                   # Look for secrets
                   for secret_type, pattern in secret_patterns.items():
                       matches = re.finditer(pattern, js_content, re.IGNORECASE)
                       for match in matches:
                           # Mask the secret value for security
                           secret_value = match.group(1) if match.groups() else match.group(0)
                           masked_value = secret_value[:4] + '...' + secret_value[-4:] if len(secret_value) > 8 else '****'
                           
                           result["secrets"].append({
                               "type": secret_type,
                               "file": filename,
                               "value": masked_value
                           })
                   
                   # Look for API endpoints
                   endpoint_matches = re.finditer(endpoint_pattern, js_content)
                   for match in endpoint_matches:
                       endpoint = match.group(1) if match.groups() else match.group(0).strip('"\'`')
                       if endpoint not in result["endpoints"]:
                           result["endpoints"].append(endpoint)
                   
                   # Look for dependencies
                   for dep_type, pattern in dependency_patterns.items():
                       matches = re.finditer(pattern, js_content)
                       for match in matches:
                           dependency = match.group(1)
                           # Extract the package name (remove version and path)
                           package_name = dependency.split('/')[0]
                           if package_name.startswith('@'):
                               # Handle scoped packages like @angular/core
                               if '/' in dependency:
                                   package_name = '/'.join(dependency.split('/')[:2])
                           
                           if package_name in result["dependencies"]:
                               result["dependencies"][package_name] += 1
                           else:
                               result["dependencies"][package_name] = 1
                   
                   # Extract comments that might contain sensitive information
                   comment_patterns = [
                       r'/\*\*(.*?)\*/', # JSDoc comments
                       r'//\s*TODO:(.+)$', # TODO comments
                       r'//\s*FIXME:(.+)$', # FIXME comments
                       r'//\s*NOTE:(.+)$', # NOTE comments
                       r'//\s*HACK:(.+)$' # HACK comments
                   ]
                   
                   for pattern in comment_patterns:
                       matches = re.finditer(pattern, js_content, re.MULTILINE | re.DOTALL)
                       for match in matches:
                           comment = match.group(1) if match.groups() else match.group(0)
                           # Clean up the comment
                           comment = comment.strip()
                           comment = re.sub(r'\s+', ' ', comment)
                           if comment and len(comment) > 5:  # Ignore very short comments
                               result["comments"].append(comment)
           
           except Exception as e:
               logger.error(f"Error analyzing JavaScript file {filename}: {e}")
       
       # Also check for inline scripts
       inline_scripts = soup.find_all('script', src=False)
       for i, script in enumerate(inline_scripts):
           if script.string:
               filename = f"inline-script-{i+1}"
               
               # Add to the list of files
               if filename not in result["files"]:
                   result["files"].append(filename)
               
               # Analyze the inline script
               js_content = script.string
               
               # Look for secrets
               for secret_type, pattern in secret_patterns.items():
                   matches = re.finditer(pattern, js_content, re.IGNORECASE)
                   for match in matches:
                       # Mask the secret value for security
                       secret_value = match.group(1) if match.groups() else match.group(0)
                       masked_value = secret_value[:4] + '...' + secret_value[-4:] if len(secret_value) > 8 else '****'
                       
                       result["secrets"].append({
                           "type": secret_type,
                           "file": filename,
                           "value": masked_value
                       })
               
               # Look for API endpoints
               endpoint_matches = re.finditer(endpoint_pattern, js_content)
               for match in endpoint_matches:
                   endpoint = match.group(1) if match.groups() else match.group(0).strip('"\'`')
                   if endpoint not in result["endpoints"]:
                       result["endpoints"].append(endpoint)
               
               # Look for dependencies
               for dep_type, pattern in dependency_patterns.items():
                   matches = re.finditer(pattern, js_content)
                   for match in matches:
                       dependency = match.group(1)
                       # Extract the package name (remove version and path)
                       package_name = dependency.split('/')[0]
                       if package_name.startswith('@'):
                           # Handle scoped packages like @angular/core
                           if '/' in dependency:
                               package_name = '/'.join(dependency.split('/')[:2])
                       
                       if package_name in result["dependencies"]:
                           result["dependencies"][package_name] += 1
                       else:
                           result["dependencies"][package_name] = 1
   
   except Exception as e:
       logger.error(f"Error scanning JavaScript: {e}")
   
   return result

async def scan_cloud_security(url: str) -> dict:
    """Scan for cloud security issues."""
    domain = get_domain_from_url(url)
    result = {
        "s3Buckets": [],
        "azureBlobs": [],
        "googleStorage": [],
        "firebaseApps": [],
        "cloudfront": [],
        "exposed": False,
        "misconfigurations": []
    }
    
    # Create a session for requests
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    })
    
    # Check for S3 buckets
    s3_bucket_patterns = [
        f"{domain.replace('.', '-')}.s3.amazonaws.com",
        f"s3.amazonaws.com/{domain.replace('.', '-')}",
        f"{domain.split('.')[0]}.s3.amazonaws.com",
        f"s3.amazonaws.com/{domain.split('.')[0]}"
    ]
    
    for bucket_url in s3_bucket_patterns:
        try:
            response = session.head(f"https://{bucket_url}", timeout=5, verify=False)
            
            if response.status_code != 404:  # Bucket might exist
                # Check if bucket is public
                is_public = False
                try:
                    list_response = session.get(f"https://{bucket_url}", timeout=5, verify=False)
                    if list_response.status_code == 200 and ('<ListBucketResult' in list_response.text or 'Contents' in list_response.text):
                        is_public = True
                        result["exposed"] = True
                except Exception:
                    pass
                
                result["s3Buckets"].append({
                    "url": bucket_url,
                    "public": is_public
                })
                
                # Add misconfiguration if public
                if is_public:
                    result["misconfigurations"].append({
                        "type": "Public S3 Bucket",
                        "service": "AWS S3",
                        "severity": "High",
                        "description": f"S3 bucket {bucket_url} is publicly accessible"
                    })
        except Exception as e:
            logger.debug(f"Error checking S3 bucket {bucket_url}: {e}")
    
    # Check for Azure Blob Storage
    azure_patterns = [
        f"{domain.replace('.', '')}.blob.core.windows.net",
        f"{domain.split('.')[0]}.blob.core.windows.net"
    ]
    
    for blob_url in azure_patterns:
        try:
            response = session.head(f"https://{blob_url}", timeout=5, verify=False)
            
            if response.status_code != 404:  # Blob storage might exist
                # Check if blob storage is public
                is_public = False
                try:
                    list_response = session.get(f"https://{blob_url}", timeout=5, verify=False)
                    if list_response.status_code == 200 and ('EnumerationResults' in list_response.text or 'Blobs' in list_response.text):
                        is_public = True
                        result["exposed"] = True
                except Exception:
                    pass
                
                result["azureBlobs"].append({
                    "url": blob_url,
                    "public": is_public
                })
                
                # Add misconfiguration if public
                if is_public:
                    result["misconfigurations"].append({
                        "type": "Public Azure Blob Storage",
                        "service": "Azure Storage",
                        "severity": "High",
                        "description": f"Azure Blob Storage {blob_url} is publicly accessible"
                    })
        except Exception as e:
            logger.debug(f"Error checking Azure Blob Storage {blob_url}: {e}")
    
    # Check for Google Cloud Storage
    gcs_patterns = [
        f"storage.googleapis.com/{domain.replace('.', '-')}",
        f"storage.googleapis.com/{domain.split('.')[0]}"
    ]
    
    for gcs_url in gcs_patterns:
        try:
            response = session.head(f"https://{gcs_url}", timeout=5, verify=False)
            
            if response.status_code != 404:  # GCS might exist
                # Check if GCS is public
                is_public = False
                try:
                    list_response = session.get(f"https://{gcs_url}", timeout=5, verify=False)
                    if list_response.status_code == 200:
                        is_public = True
                        result["exposed"] = True
                except Exception:
                    pass
                
                result["googleStorage"].append({
                    "url": gcs_url,
                    "public": is_public
                })
                
                # Add misconfiguration if public
                if is_public:
                    result["misconfigurations"].append({
                        "type": "Public Google Cloud Storage",
                        "service": "Google Cloud Storage",
                        "severity": "High",
                        "description": f"Google Cloud Storage {gcs_url} is publicly accessible"
                    })
        except Exception as e:
            logger.debug(f"Error checking Google Cloud Storage {gcs_url}: {e}")
    
    # Check for Firebase
    firebase_patterns = [
        f"{domain.replace('.', '-')}.firebaseio.com",
        f"{domain.split('.')[0]}.firebaseio.com"
    ]
    
    for firebase_url in firebase_patterns:
        try:
            response = session.get(f"https://{firebase_url}/.json", timeout=5, verify=False)
            
            if response.status_code != 404:  # Firebase might exist
                # Check if Firebase is public
                is_public = False
                if response.status_code == 200 and response.text != 'null':
                    is_public = True
                    result["exposed"] = True
                
                result["firebaseApps"].append({
                    "url": firebase_url,
                    "public": is_public
                })
                
                # Add misconfiguration if public
                if is_public:
                    result["misconfigurations"].append({
                        "type": "Public Firebase Database",
                        "service": "Firebase",
                        "severity": "Critical",
                        "description": f"Firebase database {firebase_url} is publicly accessible without authentication"
                    })
        except Exception as e:
            logger.debug(f"Error checking Firebase {firebase_url}: {e}")
    
    # Check for CloudFront distributions
    try:
        response = session.get(url, timeout=10, verify=False)
        
        # Check headers for CloudFront
        if 'x-amz-cf-id' in response.headers or 'X-Amz-Cf-Id' in response.headers:
            result["cloudfront"].append({
                "domain": domain,
                "origin": response.headers.get('x-amz-cf-pop', 'Unknown')
            })
            
            # Check for misconfiguration: missing security headers
            security_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection']
            missing_headers = [header for header in security_headers if header.lower() not in [h.lower() for h in response.headers]]
            
            if missing_headers:
                result["misconfigurations"].append({
                    "type": "Missing Security Headers",
                    "service": "CloudFront",
                    "severity": "Medium",
                    "description": f"CloudFront distribution is missing security headers: {', '.join(missing_headers)}"
                })
    except Exception as e:
        logger.error(f"Error checking CloudFront: {e}")
    
    # Check for common cloud misconfigurations
    # 1. CORS misconfiguration
    try:
        headers = {
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Content-Type"
        }
        response = session.options(url, headers=headers, timeout=5, verify=False)
        
        if 'Access-Control-Allow-Origin' in response.headers:
            if response.headers['Access-Control-Allow-Origin'] == '*' or response.headers['Access-Control-Allow-Origin'] == 'https://evil.com':
                result["misconfigurations"].append({
                    "type": "CORS Misconfiguration",
                    "service": "Web Server",
                    "severity": "Medium",
                    "description": "Server has permissive CORS policy that may allow cross-origin attacks"
                })
    except Exception as e:
        logger.debug(f"Error checking CORS: {e}")
    
    # 2. Check for exposed .git directory
    try:
        git_response = session.get(f"{url.rstrip('/')}/.git/HEAD", timeout=5, verify=False)
        
        if git_response.status_code == 200 and 'ref:' in git_response.text:
            result["misconfigurations"].append({
                "type": "Exposed Git Repository",
                "service": "Web Server",
                "severity": "High",
                "description": "Git repository is publicly accessible, which may expose source code and sensitive information"
            })
            result["exposed"] = True
    except Exception as e:
        logger.debug(f"Error checking .git directory: {e}")
    
    return result

async def scan_vulnerabilities(url: str) -> dict:
    """Scan for vulnerabilities."""
    normalized_url = normalize_url(url)
    domain = get_domain_from_url(normalized_url)
    result = {
        "vulnerabilities": [],
        "cves": [],
        "securityIssues": [],
        "riskScore": "Low",
        "misconfigurations": []
    }
    
    # Create a session for requests
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    })
    
    # Check for common web vulnerabilities
    
    # 1. Check for XSS vulnerabilities
    xss_payloads = [
        "<script>alert(1)</script>",
        "javascript:alert(1)",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>"
    ]
    
    for payload in xss_payloads:
        try:
            # Try in URL parameters
            test_url = f"{normalized_url}?test={payload}"
            response = session.get(test_url, timeout=5, verify=False)
            
            if payload in response.text:
                result["vulnerabilities"].append({
                    "name": "Reflected XSS",
                    "severity": "High",
                    "description": "Application reflects unfiltered user input in the response",
                    "remediation": "Implement proper input validation and output encoding"
                })
                break
        except Exception as e:
            logger.debug(f"Error checking XSS: {e}")
    
    # 2. Check for SQL Injection vulnerabilities
    sqli_payloads = [
        "' OR '1'='1",
        "1' OR '1'='1",
        "1 OR 1=1",
        "' OR 1=1--",
        "admin'--"
    ]
    
    for payload in sqli_payloads:
        try:
            # Try in URL parameters
            test_url = f"{normalized_url}?id={payload}"
            response = session.get(test_url, timeout=5, verify=False)
            
            # Look for SQL error messages
            sql_errors = [
                "SQL syntax",
                "mysql_fetch_array",
                "ORA-",
                "PostgreSQL",
                "SQLite3::",
                "Microsoft SQL Server",
                "ODBC Driver",
                "You have an error in your SQL syntax",
                "Division by zero in SQL statement"
            ]
            
            for error in sql_errors:
                if error in response.text:
                    
                    result["vulnerabilities"].append({
                        "name": "SQL Injection",
                        "severity": "Critical",
                        "description": "Application is vulnerable to SQL injection attacks",
                        "remediation": "Use parameterized queries or prepared statements"
                    })
                    break
        except Exception as e:
            logger.debug(f"Error checking SQL Injection: {e}")
    
    # 3. Check for open redirects
    redirect_payloads = [
        "https://evil.com",
        "//evil.com",
        "\\\\evil.com"
    ]
    
    for payload in redirect_payloads:
        try:
            # Try in URL parameters
            test_url = f"{normalized_url}?redirect={payload}&url={payload}&next={payload}&return={payload}"
            response = session.get(test_url, timeout=5, allow_redirects=False, verify=False)
            
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                if 'evil.com' in location:
                    result["vulnerabilities"].append({
                        "name": "Open Redirect",
                        "severity": "Medium",
                        "description": "Application allows open redirects to arbitrary domains",
                        "remediation": "Validate redirect URLs against a whitelist"
                    })
                    break
        except Exception as e:
            logger.debug(f"Error checking Open Redirect: {e}")
    
    # 4. Check for CSRF vulnerabilities
    try:
        response = session.get(normalized_url, timeout=5, verify=False)
        
        # Look for forms without CSRF tokens
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            # Check if form has CSRF token
            has_csrf_token = False
            inputs = form.find_all('input')
            
            for input_field in inputs:
                input_name = input_field.get('name', '').lower()
                if 'csrf' in input_name or 'token' in input_name or '_token' in input_name:
                    has_csrf_token = True
                    break
            
            if not has_csrf_token and form.get('method', '').lower() != 'get':
                result["vulnerabilities"].append({
                    "name": "CSRF Vulnerability",
                    "severity": "Medium",
                    "description": "Application contains forms without CSRF protection",
                    "remediation": "Implement CSRF tokens for all state-changing operations"
                })
                break
    except Exception as e:
        logger.debug(f"Error checking CSRF: {e}")
    
    # 5. Check for security headers
    try:
        response = session.get(normalized_url, timeout=5, verify=False)
        
        # Important security headers
        security_headers = {
            "Strict-Transport-Security": "Missing HSTS header",
            "Content-Security-Policy": "Missing Content Security Policy",
            "X-Content-Type-Options": "Missing X-Content-Type-Options header",
            "X-Frame-Options": "Missing X-Frame-Options header",
            "X-XSS-Protection": "Missing X-XSS-Protection header",
            "Referrer-Policy": "Missing Referrer-Policy header"
        }
        
        for header, issue in security_headers.items():
            if header not in response.headers:
                result["securityIssues"].append({
                    "name": issue,
                    "severity": "Medium" if header in ["Strict-Transport-Security", "Content-Security-Policy"] else "Low",
                    "status": "Vulnerable",
                    "details": f"The {header} header is not set, which may expose the site to various attacks"
                })
    except Exception as e:
        logger.debug(f"Error checking security headers: {e}")
    
    # 6. Check for information disclosure
    info_disclosure_paths = [
        "phpinfo.php",
        "info.php",
        "test.php",
        "server-status",
        "server-info",
        ".env",
        "config.php",
        "wp-config.php",
        "config.js",
        "config.json"
    ]
    
    for path in info_disclosure_paths:
        try:
            test_url = f"{normalized_url.rstrip('/')}/{path}"
            response = session.get(test_url, timeout=5, verify=False)
            
            if response.status_code == 200:
                # Check for sensitive information
                sensitive_patterns = [
                    "password", "secret", "token", "api_key", "apikey", "connection string",
                    "database", "db_", "phpinfo", "php info", "php version", "server info"
                ]
                
                for pattern in sensitive_patterns:
                    if pattern in response.text.lower():
                        result["vulnerabilities"].append({
                            "name": "Information Disclosure",
                            "severity": "High",
                            "description": f"Application exposes sensitive information through {path}",
                            "remediation": "Remove or restrict access to files containing sensitive information"
                        })
                        break
        except Exception as e:
            logger.debug(f"Error checking information disclosure: {e}")
    
    # 7. Check for directory listing
    try:
        test_dirs = ["images", "uploads", "files", "backup", "includes", "js", "css"]
        
        for dir_name in test_dirs:
            test_url = f"{normalized_url.rstrip('/')}/{dir_name}/"
            response = session.get(test_url, timeout=5, verify=False)
            
            if response.status_code == 200:
                # Check for directory listing
                dir_listing_indicators = [
                    "Index of /", "Directory Listing", "Parent Directory",
                    "<title>Index of", "<h1>Index of"
                ]
                
                for indicator in dir_listing_indicators:
                    if indicator in response.text:
                        result["vulnerabilities"].append({
                            "name": "Directory Listing",
                            "severity": "Medium",
                            "description": f"Directory listing is enabled for {dir_name}/",
                            "remediation": "Disable directory listing in web server configuration"
                        })
                        break
        
    except Exception as e:
        logger.debug(f"Error checking directory listing: {e}")
    
    # 8. Check for outdated software and CVEs
    # First check Shodan if available
    if shodan_api:
        try:
            # Get IP address
            ip = socket.gethostbyname(domain)
            
            # Query Shodan
            host_info = shodan_api.host(ip)
            
            # Check for vulnerabilities
            for item in host_info.get('data', []):
                # Check for CVEs
                for cve_id in item.get('vulns', {}):
                    cve_info = item['vulns'][cve_id]
                    
                    # Determine severity
                    severity = "Medium"
                    if 'cvss' in cve_info:
                        cvss = float(cve_info['cvss'])
                        if cvss >= 9.0:
                            severity = "Critical"
                        elif cvss >= 7.0:
                            severity = "High"
                        elif cvss >= 4.0:
                            severity = "Medium"
                        else:
                            severity = "Low"
                    
                    result["cves"].append({
                        "id": cve_id,
                        "severity": severity,
                        "description": cve_info.get('summary', 'No description available'),
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    })
        except Exception as e:
            logger.error(f"Error checking Shodan for vulnerabilities: {e}")
    
    # Now use the NVD API for more comprehensive CVE detection
    try:
        # Use technology stack info to find CVEs
        if 'tech_stack' in scan_result.get('modules', {}):
            tech_data = scan_result['modules']['tech_stack']
            
            # Check for web server vulnerabilities
            if tech_data.get('webServer'):
                web_server = tech_data.get('webServer').split('/')[0].lower()
                version = None
                
                # Try to extract version from web server string
                if '/' in tech_data.get('webServer'):
                    version = tech_data.get('webServer').split('/')[1].split(' ')[0]
                
                cves = nvd.get_cves_for_software(web_server, version)
                formatted_cves = nvd.format_cves(cves)
                
                # Add unique CVEs
                existing_cve_ids = [c.get('id') for c in result["cves"]]
                for cve in formatted_cves:
                    if cve.get('id') not in existing_cve_ids:
                        result["cves"].append(cve)
                        existing_cve_ids.append(cve.get('id'))
            
            # Check for CMS vulnerabilities
            if tech_data.get('cms'):
                cms = tech_data.get('cms').lower()
                cves = nvd.get_cves_for_software(cms)
                formatted_cves = nvd.format_cves(cves)
                
                # Add unique CVEs
                existing_cve_ids = [c.get('id') for c in result["cves"]]
                for cve in formatted_cves:
                    if cve.get('id') not in existing_cve_ids:
                        result["cves"].append(cve)
                        existing_cve_ids.append(cve.get('id'))
            
            # Check for framework vulnerabilities
            for framework in tech_data.get('frameworks', []):
                cves = nvd.get_cves_for_software(framework.lower())
                formatted_cves = nvd.format_cves(cves)
                
                # Add unique CVEs
                existing_cve_ids = [c.get('id') for c in result["cves"]]
                for cve in formatted_cves:
                    if cve.get('id') not in existing_cve_ids:
                        result["cves"].append(cve)
                        existing_cve_ids.append(cve.get('id'))
            
            # Check versions explicitly
            for software, version in tech_data.get('versions', {}).items():
                cves = nvd.get_cves_for_software(software.lower(), version)
                formatted_cves = nvd.format_cves(cves)
                
                # Add unique CVEs
                existing_cve_ids = [c.get('id') for c in result["cves"]]
                for cve in formatted_cves:
                    if cve.get('id') not in existing_cve_ids:
                        result["cves"].append(cve)
                        existing_cve_ids.append(cve.get('id'))
        
        # Limit total CVEs to 20 to avoid overwhelming the report
        if len(result["cves"]) > 20:
            # Sort by severity (Critical first)
            result["cves"] = sorted(
                result["cves"], 
                key=lambda x: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(x.get('severity', "Low"), 4)
            )[:20]
            
    except Exception as e:
        logger.error(f"Error checking NVD for vulnerabilities: {e}")
    
    # Calculate risk score based on findings
    critical_count = len([v for v in result["vulnerabilities"] if v["severity"] == "Critical"])
    high_count = len([v for v in result["vulnerabilities"] if v["severity"] == "High"])
    medium_count = len([v for v in result["vulnerabilities"] if v["severity"] == "Medium"])
    low_count = len([v for v in result["vulnerabilities"] if v["severity"] == "Low"])
    
    cve_critical_count = len([c for c in result["cves"] if c["severity"] == "Critical"])
    cve_high_count = len([c for c in result["cves"] if c["severity"] == "High"])
    
    if critical_count > 0 or cve_critical_count > 0:
        result["riskScore"] = "Critical"
    elif high_count > 0 or cve_high_count > 0:
        result["riskScore"] = "High"
    elif medium_count > 0:
        result["riskScore"] = "Medium"
    elif low_count > 0:
        result["riskScore"] = "Low"
    else:
        result["riskScore"] = "Low"
    
    return result

async def scan_email_credentials(domain: str) -> dict:
    """Scan for email addresses and credentials associated with the domain."""
    result = {
        "emails": [],
        "pastBreaches": [],
        "exposedData": {},
        "articles": [],
        "credentials": []
    }
    
    # Create a session for requests
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    })
    
    # 1. Find email addresses associated with the domain
    try:
        # Try to find emails on the website
        url = f"http://{domain}"
        response = session.get(url, timeout=10, verify=False)
        
        # Extract emails using regex
        email_pattern = r'[a-zA-Z0-9._%+-]+@{0}'.format(domain.replace('.', r'\.'))
        emails = re.findall(email_pattern, response.text)
        
        # Add unique emails to the result
        for email in set(emails):
            if email not in result["emails"]:
                result["emails"].append(email)
        
        # Check common email patterns
        common_prefixes = ["info", "contact", "admin", "support", "sales", "help", "webmaster", "security"]
        for prefix in common_prefixes:
            result["emails"].append(f"{prefix}@{domain}")
    
    except Exception as e:
        logger.error(f"Error finding emails: {e}")
    
    # 2. Check for past breaches (simulated)
    # In a real implementation, this would use a service like Have I Been Pwned or a breach database
    try:
        # Simulate breach data
        if settings.VT_API_KEY:
            # Use VirusTotal to check domain reputation
            vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {"x-apikey": settings.VT_API_KEY}
            
            response = requests.get(vt_url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                # Check if domain has been associated with malicious activity
                malicious_count = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                
                if malicious_count > 0:
                    result["pastBreaches"].append({
                        "name": "VirusTotal Alert",
                        "date": datetime.now().strftime("%Y-%m-%d"),
                        "description": f"Domain has been flagged by {malicious_count} security vendors on VirusTotal"
                    })
    
    except Exception as e:
        logger.error(f"Error checking breaches: {e}")
    
    # 3. Check for exposed data types (simulated)
    # In a real implementation, this would use a service like Have I Been Pwned or a breach database
    try:
        # Simulate exposed data types
        if len(result["emails"]) > 0:
            result["exposedData"] = {
                "Email Addresses": len(result["emails"]),
                "Passwords": 0,
                "Phone Numbers": 0,
                "Names": 0,
                "Addresses": 0
            }
    
    except Exception as e:
        logger.error(f"Error checking exposed data: {e}")
    
    # 4. Find related security articles (simulated)
    # In a real implementation, this would use a news API or security blog search
    try:
        # Simulate related articles
        result["articles"] = [
            {
                "title": f"Security Best Practices for {domain}",
                "url": f"https://example.com/security/{domain}",
                "date": datetime.now().strftime("%Y-%m-%d")
            }
        ]
    
    except Exception as e:
        logger.error(f"Error finding articles: {e}")
    
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
        "use_llm": scan_request.use_llm and settings.ENABLE_LLM,  # Respect both user preference and global setting
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
        "use_llm": scan_result["use_llm"],
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
        logger.error(f"Error during scan: {e}")
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
    training_id = await save_training_data(training_data)
    
    return {
        "status": "success", 
        "message": "Feedback submitted successfully",
        "training_id": training_id
    }

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
    
    # Check if LLM is enabled (both globally and for this request)
    use_llm = analysis_request.use_llm and settings.ENABLE_LLM
    
    if not use_llm:
        return {
            "analysis": "LLM analysis is disabled. Please enable it in settings or for this specific request."
        }
    
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
            model_name = analysis_request.model or settings.DEFAULT_LLM_MODEL
            
            # Check if model exists, if not, try to pull it
            try:
                models = ollama.list_models()
                model_exists = any(model.get('name') == model_name for model in models)
                
                if not model_exists:
                    logger.info(f"Model {model_name} not found, attempting to pull...")
                    ollama.pull_model(model_name)
            except Exception as e:
                logger.error(f"Error checking/pulling model: {e}")
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
            logger.error(f"Error with Ollama: {e}")
            # Try with OpenAI if available
            if settings.OPENAI_API_KEY:
                try:
                    from openai import OpenAI
                    client = OpenAI(api_key=settings.OPENAI_API_KEY)
                    
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
                    logger.error(f"Error with OpenAI fallback: {openai_error}")
                    raise HTTPException(status_code=500, detail=f"Failed to generate analysis: {str(e)}")
            else:
                raise HTTPException(status_code=500, detail=f"Failed to generate analysis: {str(e)}")
    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        
        # Return a generic error message
        return {
            "analysis": f"Analysis failed due to an error. Please try again later or contact support. Error: {str(e)}"
        }

@app.post("/api/train", response_model=dict)
async def train_model(request: ModelTrainRequest, admin: dict = Depends(verify_admin)):
    """Train a custom LLM model with collected feedback data."""
    try:
        # Verify the verification code (this would be sent to admin's email/phone in a real system)
        # For demo purposes, we'll just check if it's not empty
        if not request.verification_code:
            raise HTTPException(status_code=400, detail="Verification code is required")
        
        # Load training data
        training_data = []
        if request.training_data_ids:
            for data_id in request.training_data_ids:
                data = await get_training_data(data_id)
                if data:
                    training_data.append(data)
        else:
            training_data = await get_training_data()
        
        if not training_data:
            return {"status": "error", "message": "No training data available"}
        
        # Create Modelfile content
        system_prompt = request.system_prompt or """
        You are an advanced cybersecurity AI assistant specializing in threat detection, 
        vulnerability assessment, and security analysis. You provide detailed, technical 
        responses about cybersecurity topics, focusing on actionable insights and 
        practical recommendations. You maintain a serious, professional tone appropriate 
        for security professionals.
        """
        
        modelfile_content = f"""
        FROM {request.base_model}
        SYSTEM {system_prompt}
        """
        
        # In a real implementation, this would call Ollama's API to create and train the model
        # For now, we'll just simulate the training process
        
        # Save model information
        model_info = {
            "name": request.name,
            "description": request.description,
            "base_model": request.base_model,
            "system_prompt": system_prompt,
            "training_data_count": len(training_data),
            "created_at": datetime.now().isoformat(),
            "created_by": admin["username"],
            "status": "training"
        }
        
        await save_model_info(model_info)
        
        # In a real implementation, you would start a background task to train the model
        # For now, we'll just update the status after a delay to simulate training
        async def update_model_status():
            await asyncio.sleep(5)  # Simulate training time
            model_info["status"] = "active"
            await save_model_info(model_info)
        
        asyncio.create_task(update_model_status())
        
        return {
            "status": "success",
            "message": f"Model training initiated with {len(training_data)} data points",
            "model_name": request.name
        }
    except Exception as e:
        logger.error(f"Error training model: {e}")
        return {"status": "error", "message": str(e)}

@app.get("/api/models", response_model=List[dict])
async def list_models():
    """List all models."""
    models = await get_models()
    return models

@app.get("/api/settings", response_model=dict)
async def get_settings(admin: dict = Depends(verify_admin)):
    """Get application settings."""
    return {
        "enable_llm": settings.ENABLE_LLM,
        "default_llm_model": settings.DEFAULT_LLM_MODEL,
    }

@app.post("/api/settings", response_model=dict)
async def update_settings(
    enable_llm: bool = Form(...),
    default_llm_model: str = Form(...),
    admin: dict = Depends(verify_admin)
):
    """Update application settings."""
    # In a real implementation, this would update the .env file or database
    # For now, we'll just update the settings in memory
    settings.ENABLE_LLM = enable_llm
    settings.DEFAULT_LLM_MODEL = default_llm_model
    
    return {
        "status": "success",
        "message": "Settings updated successfully",
        "settings": {
            "enable_llm": settings.ENABLE_LLM,
            "default_llm_model": settings.DEFAULT_LLM_MODEL,
        }
    }

@app.post("/api/users", response_model=dict)
async def create_user(user: UserCreate, admin: dict = Depends(verify_admin)):
    """Create a new user."""
    try:
        with open(USERS_DB, "r") as f:
            users = json.load(f)
        
        # Check if username already exists
        if any(u["username"] == user.username for u in users):
            raise HTTPException(status_code=400, detail="Username already exists")
        
        # Create new user
        new_user = {
            "username": user.username,
            "password_hash": hashlib.sha256(user.password.encode()).hexdigest(),
            "role": user.role,
            "created_at": datetime.now().isoformat(),
            "created_by": admin["username"]
        }
        
        users.append(new_user)
        
        with open(USERS_DB, "w") as f:
            json.dump(users, f, indent=2)
        
        return {"status": "success", "message": "User created successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create user: {str(e)}")

@app.post("/api/login", response_model=dict)
async def login(user: UserLogin):
    """Login and get API key."""
    try:
        with open(USERS_DB, "r") as f:
            users = json.load(f)
        
        user_data = next((u for u in users if u["username"] == user.username), None)
        
        if not user_data or user_data["password_hash"] != hashlib.sha256(user.password.encode()).hexdigest():
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # In a real implementation, this would generate a JWT token
        # For now, we'll just return the user's role
        return {
            "status": "success",
            "username": user.username,
            "role": user_data["role"],
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during login: {e}")
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")

@app.get("/api/verification-code", response_model=dict)
async def get_verification_code(admin: dict = Depends(verify_admin)):
    """Generate a verification code for sensitive operations."""
    code = generate_verification_code()
    
    # In a real implementation, this would send the code to the admin's email/phone
    # For now, we'll just return it
    return {
        "code": code,
        "expires_in": "10 minutes"
    }

@app.get("/health", response_model=dict)
async def health_check():
    """Health check endpoint."""
    return {
        "status": "ok",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/report/{scan_id}", response_model=dict)
async def generate_report(scan_id: str, include_modules: Optional[str] = None):
    """Generate a PDF report for a scan."""
    scan_result = await get_scan_by_id(scan_id)
    if not scan_result:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Parse include_modules query parameter if provided
    modules_list = None
    if include_modules:
        modules_list = include_modules.split(',')
    
    try:
        # Generate the PDF report
        report_path = pdf_generator.generate_report(scan_result, modules_list)
        
        # Extract filename from path
        filename = os.path.basename(report_path)
        
        # Return the report path and filename
        return {
            "status": "success",
            "message": "Report generated successfully",
            "filename": filename,
            "path": report_path
        }
        
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")

# Add a direct file download endpoint
@app.get("/download/report/{filename}")
async def download_report(filename: str):
    """Download a generated report."""
    reports_dir = os.path.join(settings.DATA_DIR, "reports")
    file_path = os.path.join(reports_dir, filename)
    
    # Add debug logging
    logger.info(f"Attempting to download report: {filename}")
    logger.info(f"Looking for file at path: {file_path}")
    
    if not os.path.exists(file_path):
        # List available files for debugging
        try:
            available_files = os.listdir(reports_dir)
            logger.info(f"Available files in reports directory: {available_files}")
        except Exception as e:
            logger.error(f"Error listing report files: {e}")
        
        # Check if the reports directory exists
        if not os.path.exists(reports_dir):
            logger.error(f"Reports directory does not exist: {reports_dir}")
            raise HTTPException(status_code=500, detail=f"Reports directory not found: {reports_dir}")
        
        # Check if we have permission to read the directory
        try:
            os.access(reports_dir, os.R_OK)
            logger.info(f"Reports directory is readable")
        except Exception as e:
            logger.error(f"Cannot read reports directory: {e}")
        
        raise HTTPException(status_code=404, detail=f"Report not found: {filename}")
    
    logger.info(f"Found report file, serving: {file_path}")
    
    # Check if we have permission to read the file
    if not os.access(file_path, os.R_OK):
        logger.error(f"Cannot read file: {file_path}")
        raise HTTPException(status_code=500, detail=f"Cannot read file: {filename}")
    
    return FileResponse(
        file_path, 
        filename=filename,
        media_type="application/pdf"
    )

# Add a file listing endpoint for debugging
@app.get("/api/reports/list", response_model=dict)
async def list_reports():
    """List all available reports."""
    try:
        reports_dir = os.path.join(settings.DATA_DIR, "reports")
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir, exist_ok=True)
            
        files = os.listdir(reports_dir)
        
        # Get file details
        file_details = []
        for filename in files:
            if filename.endswith('.pdf'):
                file_path = os.path.join(reports_dir, filename)
                file_details.append({
                    "filename": filename,
                    "path": file_path,
                    "size": os.path.getsize(file_path),
                    "created": datetime.fromtimestamp(os.path.getctime(file_path)).isoformat()
                })
        
        return {
            "reports_dir": reports_dir,
            "files": file_details,
            "count": len(file_details)
        }
    except Exception as e:
        logger.error(f"Error listing reports: {e}")
        return {
            "error": str(e),
            "reports_dir": os.path.join(settings.DATA_DIR, "reports"),
            "files": [],
            "count": 0
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.HOST, port=settings.PORT)
