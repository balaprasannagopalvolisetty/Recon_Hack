import os
import tempfile
from datetime import datetime
from typing import Dict, Any, List, Optional
import logging
import json
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.units import inch
import base64
import io

logger = logging.getLogger("recon-ai.pdf")

# Set up styles
styles = getSampleStyleSheet()
title_style = styles["Title"]
heading1_style = styles["Heading1"]
heading2_style = styles["Heading2"]
normal_style = styles["Normal"]

# Custom styles
header_style = ParagraphStyle(
    "Header", 
    parent=styles["Heading2"],
    textColor=colors.white,
    backColor=colors.darkgreen,
    borderPadding=5,
    alignment=1  # center
)

critical_style = ParagraphStyle(
    "Critical", 
    parent=styles["Normal"],
    textColor=colors.white,
    backColor=colors.red,
    borderPadding=2,
)

high_style = ParagraphStyle(
    "High", 
    parent=styles["Normal"],
    textColor=colors.white,
    backColor=colors.orangered,
    borderPadding=2,
)

medium_style = ParagraphStyle(
    "Medium", 
    parent=styles["Normal"],
    textColor=colors.white,
    backColor=colors.orange,
    borderPadding=2,
)

low_style = ParagraphStyle(
    "Low", 
    parent=styles["Normal"],
    textColor=colors.white,
    backColor=colors.green,
    borderPadding=2,
)

class PDFReportGenerator:
    """Generate PDF reports from scan results"""
    
    def __init__(self, output_dir: str = "data/reports"):
        # Convert to absolute path if it's relative
        if not os.path.isabs(output_dir):
            # Use the directory where the script is located as the base
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.output_dir = os.path.join(base_dir, output_dir)
        else:
            self.output_dir = output_dir
            
        # Ensure the output directory exists
        os.makedirs(self.output_dir, exist_ok=True)
        logger.info(f"PDF reports will be saved to: {self.output_dir}")
    
    def generate_report(self, scan_result: Dict[str, Any], include_modules: Optional[List[str]] = None) -> str:
        """Generate a PDF report from scan results"""
        try:
            scan_id = scan_result.get("scan_id", "unknown")
            domain = scan_result.get("domain", "unknown")
            timestamp = scan_result.get("timestamp", datetime.now().isoformat())
            
            # Convert ISO timestamp to readable format
            try:
                dt = datetime.fromisoformat(timestamp)
                formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                formatted_time = timestamp
            
            # Create a filename for the report
            filename = f"{domain.replace('.', '_')}_{scan_id[-8:]}.pdf"
            filepath = os.path.join(self.output_dir, filename)
            
            # Create a document
            doc = SimpleDocTemplate(filepath, pagesize=letter)
            elements = []
            
            # Add title
            elements.append(Paragraph(f"Security Reconnaissance Report", title_style))
            elements.append(Spacer(1, 0.25*inch))
            
            # Add scan information
            elements.append(Paragraph(f"Target: {domain}", heading1_style))
            elements.append(Paragraph(f"Scan ID: {scan_id}", normal_style))
            elements.append(Paragraph(f"Date: {formatted_time}", normal_style))
            elements.append(Paragraph(f"Status: {scan_result.get('status', 'unknown')}", normal_style))
            elements.append(Spacer(1, 0.25*inch))
            
            # Add executive summary
            elements.append(Paragraph("Executive Summary", heading1_style))
            
            # Count findings
            modules = scan_result.get("modules", {})
            
            risk_score = modules.get("vulnerabilities", {}).get("riskScore", "Unknown")
            
            vulnerabilities = modules.get("vulnerabilities", {}).get("vulnerabilities", [])
            cves = modules.get("vulnerabilities", {}).get("cves", [])
            security_issues = modules.get("vulnerabilities", {}).get("securityIssues", [])
            misconfigurations = modules.get("cloud_security", {}).get("misconfigurations", []) + \
                               modules.get("vulnerabilities", {}).get("misconfigurations", [])
            
            critical_count = 0
            high_count = 0
            medium_count = 0
            low_count = 0
            
            # Count by severity across all types of findings
            for item in vulnerabilities + cves + security_issues + misconfigurations:
                severity = item.get("severity", "").upper()
                if severity in ["CRITICAL"]:
                    critical_count += 1
                elif severity in ["HIGH"]:
                    high_count += 1
                elif severity in ["MEDIUM"]:
                    medium_count += 1
                elif severity in ["LOW"]:
                    low_count += 1
            
            # Add summary table
            summary_data = [
                ['Risk Score', 'Critical', 'High', 'Medium', 'Low', 'Total'],
                [risk_score, str(critical_count), str(high_count), str(medium_count), str(low_count), 
                 str(critical_count + high_count + medium_count + low_count)]
            ]
            
            summary_table = Table(summary_data, colWidths=[1.0*inch] * 6)
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (0, 1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('SPAN', (0, 1), (0, 1)),
                # Color the risk score cell based on value
                ('BACKGROUND', (0, 1), (0, 1), 
                 colors.red if risk_score == "Critical" else 
                 colors.orangered if risk_score == "High" else 
                 colors.orange if risk_score == "Medium" else 
                 colors.green),
                ('TEXTCOLOR', (0, 1), (0, 1), colors.white),
            ]))
            
            elements.append(summary_table)
            elements.append(Spacer(1, 0.25*inch))
            
            # Process the requested modules or all available modules
            available_modules = modules.keys()
            modules_to_include = include_modules or available_modules
            
            for module_name in modules_to_include:
                # Skip modules not in scan results
                if module_name not in modules:
                    continue
                    
                module_data = modules[module_name]
                
                # Format module name for display
                display_name = module_name.replace("_", " ").title()
                elements.append(Paragraph(display_name, heading1_style))
                
                # Module-specific content
                if module_name == "domain_dns":
                    self._add_domain_dns_section(elements, module_data)
                elif module_name == "tech_stack":
                    self._add_tech_stack_section(elements, module_data)
                elif module_name == "ports_network":
                    self._add_ports_network_section(elements, module_data)
                elif module_name == "vulnerabilities":
                    self._add_vulnerabilities_section(elements, module_data)
                elif module_name == "cloud_security":
                    self._add_cloud_security_section(elements, module_data)
                elif module_name == "files_directories":
                    self._add_files_directories_section(elements, module_data)
                elif module_name == "api_endpoints":
                    self._add_api_endpoints_section(elements, module_data)
                elif module_name == "js_analysis":
                    self._add_js_analysis_section(elements, module_data)
                elif module_name == "email_credentials":
                    self._add_email_credentials_section(elements, module_data)
                
                elements.append(Spacer(1, 0.25*inch))
            
            # Add recommendations section
            elements.append(Paragraph("Recommendations", heading1_style))
            
            # Generate recommendations based on findings
            recommendations = self._generate_recommendations(modules)
            
            for rec in recommendations:
                elements.append(Paragraph(f"• {rec}", normal_style))
            
            # Add footer
            elements.append(Spacer(1, 0.5*inch))
            elements.append(Paragraph("Generated by ReconAI - Advanced Web Reconnaissance Tool", 
                             ParagraphStyle("Footer", parent=normal_style, fontSize=8, textColor=colors.grey)))
            elements.append(Paragraph(f"Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                             ParagraphStyle("Footer", parent=normal_style, fontSize=8, textColor=colors.grey)))
            
            # Build the PDF
            doc.build(elements)
            
            return filepath
            
        except Exception as e:
            logger.error(f"Error generating PDF report: {e}")
            raise
    
    def _add_domain_dns_section(self, elements, data):
        """Add domain and DNS information to the report"""
        elements.append(Paragraph("Domain Information", heading2_style))
        
        # Basic domain info
        domain_data = [
            ['Domain', data.get('domain', 'Unknown')],
            ['IP Address', data.get('ip', 'Unknown')],
            ['Location', data.get('location', 'Unknown')],
            ['Hosting', data.get('hosting', 'Unknown')],
        ]
        
        domain_table = Table(domain_data, colWidths=[1.5*inch, 4*inch])
        domain_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        
        elements.append(domain_table)
        elements.append(Spacer(1, 0.15*inch))
        
        # WHOIS info
        if data.get('whois'):
            elements.append(Paragraph("WHOIS Information", heading2_style))
            
            whois_data = [
                ['Registrar', data.get('whois', {}).get('registrar', 'Unknown')],
                ['Created', data.get('whois', {}).get('created', 'Unknown')],
                ['Updated', data.get('whois', {}).get('updated', 'Unknown')],
                ['Expires', data.get('whois', {}).get('expires', 'Unknown')],
            ]
            
            whois_table = Table(whois_data, colWidths=[1.5*inch, 4*inch])
            whois_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            
            elements.append(whois_table)
            elements.append(Spacer(1, 0.15*inch))
        
        # DNS Records
        if data.get('dns'):
            elements.append(Paragraph("DNS Records", heading2_style))
            
            for record_type, records in data.get('dns', {}).items():
                if not records:
                    continue
                
                elements.append(Paragraph(f"{record_type} Records", 
                                ParagraphStyle("RecordType", parent=normal_style, fontName="Helvetica-Bold")))
                
                for record in records:
                    elements.append(Paragraph(record, 
                                   ParagraphStyle("Record", parent=normal_style, fontName="Courier")))
                
                elements.append(Spacer(1, 0.1*inch))
        
        # SSL Information
        if data.get('ssl'):
            elements.append(Paragraph("SSL/TLS Information", heading2_style))
            
            ssl_data = [
                ['Issuer', data.get('ssl', {}).get('issuer', 'Unknown')],
                ['Subject', data.get('ssl', {}).get('subject', 'Unknown')],
                ['Valid Until', data.get('ssl', {}).get('validUntil', 'Unknown')],
                ['Grade', data.get('ssl', {}).get('grade', 'Unknown')],
            ]
            
            ssl_table = Table(ssl_data, colWidths=[1.5*inch, 4*inch])
            ssl_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            
            elements.append(ssl_table)
    
    def _add_tech_stack_section(self, elements, data):
        """Add technology stack information to the report"""
        # Server Information
        elements.append(Paragraph("Server Information", heading2_style))
        
        server_data = [
            ['Web Server', data.get('webServer', 'Unknown')],
            ['CMS', data.get('cms', 'None detected')],
            ['Database', data.get('database', 'None detected')],
            ['Operating System', data.get('os', 'Unknown')],
        ]
        
        server_table = Table(server_data, colWidths=[1.5*inch, 4*inch])
        server_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        
        elements.append(server_table)
        elements.append(Spacer(1, 0.15*inch))
        
        # Programming Languages
        if data.get('languages'):
            elements.append(Paragraph("Programming Languages", heading2_style))
            languages = ', '.join(data.get('languages', []))
            elements.append(Paragraph(languages, normal_style))
            elements.append(Spacer(1, 0.15*inch))
        
        # Frameworks
        if data.get('frameworks'):
            elements.append(Paragraph("Frameworks", heading2_style))
            frameworks = ', '.join(data.get('frameworks', []))
            elements.append(Paragraph(frameworks, normal_style))
            elements.append(Spacer(1, 0.15*inch))
        
        # Libraries
        if data.get('libraries'):
            elements.append(Paragraph("Libraries", heading2_style))
            libraries = ', '.join(data.get('libraries', []))
            elements.append(Paragraph(libraries, normal_style))
            elements.append(Spacer(1, 0.15*inch))
        
        # Software Versions
        if data.get('versions') and len(data.get('versions', {})) > 0:
            elements.append(Paragraph("Software Versions", heading2_style))
            
            versions_data = []
            for software, version in data.get('versions', {}).items():
                versions_data.append([software, version])
            
            versions_table = Table(versions_data, colWidths=[2*inch, 3.5*inch])
            versions_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            
            elements.append(versions_table)
    
    def _add_ports_network_section(self, elements, data):
        """Add ports and network information to the report"""
        # Open Ports
        elements.append(Paragraph("Open Ports", heading2_style))
        
        if data.get('openPorts') and len(data.get('openPorts', [])) > 0:
            ports_data = [['Port', 'Service']]
            
            for port in data.get('openPorts', []):
                service = data.get('services', {}).get(str(port), 'Unknown')
                ports_data.append([str(port), service])
            
            ports_table = Table(ports_data, colWidths=[1*inch, 4.5*inch])
            ports_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ]))
            
            elements.append(ports_table)
        else:
            elements.append(Paragraph("No open ports detected", normal_style))
        
        elements.append(Spacer(1, 0.15*inch))
        
        # Firewalls & WAFs
        if data.get('firewalls') and len(data.get('firewalls', [])) > 0:
            elements.append(Paragraph("Firewalls & WAFs", heading2_style))
            firewalls = ', '.join(data.get('firewalls', []))
            elements.append(Paragraph(firewalls, normal_style))
            elements.append(Spacer(1, 0.15*inch))
    
    def _add_vulnerabilities_section(self, elements, data):
        """Add vulnerability information to the report"""
        # Security Overview
        elements.append(Paragraph("Security Overview", heading2_style))
        
        overview_data = [
            ['Risk Score', data.get('riskScore', 'Unknown')],
            ['Vulnerabilities', str(len(data.get('vulnerabilities', [])))],
            ['CVEs', str(len(data.get('cves', [])))],
        ]
        
        overview_table = Table(overview_data, colWidths=[1.5*inch, 4*inch])
        overview_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            # Color risk score based on value
            ('BACKGROUND', (1, 0), (1, 0), 
             colors.red if data.get('riskScore') == "Critical" else 
             colors.orangered if data.get('riskScore') == "High" else 
             colors.orange if data.get('riskScore') == "Medium" else 
             colors.green),
            ('TEXTCOLOR', (1, 0), (1, 0), colors.white),
        ]))
        
        elements.append(overview_table)
        elements.append(Spacer(1, 0.15*inch))
        
        # Vulnerabilities
        if data.get('vulnerabilities') and len(data.get('vulnerabilities', [])) > 0:
            elements.append(Paragraph("Vulnerabilities", heading2_style))
            
            vuln_data = [['Name', 'Severity', 'Description', 'Remediation']]
            
            for vuln in data.get('vulnerabilities', []):
                vuln_data.append([
                    vuln.get('name', 'Unknown'),
                    vuln.get('severity', 'Unknown'),
                    vuln.get('description', 'No description'),
                    vuln.get('remediation', 'No remediation')
                ])
            
            vuln_table = Table(vuln_data, colWidths=[1*inch, 0.8*inch, 2*inch, 1.7*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            
            # Color severity cells based on value
            for i, row in enumerate(vuln_data[1:], 1):
                severity = row[1]
                if severity == "Critical":
                    vuln_table.setStyle(TableStyle([('BACKGROUND', (1, i), (1, i), colors.red),
                                                ('TEXTCOLOR', (1, i), (1, i), colors.white)]))
                elif severity == "High":
                    vuln_table.setStyle(TableStyle([('BACKGROUND', (1, i), (1, i), colors.orangered),
                                                ('TEXTCOLOR', (1, i), (1, i), colors.white)]))
                elif severity == "Medium":
                    vuln_table.setStyle(TableStyle([('BACKGROUND', (1, i), (1, i), colors.orange),
                                                ('TEXTCOLOR', (1, i), (1, i), colors.white)]))
                elif severity == "Low":
                    vuln_table.setStyle(TableStyle([('BACKGROUND', (1, i), (1, i), colors.green),
                                                ('TEXTCOLOR', (1, i), (1, i), colors.white)]))
            
            elements.append(vuln_table)
            elements.append(Spacer(1, 0.15*inch))
        
        # CVEs
        if data.get('cves') and len(data.get('cves', [])) > 0:
            elements.append(Paragraph("CVEs", heading2_style))
            
            cve_data = [['ID', 'Severity', 'Description']]
            
            for cve in data.get('cves', []):
                cve_data.append([
                    cve.get('id', 'Unknown'),
                    cve.get('severity', 'Unknown'),
                    cve.get('description', 'No description')
                ])
            
            cve_table = Table(cve_data, colWidths=[1.2*inch, 0.8*inch, 3.5*inch])
            cve_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            
            # Color severity cells based on value
            for i, row in enumerate(cve_data[1:], 1):
                severity = row[1].upper()
                if severity == "CRITICAL":
                    cve_table.setStyle(TableStyle([('BACKGROUND', (1, i), (1, i), colors.red),
                                               ('TEXTCOLOR', (1, i), (1, i), colors.white)]))
                elif severity == "HIGH":
                    cve_table.setStyle(TableStyle([('BACKGROUND', (1, i), (1, i), colors.orangered),
                                               ('TEXTCOLOR', (1, i), (1, i), colors.white)]))
                elif severity == "MEDIUM":
                    cve_table.setStyle(TableStyle([('BACKGROUND', (1, i), (1, i), colors.orange),
                                               ('TEXTCOLOR', (1, i), (1, i), colors.white)]))
                elif severity == "LOW":
                    cve_table.setStyle(TableStyle([('BACKGROUND', (1, i), (1, i), colors.green),
                                               ('TEXTCOLOR', (1, i), (1, i), colors.white)]))
            
            elements.append(cve_table)
            elements.append(Spacer(1, 0.15*inch))
    
    def _add_cloud_security_section(self, elements, data):
        """Add cloud security information to the report"""
        # Cloud Resources Summary
        elements.append(Paragraph("Cloud Resources", heading2_style))
        
        resources_data = [
            ['S3 Buckets', str(len(data.get('s3Buckets', [])))],
            ['Azure Blobs', str(len(data.get('azureBlobs', [])))],
            ['Google Storage', str(len(data.get('googleStorage', [])))],
            ['Firebase Apps', str(len(data.get('firebaseApps', [])))],
            ['CloudFront', str(len(data.get('cloudfront', [])))],
            ['Publicly Exposed', 'Yes' if data.get('exposed') else 'No'],
        ]
        
        resources_table = Table(resources_data, colWidths=[1.5*inch, 4*inch])
        resources_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            # Color exposed cell based on value
            ('BACKGROUND', (1, 5), (1, 5), colors.red if data.get('exposed') else colors.green),
            ('TEXTCOLOR', (1, 5), (1, 5), colors.white),
        ]))
        
        elements.append(resources_table)
        elements.append(Spacer(1, 0.15*inch))
        
        # Cloud Misconfigurations
        if data.get('misconfigurations') and len(data.get('misconfigurations', [])) > 0:
            elements.append(Paragraph("Cloud Misconfigurations", heading2_style))
            
            misconfig_data = [['Type', 'Service', 'Severity', 'Description']]
            
            for misconfig in data.get('misconfigurations', []):
                misconfig_data.append([
                    misconfig.get('type', 'Unknown'),
                    misconfig.get('service', 'Unknown'),
                    misconfig.get('severity', 'Unknown'),
                    misconfig.get('description', 'No description')
                ])
            
            misconfig_table = Table(misconfig_data, colWidths=[1.2*inch, 1*inch, 0.8*inch, 2.5*inch])
            misconfig_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            
            # Color severity cells based on value
            for i, row in enumerate(misconfig_data[1:], 1):
                severity = row[2]
                if severity == "Critical":
                    misconfig_table.setStyle(TableStyle([('BACKGROUND', (2, i), (2, i), colors.red),
                                                      ('TEXTCOLOR', (2, i), (2, i), colors.white)]))
                elif severity == "High":
                    misconfig_table.setStyle(TableStyle([('BACKGROUND', (2, i), (2, i), colors.orangered),
                                                      ('TEXTCOLOR', (2, i), (2, i), colors.white)]))
                elif severity == "Medium":
                    misconfig_table.setStyle(TableStyle([('BACKGROUND', (2, i), (2, i), colors.orange),
                                                      ('TEXTCOLOR', (2, i), (2, i), colors.white)]))
                elif severity == "Low":
                    misconfig_table.setStyle(TableStyle([('BACKGROUND', (2, i), (2, i), colors.green),
                                                      ('TEXTCOLOR', (2, i), (2, i), colors.white)]))
            
            elements.append(misconfig_table)
    
    def _add_files_directories_section(self, elements, data):
        """Add files and directories information to the report"""
        # Sensitive Files
        if data.get('sensitiveFiles') and len(data.get('sensitiveFiles', [])) > 0:
            elements.append(Paragraph("Sensitive Files", heading2_style))
            
            files_data = [['File', 'Sensitivity Level']]
            
            for file in data.get('sensitiveFiles', []):
                files_data.append([
                    file.get('file', 'Unknown'),
                    file.get('level', 'Unknown')
                ])
            
            files_table = Table(files_data, colWidths=[3*inch, 2.5*inch])
            files_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ]))
            
            # Color sensitivity level cells based on value
            for i, row in enumerate(files_data[1:], 1):
                level = row[1]
                if level == "high":
                    files_table.setStyle(TableStyle([('BACKGROUND', (1, i), (1, i), colors.red),
                                                  ('TEXTCOLOR', (1, i), (1, i), colors.white)]))
                elif level == "medium":
                    files_table.setStyle(TableStyle([('BACKGROUND', (1, i), (1, i), colors.orange),
                                                  ('TEXTCOLOR', (1, i), (1, i), colors.white)]))
                elif level == "low":
                    files_table.setStyle(TableStyle([('BACKGROUND', (1, i), (1, i), colors.green),
                                                  ('TEXTCOLOR', (1, i), (1, i), colors.white)]))
            
            elements.append(files_table)
            elements.append(Spacer(1, 0.15*inch))
        
        # Directories
        if data.get('directories') and len(data.get('directories', [])) > 0:
            elements.append(Paragraph("Discovered Directories", heading2_style))
            
            # Create a multi-column layout for directories
            dir_chunks = [data.get('directories', [])[i:i+10] for i in range(0, len(data.get('directories', [])), 10)]
            
            for chunk in dir_chunks:
                for directory in chunk:
                    elements.append(Paragraph(f"• {directory}", normal_style))
            
            elements.append(Spacer(1, 0.15*inch))
        
        # Backup Files
        if data.get('backups') and len(data.get('backups', [])) > 0:
            elements.append(Paragraph("Backup Files", heading2_style))
            
            for backup in data.get('backups', []):
                elements.append(Paragraph(f"• {backup}", normal_style))
    
    def _add_api_endpoints_section(self, elements, data):
        """Add API endpoints information to the report"""
        # API Configuration
        elements.append(Paragraph("API Configuration", heading2_style))
        
        config_data = [
            ['Authentication', data.get('authentication', 'Unknown')],
            ['CORS', data.get('cors', 'Unknown')],
            ['Swagger/OpenAPI', 'Available' if data.get('swagger') else 'Not found'],
            ['GraphQL', 'Available' if data.get('graphql') else 'Not found'],
        ]
        
        config_table = Table(config_data, colWidths=[1.5*inch, 4*inch])
        config_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        
        elements.append(config_table)
        elements.append(Spacer(1, 0.15*inch))
        
        # API Endpoints
        if data.get('endpoints') and len(data.get('endpoints', [])) > 0:
            elements.append(Paragraph("API Endpoints", heading2_style))
            
            for endpoint in data.get('endpoints', []):
                elements.append(Paragraph(f"• {endpoint}", normal_style))
            
            elements.append(Spacer(1, 0.15*inch))
        
        # HTTP Methods
        if data.get('methods') and len(data.get('methods', {})) > 0:
            elements.append(Paragraph("HTTP Methods", heading2_style))
            
            methods_data = [['Endpoint', 'Methods']]
            
            for endpoint, methods in data.get('methods', {}).items():
                methods_data.append([
                    endpoint,
                    ', '.join(methods)
                ])
            
            methods_table = Table(methods_data, colWidths=[2.5*inch, 3*inch])
            methods_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ]))
            
            elements.append(methods_table)
    
    def _add_js_analysis_section(self, elements, data):
        """Add JavaScript analysis information to the report"""
        # Secrets
        if data.get('secrets') and len(data.get('secrets', [])) > 0:
            elements.append(Paragraph("Potential Secrets", heading2_style))
            
            secrets_data = [['Type', 'File', 'Value']]
            
            for secret in data.get('secrets', []):
                secrets_data.append([
                    secret.get('type', 'Unknown'),
                    secret.get('file', 'Unknown'),
                    secret.get('value', '****')
                ])
            
            secrets_table = Table(secrets_data, colWidths=[1.5*inch, 1.5*inch, 2.5*inch])
            secrets_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ]))
            
            elements.append(secrets_table)
            elements.append(Spacer(1, 0.15*inch))
        
        # JavaScript Libraries
        if data.get('libraries') and len(data.get('libraries', [])) > 0:
            elements.append(Paragraph("JavaScript Libraries", heading2_style))
            
            libraries = ', '.join(data.get('libraries', []))
            elements.append(Paragraph(libraries, normal_style))
            elements.append(Spacer(1, 0.15*inch))
        
        # Dependencies
        if data.get('dependencies') and len(data.get('dependencies', {})) > 0:
            elements.append(Paragraph("Dependencies", heading2_style))
            
            # Sort dependencies by usage count (descending)
            sorted_deps = sorted(data.get('dependencies', {}).items(), key=lambda x: x[1], reverse=True)
            
            deps_data = [['Package', 'Usage Count']]
            for dep, count in sorted_deps[:20]:  # Show top 20
                deps_data.append([dep, str(count)])
            
            if len(sorted_deps) > 20:
                deps_data.append(['...', f'and {len(sorted_deps) - 20} more'])
            
            deps_table = Table(deps_data, colWidths=[3*inch, 2.5*inch])
            deps_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ]))
            
            elements.append(deps_table)
    
    def _add_email_credentials_section(self, elements, data):
        """Add email and credentials information to the report"""
        # Emails
        if data.get('emails') and len(data.get('emails', [])) > 0:
            elements.append(Paragraph("Email Addresses", heading2_style))
            
            for email in data.get('emails', []):
                elements.append(Paragraph(f"• {email}", normal_style))
            
            elements.append(Spacer(1, 0.15*inch))
        
        # Past Breaches
        if data.get('pastBreaches') and len(data.get('pastBreaches', [])) > 0:
            elements.append(Paragraph("Past Breaches", heading2_style))
            
            breaches_data = [['Breach', 'Date', 'Description']]
            
            for breach in data.get('pastBreaches', []):
                breaches_data.append([
                    breach.get('name', 'Unknown'),
                    breach.get('date', 'Unknown'),
                    breach.get('description', 'No description')
                ])
            
            breaches_table = Table(breaches_data, colWidths=[1.5*inch, 1*inch, 3*inch])
            breaches_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            
            elements.append(breaches_table)
            elements.append(Spacer(1, 0.15*inch))
        
        # Exposed Data
        if data.get('exposedData') and len(data.get('exposedData', {})) > 0:
            elements.append(Paragraph("Exposed Data Types", heading2_style))
            
            exposed_data = [['Data Type', 'Count']]
            
            for data_type, count in data.get('exposedData', {}).items():
                exposed_data.append([data_type, str(count)])
            
            exposed_table = Table(exposed_data, colWidths=[3*inch, 2.5*inch])
            exposed_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ]))
            
            elements.append(exposed_table)
    
    def _generate_recommendations(self, modules):
        """Generate recommendations based on scan findings"""
        recommendations = []
        
        # Vulnerabilities recommendations
        if 'vulnerabilities' in modules:
            vulns = modules['vulnerabilities'].get('vulnerabilities', [])
            cves = modules['vulnerabilities'].get('cves', [])
            
            if any(v.get('severity') in ['Critical', 'High'] for v in vulns):
                recommendations.append("Address all critical and high severity vulnerabilities immediately")
            
            # XSS
            if any('XSS' in v.get('name', '') for v in vulns):
                recommendations.append("Implement proper input validation and output encoding to prevent XSS attacks")
            
            # SQL Injection
            if any('SQL' in v.get('name', '') for v in vulns):
                recommendations.append("Use parameterized queries or prepared statements to prevent SQL Injection")
            
            # CSRF
            if any('CSRF' in v.get('name', '') for v in vulns):
                recommendations.append("Implement CSRF tokens for all state-changing operations")
            
            # Security Headers
            if any('Header' in v.get('name', '') for v in vulns):
                recommendations.append("Implement recommended security headers (HSTS, CSP, X-Content-Type-Options, etc.)")
            
            if len(cves) > 0:
                recommendations.append("Update software components to address identified CVEs")
        
        # Cloud security recommendations
        if 'cloud_security' in modules:
            misconfigs = modules['cloud_security'].get('misconfigurations', [])
            exposed = modules['cloud_security'].get('exposed', False)
            
            if exposed:
                recommendations.append("Secure publicly exposed cloud resources immediately")
            
            if any('S3 Bucket' in m.get('type', '') for m in misconfigs):
                recommendations.append("Review S3 bucket permissions and apply the principle of least privilege")
            
            if any('CORS' in m.get('type', '') for m in misconfigs):
                recommendations.append("Configure CORS policies to restrict cross-origin requests to trusted domains only")
        
        # Files and directories recommendations
        if 'files_directories' in modules:
            sensitive_files = modules['files_directories'].get('sensitiveFiles', [])
            backups = modules['files_directories'].get('backups', [])
            
            if len(sensitive_files) > 0:
                recommendations.append("Remove or restrict access to sensitive files exposed on the web server")
            
            if len(backups) > 0:
                recommendations.append("Remove backup files from production environments")
            
            if any('Directory Listing' in v.get('name', '') for v in modules.get('vulnerabilities', {}).get('vulnerabilities', [])):
                recommendations.append("Disable directory listing in web server configuration")
        
        # API recommendations
        if 'api_endpoints' in modules:
            api_data = modules['api_endpoints']
            
            if api_data.get('cors') == 'permissive':
                recommendations.append("Configure API CORS headers to restrict access to trusted domains")
            
            if api_data.get('authentication') in [None, 'Unknown', '']:
                recommendations.append("Implement API authentication mechanisms")
            
            if api_data.get('swagger', False):
                recommendations.append("Restrict access to API documentation in production environments")
        
        # JavaScript recommendations
        if 'js_analysis' in modules:
            secrets = modules['js_analysis'].get('secrets', [])
            
            if len(secrets) > 0:
                recommendations.append("Remove sensitive information (API keys, tokens, etc.) from client-side JavaScript")
        
        # Add general recommendations if we have few specific ones
        if len(recommendations) < 5:
            general_recs = [
                "Implement a Web Application Firewall (WAF) for additional protection",
                "Perform regular security assessments and penetration testing",
                "Set up security monitoring and logging",
                "Develop and maintain a security incident response plan",
                "Keep all software components and libraries up to date",
                "Apply the principle of least privilege across all systems"
            ]
            
            recommendations.extend(general_recs)
        
        # Return unique recommendations, limited to 10
        return list(dict.fromkeys(recommendations))[:10]

# Create singleton instance
pdf_generator = PDFReportGenerator()
