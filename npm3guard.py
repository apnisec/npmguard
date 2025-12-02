#!/usr/bin/env python3
"""
NPM3Guard v2.3 - Enhanced Enterprise Vulnerability Scanner with Enhanced Slack Alerts
===================================================================================
An advanced NPM package vulnerability scanner for VAPT teams with comprehensive Slack reporting
Author: Apnisec
Version: 2.3.0 - Enhanced Slack alerts with detailed vulnerability reporting
"""

import requests
import os
import json
import argparse
import time
import logging
import csv
from pathlib import Path
import getpass
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import base64
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import sqlite3
import hashlib
import re
from dataclasses import dataclass, asdict
from urllib.parse import urlparse

# Enhanced imports for enterprise features
try:
    from semantic_version import Version, NpmSpec
except ImportError:
    print("[!] Please install semantic_version: pip install semantic_version")
    exit(1)

# ------------------ Tool Banner ------------------
TOOL_NAME = r"""
███    ██ ██████  ███    ███ ██████   ██████  ██    ██  █████  ██████  ██████  
████   ██ ██   ██ ████  ████      ██ ██       ██    ██ ██   ██ ██   ██ ██   ██ 
██ ██  ██ ██████  ██ ████ ██  █████  ██   ███ ██    ██ ███████ ██████  ██   ██ 
██  ██ ██ ██      ██  ██  ██      ██ ██    ██ ██    ██ ██   ██ ██   ██ ██   ██ 
██   ████ ██      ██      ██ ██████   ██████   ██████  ██   ██ ██   ██ ██████  

                ▂▃▅▇█▓▒░ Enterprise VAPT Edition v2.3 - Enhanced Slack Alerts ░▒▓█▇▅▃▂
                                   
"""

# ------------------ Enhanced Configuration ------------------
@dataclass
class ScanConfig:
    """Configuration class for scan parameters"""
    rate_limit_delay: float = 1.0
    max_workers: int = 10
    timeout: int = 30
    retries: int = 3
    save_reports: bool = True
    report_format: str = "json"  # json, csv, html
    enable_logging: bool = True
    log_level: str = "INFO"
    custom_vuln_db: Optional[str] = None
    whitelist_packages: List[str] = None
    slack_webhook: Optional[str] = None
    teams_webhook: Optional[str] = None
    recursive_scan: bool = True  # Enable recursive scanning
    detailed_slack_alerts: bool = True  # Enable detailed Slack alerts

# ------------------ Enhanced Vulnerability Database ------------------
class VulnerabilityDatabase:
    """Enhanced vulnerability database with real-time updates"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.db_path = Path("vuln_database.db")
        self.init_database()
        self.load_vulnerabilities()
    
    def init_database(self):
        """Initialize SQLite database for vulnerability storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY,
                package_name TEXT NOT NULL,
                version_range TEXT NOT NULL,
                severity TEXT NOT NULL,
                cve_id TEXT,
                description TEXT,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source TEXT DEFAULT 'builtin'
            )
        ''')
        conn.commit()
        conn.close()
    
    def load_vulnerabilities(self):
        """Load vulnerabilities from database and external sources"""
        self.vulnerabilities = {}
        
        # Load from database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT package_name, version_range, severity, cve_id, description FROM vulnerabilities')
        
        for row in cursor.fetchall():
            package_name, version_range, severity, cve_id, description = row
            if package_name not in self.vulnerabilities:
                self.vulnerabilities[package_name] = []
            
            self.vulnerabilities[package_name].append({
                'range': version_range,
                'severity': severity,
                'cve_id': cve_id,
                'description': description
            })
        
        conn.close()
        
        # Load built-in vulnerabilities if database is empty
        if not self.vulnerabilities:
            self._load_builtin_vulnerabilities()
    
    def _load_builtin_vulnerabilities(self):
        """Load enhanced built-in vulnerability database with 2024 CVEs"""
        builtin_vulns = {
            # 2024 Critical Vulnerabilities
            "braces": [
                {"range": "<3.0.3", "severity": "HIGH", "cve_id": "CVE-2024-4068", "description": "ReDoS vulnerability in braces package"}
            ],
            "ws": [
                {"range": ">=8.0.0 <8.17.1", "severity": "HIGH", "cve_id": "CVE-2024-37890", "description": "Unhandled exception and resource exhaustion"},
                {"range": ">=7.0.0 <7.4.6", "severity": "HIGH", "cve_id": "CVE-2021-32640", "description": "ReDoS vulnerability"},
                {"range": ">=6.0.0 <6.2.2", "severity": "HIGH", "cve_id": "CVE-2021-32640", "description": "ReDoS vulnerability"}
            ],
            "micromatch": [
                {"range": "<4.0.8", "severity": "MEDIUM", "cve_id": "CVE-2024-4067", "description": "ReDoS vulnerability in micromatch"}
            ],
            "path-to-regexp": [
                {"range": "<8.0.0", "severity": "HIGH", "cve_id": "CVE-2024-45296", "description": "ReDoS vulnerability affecting Express.js"}
            ],
            "cookie": [
                {"range": "<0.7.0", "severity": "MEDIUM", "cve_id": "CVE-2024-47764", "description": "DoS via malformed cookie"}
            ],
            # Existing vulnerabilities
            "lodash": [
                {"range": "<4.17.21", "severity": "HIGH", "cve_id": "CVE-2021-23337", "description": "Command injection vulnerability"},
                {"range": ">=4.0.0 <4.17.21", "severity": "HIGH", "cve_id": "CVE-2020-8203", "description": "Prototype pollution"}
            ],
            "axios": [
                {"range": "<0.21.2", "severity": "HIGH", "cve_id": "CVE-2021-3749", "description": "Regular expression denial of service"},
                {"range": ">=0.8.1 <1.6.0", "severity": "MEDIUM", "cve_id": "CVE-2023-45857", "description": "SSRF vulnerability"}
            ],
            "express": [
                {"range": "<4.18.3", "severity": "MEDIUM", "cve_id": "CVE-2022-24999", "description": "Open redirect vulnerability"},
                {"range": ">=4.0.0 <4.19.2", "severity": "HIGH", "cve_id": "CVE-2024-29041", "description": "Path traversal"}
            ],
            "jquery": [
                {"range": "<3.5.1", "severity": "MEDIUM", "cve_id": "CVE-2020-11022", "description": "Cross-site scripting"},
                {"range": "<3.6.0", "severity": "MEDIUM", "cve_id": "CVE-2020-11023", "description": "Cross-site scripting"}
            ],
            "react": [
                {"range": ">=16.0.0 <16.14.0", "severity": "MEDIUM", "cve_id": "CVE-2021-44906", "description": "Prototype pollution"},
                {"range": ">=17.0.0 <18.2.1", "severity": "LOW", "cve_id": "CVE-2023-26115", "description": "Memory leak"}
            ],
            "debug": [
                {"range": "<=4.3.1", "severity": "LOW", "cve_id": "CVE-2017-20165", "description": "Regular expression denial of service"}
            ],
            "node-forge": [
                {"range": "<1.3.0", "severity": "HIGH", "cve_id": "CVE-2022-24771", "description": "Signature verification bypass"},
                {"range": "<1.3.1", "severity": "HIGH", "cve_id": "CVE-2022-24772", "description": "URL parsing issue"}
            ],
            "minimist": [
                {"range": "<0.2.4", "severity": "LOW", "cve_id": "CVE-2021-44906", "description": "Prototype pollution"},
                {"range": "<1.2.6", "severity": "MEDIUM", "cve_id": "CVE-2020-7598", "description": "Prototype pollution"}
            ],
            "moment": [
                {"range": "<2.29.2", "severity": "HIGH", "cve_id": "CVE-2022-24785", "description": "Path traversal vulnerability"},
                {"range": "<2.29.4", "severity": "MEDIUM", "cve_id": "CVE-2022-31129", "description": "ReDoS vulnerability"}
            ],
            "semver": [
                {"range": "<7.5.2", "severity": "HIGH", "cve_id": "CVE-2022-25883", "description": "ReDoS vulnerability"}
            ],
            "tar": [
                {"range": "<6.1.9", "severity": "HIGH", "cve_id": "CVE-2021-37701", "description": "Arbitrary file creation/overwrite"}
            ],
            "jsonwebtoken": [
                {"range": "<9.0.0", "severity": "HIGH", "cve_id": "CVE-2022-23529", "description": "JWT algorithm confusion"}
            ],
            "got": [
                {"range": "<11.8.5", "severity": "MEDIUM", "cve_id": "CVE-2022-33987", "description": "HTTP request smuggling"}
            ]
        }
        
        # Insert built-in vulnerabilities into database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for package_name, vulns in builtin_vulns.items():
            for vuln in vulns:
                cursor.execute('''
                    INSERT OR REPLACE INTO vulnerabilities 
                    (package_name, version_range, severity, cve_id, description, source)
                    VALUES (?, ?, ?, ?, ?, 'builtin')
                ''', (package_name, vuln['range'], vuln['severity'], vuln['cve_id'], vuln['description']))
        
        conn.commit()
        conn.close()
        
        self.vulnerabilities = builtin_vulns
    
    def is_vulnerable(self, package_name: str, version: str) -> List[Dict]:
        """Check if a package version is vulnerable"""
        vulnerabilities = []
        
        if package_name in self.vulnerabilities:
            for vuln in self.vulnerabilities[package_name]:
                if self._is_version_in_range(version, vuln['range']):
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _is_version_in_range(self, version: str, range_expr: str) -> bool:
        """Check if version falls within vulnerable range"""
        try:
            spec = NpmSpec(range_expr)
            normalized_version = version.lstrip("^~")
            return Version(normalized_version) in spec
        except Exception:
            return False

# ------------------ Enhanced Logging ------------------
def setup_logging(config: ScanConfig):
    """Setup enhanced logging with different levels"""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    if config.enable_logging:
        logging.basicConfig(
            level=getattr(logging, config.log_level.upper()),
            format=log_format,
            handlers=[
                logging.FileHandler(f'npm3guard_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
                logging.StreamHandler()
            ]
        )
    else:
        logging.basicConfig(level=logging.CRITICAL)

# ------------------ Enhanced Notification System ------------------
class NotificationManager:
    """Enhanced notification system with detailed Slack reporting"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
    
    def send_detailed_scan_alert(self, scan_summary: Dict, vulnerabilities: List[Dict]):
        """Send detailed scan completion alert with vulnerability breakdown"""
        if not self.config.slack_webhook:
            return
            
        total_vulns = scan_summary.get('total_vulnerabilities', 0)
        if total_vulns == 0:
            return  # Don't send alerts for clean scans
            
        org_name = scan_summary.get('username', 'unknown')
        high_count = scan_summary.get('high_severity', 0)
        medium_count = scan_summary.get('medium_severity', 0)
        low_count = scan_summary.get('low_severity', 0)
        
        # Create detailed message
        alert_message = f"🚨 *NPM3Guard Security Alert*\n\n"
        alert_message += f"*Total {total_vulns} vulnerabilities found in `{org_name}`*\n\n"
        alert_message += f"📊 *Severity Breakdown:*\n"
        alert_message += f"• 🔴 High severity: {high_count}\n"
        alert_message += f"• 🟡 Medium severity: {medium_count}\n"
        alert_message += f"• 🟢 Low severity: {low_count}\n\n"
        
        # Group vulnerabilities by repository
        vulns_by_repo = {}
        for vuln in vulnerabilities:
            repo = vuln.get('repository', 'unknown')
            if repo not in vulns_by_repo:
                vulns_by_repo[repo] = []
            vulns_by_repo[repo].append(vuln)
        
        alert_message += f"📁 *Affected Repositories ({len(vulns_by_repo)}):*\n"
        
        for repo, repo_vulns in vulns_by_repo.items():
            repo_high = sum(1 for v in repo_vulns if v.get('severity') == 'HIGH')
            repo_medium = sum(1 for v in repo_vulns if v.get('severity') == 'MEDIUM')  
            repo_low = sum(1 for v in repo_vulns if v.get('severity') == 'LOW')
            
            alert_message += f"\n*{repo}* ({len(repo_vulns)} vulnerabilities)\n"
            if repo_high > 0:
                alert_message += f"  🔴 {repo_high} high"
            if repo_medium > 0:
                alert_message += f"  🟡 {repo_medium} medium"
            if repo_low > 0:
                alert_message += f"  🟢 {repo_low} low"
            alert_message += "\n"
            
            # List top vulnerabilities for this repo (limit to 5)
            for vuln in repo_vulns[:5]:
                severity_emoji = "🔴" if vuln.get('severity') == 'HIGH' else "🟡" if vuln.get('severity') == 'MEDIUM' else "🟢"
                alert_message += f"  {severity_emoji} `{vuln.get('package', 'unknown')}` v{vuln.get('clean_version', 'unknown')} - {vuln.get('cve_id', 'N/A')}\n"
                alert_message += f"     📍 {vuln.get('file', 'unknown')}\n"
                alert_message += f"     💡 {vuln.get('description', 'No description')}\n"
            
            if len(repo_vulns) > 5:
                alert_message += f"  ... and {len(repo_vulns) - 5} more\n"
        
        alert_message += f"\n⏰ *Scan completed:* {scan_summary.get('scan_time', 'unknown')}\n"
        alert_message += f"🔧 *Tool:* NPM3Guard v2.3 Enterprise\n"
        alert_message += f"🔍 *Platform:* {scan_summary.get('platform', 'GitHub')}\n"
        alert_message += f"♻️ *Recursive scan:* {'✅ Enabled' if scan_summary.get('recursive_scan', False) else '❌ Disabled'}\n"
        
        # Send to Slack
        self._send_slack_message(alert_message)
        
        if self.config.teams_webhook:
            self._send_teams_alert(f"Security Alert: {total_vulns} vulnerabilities found in {org_name}")
    
    def send_alert(self, message: str, severity: str = "INFO"):
        """Send simple alert to configured notification channels"""
        formatted_message = f"[{severity}] NPM3Guard Alert: {message}"
        
        if self.config.slack_webhook:
            self._send_slack_message(formatted_message)
        
        if self.config.teams_webhook:
            self._send_teams_alert(formatted_message)
    
    def _send_slack_message(self, message: str):
        """Send formatted message to Slack"""
        try:
            payload = {
                "text": message,
                "username": "NPM3Guard",
                "icon_emoji": ":warning:",
                "mrkdwn": True
            }
            response = requests.post(self.config.slack_webhook, json=payload, timeout=10)
            if response.status_code != 200:
                logging.error(f"Slack alert failed: {response.status_code} {response.text}")
            else:
                logging.info("Detailed Slack alert sent successfully")
        except Exception as e:
            logging.error(f"Slack alert error: {e}")
    
    def _send_teams_alert(self, message: str):
        """Send alert to Microsoft Teams"""
        try:
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "0076D7",
                "summary": "NPM3Guard Security Alert",
                "sections": [{
                    "activityTitle": "NPM3Guard Security Scanner",
                    "activitySubtitle": "Vulnerability Detection Alert",
                    "text": message
                }]
            }
            response = requests.post(self.config.teams_webhook, json=payload, timeout=10)
            if response.status_code != 200:
                logging.error(f"Teams alert failed: {response.status_code} {response.text}")
        except Exception as e:
            logging.error(f"Teams alert error: {e}")

# ------------------ Enhanced Git Platform Handlers ------------------
class GitPlatformHandler:
    """Base class for Git platform handlers"""
    
    def __init__(self, config: ScanConfig, notification_manager: NotificationManager):
        self.config = config
        self.notification_manager = notification_manager
        self.session = requests.Session()
        self.session.timeout = config.timeout
        self.dependency_files = ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"]
    
    def _make_request_with_retry(self, url: str, headers: Dict = None, **kwargs) -> Optional[requests.Response]:
        """Make HTTP request with retry logic and rate limiting"""
        headers = headers or {}
        
        for attempt in range(self.config.retries):
            try:
                time.sleep(self.config.rate_limit_delay)
                response = self.session.get(url, headers=headers, **kwargs)
                
                if response.status_code == 200:
                    return response
                elif response.status_code == 403:
                    logging.warning(f"Rate limited. Waiting 60 seconds... (Attempt {attempt + 1})")
                    time.sleep(60)
                elif response.status_code == 401:
                    logging.error("Authentication failed. Check your token permissions.")
                    return None
                else:
                    logging.warning(f"HTTP {response.status_code} for {url}")
                    
            except requests.exceptions.RequestException as e:
                logging.error(f"Request failed (attempt {attempt + 1}): {e}")
                if attempt < self.config.retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
        
        return None

class GitHubHandler(GitPlatformHandler):
    """Enhanced GitHub API handler with organization support and detailed alerts"""
    
    def __init__(self, token: str, config: ScanConfig, notification_manager: NotificationManager):
        super().__init__(config, notification_manager)
        self.token = token
        self.base_url = "https://api.github.com"
        self.headers = {
            "Authorization": f"Bearer {token}" if token else {},
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
    
    def get_account_type(self, username: str) -> Optional[str]:
        """Determine if username is a User or Organization"""
        url = f"{self.base_url}/users/{username}"
        response = self._make_request_with_retry(url, headers=self.headers)
        
        if response and response.status_code == 200:
            data = response.json()
            account_type = data.get('type', 'User')
            logging.info(f"Detected account type for '{username}': {account_type}")
            return account_type
        else:
            logging.warning(f"Could not determine account type for '{username}', defaulting to User")
            return "User"
    
    def fetch_repositories(self, username: str) -> List[Dict]:
        """Fetch all repositories for a user/organization with pagination and proper endpoint detection"""
        account_type = self.get_account_type(username)
        
        # Choose correct API endpoint based on account type
        if account_type == "Organization":
            base_endpoint = f"{self.base_url}/orgs/{username}/repos"
        else:
            base_endpoint = f"{self.base_url}/users/{username}/repos"
        
        repos = []
        page = 1
        per_page = 100
        
        while True:
            url = base_endpoint
            params = {
                "per_page": per_page, 
                "page": page, 
                "type": "all",  # Include all types: owner, member, etc.
                "sort": "updated",
                "direction": "desc"
            }
            
            response = self._make_request_with_retry(url, headers=self.headers, params=params)
            if not response:
                logging.error(f"Failed to fetch repositories from {url}")
                break
            
            data = response.json()
            if not data:
                break
            
            repos.extend(data)
            logging.info(f"Fetched {len(data)} repositories (page {page}) from {account_type}")
            
            # Check if we have more pages
            if len(data) < per_page:
                break
            page += 1
        
        logging.info(f"Total repositories found for '{username}' ({account_type}): {len(repos)}")
        return repos
    
    def fetch_repository_tree(self, repo_full_name: str, branch: str = "main") -> List[Dict]:
        """Fetch complete file tree of a repository recursively"""
        url = f"{self.base_url}/repos/{repo_full_name}/git/trees/{branch}"
        params = {"recursive": "1"}
        
        response = self._make_request_with_retry(url, headers=self.headers, params=params)
        if not response:
            # Try with master branch if main doesn't exist
            url = f"{self.base_url}/repos/{repo_full_name}/git/trees/master"
            response = self._make_request_with_retry(url, headers=self.headers, params=params)
        
        if response:
            data = response.json()
            return data.get('tree', [])
        
        return []
    
    def find_dependency_files(self, repo_full_name: str) -> List[str]:
        """Find all dependency files in the repository recursively"""
        dependency_files_found = []
        tree = self.fetch_repository_tree(repo_full_name)
        
        for item in tree:
            if item.get('type') == 'blob':  # Only files, not directories
                file_path = item.get('path', '')
                file_name = os.path.basename(file_path)
                
                if file_name in self.dependency_files:
                    dependency_files_found.append(file_path)
                    logging.debug(f"Found dependency file: {file_path}")
        
        logging.info(f"Found {len(dependency_files_found)} dependency files in {repo_full_name}")
        return dependency_files_found
    
    def download_file(self, repo_full_name: str, file_path: str) -> Optional[str]:
        """Download file contents from GitHub repository"""
        url = f"{self.base_url}/repos/{repo_full_name}/contents/{file_path}"
        
        response = self._make_request_with_retry(url, headers=self.headers)
        if not response:
            return None
        
        try:
            data = response.json()
            if data.get('encoding') == 'base64':
                content = base64.b64decode(data['content']).decode('utf-8')
                return content
            elif 'download_url' in data:
                # Use download_url for larger files
                download_response = self._make_request_with_retry(data['download_url'])
                return download_response.text if download_response else None
        except Exception as e:
            logging.error(f"Error downloading file {file_path} from {repo_full_name}: {e}")
        
        return None
    
    def scan_repositories(self, username: str, vuln_db: VulnerabilityDatabase) -> List[Dict]:
        """Scan all repositories for vulnerabilities with enhanced Slack alerts"""
        repos = self.fetch_repositories(username)
        all_vulnerabilities = []
        
        if not repos:
            logging.warning(f"No repositories found for '{username}'. Check username and token permissions.")
            return all_vulnerabilities
        
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            future_to_repo = {
                executor.submit(self._scan_single_repository, repo, vuln_db): repo 
                for repo in repos
            }
            
            for future in as_completed(future_to_repo):
                repo = future_to_repo[future]
                try:
                    vulnerabilities = future.result()
                    if vulnerabilities:
                        all_vulnerabilities.extend(vulnerabilities)
                        logging.info(f"Found {len(vulnerabilities)} vulnerabilities in {repo['name']}")
                except Exception as e:
                    logging.error(f"Error scanning repository {repo['name']}: {e}")
        
        return all_vulnerabilities
    
    def _scan_single_repository(self, repo: Dict, vuln_db: VulnerabilityDatabase) -> List[Dict]:
        """Scan a single repository for vulnerabilities with recursive file discovery"""
        repo_name = repo['name']
        repo_full_name = repo['full_name']
        vulnerabilities = []
        
        logging.info(f"Scanning repository: {repo_name}")
        
        # Find all dependency files recursively
        dependency_files = self.find_dependency_files(repo_full_name)
        
        if not dependency_files:
            logging.info(f"No dependency files found in {repo_name}")
            return vulnerabilities
        
        # Scan each dependency file found
        for dep_file_path in dependency_files:
            content = self.download_file(repo_full_name, dep_file_path)
            if content:
                logging.debug(f"Downloaded {dep_file_path} from {repo_name}")
                
                # Save file for audit trail
                self._save_dependency_file(repo_name, dep_file_path, content)
                
                # Scan for vulnerabilities
                file_name = os.path.basename(dep_file_path)
                file_vulns = self._scan_dependency_file(content, file_name, vuln_db)
                for vuln in file_vulns:
                    vuln.update({
                        'repository': repo_name,
                        'file': dep_file_path,  # Full path including subdirectories
                        'platform': 'github'
                    })
                vulnerabilities.extend(file_vulns)
        
        return vulnerabilities
    
    def _save_dependency_file(self, repo_name: str, file_path: str, content: str):
        """Save dependency file for audit purposes"""
        if self.config.save_reports:
            base_path = Path("scanned_files") / "github" / repo_name
            base_path.mkdir(parents=True, exist_ok=True)
            
            # Replace path separators for Windows compatibility
            safe_file_path = file_path.replace('/', '_').replace('\\', '_')
            file_save_path = base_path / safe_file_path
            file_save_path.write_text(content, encoding="utf-8")
    
    def _scan_dependency_file(self, content: str, file_type: str, vuln_db: VulnerabilityDatabase) -> List[Dict]:
        """Scan dependency file content for vulnerabilities"""
        vulnerabilities = []
        
        try:
            if file_type in ["package.json", "package-lock.json"]:
                vulnerabilities = self._scan_json_dependencies(content, vuln_db)
            elif file_type == "yarn.lock":
                vulnerabilities = self._scan_yarn_lock(content, vuln_db)
            elif file_type == "pnpm-lock.yaml":
                vulnerabilities = self._scan_pnpm_lock(content, vuln_db)
        except Exception as e:
            logging.error(f"Error scanning {file_type}: {e}")
        
        return vulnerabilities
    
    def _scan_json_dependencies(self, content: str, vuln_db: VulnerabilityDatabase) -> List[Dict]:
        """Scan JSON dependency files"""
        vulnerabilities = []
        
        try:
            data = json.loads(content)
            dependencies = {}
            dependencies.update(data.get("dependencies", {}))
            dependencies.update(data.get("devDependencies", {}))
            dependencies.update(data.get("peerDependencies", {}))
            dependencies.update(data.get("optionalDependencies", {}))
            
            for package_name, version in dependencies.items():
                # Clean version string
                clean_version = re.sub(r'^[\^~>=<\s]*', '', version)
                
                # Check for vulnerabilities
                package_vulns = vuln_db.is_vulnerable(package_name, clean_version)
                for vuln in package_vulns:
                    vulnerabilities.append({
                        'package': package_name,
                        'version': version,
                        'clean_version': clean_version,
                        'severity': vuln['severity'],
                        'cve_id': vuln.get('cve_id'),
                        'description': vuln.get('description'),
                        'vulnerable_range': vuln['range']
                    })
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in dependency file: {e}")
        
        return vulnerabilities
    
    def _scan_yarn_lock(self, content: str, vuln_db: VulnerabilityDatabase) -> List[Dict]:
        """Scan yarn.lock files"""
        vulnerabilities = []
        
        try:
            lines = content.splitlines()
            current_package = None
            current_version = None
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    if line.endswith(':') and '@' in line:
                        # Package line
                        package_info = line.rstrip(':')
                        if '@' in package_info:
                            current_package = package_info.split('@')[0]
                    elif line.startswith('version') and current_package:
                        # Version line
                        current_version = line.split('"')[1] if '"' in line else None
                        
                        if current_version:
                            package_vulns = vuln_db.is_vulnerable(current_package, current_version)
                            for vuln in package_vulns:
                                vulnerabilities.append({
                                    'package': current_package,
                                    'version': current_version,
                                    'clean_version': current_version,
                                    'severity': vuln['severity'],
                                    'cve_id': vuln.get('cve_id'),
                                    'description': vuln.get('description'),
                                    'vulnerable_range': vuln['range']
                                })
                        
                        current_package = None
                        current_version = None
        except Exception as e:
            logging.error(f"Error parsing yarn.lock: {e}")
        
        return vulnerabilities
    
    def _scan_pnpm_lock(self, content: str, vuln_db: VulnerabilityDatabase) -> List[Dict]:
        """Scan pnpm-lock.yaml files"""
        vulnerabilities = []
        # Basic YAML parsing for PNPM lock files
        try:
            lines = content.splitlines()
            in_packages_section = False
            
            for line in lines:
                if line.strip() == "packages:":
                    in_packages_section = True
                    continue
                
                if in_packages_section and line.startswith("  /"):
                    # Package definition
                    package_line = line.strip().lstrip("/")
                    if "@" in package_line:
                        parts = package_line.split("@")
                        if len(parts) >= 2:
                            package_name = parts[0]
                            version = parts[1].split(":")[0] if ":" in parts[1] else parts[1]
                            
                            package_vulns = vuln_db.is_vulnerable(package_name, version)
                            for vuln in package_vulns:
                                vulnerabilities.append({
                                    'package': package_name,
                                    'version': version,
                                    'clean_version': version,
                                    'severity': vuln['severity'],
                                    'cve_id': vuln.get('cve_id'),
                                    'description': vuln.get('description'),
                                    'vulnerable_range': vuln['range']
                                })
        except Exception as e:
            logging.error(f"Error parsing pnpm-lock.yaml: {e}")
        
        return vulnerabilities

# ------------------ Enhanced Report Generator ------------------
class ReportGenerator:
    """Enhanced report generation with multiple formats"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def generate_report(self, vulnerabilities: List[Dict], scan_summary: Dict):
        """Generate comprehensive report in specified format"""
        if self.config.report_format.lower() == "json":
            self._generate_json_report(vulnerabilities, scan_summary)
        elif self.config.report_format.lower() == "csv":
            self._generate_csv_report(vulnerabilities, scan_summary)
        elif self.config.report_format.lower() == "html":
            self._generate_html_report(vulnerabilities, scan_summary)
        else:
            self._generate_json_report(vulnerabilities, scan_summary)
    
    def _generate_json_report(self, vulnerabilities: List[Dict], scan_summary: Dict):
        """Generate JSON report"""
        report = {
            "scan_metadata": {
                "timestamp": self.timestamp,
                "tool_version": "NPM3Guard v2.3 - Enhanced Slack Alerts",
                "scan_summary": scan_summary
            },
            "vulnerabilities": vulnerabilities
        }
        
        filename = f"npm3guard_report_{self.timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logging.info(f"JSON report saved: {filename}")
    
    def _generate_csv_report(self, vulnerabilities: List[Dict], scan_summary: Dict):
        """Generate CSV report"""
        filename = f"npm3guard_report_{self.timestamp}.csv"
        
        if not vulnerabilities:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["No vulnerabilities found"])
            return
        
        fieldnames = list(vulnerabilities[0].keys())
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(vulnerabilities)
        
        logging.info(f"CSV report saved: {filename}")
    
    def _generate_html_report(self, vulnerabilities: List[Dict], scan_summary: Dict):
        """Generate HTML report"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>NPM3Guard Security Report v2.3</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .summary {{ margin: 20px 0; background-color: white; padding: 15px; border-radius: 5px; }}
                .vulnerability {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; background-color: white; }}
                .high {{ border-left: 5px solid #dc3545; }}
                .medium {{ border-left: 5px solid #ffc107; }}
                .low {{ border-left: 5px solid #28a745; }}
                .critical {{ border-left: 5px solid #721c24; }}
                .file-path {{ font-family: monospace; background-color: #f8f9fa; padding: 2px 4px; border-radius: 3px; }}
                .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
                .stat-box {{ text-align: center; padding: 10px; background-color: white; border-radius: 5px; }}
                .slack-alert {{ background-color: #e8f5e8; padding: 10px; border-radius: 5px; margin: 10px 0; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>NPM3Guard Security Report v2.3</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>✅ Enhanced Slack Alerts + Organization Support + Recursive Scanning</p>
            </div>
            
            <div class="slack-alert">
                <strong>🔔 Enhanced Slack Alerts:</strong> Detailed vulnerability reports are automatically sent to Slack with full breakdown by repository and severity.
            </div>
            
            <div class="stats">
                <div class="stat-box">
                    <h3>{len(vulnerabilities)}</h3>
                    <p>Total Vulnerabilities</p>
                </div>
                <div class="stat-box">
                    <h3>{len([v for v in vulnerabilities if v.get('severity') == 'HIGH'])}</h3>
                    <p>High Severity</p>
                </div>
                <div class="stat-box">
                    <h3>{len([v for v in vulnerabilities if v.get('severity') == 'MEDIUM'])}</h3>
                    <p>Medium Severity</p>
                </div>
                <div class="stat-box">
                    <h3>{len([v for v in vulnerabilities if v.get('severity') == 'LOW'])}</h3>
                    <p>Low Severity</p>
                </div>
            </div>
            
            <div class="summary">
                <h2>Scan Summary</h2>
                <ul>
        """
        
        for key, value in scan_summary.items():
            html_content += f"<li><strong>{key}:</strong> {value}</li>"
        
        html_content += """
                </ul>
            </div>
            
            <div class="vulnerabilities">
                <h2>Vulnerabilities Found</h2>
        """
        
        for vuln in vulnerabilities:
            severity_class = vuln.get('severity', 'low').lower()
            html_content += f"""
                <div class="vulnerability {severity_class}">
                    <h3>{vuln.get('package', 'Unknown Package')}</h3>
                    <p><strong>Version:</strong> {vuln.get('version', 'Unknown')}</p>
                    <p><strong>Severity:</strong> {vuln.get('severity', 'Unknown')}</p>
                    <p><strong>CVE ID:</strong> {vuln.get('cve_id', 'N/A')}</p>
                    <p><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>
                    <p><strong>Repository:</strong> {vuln.get('repository', 'N/A')}</p>
                    <p><strong>File:</strong> <span class="file-path">{vuln.get('file', 'N/A')}</span></p>
                    <p><strong>Platform:</strong> {vuln.get('platform', 'N/A').upper()}</p>
                </div>
            """
        
        html_content += """
            </div>
        </body>
        </html>
        """
        
        filename = f"npm3guard_report_{self.timestamp}.html"
        with open(filename, 'w') as f:
            f.write(html_content)
        
        logging.info(f"HTML report saved: {filename}")

# ------------------ Main NPM3Guard Class ------------------
class NPM3Guard:
    """Main NPM3Guard scanner class with enhanced Slack alerts"""
    
    def __init__(self, config: ScanConfig = None):
        self.config = config or ScanConfig()
        setup_logging(self.config)
        
        self.vuln_db = VulnerabilityDatabase(self.config)
        self.notification_manager = NotificationManager(self.config)
        self.report_generator = ReportGenerator(self.config)
        
        logging.info("NPM3Guard v2.3 initialized with enhanced Slack alerts")
    
    def scan_github(self, username: str, token: str) -> Dict:
        """Scan GitHub repositories with enhanced Slack alerts"""
        logging.info(f"Starting GitHub scan with enhanced alerts for: {username}")
        
        handler = GitHubHandler(token, self.config, self.notification_manager)
        vulnerabilities = handler.scan_repositories(username, self.vuln_db)
        
        scan_summary = {
            "platform": "GitHub",
            "username": username,
            "total_vulnerabilities": len(vulnerabilities),
            "high_severity": len([v for v in vulnerabilities if v.get('severity') == 'HIGH']),
            "medium_severity": len([v for v in vulnerabilities if v.get('severity') == 'MEDIUM']),
            "low_severity": len([v for v in vulnerabilities if v.get('severity') == 'LOW']),
            "scan_time": datetime.now().isoformat(),
            "recursive_scan": self.config.recursive_scan,
            "organization_support": True
        }
        
        # Send detailed Slack alert
        if self.config.detailed_slack_alerts:
            self.notification_manager.send_detailed_scan_alert(scan_summary, vulnerabilities)
        
        if self.config.save_reports:
            self.report_generator.generate_report(vulnerabilities, scan_summary)
        
        return {"vulnerabilities": vulnerabilities, "summary": scan_summary}

# ------------------ CLI Interface ------------------
def create_config_from_args() -> ScanConfig:
    """Create configuration from command line arguments or interactive input"""
    config = ScanConfig()
    
    # Interactive configuration
    print("\n" + "="*75)
    print("NPM3Guard v2.3 Configuration - Enhanced Slack Alerts + Recursive Scanning")
    print("="*75)
    
    # Rate limiting
    rate_limit = input(f"Rate limit delay in seconds (default: {config.rate_limit_delay}): ").strip()
    if rate_limit:
        try:
            config.rate_limit_delay = float(rate_limit)
        except ValueError:
            print("Invalid rate limit, using default")
    
    # Workers
    workers = input(f"Max concurrent workers (default: {config.max_workers}): ").strip()
    if workers:
        try:
            config.max_workers = int(workers)
        except ValueError:
            print("Invalid worker count, using default")
    
    # Report format
    format_choice = input("Report format (json/csv/html) [default: json]: ").strip().lower()
    if format_choice in ['json', 'csv', 'html']:
        config.report_format = format_choice
    
    # Notification webhooks
    slack_webhook = input("Slack webhook URL (optional): ").strip()
    if slack_webhook:
        config.slack_webhook = slack_webhook
        config.detailed_slack_alerts = True
    
    teams_webhook = input("Microsoft Teams webhook URL (optional): ").strip()
    if teams_webhook:
        config.teams_webhook = teams_webhook
    
    return config

def main():
    """Main function with enhanced CLI interface"""
    print(TOOL_NAME)
    
    # Create configuration
    config = create_config_from_args()
    
    # Initialize scanner
    scanner = NPM3Guard(config)
    
    print("\n" + "="*75)
    print("🔔 Enhanced Slack Alerts + GitHub Organization & User Support")
    print("✅ Automatically detects if target is User or Organization")
    print("✅ Recursively scans ALL subfolders for dependency files")
    print("✅ Sends detailed vulnerability reports to Slack with breakdown")
    print("="*75)
    
    username = input("GitHub username/organization (e.g., 'hackerone'): ").strip()
    token = getpass.getpass("GitHub Personal Access Token (ghp_...): ").strip()
    
    if not username:
        print("[!] Username/organization is required")
        return
    
    try:
        print(f"\n[*] Starting GitHub scan for '{username}'...")
        print("[*] Detecting account type (User/Organization)...")
        print("[*] This will scan ALL dependency files in ALL subfolders...")
        
        if config.slack_webhook:
            print("[*] Enhanced Slack alerts are ENABLED - detailed reports will be sent")
        
        result = scanner.scan_github(username, token)
        
        print(f"\n[+] ✅ Scan completed successfully!")
        print(f"[+] Total vulnerabilities found: {result['summary']['total_vulnerabilities']}")
        print(f"[+] High severity: {result['summary']['high_severity']}")
        print(f"[+] Medium severity: {result['summary']['medium_severity']}")
        print(f"[+] Low severity: {result['summary']['low_severity']}")
        
        if result['summary']['total_vulnerabilities'] > 0:
            print(f"\n[!] ⚠️  Vulnerabilities detected! Check the generated reports for details.")
            if config.slack_webhook:
                print(f"[!] 🔔 Detailed Slack alert has been sent with vulnerability breakdown.")
        else:
            print(f"\n[+] 🎉 No vulnerabilities found in the scanned repositories!")
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        logging.error(f"Scan failed: {e}")
        print(f"[!] Scan failed: {e}")
    
    print("\n[*] 🔍 NPM3Guard v2.3 scan completed.")
    print("[*] 📁 Check reports and logs for detailed vulnerability information.")
    print("[*] 🔔 Enhanced Slack alerts provide real-time vulnerability notifications.")

if __name__ == "__main__":
    main()
