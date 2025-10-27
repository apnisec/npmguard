# NPM3Guard v2.2 - Enterprise Vulnerability Scanner

<div align="center">

```
███    ██ ██████  ███    ███ ██████   ██████  ██    ██  █████  ██████  ██████  
████   ██ ██   ██ ████  ████      ██ ██       ██    ██ ██   ██ ██   ██ ██   ██ 
██ ██  ██ ██████  ██ ████ ██  █████  ██   ███ ██    ██ ███████ ██████  ██   ██ 
██  ██ ██ ██      ██  ██  ██      ██ ██    ██ ██    ██ ██   ██ ██   ██ ██   ██ 
██   ████ ██      ██      ██ ██████   ██████   ██████  ██   ██ ██   ██ ██████  
```

**Enterprise VAPT Edition v2.2 - Organization Support + Recursive Scanning**

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-VAPT-red.svg)](#)

</div>

## 🛡️ Overview

**NPM3Guard** is an advanced NPM package vulnerability scanner designed specifically for **VAPT (Vulnerability Assessment and Penetration Testing)** teams and cybersecurity professionals. It provides comprehensive security scanning of NPM dependencies across GitHub, GitLab, and Bitbucket repositories with enterprise-grade features.

### 🎯 Key Features

- **🏢 GitHub Organization Support** - Automatically detects and scans both user accounts and organizations
- **🔄 Recursive Scanning** - Finds dependency files in ALL subfolders and nested directories  
- **🚀 Multi-Platform Support** - GitHub, GitLab, and Bitbucket integration
- **📊 Multiple Report Formats** - JSON, CSV, and HTML reports with executive summaries
- **⚡ Multi-threaded Processing** - Concurrent scanning for faster bulk repository analysis
- **🔔 Real-time Alerts** - Slack and Microsoft Teams webhook notifications
- **🗄️ SQLite Vulnerability Database** - Local caching with 2024 CVE updates
- **📁 Complete Audit Trail** - File storage and scanning history for compliance
- **🎛️ Enterprise Configuration** - Customizable rate limiting, workers, and reporting

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/npm3guard.git
cd npm3guard

# Install dependencies
pip install -r requirements.txt

# Run the scanner
python npm3guard.py
```

### Basic Usage

```bash
python npm3guard.py
```

Follow the interactive prompts to configure and run your scan.

## 📋 Prerequisites

- **Python 3.8+**
- **GitHub Personal Access Token** (for GitHub scanning)
- **GitLab Personal Access Token** (for GitLab scanning)  
- **Bitbucket App Password** (for Bitbucket scanning)

## 🔧 Installation Guide

### 1. System Requirements

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip git

# CentOS/RHEL  
sudo yum install python3 python3-pip git

# macOS
brew install python3 git
```

### 2. Install NPM3Guard

```bash
# Method 1: Direct download
wget https://raw.githubusercontent.com/your-org/npm3guard/main/npm3guard.py
pip install -r requirements.txt

# Method 2: Git clone
git clone https://github.com/your-org/npm3guard.git
cd npm3guard
pip install -r requirements.txt
```

### 3. GitHub Token Setup

1. Go to GitHub Settings → Developer Settings → Personal Access Tokens
2. Click "Generate new token (classic)"
3. Select these scopes:
   - ✅ `repo` (Full control of private repositories)
   - ✅ `read:org` (Read org and team membership)
   - ✅ `user:email` (Access user email addresses)
4. Copy the generated token (starts with `ghp_`)

## 🏢 Enterprise Features

### Organization Support

NPM3Guard v2.2 automatically detects whether the target is a GitHub user or organization and uses the appropriate API endpoints:

- **Users**: `/users/{username}/repos`
- **Organizations**: `/orgs/{orgname}/repos`

### Recursive File Discovery

The tool recursively scans ALL subfolders to find dependency files:

- `frontend/package.json`
- `backend/api/yarn.lock`  
- `microservices/auth/package-lock.json`
- `apps/admin/dashboard/pnpm-lock.yaml`
- Any nested dependency files at any depth

### Vulnerability Database (2024 CVEs)

NPM3Guard includes an updated vulnerability database with the latest 2024 CVEs:

| Package | CVE | Severity | Description |
|---------|-----|----------|-------------|
| braces | CVE-2024-4068 | HIGH | ReDoS vulnerability |
| ws | CVE-2024-37890 | HIGH | Unhandled exception |
| path-to-regexp | CVE-2024-45296 | HIGH | ReDoS affecting Express.js |
| micromatch | CVE-2024-4067 | MEDIUM | ReDoS vulnerability |
| cookie | CVE-2024-47764 | MEDIUM | DoS via malformed cookie |

## 📊 Report Formats

### JSON Report
```json
{
  "scan_metadata": {
    "timestamp": "20251001_171600",
    "tool_version": "NPM3Guard v2.2",
    "scan_summary": {
      "platform": "GitHub",
      "total_vulnerabilities": 15,
      "organization_support": true
    }
  },
  "vulnerabilities": [...]
}
```

### HTML Report
- Executive dashboard with vulnerability statistics
- Color-coded severity indicators
- Full file paths for better remediation
- Responsive design for presentations

### CSV Report  
- Spreadsheet-compatible format
- Ideal for data analysis and filtering
- Easy import into vulnerability management systems

## 🔔 Notifications

### Slack Integration
```python
# Configure Slack webhook during setup
slack_webhook = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
```

### Microsoft Teams Integration
```python
# Configure Teams webhook during setup  
teams_webhook = "https://outlook.office.com/webhook/YOUR/TEAMS/WEBHOOK"
```

## ⚙️ Configuration Options

### Interactive Configuration
When you run the tool, you'll be prompted to configure:

- **Rate Limiting** (1-2 seconds recommended for GitHub)
- **Concurrent Workers** (5-10 for enterprise environments)
- **Report Format** (JSON/CSV/HTML)
- **Notification Webhooks** (Slack/Teams)
- **Recursive Scanning** (enabled by default)

### Advanced Configuration
For programmatic use, modify the `ScanConfig` class:

```python
config = ScanConfig(
    rate_limit_delay=1.5,
    max_workers=8,
    report_format="html",
    slack_webhook="https://hooks.slack.com/services/...",
    recursive_scan=True
)
```

## 🎯 Use Cases for VAPT Teams

### 1. Client Repository Assessment
```bash
# Scan entire client organization
python npm3guard.py
# Input: client-org-name
# Token: Your GitHub PAT with org access
```

### 2. Compliance Auditing
- Generate HTML reports for executive presentations
- CSV exports for vulnerability tracking spreadsheets
- Complete audit trails for regulatory compliance

### 3. Continuous Monitoring
- Set up scheduled scans with cron jobs
- Real-time Slack/Teams alerts for new vulnerabilities
- Integration with SIEM systems via JSON reports

### 4. Penetration Testing
- Identify vulnerable dependencies for exploit development
- Map attack surfaces across complex multi-repo projects
- Document findings with full file path context

## 🚨 Troubleshooting

### Common Issues

#### "0 repositories found"
- **Check organization name spelling** - Ensure exact match
- **Verify token permissions** - Token needs `repo` and `read:org` scopes
- **Test token manually** - Try `curl -H "Authorization: Bearer ghp_..." https://api.github.com/user`

#### Rate Limiting
- **Increase delay** - Set rate_limit_delay to 2+ seconds
- **Reduce workers** - Lower max_workers to 3-5
- **Check quotas** - GitHub allows 5000 requests/hour for authenticated users

#### Authentication Errors
- **Token format** - Ensure token starts with `ghp_` for GitHub
- **Scope permissions** - Private repos require `repo` scope
- **Token expiration** - Check if token is still valid

### Debug Mode

Enable detailed logging:

```python
config = ScanConfig(
    log_level="DEBUG",
    enable_logging=True
)
```

## 📈 Performance Optimization

### For Large Organizations

```python
config = ScanConfig(
    rate_limit_delay=0.5,    # Faster for enterprise GitHub
    max_workers=15,          # More concurrent processing
    timeout=60,              # Longer timeout for large repos
    retries=5                # More resilient to failures
)
```

### For Rate-Limited Environments

```python
config = ScanConfig(
    rate_limit_delay=3.0,    # Slower requests
    max_workers=3,           # Less concurrency
    timeout=30,              # Standard timeout
    retries=3                # Standard retries
)
```

## 🔒 Security Considerations

### Token Management
- **Environment Variables** - Store tokens in environment variables
```bash
export GITHUB_TOKEN="ghp_your_token_here"
export GITLAB_TOKEN="glpat_your_token_here"
```

- **Token Rotation** - Regularly rotate access tokens
- **Minimal Permissions** - Use least-privilege principle
- **Secure Storage** - Never commit tokens to repositories

### Network Security
- **TLS Verification** - All API calls use HTTPS with certificate verification
- **Rate Limiting** - Built-in rate limiting prevents API abuse
- **Timeout Handling** - Prevents hanging connections

## 🤝 Contributing

We welcome contributions from the cybersecurity community!

### Development Setup
```bash
git clone https://github.com/your-org/npm3guard.git
cd npm3guard
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### Running Tests
```bash
pytest tests/
```

### Code Style
```bash
black npm3guard.py
flake8 npm3guard.py
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **GitHub Advisory Database** - For vulnerability data
- **OWASP** - For security best practices
- **CVE Program** - For vulnerability identification standards

## 📞 Support

### Community Support
- **GitHub Issues** - [Report bugs and request features](https://github.com/your-org/npm3guard/issues)
- **Discussions** - [Community discussions and Q&A](https://github.com/your-org/npm3guard/discussions)

---

<div align="center">

[Website](https://apnisec.com) • [GitHub](https://github.com/your-org) • [LinkedIn](https://linkedin.com/company/apnisec)

</div>
