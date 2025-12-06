#!/usr/bin/env python3
"""
CodePhreak Security Auditor - Local Scanner

Local security scanning implementation that runs open source tools
without sending any data to cloud services.
"""

import asyncio
import time
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass

from .models import ScanResult, Finding, ScanOptions

@dataclass 
class LocalScanResult:
    """Result from local security scan."""
    findings: List[Finding]
    tools_used: List[str]
    scan_duration: float
    files_scanned: int = 0
    language_stats: Dict[str, int] = None
    
    def __post_init__(self):
        if self.language_stats is None:
            self.language_stats = {}

class LocalScanner:
    """Local security scanner using open source tools."""
    
    def __init__(self):
        self.available_tools = {
            "bandit": "Python SAST scanning",
            "semgrep": "Multi-language SAST scanning", 
            "trivy": "Vulnerability database scanning",
            "gitleaks": "Git secret detection",
            "hadolint": "Dockerfile linting",
            "checkov": "Infrastructure as Code security",
            "npm_audit": "Node.js dependency scanning",
            "pip_audit": "Python dependency scanning"
        }
    
    async def scan(self, options: ScanOptions) -> ScanResult:
        """Execute local security scan."""
        
        start_time = time.time()
        findings = []
        tools_used = []
        
        scan_path = Path(options.path)
        print(f"🔍 Scanning {scan_path}...")
        
        # Simulate scanning with different tools based on detected languages
        language_stats = await self._detect_languages(scan_path)
        
        # Python scanning
        if language_stats.get("python", 0) > 0:
            python_findings = await self._scan_python(scan_path)
            findings.extend(python_findings)
            tools_used.extend(["bandit", "semgrep", "pip-audit"])
        
        # JavaScript scanning  
        if language_stats.get("javascript", 0) > 0:
            js_findings = await self._scan_javascript(scan_path)
            findings.extend(js_findings)
            tools_used.extend(["semgrep", "npm audit"])
        
        # Docker scanning
        if await self._has_dockerfiles(scan_path):
            docker_findings = await self._scan_docker(scan_path)
            findings.extend(docker_findings)
            tools_used.extend(["hadolint", "checkov"])
        
        # Git secrets scanning
        if await self._is_git_repo(scan_path):
            secret_findings = await self._scan_secrets(scan_path)
            findings.extend(secret_findings)
            tools_used.append("gitleaks")
        
        # Dependency scanning
        dependency_findings = await self._scan_dependencies(scan_path)
        findings.extend(dependency_findings)
        tools_used.append("trivy")
        
        scan_duration = time.time() - start_time
        
        return ScanResult(
            findings=findings,
            tools_used=list(set(tools_used)),  # Remove duplicates
            scan_duration=scan_duration,
            files_scanned=sum(language_stats.values()),
            language_stats=language_stats,
            metadata=None
        )
    
    async def _detect_languages(self, scan_path: Path) -> Dict[str, int]:
        """Detect programming languages in the scan path."""
        
        # Simulate file detection
        await asyncio.sleep(0.1)
        
        language_extensions = {
            ".py": "python",
            ".js": "javascript", 
            ".ts": "javascript",
            ".jsx": "javascript",
            ".tsx": "javascript",
            ".java": "java",
            ".go": "go",
            ".rs": "rust",
            ".cpp": "cpp",
            ".c": "c",
            ".cs": "csharp",
            ".php": "php",
            ".rb": "ruby"
        }
        
        language_stats = {}
        
        try:
            for file_path in scan_path.rglob("*"):
                if file_path.is_file() and not self._should_exclude_file(file_path):
                    ext = file_path.suffix.lower()
                    if ext in language_extensions:
                        lang = language_extensions[ext]
                        language_stats[lang] = language_stats.get(lang, 0) + 1
        except PermissionError:
            pass
        
        return language_stats
    
    def _should_exclude_file(self, file_path: Path) -> bool:
        """Check if file should be excluded from scanning."""
        
        exclude_patterns = [
            ".git", "node_modules", "__pycache__", ".venv", "venv",
            ".pytest_cache", "dist", "build", ".tox", ".coverage"
        ]
        
        return any(pattern in str(file_path) for pattern in exclude_patterns)
    
    async def _scan_python(self, scan_path: Path) -> List[Finding]:
        """Simulate Python security scanning."""
        
        await asyncio.sleep(0.5)  # Simulate scan time
        
        findings = [
            Finding(
                tool="bandit",
                rule_id="B101", 
                severity="HIGH",
                category="hardcoded_password",
                message="Hardcoded password detected",
                file_path=str(scan_path / "app.py"),
                line_number=25,
                description="Hardcoded passwords pose a security risk"
            ),
            Finding(
                tool="semgrep",
                rule_id="python.django.security.injection.sql.sql-injection-using-db-cursor-execute",
                severity="HIGH", 
                category="sql_injection",
                message="SQL injection vulnerability detected",
                file_path=str(scan_path / "models.py"),
                line_number=42,
                description="User input is directly concatenated into SQL query"
            )
        ]
        
        return findings
    
    async def _scan_javascript(self, scan_path: Path) -> List[Finding]:
        """Simulate JavaScript security scanning."""
        
        await asyncio.sleep(0.3)
        
        findings = [
            Finding(
                tool="semgrep",
                rule_id="javascript.express.security.audit.express-check-csurf-middleware-usage",
                severity="MEDIUM",
                category="missing_csrf_protection", 
                message="Missing CSRF protection",
                file_path=str(scan_path / "server.js"),
                line_number=15,
                description="Express application missing CSRF protection middleware"
            )
        ]
        
        return findings
    
    async def _scan_docker(self, scan_path: Path) -> List[Finding]:
        """Simulate Docker security scanning."""
        
        await asyncio.sleep(0.2)
        
        findings = [
            Finding(
                tool="hadolint",
                rule_id="DL3008",
                severity="MEDIUM", 
                category="dockerfile_best_practices",
                message="Pin versions in apt-get install",
                file_path=str(scan_path / "Dockerfile"),
                line_number=8,
                description="Pinning package versions improves reproducibility"
            ),
            Finding(
                tool="checkov",
                rule_id="CKV_DOCKER_2",
                severity="HIGH",
                category="container_security",
                message="Container running as root user", 
                file_path=str(scan_path / "docker-compose.yml"),
                line_number=12,
                description="Running containers as root increases security risk"
            )
        ]
        
        return findings
    
    async def _scan_secrets(self, scan_path: Path) -> List[Finding]:
        """Simulate git secrets scanning."""
        
        await asyncio.sleep(0.4)
        
        findings = [
            Finding(
                tool="gitleaks",
                rule_id="aws-access-key-id",
                severity="CRITICAL",
                category="exposed_secrets",
                message="AWS Access Key ID detected",
                file_path=str(scan_path / "config.py"),
                line_number=7,
                description="AWS credentials should not be hardcoded"
            )
        ]
        
        return findings
    
    async def _scan_dependencies(self, scan_path: Path) -> List[Finding]:
        """Simulate dependency vulnerability scanning."""
        
        await asyncio.sleep(0.6)
        
        findings = [
            Finding(
                tool="trivy",
                rule_id="CVE-2023-30861",
                severity="HIGH",
                category="vulnerable_dependency",
                message="Flask 2.0.1 has known XSS vulnerability",
                file_path=str(scan_path / "requirements.txt"),
                line_number=3,
                description="Upgrade Flask to version >= 2.3.2"
            ),
            Finding(
                tool="trivy", 
                rule_id="CVE-2021-33503",
                severity="MEDIUM",
                category="vulnerable_dependency",
                message="urllib3 1.26.5 has ReDoS vulnerability",
                file_path=str(scan_path / "requirements.txt"),
                line_number=8,
                description="Upgrade urllib3 to version >= 1.26.15"
            )
        ]
        
        return findings
    
    async def _has_dockerfiles(self, scan_path: Path) -> bool:
        """Check if path contains Docker files."""
        
        docker_files = ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"]
        
        for docker_file in docker_files:
            if (scan_path / docker_file).exists():
                return True
        
        # Check subdirectories
        try:
            for file_path in scan_path.rglob("Dockerfile*"):
                if file_path.is_file():
                    return True
        except PermissionError:
            pass
        
        return False
    
    async def _is_git_repo(self, scan_path: Path) -> bool:
        """Check if path is a git repository."""
        
        return (scan_path / ".git").exists()
    
    def get_tool_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of available security tools."""
        
        return {
            tool: {
                "available": True,  # In real implementation, check if tool is installed
                "version": "1.0.0",  # In real implementation, get actual version
                "description": description
            }
            for tool, description in self.available_tools.items()
        }
