#!/usr/bin/env python3
"""
CodePhreak Security Auditor - Data Models

Core data models for the security auditor system.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from datetime import datetime
from enum import Enum

class SeverityLevel(Enum):
    """Enumeration of vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ConfidenceLevel(Enum):
    """Enumeration of finding confidence levels."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class Finding:
    """Represents a security finding from a tool."""
    tool: str
    rule_id: str
    severity: str
    category: str
    message: str
    file_path: str
    line_number: int
    description: str
    confidence: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: Optional[Dict[str, Any]] = None
    priority_score: Optional[float] = None
    
    def __post_init__(self):
        if self.confidence is None:
            self.confidence = "MEDIUM"

@dataclass
class ScanOptions:
    """Options for configuring a security scan."""
    path: str
    output_format: str = "json"
    include_patterns: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=list)
    severity_filter: Optional[str] = None
    tools_to_run: Optional[List[str]] = None
    timeout: int = 1800  # 30 minutes default

@dataclass
class ComplianceResult:
    """Results from compliance framework checking."""
    framework: str
    score: float
    passed_checks: int
    total_checks: int
    failed_checks: List[str]
    recommendations: List[str] = field(default_factory=list)

@dataclass
class TrendAnalysis:
    """Vulnerability trend analysis data."""
    vulnerability_growth: str
    most_common_categories: List[str]
    risk_trend: str
    historical_comparison: Dict[str, int]
    time_period: str = "30d"

@dataclass
class ScanMetadata:
    """Metadata about a security scan."""
    scan_id: str
    timestamp: datetime
    local_duration: float
    cloud_duration: Optional[float] = None
    tools_used: List[str] = field(default_factory=list)
    enhanced_features: List[str] = field(default_factory=list)
    total_files_scanned: int = 0
    language_stats: Dict[str, int] = field(default_factory=dict)

@dataclass
class ScanResult:
    """Complete results from a security scan."""
    findings: List[Finding]
    tools_used: List[str]
    scan_duration: float
    files_scanned: int = 0
    language_stats: Dict[str, int] = field(default_factory=dict)
    compliance_results: Optional[Dict[str, ComplianceResult]] = None
    trends: Optional[TrendAnalysis] = None
    metadata: Optional[ScanMetadata] = None
    
    def get_severity_count(self, severity: str) -> int:
        """Get count of findings by severity level."""
        return len([f for f in self.findings if f.severity.upper() == severity.upper()])
    
    def get_findings_by_tool(self, tool: str) -> List[Finding]:
        """Get findings from a specific tool."""
        return [f for f in self.findings if f.tool == tool]
    
    def get_findings_by_category(self, category: str) -> List[Finding]:
        """Get findings by category."""
        return [f for f in self.findings if f.category == category]
    
    def get_critical_findings(self) -> List[Finding]:
        """Get all critical severity findings."""
        return [f for f in self.findings if f.severity == "CRITICAL"]
    
    def get_high_priority_findings(self, threshold: float = 0.8) -> List[Finding]:
        """Get findings with high priority scores."""
        return [f for f in self.findings 
                if f.priority_score and f.priority_score >= threshold]
    
    @property
    def total_findings(self) -> int:
        """Total number of findings."""
        return len(self.findings)
    
    @property
    def severity_breakdown(self) -> Dict[str, int]:
        """Breakdown of findings by severity."""
        breakdown = {}
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            breakdown[severity] = self.get_severity_count(severity)
        return breakdown
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            "scan_metadata": {
                "total_findings": self.total_findings,
                "scan_duration": self.scan_duration,
                "files_scanned": self.files_scanned,
                "language_stats": self.language_stats,
                "tools_used": self.tools_used
            },
            "severity_breakdown": self.severity_breakdown,
            "findings": [
                {
                    "tool": f.tool,
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "category": f.category,
                    "message": f.message,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "description": f.description,
                    "confidence": f.confidence,
                    "cwe_id": f.cwe_id,
                    "priority_score": f.priority_score
                }
                for f in self.findings
            ],
            "compliance_results": self.compliance_results,
            "trends": self.trends,
            "metadata": self.metadata
        }

@dataclass
class ToolStatus:
    """Status information for a security tool."""
    name: str
    category: str
    available: bool
    version: Optional[str] = None
    description: Optional[str] = None
    installation_url: Optional[str] = None

@dataclass
class SecurityProfile:
    """Security profile for an application or project."""
    project_name: str
    languages: List[str]
    frameworks: List[str]
    security_tools: List[str]
    compliance_requirements: List[str] = field(default_factory=list)
    risk_level: str = "MEDIUM"
    
@dataclass
class ReportConfiguration:
    """Configuration for report generation."""
    format: str
    output_path: Optional[str] = None
    include_remediation: bool = True
    include_compliance: bool = False
    template_path: Optional[str] = None
    custom_logo: Optional[str] = None

@dataclass
class TeamCollaboration:
    """Team collaboration features data."""
    team_id: str
    dashboard_url: str
    shared_findings: List[Finding]
    team_members: List[str] = field(default_factory=list)
    
@dataclass
class CloudAnalysisRequest:
    """Request structure for cloud analysis services."""
    scan_id: str
    scan_summary: Dict[str, Any]
    analysis_type: str
    options: Dict[str, Any] = field(default_factory=dict)

@dataclass
class CloudAnalysisResponse:
    """Response structure from cloud analysis services."""
    scan_id: str
    analysis_type: str
    findings: List[Finding] = field(default_factory=list)
    insights: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    confidence: float = 1.0

# Type aliases for convenience
FindingsList = List[Finding]
ToolsDict = Dict[str, ToolStatus]
ComplianceDict = Dict[str, ComplianceResult]
