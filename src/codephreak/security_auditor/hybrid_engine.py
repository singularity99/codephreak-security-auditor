#!/usr/bin/env python3
"""
CodePhreak Security Auditor - Hybrid Execution Engine

Combines local security scanning with optional cloud-enhanced analysis
based on subscription tier and user preferences.
"""

import asyncio
import json
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime

from .auth import get_auth, SubscriptionTier
from .cloud_client import CloudClient
from .local_scanner import LocalScanner
from .models import ScanResult, Finding, ScanOptions

@dataclass
class HybridScanOptions:
    """Options for hybrid scanning."""
    path: str
    include_cloud_analysis: bool = False
    enable_ai_features: bool = False
    compliance_frameworks: List[str] = None
    custom_rules: List[str] = None
    priority_mode: bool = False
    generate_reports: List[str] = None  # ['json', 'html', 'pdf', 'sarif']
    team_id: Optional[str] = None
    
    def __post_init__(self):
        if self.compliance_frameworks is None:
            self.compliance_frameworks = []
        if self.custom_rules is None:
            self.custom_rules = []
        if self.generate_reports is None:
            self.generate_reports = ['json']

@dataclass
class ScanMetadata:
    """Metadata about the scan execution."""
    scan_id: str
    timestamp: datetime
    local_duration: float
    cloud_duration: Optional[float] = None
    tools_used: List[str] = None
    enhanced_features: List[str] = None
    total_files_scanned: int = 0
    
    def __post_init__(self):
        if self.tools_used is None:
            self.tools_used = []
        if self.enhanced_features is None:
            self.enhanced_features = []

class HybridScanEngine:
    """Hybrid scanning engine that combines local and cloud capabilities."""
    
    def __init__(self):
        self.auth = get_auth()
        self.local_scanner = LocalScanner()
        self.cloud_client = CloudClient()
        
    async def scan(self, options: HybridScanOptions) -> ScanResult:
        """Execute hybrid scan with local and optional cloud analysis."""
        
        # Generate unique scan ID
        scan_id = self._generate_scan_id(options.path)
        start_time = time.time()
        
        # Always run local scan first (free tier)
        print("🔍 Running local security scan...")
        local_start = time.time()
        local_result = await self.local_scanner.scan(ScanOptions(
            path=options.path,
            output_format="json"
        ))
        local_duration = time.time() - local_start
        
        print(f"✅ Local scan completed in {local_duration:.2f}s")
        print(f"   Found {len(local_result.findings)} potential issues")
        
        # Prepare scan metadata
        metadata = ScanMetadata(
            scan_id=scan_id,
            timestamp=datetime.now(),
            local_duration=local_duration,
            tools_used=local_result.tools_used or [],
            total_files_scanned=getattr(local_result, 'files_scanned', 0)
        )
        
        # Check for premium features
        enhanced_result = local_result
        cloud_duration = None
        
        if self._should_use_cloud_features(options):
            try:
                print("☁️ Enhancing with cloud analysis...")
                cloud_start = time.time()
                
                enhanced_result = await self._enhance_with_cloud(
                    local_result, options, scan_id
                )
                
                cloud_duration = time.time() - cloud_start
                metadata.cloud_duration = cloud_duration
                
                print(f"✅ Cloud enhancement completed in {cloud_duration:.2f}s")
                print(f"   Enhanced analysis added {len(enhanced_result.findings) - len(local_result.findings)} insights")
                
            except Exception as e:
                print(f"⚠️ Cloud enhancement failed: {e}")
                print("   Continuing with local results only")
                enhanced_result = local_result
        
        # Add metadata to result
        enhanced_result.metadata = metadata
        
        # Generate reports if requested
        if options.generate_reports and len(options.generate_reports) > 1:
            await self._generate_reports(enhanced_result, options)
        
        total_duration = time.time() - start_time
        print(f"🎉 Scan completed in {total_duration:.2f}s")
        
        return enhanced_result
    
    def _generate_scan_id(self, path: str) -> str:
        """Generate unique scan ID based on path and timestamp."""
        content = f"{path}:{datetime.now().isoformat()}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _should_use_cloud_features(self, options: HybridScanOptions) -> bool:
        """Determine if cloud features should be used."""
        
        # User explicitly disabled cloud features
        if not options.include_cloud_analysis:
            return False
        
        # Check if user has API key configured
        if not self.auth.get_api_key():
            return False
        
        # Check subscription tier for cloud features
        tier = self.auth.get_tier()
        if tier == SubscriptionTier.FREE:
            return False
        
        # Check for specific premium features requested
        premium_features_requested = [
            options.enable_ai_features and "ai_analysis",
            options.compliance_frameworks and "compliance_reports", 
            options.priority_mode and "priority_scanning",
            options.custom_rules and "advanced_rules"
        ]
        
        # If any premium features requested, validate access
        for feature in premium_features_requested:
            if feature and not self.auth.is_premium_feature(feature):
                print(f"⚠️ Premium feature '{feature}' not available in {tier.value} tier")
                return False
        
        return True
    
    async def _enhance_with_cloud(
        self, 
        local_result: ScanResult, 
        options: HybridScanOptions,
        scan_id: str
    ) -> ScanResult:
        """Enhance local results with cloud analysis."""
        
        enhanced_features = []
        
        # Prepare scan summary for cloud analysis (no code sent)
        scan_summary = self._create_scan_summary(local_result, options.path)
        
        # AI-powered vulnerability analysis
        if options.enable_ai_features and self.auth.is_premium_feature("ai_analysis"):
            ai_insights = await self.cloud_client.analyze_with_ai(scan_summary, scan_id)
            if ai_insights:
                local_result.findings.extend(ai_insights.get("findings", []))
                enhanced_features.append("ai_analysis")
        
        # Compliance framework analysis
        if options.compliance_frameworks and self.auth.is_premium_feature("compliance_reports"):
            compliance_results = await self.cloud_client.check_compliance(
                scan_summary, options.compliance_frameworks, scan_id
            )
            if compliance_results:
                local_result.compliance_results = compliance_results
                enhanced_features.append("compliance_reports")
        
        # Vulnerability trend analysis
        if self.auth.is_premium_feature("vulnerability_trends"):
            trends = await self.cloud_client.get_vulnerability_trends(
                scan_summary, scan_id
            )
            if trends:
                local_result.trends = trends
                enhanced_features.append("vulnerability_trends")
        
        # Priority scoring
        if options.priority_mode and self.auth.is_premium_feature("priority_scanning"):
            priorities = await self.cloud_client.calculate_priorities(
                scan_summary, scan_id
            )
            if priorities:
                self._apply_priority_scores(local_result, priorities)
                enhanced_features.append("priority_scanning")
        
        # Auto-remediation suggestions
        if self.auth.is_premium_feature("auto_remediation"):
            remediation = await self.cloud_client.suggest_remediation(
                scan_summary, scan_id
            )
            if remediation:
                self._add_remediation_suggestions(local_result, remediation)
                enhanced_features.append("auto_remediation")
        
        # Update metadata
        if hasattr(local_result, 'metadata'):
            local_result.metadata.enhanced_features = enhanced_features
        
        return local_result
    
    def _create_scan_summary(self, result: ScanResult, scan_path: str) -> Dict[str, Any]:
        """Create anonymized scan summary for cloud analysis."""
        
        # Create summary without exposing source code
        summary = {
            "scan_metadata": {
                "path_hash": hashlib.sha256(scan_path.encode()).hexdigest()[:16],
                "file_count": getattr(result, 'files_scanned', 0),
                "language_stats": getattr(result, 'language_stats', {}),
                "scan_timestamp": datetime.now().isoformat()
            },
            "findings_summary": [
                {
                    "tool": finding.tool,
                    "severity": finding.severity,
                    "category": finding.category,
                    "rule_id": finding.rule_id,
                    "cwe_id": getattr(finding, 'cwe_id', None),
                    "file_extension": Path(finding.file_path).suffix if finding.file_path else None
                }
                for finding in result.findings
            ],
            "tool_stats": {
                "tools_used": result.tools_used or [],
                "total_findings": len(result.findings),
                "severity_breakdown": self._get_severity_breakdown(result.findings)
            }
        }
        
        return summary
    
    def _get_severity_breakdown(self, findings: List[Finding]) -> Dict[str, int]:
        """Get breakdown of findings by severity."""
        breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in findings:
            severity = finding.severity.upper()
            if severity in breakdown:
                breakdown[severity] += 1
        return breakdown
    
    def _apply_priority_scores(self, result: ScanResult, priorities: Dict[str, Any]) -> None:
        """Apply priority scores to findings."""
        priority_map = priorities.get("finding_priorities", {})
        
        for finding in result.findings:
            finding_key = f"{finding.tool}:{finding.rule_id}"
            if finding_key in priority_map:
                finding.priority_score = priority_map[finding_key]
        
        # Sort findings by priority score (highest first)
        result.findings.sort(key=lambda f: getattr(f, 'priority_score', 0), reverse=True)
    
    def _add_remediation_suggestions(self, result: ScanResult, remediation: Dict[str, Any]) -> None:
        """Add remediation suggestions to findings."""
        suggestions = remediation.get("suggestions", {})
        
        for finding in result.findings:
            finding_key = f"{finding.rule_id}"
            if finding_key in suggestions:
                finding.remediation = suggestions[finding_key]
    
    async def _generate_reports(self, result: ScanResult, options: HybridScanOptions) -> None:
        """Generate various report formats."""
        
        for report_format in options.generate_reports:
            if report_format == "json":
                continue  # Already in JSON format
            
            if report_format == "html" and self.auth.is_premium_feature("html_reports"):
                await self._generate_html_report(result, options)
            
            elif report_format == "pdf" and self.auth.is_premium_feature("pdf_reports"):
                await self._generate_pdf_report(result, options)
            
            elif report_format == "sarif":
                await self._generate_sarif_report(result, options)
    
    async def _generate_html_report(self, result: ScanResult, options: HybridScanOptions) -> None:
        """Generate HTML report (Premium feature)."""
        # Implementation would generate rich HTML report
        print("📄 Generating HTML report...")
    
    async def _generate_pdf_report(self, result: ScanResult, options: HybridScanOptions) -> None:
        """Generate PDF report (Premium feature)."""
        # Implementation would generate PDF report
        print("📄 Generating PDF report...")
    
    async def _generate_sarif_report(self, result: ScanResult, options: HybridScanOptions) -> None:
        """Generate SARIF report."""
        # Implementation would generate SARIF format report
        print("📄 Generating SARIF report...")
    
    def get_available_features(self) -> Dict[str, bool]:
        """Get list of available features based on subscription."""
        all_features = [
            "basic_scanning", "json_reports", "sarif_reports", "html_reports", 
            "pdf_reports", "ai_analysis", "compliance_reports", "priority_scanning",
            "vulnerability_trends", "auto_remediation", "team_collaboration"
        ]
        
        return {
            feature: self.auth.is_premium_feature(feature)
            for feature in all_features
        }
    
    async def validate_premium_features(self, options: HybridScanOptions) -> List[str]:
        """Validate requested premium features and return unavailable ones."""
        unavailable = []
        
        if options.enable_ai_features and not self.auth.is_premium_feature("ai_analysis"):
            unavailable.append("ai_analysis")
        
        if options.compliance_frameworks and not self.auth.is_premium_feature("compliance_reports"):
            unavailable.append("compliance_reports")
        
        if options.priority_mode and not self.auth.is_premium_feature("priority_scanning"):
            unavailable.append("priority_scanning")
        
        if "html" in options.generate_reports and not self.auth.is_premium_feature("html_reports"):
            unavailable.append("html_reports")
        
        if "pdf" in options.generate_reports and not self.auth.is_premium_feature("pdf_reports"):
            unavailable.append("pdf_reports")
        
        return unavailable
