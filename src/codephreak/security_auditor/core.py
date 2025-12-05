"""
CodePhreak Security Auditor Droid Core

Main orchestration engine for security vulnerability scanning using open source tools.
"""

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from rich.progress import Progress

from .config import Config
from .models import SecurityResults, Vulnerability, ScanContext
from .tools import ToolRegistry, ToolExecutor
from .utils.tech_stack import TechnologyStackDetector
from .utils.normalizer import ResultsNormalizer
from .utils.prioritizer import VulnerabilityPrioritizer
from .utils.deduplicator import VulnerabilityDeduplicator
from .reporting import ReportGenerator


logger = logging.getLogger(__name__)


@dataclass
class ExecutionMetrics:
    """Metrics for audit execution tracking"""
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    total_duration: Optional[float] = None
    tool_executions: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    findings_count: int = 0
    tools_succeeded: int = 0
    tools_failed: int = 0
    
    def mark_completed(self):
        self.end_time = time.time()
        self.total_duration = self.end_time - self.start_time


class SecurityAuditorDroid:
    """
    Main Security Auditor Droid class that orchestrates comprehensive security scanning
    using multiple open source tools across different security domains.
    """
    
    def __init__(
        self, 
        target_path: Path,
        config: Optional[Config] = None,
        workflow_type: str = "full-audit",
        compliance_framework: Optional[str] = None
    ):
        self.target_path = target_path.resolve()
        self.config = config or Config()
        self.workflow_type = workflow_type
        self.compliance_framework = compliance_framework
        
        # Initialize components
        self.tool_registry = ToolRegistry()
        self.tool_executor = ToolExecutor()
        self.tech_detector = TechnologyStackDetector()
        self.normalizer = ResultsNormalizer()
        self.prioritizer = VulnerabilityPrioritizer()
        self.deduplicator = VulnerabilityDeduplicator()
        self.report_generator = ReportGenerator()
        
        # Execution tracking
        self.metrics = ExecutionMetrics()
        self.scan_context = None
        
        logger.info(f"Initialized SecurityAuditorDroid for target: {self.target_path}")
    
    async def execute(self) -> SecurityResults:
        """Execute the main security audit workflow"""
        logger.info(f"Starting {self.workflow_type} workflow")
        
        try:
            # Phase 1: Discovery and setup
            await self._setup_scan_context()
            
            # Phase 2: Execute security scans based on workflow
            raw_results = await self._execute_workflow()
            
            # Phase 3: Process and consolidate results
            processed_results = await self._process_results(raw_results)
            
            # Phase 4: Generate final security results
            security_results = await self._finalize_results(processed_results)
            
            self.metrics.mark_completed()
            logger.info(f"Audit completed in {self.metrics.total_duration:.2f} seconds")
            
            return security_results
            
        except Exception as e:
            logger.error(f"Audit execution failed: {e}")
            self.metrics.mark_completed()
            raise
    
    async def execute_with_progress(self, progress: Progress, main_task) -> SecurityResults:
        """Execute audit with rich progress tracking"""
        
        # Phase 1: Discovery (10% of progress)
        progress.update(main_task, completed=5, description="🔍 Discovering technology stack...")
        await self._setup_scan_context()
        progress.update(main_task, completed=10, description="✅ Discovery completed")
        
        # Phase 2: Security scanning (70% of progress)
        progress.update(main_task, completed=15, description="🔒 Running security scans...")
        raw_results = await self._execute_workflow_with_progress(progress, main_task, start_percent=15, end_percent=85)
        
        # Phase 3: Processing results (15% of progress)
        progress.update(main_task, completed=85, description="⚙️ Processing results...")
        processed_results = await self._process_results(raw_results)
        progress.update(main_task, completed=90, description="📊 Prioritizing vulnerabilities...")
        
        # Phase 4: Finalization (10% of progress)
        progress.update(main_task, completed=95, description="📋 Finalizing report...")
        security_results = await self._finalize_results(processed_results)
        
        self.metrics.mark_completed()
        return security_results
    
    async def _setup_scan_context(self) -> None:
        """Set up scan context with technology stack detection"""
        logger.debug("Setting up scan context")
        
        # Detect technology stack
        tech_stack = await self.tech_detector.detect(self.target_path)
        
        # Create scan context
        self.scan_context = ScanContext(
            target_path=self.target_path,
            technology_stack=tech_stack,
            workflow_type=self.workflow_type,
            compliance_framework=self.compliance_framework,
            start_time=datetime.now()
        )
        
        logger.info(f"Detected technology stack: {', '.join(tech_stack.languages)}")
        logger.debug(f"Scan context: {self.scan_context}")
    
    async def _execute_workflow(self) -> Dict[str, Any]:
        """Execute the selected security workflow"""
        workflows = {
            "quick-check": self._execute_quick_check,
            "full-audit": self._execute_full_audit,
            "compliance": self._execute_compliance_audit
        }
        
        workflow_func = workflows.get(self.workflow_type, self._execute_full_audit)
        return await workflow_func()
    
    async def _execute_workflow_with_progress(
        self, 
        progress: Progress, 
        main_task, 
        start_percent: int, 
        end_percent: int
    ) -> Dict[str, Any]:
        """Execute workflow with progress updates"""
        workflows = {
            "quick-check": self._execute_quick_check_with_progress,
            "full-audit": self._execute_full_audit_with_progress,
            "compliance": self._execute_compliance_audit_with_progress
        }
        
        workflow_func = workflows.get(self.workflow_type, self._execute_full_audit_with_progress)
        return await workflow_func(progress, main_task, start_percent, end_percent)
    
    async def _execute_quick_check(self) -> Dict[str, Any]:
        """Execute quick security check workflow (5-10 minutes)"""
        logger.info("Executing quick security check")
        
        # Select essential tools for quick scan
        tools_to_run = [
            # Critical secrets detection
            ("gitleaks", "secrets"),
            # High-risk dependencies 
            ("trivy", "sca") if self.scan_context.technology_stack.has_containers else ("npm-audit", "sca"),
            # OWASP Top 10 patterns
            ("semgrep", "sast"),
        ]
        
        # Add container security if Docker is detected
        if self.scan_context.technology_stack.has_containers:
            tools_to_run.append(("hadolint", "containers"))
        
        return await self._execute_tools(tools_to_run)
    
    async def _execute_quick_check_with_progress(
        self, 
        progress: Progress, 
        main_task,
        start_percent: int, 
        end_percent: int
    ) -> Dict[str, Any]:
        """Execute quick check with progress tracking"""
        
        tools_to_run = [
            ("gitleaks", "secrets", "🔐 Scanning for secrets..."),
            ("trivy", "sca", "📦 Checking dependencies..."),
            ("semgrep", "sast", "🔍 Analyzing code patterns..."),
        ]
        
        if self.scan_context.technology_stack.has_containers:
            tools_to_run.append(("hadolint", "containers", "🐳 Scanning containers..."))
        
        return await self._execute_tools_with_progress(
            tools_to_run, progress, main_task, start_percent, end_percent
        )
    
    async def _execute_full_audit(self) -> Dict[str, Any]:
        """Execute comprehensive security audit (15-30 minutes)"""
        logger.info("Executing full security audit")
        
        # Build comprehensive tool list based on detected technology
        tools_to_run = []
        
        # 1. Static Code Analysis (SAST)
        tools_to_run.append(("semgrep", "sast"))  # Universal scanner
        
        # Language-specific SAST tools
        tech_stack = self.scan_context.technology_stack
        if tech_stack.has_python:
            tools_to_run.append(("bandit", "sast"))
        if tech_stack.has_javascript:
            tools_to_run.append(("eslint", "sast"))
        if tech_stack.has_java:
            tools_to_run.append(("spotbugs", "sast"))
        if tech_stack.has_go:
            tools_to_run.append(("gosec", "sast"))
        
        # 2. Software Composition Analysis (SCA)
        tools_to_run.extend([
            ("trivy", "sca"),  # Comprehensive scanner
            ("owasp-dependency-check", "sca"),  # Multi-language
        ])
        
        # Native package manager audits
        if tech_stack.has_nodejs and (self.target_path / "package.json").exists():
            tools_to_run.append(("npm-audit", "sca"))
        if tech_stack.has_python and (self.target_path / "requirements.txt").exists():
            tools_to_run.append(("pip-audit", "sca"))
        
        # 3. Secret Detection
        tools_to_run.extend([
            ("gitleaks", "secrets"),
            ("trufflehog", "secrets"),
            ("detect-secrets", "secrets"),
        ])
        
        # 4. Infrastructure as Code (IaC)
        if tech_stack.has_terraform:
            tools_to_run.extend([("checkov", "iac"), ("tfsec", "iac")])
        if tech_stack.has_kubernetes:
            tools_to_run.extend([("checkov", "iac"), ("kubescape", "iac")])
        if tech_stack.has_containers:
            tools_to_run.extend([("checkov", "iac"), ("hadolint", "containers")])
        
        # 5. Container Security
        if tech_stack.has_containers:
            tools_to_run.extend([
                ("trivy", "containers"),
                ("docker-bench", "containers")
            ])
        
        return await self._execute_tools(tools_to_run)
    
    async def _execute_full_audit_with_progress(
        self, 
        progress: Progress, 
        main_task,
        start_percent: int, 
        end_percent: int
    ) -> Dict[str, Any]:
        """Execute full audit with progress tracking"""
        
        # Build tool list with progress descriptions
        tools_to_run = [
            ("semgrep", "sast", "🔍 Universal code analysis..."),
            ("trivy", "sca", "📦 Comprehensive dependency scan..."),
            ("gitleaks", "secrets", "🔐 Deep secret detection..."),
            ("checkov", "iac", "🏗️ Infrastructure security..."),
        ]
        
        tech_stack = self.scan_context.technology_stack
        
        # Add language-specific tools
        if tech_stack.has_python:
            tools_to_run.append(("bandit", "sast", "🐍 Python security analysis..."))
        if tech_stack.has_javascript:
            tools_to_run.append(("eslint", "sast", "📜 JavaScript security linting..."))
        if tech_stack.has_containers:
            tools_to_run.append(("hadolint", "containers", "🐳 Docker security scan..."))
        
        return await self._execute_tools_with_progress(
            tools_to_run, progress, main_task, start_percent, end_percent
        )
    
    async def _execute_compliance_audit(self) -> Dict[str, Any]:
        """Execute compliance-focused security audit"""
        logger.info(f"Executing compliance audit for {self.compliance_framework}")
        
        # Execute full audit first
        results = await self._execute_full_audit()
        
        # Add compliance-specific scans
        compliance_tools = []
        
        if self.compliance_framework in ["pci-dss", "owasp-asvs"]:
            compliance_tools.extend([
                ("checkov", "iac"),  # With compliance-specific rules
                ("kubescape", "iac")  # With compliance frameworks
            ])
        
        if compliance_tools:
            compliance_results = await self._execute_tools(compliance_tools)
            # Merge with existing results
            for tool_name, tool_results in compliance_results.items():
                results[f"{tool_name}_compliance"] = tool_results
        
        return results
    
    async def _execute_compliance_audit_with_progress(
        self, 
        progress: Progress, 
        main_task,
        start_percent: int, 
        end_percent: int
    ) -> Dict[str, Any]:
        """Execute compliance audit with progress tracking"""
        
        # Execute full audit with 80% of progress allocation
        full_audit_end = start_percent + int((end_percent - start_percent) * 0.8)
        results = await self._execute_full_audit_with_progress(
            progress, main_task, start_percent, full_audit_end
        )
        
        # Compliance-specific scans for remaining 20%
        compliance_tools = [
            ("checkov", "iac", f"📋 {self.compliance_framework.upper()} compliance..."),
        ]
        
        if compliance_tools:
            progress.update(main_task, completed=full_audit_end, description="🏛️ Compliance assessment...")
            compliance_results = await self._execute_tools_with_progress(
                compliance_tools, progress, main_task, full_audit_end, end_percent
            )
            
            # Merge results
            for tool_name, tool_results in compliance_results.items():
                results[f"{tool_name}_compliance"] = tool_results
        
        return results
    
    async def _execute_tools(self, tools_to_run: List[Tuple[str, str]]) -> Dict[str, Any]:
        """Execute a list of security tools"""
        results = {}
        
        # Create semaphore for concurrency control
        max_concurrent = self.config.execution.max_concurrent_tools
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def execute_single_tool(tool_name: str, category: str) -> Tuple[str, Any]:
            async with semaphore:
                start_time = time.time()
                try:
                    logger.debug(f"Executing {tool_name} ({category})")
                    
                    result = await self.tool_executor.execute_tool(
                        tool_name,
                        target_path=self.target_path,
                        scan_context=self.scan_context
                    )
                    
                    execution_time = time.time() - start_time
                    self.metrics.tool_executions[tool_name] = {
                        "category": category,
                        "status": "success",
                        "execution_time": execution_time,
                        "findings_count": len(result.get("findings", [])),
                    }
                    self.metrics.tools_succeeded += 1
                    
                    logger.info(f"✅ {tool_name} completed in {execution_time:.2f}s")
                    return tool_name, result
                    
                except Exception as e:
                    execution_time = time.time() - start_time
                    self.metrics.tool_executions[tool_name] = {
                        "category": category,
                        "status": "failed",
                        "execution_time": execution_time,
                        "error": str(e),
                    }
                    self.metrics.tools_failed += 1
                    
                    logger.error(f"❌ {tool_name} failed after {execution_time:.2f}s: {e}")
                    return tool_name, {"status": "failed", "error": str(e), "findings": []}
        
        # Execute tools concurrently
        tasks = [
            execute_single_tool(tool_name, category) 
            for tool_name, category in tools_to_run
        ]
        
        tool_results = await asyncio.gather(*tasks)
        
        # Collect results
        for tool_name, result in tool_results:
            results[tool_name] = result
        
        return results
    
    async def _execute_tools_with_progress(
        self,
        tools_to_run: List[Tuple[str, str, str]],  # (tool_name, category, description)
        progress: Progress,
        main_task,
        start_percent: int,
        end_percent: int
    ) -> Dict[str, Any]:
        """Execute tools with progress tracking"""
        
        results = {}
        total_tools = len(tools_to_run)
        progress_per_tool = (end_percent - start_percent) / total_tools if total_tools > 0 else 0
        
        # Execute tools sequentially for better progress tracking
        for i, (tool_name, category, description) in enumerate(tools_to_run):
            current_progress = start_percent + (i * progress_per_tool)
            progress.update(main_task, completed=int(current_progress), description=description)
            
            start_time = time.time()
            try:
                result = await self.tool_executor.execute_tool(
                    tool_name,
                    target_path=self.target_path,
                    scan_context=self.scan_context
                )
                
                execution_time = time.time() - start_time
                self.metrics.tool_executions[tool_name] = {
                    "category": category,
                    "status": "success",
                    "execution_time": execution_time,
                    "findings_count": len(result.get("findings", [])),
                }
                self.metrics.tools_succeeded += 1
                results[tool_name] = result
                
            except Exception as e:
                execution_time = time.time() - start_time
                self.metrics.tool_executions[tool_name] = {
                    "category": category,
                    "status": "failed",
                    "execution_time": execution_time,
                    "error": str(e),
                }
                self.metrics.tools_failed += 1
                results[tool_name] = {"status": "failed", "error": str(e), "findings": []}
        
        return results
    
    async def _process_results(self, raw_results: Dict[str, Any]) -> List[Vulnerability]:
        """Process and normalize raw tool results"""
        logger.debug("Processing raw results")
        
        all_vulnerabilities = []
        
        # Normalize results from each tool
        for tool_name, tool_result in raw_results.items():
            if tool_result.get("status") == "failed":
                continue
                
            try:
                normalized_vulns = await self.normalizer.normalize_tool_results(
                    tool_name, tool_result, self.scan_context
                )
                all_vulnerabilities.extend(normalized_vulns)
                
            except Exception as e:
                logger.error(f"Failed to normalize results from {tool_name}: {e}")
        
        # Deduplicate similar vulnerabilities
        deduplicated_vulns = await self.deduplicator.deduplicate(all_vulnerabilities)
        
        # Prioritize vulnerabilities
        prioritized_vulns = await self.prioritizer.prioritize(
            deduplicated_vulns, self.scan_context
        )
        
        self.metrics.findings_count = len(prioritized_vulns)
        logger.info(f"Processed {len(all_vulnerabilities)} raw findings into {len(prioritized_vulns)} unique vulnerabilities")
        
        return prioritized_vulns
    
    async def _finalize_results(self, vulnerabilities: List[Vulnerability]) -> SecurityResults:
        """Create final SecurityResults object"""
        logger.debug("Finalizing security results")
        
        return SecurityResults(
            scan_context=self.scan_context,
            vulnerabilities=vulnerabilities,
            execution_metrics=self.metrics,
            generated_at=datetime.now()
        )
    
    async def generate_reports(
        self,
        results: SecurityResults,
        formats: List[str],
        output_path: Optional[Path] = None
    ) -> Dict[str, Path]:
        """Generate security reports in specified formats"""
        logger.info(f"Generating reports in formats: {formats}")
        
        return await self.report_generator.generate_reports(
            results=results,
            formats=formats,
            output_path=output_path or (self.target_path / "security-reports"),
            config=self.config
        )
