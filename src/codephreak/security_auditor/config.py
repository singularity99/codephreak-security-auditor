"""
CodePhreak Security Auditor Configuration

Configuration management for the Security Auditor Droid with support for
open core functionality and premium SaaS feature flags.
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field, asdict
from enum import Enum

from .utils.logger import get_logger

logger = get_logger(__name__)


class WorkflowType(Enum):
    QUICK_CHECK = "quick-check"
    FULL_AUDIT = "full-audit"
    COMPLIANCE = "compliance"


class OutputFormat(Enum):
    JSON = "json"
    HTML = "html"
    SARIF = "sarif"
    PDF = "pdf"


class ComplianceFramework(Enum):
    OWASP_ASVS = "owasp-asvs"
    PCI_DSS = "pci-dss"
    NIST_CYBERSECURITY = "nist-cybersecurity"
    ISO_27001 = "iso-27001"


@dataclass
class ToolConfig:
    """Configuration for individual security tools"""
    enabled: bool = True
    timeout: int = 600  # 10 minutes default
    retry_count: int = 2
    custom_args: Dict[str, Any] = field(default_factory=dict)
    custom_rules: Optional[str] = None  # Path to custom rules file


@dataclass
class ExecutionConfig:
    """Execution configuration"""
    max_concurrent_tools: int = 3
    global_timeout: int = 1800  # 30 minutes
    fail_fast: bool = False
    continue_on_error: bool = True


@dataclass
class ReportingConfig:
    """Reporting configuration"""
    include_raw_output: bool = False
    include_execution_metrics: bool = True
    executive_summary: bool = True
    compliance_mapping: bool = True
    custom_templates_dir: Optional[Path] = None


@dataclass
class PremiumConfig:
    """Premium/SaaS feature configuration"""
    api_endpoint: str = "https://api.codephreak.ai"
    api_key: Optional[str] = None
    enable_ai_prioritization: bool = False
    enable_hosted_scanning: bool = False
    enable_team_features: bool = False
    organization_id: Optional[str] = None
    
    def is_premium_enabled(self) -> bool:
        """Check if premium features are available"""
        return self.api_key is not None and self.organization_id is not None


@dataclass
class WorkflowConfig:
    """Workflow-specific configuration"""
    tools: Dict[str, List[str]] = field(default_factory=lambda: {
        "sast": ["semgrep", "bandit", "eslint"],
        "sca": ["trivy", "npm-audit", "pip-audit", "owasp-dependency-check"],
        "secrets": ["gitleaks", "trufflehog", "detect-secrets"],
        "iac": ["checkov", "tfsec", "kubescape"],
        "containers": ["trivy", "hadolint", "docker-bench"]
    })
    exclude_tools: List[str] = field(default_factory=list)
    custom_workflows: Dict[str, Dict[str, Any]] = field(default_factory=dict)


class Config:
    """Main configuration class for CodePhreak Security Auditor"""
    
    def __init__(self, config_path: Optional[Path] = None):
        # Core configuration
        self.execution = ExecutionConfig()
        self.reporting = ReportingConfig()
        self.workflows = WorkflowConfig()
        
        # Premium/SaaS configuration
        self.premium = PremiumConfig()
        
        # Tool-specific configurations
        self.tools: Dict[str, ToolConfig] = self._get_default_tool_configs()
        
        # Rule and policy paths
        self.rules_dir = Path(__file__).parent / "rules"
        self.policies_dir = Path(__file__).parent / "policies"
        self.templates_dir = Path(__file__).parent / "templates"
        
        # Load configuration if provided
        if config_path:
            self.load_from_file(config_path)
        else:
            self.load_from_environment()
    
    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> "Config":
        """Factory method to create Config instance"""
        return cls(config_path)
    
    def load_from_file(self, config_path: Path) -> None:
        """Load configuration from YAML or JSON file"""
        try:
            if not config_path.exists():
                logger.warning(f"Configuration file not found: {config_path}")
                return
            
            with open(config_path, 'r') as f:
                if config_path.suffix.lower() in ['.yml', '.yaml']:
                    config_data = yaml.safe_load(f)
                else:
                    config_data = json.load(f)
            
            self._apply_config_data(config_data)
            logger.info(f"Loaded configuration from {config_path}")
            
        except Exception as e:
            logger.error(f"Failed to load configuration from {config_path}: {e}")
            raise
    
    def load_from_environment(self) -> None:
        """Load configuration from environment variables"""
        
        # Execution configuration
        if os.getenv("CP_MAX_CONCURRENT_TOOLS"):
            self.execution.max_concurrent_tools = int(os.getenv("CP_MAX_CONCURRENT_TOOLS"))
        
        if os.getenv("CP_GLOBAL_TIMEOUT"):
            self.execution.global_timeout = int(os.getenv("CP_GLOBAL_TIMEOUT"))
        
        # Premium/SaaS configuration
        if os.getenv("CODEPHREAK_API_KEY"):
            self.premium.api_key = os.getenv("CODEPHREAK_API_KEY")
        
        if os.getenv("CODEPHREAK_ORG_ID"):
            self.premium.organization_id = os.getenv("CODEPHREAK_ORG_ID")
        
        if os.getenv("CODEPHREAK_API_ENDPOINT"):
            self.premium.api_endpoint = os.getenv("CODEPHREAK_API_ENDPOINT")
        
        # Feature flags from environment
        self.premium.enable_ai_prioritization = os.getenv("CP_ENABLE_AI_PRIORITIZATION", "false").lower() == "true"
        self.premium.enable_hosted_scanning = os.getenv("CP_ENABLE_HOSTED_SCANNING", "false").lower() == "true"
        self.premium.enable_team_features = os.getenv("CP_ENABLE_TEAM_FEATURES", "false").lower() == "true"
    
    def _apply_config_data(self, config_data: Dict[str, Any]) -> None:
        """Apply configuration data from file"""
        
        # Execution configuration
        if "execution" in config_data:
            exec_config = config_data["execution"]
            self.execution.max_concurrent_tools = exec_config.get("max_concurrent_tools", self.execution.max_concurrent_tools)
            self.execution.global_timeout = exec_config.get("global_timeout", self.execution.global_timeout)
            self.execution.fail_fast = exec_config.get("fail_fast", self.execution.fail_fast)
        
        # Reporting configuration
        if "reporting" in config_data:
            report_config = config_data["reporting"]
            self.reporting.include_raw_output = report_config.get("include_raw_output", self.reporting.include_raw_output)
            self.reporting.executive_summary = report_config.get("executive_summary", self.reporting.executive_summary)
        
        # Workflows configuration
        if "workflows" in config_data:
            workflow_config = config_data["workflows"]
            if "tools" in workflow_config:
                self.workflows.tools.update(workflow_config["tools"])
            if "exclude_tools" in workflow_config:
                self.workflows.exclude_tools = workflow_config["exclude_tools"]
        
        # Tool configurations
        if "tools" in config_data:
            for tool_name, tool_config in config_data["tools"].items():
                if tool_name not in self.tools:
                    self.tools[tool_name] = ToolConfig()
                
                self.tools[tool_name].enabled = tool_config.get("enabled", True)
                self.tools[tool_name].timeout = tool_config.get("timeout", 600)
                self.tools[tool_name].custom_args = tool_config.get("custom_args", {})
        
        # Premium configuration
        if "premium" in config_data:
            premium_config = config_data["premium"]
            self.premium.api_key = premium_config.get("api_key", self.premium.api_key)
            self.premium.organization_id = premium_config.get("organization_id", self.premium.organization_id)
    
    def _get_default_tool_configs(self) -> Dict[str, ToolConfig]:
        """Get default tool configurations"""
        return {
            # SAST Tools
            "semgrep": ToolConfig(timeout=900),  # 15 minutes for comprehensive scan
            "bandit": ToolConfig(timeout=300),
            "eslint": ToolConfig(timeout=600),
            "spotbugs": ToolConfig(timeout=1200),  # 20 minutes for Java
            "gosec": ToolConfig(timeout=300),
            
            # SCA Tools
            "trivy": ToolConfig(timeout=600),
            "owasp-dependency-check": ToolConfig(timeout=1200),
            "npm-audit": ToolConfig(timeout=180),
            "pip-audit": ToolConfig(timeout=180),
            "cargo-audit": ToolConfig(timeout=180),
            
            # Secret Detection
            "gitleaks": ToolConfig(timeout=300),
            "trufflehog": ToolConfig(timeout=600),
            "detect-secrets": ToolConfig(timeout=300),
            
            # IaC Security
            "checkov": ToolConfig(timeout=600),
            "tfsec": ToolConfig(timeout=300),
            "kubescape": ToolConfig(timeout=300),
            "terrascan": ToolConfig(timeout=300),
            
            # Container Security
            "hadolint": ToolConfig(timeout=60),
            "docker-bench": ToolConfig(timeout=300),
        }
    
    def get_enabled_tools_for_workflow(self, workflow_type: str) -> Dict[str, List[str]]:
        """Get enabled tools for a specific workflow"""
        workflow_tools = self.workflows.tools.copy()
        
        # Filter out disabled tools
        for category, tools in workflow_tools.items():
            workflow_tools[category] = [
                tool for tool in tools 
                if tool not in self.workflows.exclude_tools 
                and self.tools.get(tool, ToolConfig()).enabled
            ]
        
        return workflow_tools
    
    def get_tool_config(self, tool_name: str) -> ToolConfig:
        """Get configuration for a specific tool"""
        return self.tools.get(tool_name, ToolConfig())
    
    def is_premium_feature_enabled(self, feature: str) -> bool:
        """Check if a premium feature is enabled"""
        if not self.premium.is_premium_enabled():
            return False
        
        feature_flags = {
            "ai_prioritization": self.premium.enable_ai_prioritization,
            "hosted_scanning": self.premium.enable_hosted_scanning,
            "team_features": self.premium.enable_team_features,
        }
        
        return feature_flags.get(feature, False)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            "execution": asdict(self.execution),
            "reporting": asdict(self.reporting),
            "workflows": asdict(self.workflows),
            "premium": asdict(self.premium),
            "tools": {name: asdict(config) for name, config in self.tools.items()}
        }
    
    def generate_sample_config(self, output_path: Path, format: str = "yaml") -> None:
        """Generate a sample configuration file"""
        
        sample_config = {
            "# CodePhreak Security Auditor Configuration": None,
            "# Open Source Core + Premium SaaS Integration": None,
            "": None,
            
            "execution": {
                "max_concurrent_tools": 3,
                "global_timeout": 1800,
                "fail_fast": False,
                "continue_on_error": True
            },
            
            "reporting": {
                "include_raw_output": False,
                "executive_summary": True,
                "compliance_mapping": True,
                "formats": ["json", "html", "sarif"]
            },
            
            "workflows": {
                "full-audit": {
                    "tools": {
                        "sast": ["semgrep", "bandit", "eslint"],
                        "sca": ["trivy", "npm-audit", "pip-audit"],
                        "secrets": ["gitleaks", "trufflehog"],
                        "iac": ["checkov", "tfsec", "kubescape"],
                        "containers": ["trivy", "hadolint"]
                    }
                },
                "quick-check": {
                    "tools": {
                        "sast": ["semgrep"],
                        "sca": ["trivy"],
                        "secrets": ["gitleaks"]
                    }
                }
            },
            
            "tools": {
                "semgrep": {
                    "enabled": True,
                    "timeout": 900,
                    "custom_args": {
                        "config": "auto",
                        "severity": ["ERROR", "WARNING"]
                    }
                },
                "trivy": {
                    "enabled": True,
                    "timeout": 600,
                    "custom_args": {
                        "severity": ["HIGH", "CRITICAL"],
                        "format": "json"
                    }
                }
            },
            
            "# Premium SaaS Features (codephreak.ai)": None,
            "premium": {
                "api_key": "${CODEPHREAK_API_KEY}",
                "organization_id": "${CODEPHREAK_ORG_ID}",
                "api_endpoint": "https://api.codephreak.ai",
                "enable_ai_prioritization": False,
                "enable_hosted_scanning": False,
                "enable_team_features": False
            }
        }
        
        # Remove None values (comments)
        clean_config = {k: v for k, v in sample_config.items() if v is not None}
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if format.lower() == "yaml":
            with open(output_path, 'w') as f:
                yaml.dump(clean_config, f, default_flow_style=False, indent=2)
        else:
            with open(output_path, 'w') as f:
                json.dump(clean_config, f, indent=2)
        
        logger.info(f"Sample configuration generated: {output_path}")
    
    def validate(self) -> List[str]:
        """Validate configuration and return list of issues"""
        issues = []
        
        # Validate execution config
        if self.execution.max_concurrent_tools < 1:
            issues.append("max_concurrent_tools must be at least 1")
        
        if self.execution.global_timeout < 60:
            issues.append("global_timeout must be at least 60 seconds")
        
        # Validate tool timeouts
        for tool_name, tool_config in self.tools.items():
            if tool_config.timeout < 30:
                issues.append(f"{tool_name} timeout must be at least 30 seconds")
        
        # Validate premium config if enabled
        if self.premium.enable_ai_prioritization or self.premium.enable_hosted_scanning:
            if not self.premium.api_key:
                issues.append("Premium features require api_key")
            if not self.premium.organization_id:
                issues.append("Premium features require organization_id")
        
        return issues
