#!/usr/bin/env python3
"""
CodePhreak Security Auditor - Cloud Client

Handles communication with codephreak.ai cloud services for premium features.
Ensures privacy by only sending anonymized scan metadata, never source code.
"""

import asyncio
import json
import aiohttp
import os
from typing import Dict, List, Any, Optional
from datetime import datetime

from .auth import get_auth

class CloudClient:
    """Client for CodePhreak cloud services."""
    
    def __init__(self):
        self.auth = get_auth()
        self.base_url = os.getenv("CODEPHREAK_API_URL", "https://api.codephreak.ai")
        self.timeout = aiohttp.ClientTimeout(total=30)
        
    async def _make_request(
        self, 
        method: str, 
        endpoint: str, 
        data: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """Make authenticated request to cloud API."""
        
        api_key = self.auth.get_api_key()
        if not api_key:
            raise ValueError("No API key configured")
        
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "CodePhreak-Security-Auditor/0.1.0"
        }
        
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.request(
                    method, url, headers=headers, json=data
                ) as response:
                    
                    if response.status == 401:
                        raise PermissionError("Invalid API key")
                    elif response.status == 403:
                        raise PermissionError("Feature not available in current subscription")
                    elif response.status == 429:
                        raise ConnectionError("Rate limit exceeded")
                    elif response.status >= 500:
                        raise ConnectionError("Cloud service temporarily unavailable")
                    elif response.status != 200:
                        raise ConnectionError(f"API request failed with status {response.status}")
                    
                    return await response.json()
                    
        except asyncio.TimeoutError:
            raise ConnectionError("Cloud service request timed out")
        except aiohttp.ClientError as e:
            raise ConnectionError(f"Network error: {e}")
    
    async def analyze_with_ai(
        self, 
        scan_summary: Dict[str, Any], 
        scan_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get AI-powered vulnerability analysis."""
        
        payload = {
            "scan_id": scan_id,
            "scan_summary": scan_summary,
            "analysis_type": "vulnerability_patterns",
            "include_recommendations": True
        }
        
        try:
            result = await self._make_request("POST", "/v1/ai/analyze", payload)
            return result
        except Exception as e:
            print(f"AI analysis failed: {e}")
            return None
    
    async def check_compliance(
        self, 
        scan_summary: Dict[str, Any], 
        frameworks: List[str], 
        scan_id: str
    ) -> Optional[Dict[str, Any]]:
        """Check compliance against security frameworks."""
        
        payload = {
            "scan_id": scan_id,
            "scan_summary": scan_summary,
            "frameworks": frameworks
        }
        
        try:
            result = await self._make_request("POST", "/v1/compliance/check", payload)
            return result
        except Exception as e:
            print(f"Compliance check failed: {e}")
            return None
    
    async def get_vulnerability_trends(
        self, 
        scan_summary: Dict[str, Any], 
        scan_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get vulnerability trend analysis."""
        
        payload = {
            "scan_id": scan_id,
            "scan_summary": scan_summary,
            "analysis_period": "30d"
        }
        
        try:
            result = await self._make_request("POST", "/v1/trends/analyze", payload)
            return result
        except Exception as e:
            print(f"Trend analysis failed: {e}")
            return None
    
    async def calculate_priorities(
        self, 
        scan_summary: Dict[str, Any], 
        scan_id: str
    ) -> Optional[Dict[str, Any]]:
        """Calculate priority scores for vulnerabilities."""
        
        payload = {
            "scan_id": scan_id,
            "scan_summary": scan_summary,
            "context": {
                "environment": "production",  # Could be configurable
                "business_criticality": "high"
            }
        }
        
        try:
            result = await self._make_request("POST", "/v1/priority/calculate", payload)
            return result
        except Exception as e:
            print(f"Priority calculation failed: {e}")
            return None
    
    async def suggest_remediation(
        self, 
        scan_summary: Dict[str, Any], 
        scan_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get auto-remediation suggestions."""
        
        payload = {
            "scan_id": scan_id,
            "scan_summary": scan_summary,
            "include_code_examples": True,
            "prefer_automated_fixes": True
        }
        
        try:
            result = await self._make_request("POST", "/v1/remediation/suggest", payload)
            return result
        except Exception as e:
            print(f"Remediation suggestions failed: {e}")
            return None
    
    async def upload_scan_results(
        self, 
        scan_summary: Dict[str, Any], 
        scan_id: str,
        team_id: Optional[str] = None
    ) -> Optional[str]:
        """Upload scan results for team collaboration."""
        
        payload = {
            "scan_id": scan_id,
            "scan_summary": scan_summary,
            "team_id": team_id,
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            result = await self._make_request("POST", "/v1/scans/upload", payload)
            return result.get("dashboard_url")
        except Exception as e:
            print(f"Result upload failed: {e}")
            return None
    
    async def get_custom_rules(self, rule_set: str) -> Optional[List[Dict[str, Any]]]:
        """Fetch custom security rules."""
        
        try:
            result = await self._make_request("GET", f"/v1/rules/{rule_set}")
            return result.get("rules", [])
        except Exception as e:
            print(f"Custom rules fetch failed: {e}")
            return None
    
    async def validate_api_key(self) -> bool:
        """Validate API key and check subscription status."""
        
        try:
            result = await self._make_request("GET", "/v1/auth/validate")
            return result.get("valid", False)
        except Exception:
            return False
    
    async def get_usage_stats(self) -> Optional[Dict[str, Any]]:
        """Get usage statistics for current subscription."""
        
        try:
            result = await self._make_request("GET", "/v1/usage/stats")
            return result
        except Exception as e:
            print(f"Usage stats fetch failed: {e}")
            return None
    
    async def health_check(self) -> bool:
        """Check if cloud services are available."""
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(f"{self.base_url}/health") as response:
                    return response.status == 200
        except Exception:
            return False


class MockCloudClient(CloudClient):
    """Mock cloud client for development and testing."""
    
    def __init__(self):
        super().__init__()
        self.mock_enabled = os.getenv("CODEPHREAK_MOCK_CLOUD", "false").lower() == "true"
    
    async def _make_request(
        self, 
        method: str, 
        endpoint: str, 
        data: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """Mock API responses for development."""
        
        if not self.mock_enabled:
            return await super()._make_request(method, endpoint, data)
        
        # Simulate API delay
        await asyncio.sleep(0.5)
        
        # Mock responses based on endpoint
        if "/ai/analyze" in endpoint:
            return {
                "findings": [
                    {
                        "tool": "AI_Analysis",
                        "severity": "MEDIUM",
                        "category": "potential_vulnerability",
                        "rule_id": "AI-001",
                        "message": "AI detected potential security pattern",
                        "confidence": 0.85
                    }
                ],
                "insights": [
                    "This pattern commonly leads to security vulnerabilities",
                    "Consider implementing input validation"
                ]
            }
        
        elif "/compliance/check" in endpoint:
            frameworks = data.get("frameworks", [])
            return {
                "compliance_results": {
                    framework: {
                        "score": 85,
                        "passed_checks": 17,
                        "total_checks": 20,
                        "failed_checks": [
                            "Input validation missing",
                            "Encryption not enforced", 
                            "Logging insufficient"
                        ]
                    }
                    for framework in frameworks
                }
            }
        
        elif "/trends/analyze" in endpoint:
            return {
                "trends": {
                    "vulnerability_growth": "stable",
                    "most_common_categories": ["injection", "broken_auth", "sensitive_data"],
                    "risk_trend": "decreasing",
                    "historical_comparison": {
                        "30_days_ago": 45,
                        "current": 42
                    }
                }
            }
        
        elif "/priority/calculate" in endpoint:
            return {
                "finding_priorities": {
                    "bandit:B101": 95,
                    "semgrep:sql-injection": 90,
                    "gitleaks:api-key": 85
                }
            }
        
        elif "/remediation/suggest" in endpoint:
            return {
                "suggestions": {
                    "sql-injection": {
                        "description": "Use parameterized queries to prevent SQL injection",
                        "code_example": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
                        "automated_fix": True,
                        "difficulty": "easy"
                    }
                }
            }
        
        elif "/scans/upload" in endpoint:
            return {
                "dashboard_url": "https://app.codephreak.ai/dashboard/scan/abc123"
            }
        
        elif "/auth/validate" in endpoint:
            return {"valid": True}
        
        elif "/usage/stats" in endpoint:
            return {
                "scans_this_month": 25,
                "scans_remaining": 475,
                "api_calls_this_month": 150
            }
        
        return {"status": "mock_response"}


# Use mock client in development
def get_cloud_client() -> CloudClient:
    """Get cloud client (mock or real based on environment)."""
    if os.getenv("CODEPHREAK_MOCK_CLOUD", "false").lower() == "true":
        return MockCloudClient()
    return CloudClient()
