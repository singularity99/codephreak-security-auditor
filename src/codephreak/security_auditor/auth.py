#!/usr/bin/env python3
"""
CodePhreak Security Auditor - Authentication & Premium Features

Handles authentication with codephreak.ai cloud services and manages
premium feature access based on subscription tiers.
"""

import os
import json
import hashlib
import requests
from pathlib import Path
from typing import Optional, Dict, Any, Set
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

class SubscriptionTier(Enum):
    """Subscription tier enumeration."""
    FREE = "free"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    ENTERPRISE_PLUS = "enterprise_plus"

@dataclass
class UserSubscription:
    """User subscription information."""
    tier: SubscriptionTier
    expires_at: Optional[datetime]
    features: Set[str]
    organization: Optional[str] = None
    user_id: Optional[str] = None

class PremiumFeatures:
    """Defines premium features for each subscription tier."""
    
    FREE_FEATURES = {
        "basic_scanning",
        "json_reports", 
        "sarif_reports",
        "cli_interface",
        "docker_support",
        "community_support"
    }
    
    PROFESSIONAL_FEATURES = FREE_FEATURES | {
        "html_reports",
        "pdf_reports",
        "advanced_rules",
        "priority_scanning",
        "ide_integrations",
        "vulnerability_trends",
        "compliance_reports",
        "team_collaboration",
        "historical_comparison"
    }
    
    ENTERPRISE_FEATURES = PROFESSIONAL_FEATURES | {
        "ai_analysis",
        "custom_ml_models",
        "reachability_analysis", 
        "auto_remediation",
        "sso_integration",
        "custom_compliance",
        "dedicated_support",
        "onpremise_deployment"
    }
    
    ENTERPRISE_PLUS_FEATURES = ENTERPRISE_FEATURES | {
        "iast_capabilities",
        "rasp_protection",
        "runtime_monitoring",
        "threat_detection",
        "continuous_monitoring",
        "incident_response",
        "advanced_analytics",
        "custom_integrations"
    }
    
    @classmethod
    def get_features_for_tier(cls, tier: SubscriptionTier) -> Set[str]:
        """Get available features for a subscription tier."""
        tier_features = {
            SubscriptionTier.FREE: cls.FREE_FEATURES,
            SubscriptionTier.PROFESSIONAL: cls.PROFESSIONAL_FEATURES,
            SubscriptionTier.ENTERPRISE: cls.ENTERPRISE_FEATURES,
            SubscriptionTier.ENTERPRISE_PLUS: cls.ENTERPRISE_PLUS_FEATURES
        }
        return tier_features.get(tier, cls.FREE_FEATURES)

class CodePhreakAuth:
    """CodePhreak authentication and premium feature manager."""
    
    def __init__(self):
        self.config_dir = Path.home() / ".codephreak"
        self.config_file = self.config_dir / "config.json"
        self.api_base_url = os.getenv("CODEPHREAK_API_URL", "https://api.codephreak.ai")
        
        # Create config directory if it doesn't exist
        self.config_dir.mkdir(exist_ok=True)
        
        # Load configuration
        self._config = self._load_config()
        self._subscription = None
        self._validate_subscription()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from local file."""
        if not self.config_file.exists():
            return {}
        
        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    
    def _save_config(self) -> None:
        """Save configuration to local file."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self._config, f, indent=2)
        except IOError:
            pass  # Fail silently if can't save config
    
    def _validate_subscription(self) -> None:
        """Validate current subscription status."""
        api_key = self.get_api_key()
        
        if not api_key:
            # No API key - free tier
            self._subscription = UserSubscription(
                tier=SubscriptionTier.FREE,
                expires_at=None,
                features=PremiumFeatures.FREE_FEATURES
            )
            return
        
        # Check if we have cached subscription info
        cached_sub = self._config.get("subscription")
        if cached_sub:
            expires_at = None
            if cached_sub.get("expires_at"):
                expires_at = datetime.fromisoformat(cached_sub["expires_at"])
                
                # Check if subscription has expired
                if expires_at and expires_at < datetime.now():
                    self._subscription = UserSubscription(
                        tier=SubscriptionTier.FREE,
                        expires_at=None,
                        features=PremiumFeatures.FREE_FEATURES
                    )
                    return
            
            tier = SubscriptionTier(cached_sub.get("tier", "free"))
            self._subscription = UserSubscription(
                tier=tier,
                expires_at=expires_at,
                features=PremiumFeatures.get_features_for_tier(tier),
                organization=cached_sub.get("organization"),
                user_id=cached_sub.get("user_id")
            )
            return
        
        # Validate with API (offline fallback to free tier)
        try:
            self._subscription = self._fetch_subscription_from_api(api_key)
        except Exception:
            # Fallback to free tier if API is unreachable
            self._subscription = UserSubscription(
                tier=SubscriptionTier.FREE,
                expires_at=None,
                features=PremiumFeatures.FREE_FEATURES
            )
    
    def _fetch_subscription_from_api(self, api_key: str) -> UserSubscription:
        """Fetch subscription details from API."""
        headers = {
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "CodePhreak-Security-Auditor/0.1.0"
        }
        
        response = requests.get(
            f"{self.api_base_url}/v1/subscription",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 401:
            raise ValueError("Invalid API key")
        elif response.status_code != 200:
            raise ConnectionError("Failed to validate subscription")
        
        data = response.json()
        
        tier = SubscriptionTier(data.get("tier", "free"))
        expires_at = None
        if data.get("expires_at"):
            expires_at = datetime.fromisoformat(data["expires_at"])
        
        subscription = UserSubscription(
            tier=tier,
            expires_at=expires_at,
            features=PremiumFeatures.get_features_for_tier(tier),
            organization=data.get("organization"),
            user_id=data.get("user_id")
        )
        
        # Cache subscription info
        self._config["subscription"] = {
            "tier": tier.value,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "organization": subscription.organization,
            "user_id": subscription.user_id,
            "cached_at": datetime.now().isoformat()
        }
        self._save_config()
        
        return subscription
    
    def get_api_key(self) -> Optional[str]:
        """Get API key from environment or config."""
        # Check environment variable first
        api_key = os.getenv("CODEPHREAK_API_KEY")
        if api_key:
            return api_key
        
        # Check config file
        return self._config.get("api_key")
    
    def set_api_key(self, api_key: str) -> None:
        """Set API key in configuration."""
        self._config["api_key"] = api_key
        self._save_config()
        
        # Re-validate subscription with new key
        self._validate_subscription()
    
    def login(self, api_key: str) -> bool:
        """Login with API key and validate subscription."""
        try:
            # Test the API key
            headers = {
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "CodePhreak-Security-Auditor/0.1.0"
            }
            
            response = requests.get(
                f"{self.api_base_url}/v1/auth/validate",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                self.set_api_key(api_key)
                return True
            else:
                return False
                
        except Exception:
            return False
    
    def logout(self) -> None:
        """Logout and clear stored credentials."""
        if "api_key" in self._config:
            del self._config["api_key"]
        if "subscription" in self._config:
            del self._config["subscription"]
        self._save_config()
        
        # Reset to free tier
        self._subscription = UserSubscription(
            tier=SubscriptionTier.FREE,
            expires_at=None,
            features=PremiumFeatures.FREE_FEATURES
        )
    
    def get_subscription(self) -> UserSubscription:
        """Get current subscription information."""
        if not self._subscription:
            self._validate_subscription()
        return self._subscription
    
    def get_tier(self) -> SubscriptionTier:
        """Get current subscription tier."""
        return self.get_subscription().tier
    
    def is_premium_feature(self, feature: str) -> bool:
        """Check if a feature is available in current subscription."""
        subscription = self.get_subscription()
        return feature in subscription.features
    
    def require_premium_feature(self, feature: str) -> None:
        """Raise exception if feature is not available."""
        if not self.is_premium_feature(feature):
            tier = self.get_tier()
            raise PermissionError(
                f"Feature '{feature}' requires a premium subscription. "
                f"Current tier: {tier.value}. "
                f"Upgrade at https://codephreak.ai/pricing"
            )
    
    def get_feature_info(self) -> Dict[str, Any]:
        """Get information about available features."""
        subscription = self.get_subscription()
        
        all_features = PremiumFeatures.ENTERPRISE_PLUS_FEATURES
        available = subscription.features
        unavailable = all_features - available
        
        return {
            "tier": subscription.tier.value,
            "expires_at": subscription.expires_at.isoformat() if subscription.expires_at else None,
            "organization": subscription.organization,
            "available_features": sorted(available),
            "unavailable_features": sorted(unavailable),
            "feature_count": len(available),
            "total_features": len(all_features)
        }
    
    def get_upgrade_url(self) -> str:
        """Get URL for subscription upgrade."""
        return "https://codephreak.ai/pricing"
    
    def refresh_subscription(self) -> None:
        """Force refresh subscription from API."""
        api_key = self.get_api_key()
        if api_key:
            try:
                self._subscription = self._fetch_subscription_from_api(api_key)
            except Exception:
                pass  # Keep current subscription if refresh fails

# Global auth instance
auth_manager = CodePhreakAuth()

def get_auth() -> CodePhreakAuth:
    """Get global authentication manager instance."""
    return auth_manager
