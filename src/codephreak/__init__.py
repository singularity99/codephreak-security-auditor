"""
CodePhreak Security Auditor Droid

Enterprise-grade security vulnerability scanner with 92-96% commercial parity
using open source tools.

Copyright (c) 2025 CodePhreak
Licensed under MIT License
"""

__version__ = "0.1.0"
__author__ = "CodePhreak Security Team"
__email__ = "security@codephreak.ai"
__license__ = "MIT"
__url__ = "https://codephreak.ai"

from .security_auditor.core import SecurityAuditorDroid
from .security_auditor.cli import main

__all__ = [
    "SecurityAuditorDroid",
    "main",
    "__version__",
]
