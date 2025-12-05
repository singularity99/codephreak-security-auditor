# Installation Guide - CodePhreak Security Auditor

🔒 **Enterprise-grade security vulnerability scanner with 92-96% commercial parity**

This guide covers installation methods for the CodePhreak Security Auditor Droid, from simple pip installation to enterprise Docker deployments.

## Quick Start (Recommended)

### Option 1: Python Package Installation

```bash
# Install the latest release
pip install codephreak-security-auditor

# Verify installation
codephreak-audit --version
```

### Option 2: Docker Container

```bash
# Pull and run the container
docker run --rm -v $(pwd):/workspace codephreak/security-auditor:latest \
  --target /workspace --workflow quick-check
```

### Option 3: From Source (Development)

```bash
# Clone the repository
git clone https://github.com/codephreak/security-auditor-droid.git
cd security-auditor-droid

# Install in development mode
pip install -e .[dev]

# Verify installation
codephreak-audit --help
```

## Detailed Installation Options

### 1. Python Package Manager Installation

#### Prerequisites
- **Python**: 3.8+ (3.11+ recommended)
- **pip**: Latest version
- **OS**: Linux, macOS, Windows (WSL2 recommended)

#### Standard Installation
```bash
# Create virtual environment (recommended)
python -m venv codephreak-env
source codephreak-env/bin/activate  # Linux/macOS
# codephreak-env\Scripts\activate     # Windows

# Install CodePhreak Security Auditor
pip install codephreak-security-auditor

# Test installation
codephreak-audit --help
```

#### Enhanced Installation (Phase 2+ Features)
```bash
# Install with enhanced capabilities
pip install codephreak-security-auditor[enhanced]

# Install with AI/ML features
pip install codephreak-security-auditor[ai]

# Install everything (development + enhanced + AI)
pip install codephreak-security-auditor[all]
```

### 2. Security Tools Installation

The Security Auditor requires various open source security tools. Install them using our automated script:

#### Automated Tool Installation
```bash
# Download and run the tool installation script
curl -sSL https://raw.githubusercontent.com/codephreak/security-auditor-droid/main/scripts/install_tools.sh | bash

# Or manually download and inspect first
wget https://raw.githubusercontent.com/codephreak/security-auditor-droid/main/scripts/install_tools.sh
chmod +x install_tools.sh
./install_tools.sh
```

#### Manual Tool Installation

**Core SAST Tools:**
```bash
# Semgrep (universal pattern-based scanner)
pip install semgrep

# Bandit (Python security linter) 
pip install bandit

# ESLint with security plugins (JavaScript/TypeScript)
npm install -g eslint @eslint/js eslint-plugin-security
```

**Comprehensive Vulnerability Scanner:**
```bash
# Trivy (multi-purpose scanner)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Or using package managers
brew install trivy          # macOS
apt-get install trivy       # Ubuntu/Debian
```

**Secret Detection Tools:**
```bash
# Gitleaks
brew install gitleaks       # macOS
# Or download binary from: https://github.com/gitleaks/gitleaks/releases

# TruffleHog
brew install trufflesecurity/trufflehog/trufflehog  # macOS
# Or download from: https://github.com/trufflesecurity/trufflehog/releases

# detect-secrets
pip install detect-secrets
```

**Infrastructure as Code (IaC) Security:**
```bash
# Checkov (comprehensive IaC scanner)
pip install checkov

# tfsec (Terraform security scanner)
brew install tfsec          # macOS
# Or download from: https://github.com/aquasecurity/tfsec/releases

# Kubescape (Kubernetes security)
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
```

**Container Security:**
```bash
# Hadolint (Dockerfile linter)
brew install hadolint       # macOS
# Or download from: https://github.com/hadolint/hadolint/releases

# Docker Bench Security
docker pull docker/docker-bench-security
```

### 3. Docker Installation

#### Pre-built Container
```bash
# Pull the latest image
docker pull codephreak/security-auditor:latest

# Run a quick security check
docker run --rm \
  -v $(pwd):/workspace \
  codephreak/security-auditor:latest \
  --target /workspace \
  --workflow quick-check \
  --format html,json

# Run with custom configuration
docker run --rm \
  -v $(pwd):/workspace \
  -v ~/.config/codephreak:/home/codephreak/.config/codephreak \
  codephreak/security-auditor:latest \
  --target /workspace \
  --config /home/codephreak/.config/codephreak/config.yml
```

#### Build from Source
```bash
# Clone and build
git clone https://github.com/codephreak/security-auditor-droid.git
cd security-auditor-droid

# Build the Docker image
docker build -t codephreak-security-auditor -f docker/Dockerfile .

# Run the built image
docker run --rm -v $(pwd):/workspace codephreak-security-auditor --help
```

#### Docker Compose (Development)
```bash
# Use provided docker-compose for development
docker-compose up --build

# Run security scan using compose
docker-compose run --rm security-auditor --target /workspace --workflow full-audit
```

### 4. Enterprise/CI-CD Installation

#### GitHub Actions Integration
```yaml
# .github/workflows/security-audit.yml
name: Security Audit
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install CodePhreak Security Auditor
        run: |
          pip install codephreak-security-auditor
          # Install security tools
          curl -sSL https://raw.githubusercontent.com/codephreak/security-auditor-droid/main/scripts/install_tools.sh | bash
      
      - name: Run Security Audit
        run: |
          codephreak-audit \
            --target . \
            --workflow full-audit \
            --format sarif,html \
            --output security-reports/ \
            --fail-on critical,high
      
      - name: Upload SARIF Results
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: security-reports/security_results.sarif
```

#### Jenkins Pipeline
```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Audit') {
            steps {
                sh '''
                    pip install codephreak-security-auditor
                    curl -sSL https://raw.githubusercontent.com/codephreak/security-auditor-droid/main/scripts/install_tools.sh | bash
                    
                    codephreak-audit \
                        --target . \
                        --workflow full-audit \
                        --format json,html,sarif \
                        --output security-reports/
                '''
                
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'security-reports',
                    reportFiles: 'security_report.html',
                    reportName: 'Security Audit Report'
                ])
            }
        }
    }
}
```

#### GitLab CI
```yaml
# .gitlab-ci.yml
security_audit:
  stage: test
  image: python:3.11
  before_script:
    - pip install codephreak-security-auditor
    - curl -sSL https://raw.githubusercontent.com/codephreak/security-auditor-droid/main/scripts/install_tools.sh | bash
  script:
    - codephreak-audit --target . --workflow full-audit --format json,html --output security-reports/
  artifacts:
    reports:
      sast: security-reports/security_results.sarif
    paths:
      - security-reports/
  only:
    - merge_requests
    - main
```

## Verification & Testing

### System Diagnostics
```bash
# Check system compatibility and tool availability
codephreak-audit doctor --check-deps

# List all available tools and their status
codephreak-audit tools

# Generate sample configuration
codephreak-audit init-config ~/.config/codephreak/config.yml
```

### Test Installation
```bash
# Create a test directory with sample code
mkdir test-security-audit
cd test-security-audit

# Create a sample vulnerable Python file
cat > vulnerable_app.py << 'EOF'
import os
import subprocess

# Hardcoded secret (should be detected)
API_KEY = "sk-1234567890abcdef"

def execute_command(cmd):
    # Command injection vulnerability (should be detected)
    result = subprocess.call(cmd, shell=True)
    return result

if __name__ == '__main__':
    user_input = input("Enter command: ")
    execute_command(user_input)
EOF

# Run security audit
codephreak-audit --target . --workflow quick-check --format html

# Check results
ls -la security-reports/
```

## Configuration

### Generate Configuration File
```bash
# Generate sample configuration
codephreak-audit init-config ~/.config/codephreak/config.yml

# Edit configuration
vim ~/.config/codephreak/config.yml
```

### Environment Variables
```bash
# Optional: Configure premium features
export CODEPHREAK_API_KEY="your-api-key"
export CODEPHREAK_ORG_ID="your-org-id"

# Execution configuration
export CP_MAX_CONCURRENT_TOOLS=5
export CP_GLOBAL_TIMEOUT=3600

# Feature flags
export CP_ENABLE_AI_PRIORITIZATION=true
export CP_ENABLE_HOSTED_SCANNING=false
```

## Troubleshooting

### Common Issues

**Issue**: `codephreak-audit: command not found`
```bash
# Solution: Ensure Python scripts directory is in PATH
pip install --user codephreak-security-auditor
export PATH="$HOME/.local/bin:$PATH"
```

**Issue**: Security tools not found
```bash
# Solution: Run the automated installer or install manually
curl -sSL https://raw.githubusercontent.com/codephreak/security-auditor-droid/main/scripts/install_tools.sh | bash

# Or check which tools are missing
codephreak-audit doctor --check-deps
```

**Issue**: Permission denied in Docker
```bash
# Solution: Use proper user mapping
docker run --rm --user $(id -u):$(id -g) \
  -v $(pwd):/workspace \
  codephreak/security-auditor:latest \
  --target /workspace
```

**Issue**: Slow performance
```bash
# Solution: Reduce concurrent tools or increase timeout
codephreak-audit \
  --target . \
  --workflow quick-check \  # Use faster workflow
  --timeout 1800
```

### Getting Help

- **Documentation**: [https://github.com/codephreak/security-auditor-droid/docs](https://github.com/codephreak/security-auditor-droid/docs)
- **Issues**: [https://github.com/codephreak/security-auditor-droid/issues](https://github.com/codephreak/security-auditor-droid/issues)
- **Discussions**: [https://github.com/codephreak/security-auditor-droid/discussions](https://github.com/codephreak/security-auditor-droid/discussions)
- **Enterprise Support**: [security@codephreak.ai](mailto:security@codephreak.ai)

## Next Steps

1. **Run Your First Scan**: `codephreak-audit --target /path/to/your/project`
2. **Explore Workflows**: Try `--workflow quick-check`, `full-audit`, or `compliance`
3. **Customize Configuration**: Edit `~/.config/codephreak/config.yml`
4. **Integrate with CI/CD**: Use provided pipeline examples
5. **Explore Premium Features**: Visit [codephreak.ai](https://codephreak.ai) for hosted services

---

**Ready to secure your code?** Start with: `codephreak-audit --target . --workflow quick-check` 🔒
