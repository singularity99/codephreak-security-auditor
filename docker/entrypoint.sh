#!/bin/bash
set -e

# CodePhreak Security Auditor Docker Entrypoint
# This script handles container initialization and tool execution

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[CodePhreak]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Print banner
cat << 'EOF'

 ██████╗ ██████╗ ██████╗ ███████╗██████╗ ██╗  ██╗██████╗ ███████╗ █████╗ ██╗  ██╗
██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗██║  ██║██╔══██╗██╔════╝██╔══██╗██║ ██╔╝
██║     ██║   ██║██║  ██║█████╗  ██████╔╝███████║██████╔╝█████╗  ███████║█████╔╝ 
██║     ██║   ██║██║  ██║██╔══╝  ██╔═══╝ ██╔══██║██╔══██╗██╔══╝  ██╔══██║██╔═██╗ 
╚██████╗╚██████╔╝██████╔╝███████╗██║     ██║  ██║██║  ██║███████╗██║  ██║██║  ██╗
 ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝

Security Auditor Droid v0.1.0 - Enterprise-grade vulnerability scanning
🔒 92-96% commercial parity using open source tools

EOF

# Check if running as root (discouraged)
if [ "$EUID" -eq 0 ]; then
    print_warning "Running as root. Consider using --user flag for better security."
fi

# Environment setup
export HOME=/home/codephreak
export PYTHONPATH=/app/src:$PYTHONPATH

# Create necessary directories
mkdir -p /tmp/codephreak/{cache,reports,logs}

# Initialize configuration if not exists
if [ ! -f "$HOME/.config/codephreak/config.yml" ]; then
    print_status "Initializing default configuration..."
    mkdir -p "$HOME/.config/codephreak"
    codephreak-audit init-config "$HOME/.config/codephreak/config.yml" 2>/dev/null || true
fi

# Pre-flight checks
print_status "Running pre-flight checks..."

# Check workspace permissions
if [ ! -w /workspace ]; then
    print_warning "Workspace /workspace is not writable. Reports may not be saved."
fi

# Validate essential tools
tools_status=0

check_tool() {
    local tool=$1
    local description=$2
    
    if command -v "$tool" &> /dev/null; then
        version=$($tool --version 2>/dev/null | head -n1 || echo "unknown")
        print_success "$description: $version"
    else
        print_error "$description: NOT FOUND"
        tools_status=1
    fi
}

# Check core security tools
check_tool "semgrep" "Semgrep (Universal SAST)"
check_tool "trivy" "Trivy (Vulnerability Scanner)"
check_tool "gitleaks" "Gitleaks (Secret Scanner)"
check_tool "hadolint" "Hadolint (Dockerfile Linter)"
check_tool "trufflehog" "TruffleHog (Advanced Secret Scanner)"
check_tool "tfsec" "tfsec (Terraform Security)"
check_tool "checkov" "Checkov (IaC Security)"
check_tool "bandit" "Bandit (Python Security)"

# Check optional tools
check_tool "npm" "npm (Node.js Package Manager)"

if [ $tools_status -eq 0 ]; then
    print_success "All essential security tools are available"
else
    print_warning "Some tools are missing - functionality may be limited"
fi

# Handle different execution modes
if [ $# -eq 0 ]; then
    # No arguments provided - show help
    print_status "No arguments provided. Showing help..."
    exec codephreak-audit --help
elif [ "$1" = "bash" ] || [ "$1" = "shell" ]; then
    # Interactive shell mode
    print_status "Starting interactive shell..."
    exec /bin/bash
elif [ "$1" = "doctor" ]; then
    # System diagnostics
    print_status "Running system diagnostics..."
    exec codephreak-audit doctor --check-deps
elif [ "$1" = "tools" ]; then
    # Tool status check
    print_status "Checking tool status..."
    exec codephreak-audit tools
elif [ "$1" = "demo" ]; then
    # Demo mode with sample vulnerable code
    print_status "Running demo security scan..."
    
    # Create sample vulnerable code
    cat > /tmp/vulnerable_app.py << 'EOF'
import os
import subprocess
import sqlite3
from flask import Flask, request

app = Flask(__name__)

# Hardcoded secret (vulnerability)
API_KEY = "sk-12345-abcdef-secret-key"
DATABASE_PASSWORD = "admin123"

@app.route('/exec')
def execute_command():
    # Command injection vulnerability
    cmd = request.args.get('cmd', 'ls')
    result = subprocess.call(cmd, shell=True)
    return str(result)

@app.route('/user/<user_id>')
def get_user(user_id):
    # SQL injection vulnerability
    conn = sqlite3.connect('users.db')
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor = conn.execute(query)
    return str(cursor.fetchall())

if __name__ == '__main__':
    # Debug mode in production (vulnerability)
    app.run(host='0.0.0.0', debug=True)
EOF
    
    # Create requirements.txt with vulnerable dependencies
    cat > /tmp/requirements.txt << 'EOF'
flask==2.0.1
requests==2.25.1
urllib3==1.26.5
jinja2==2.11.3
EOF
    
    print_status "Created sample vulnerable application"
    print_status "Running security scan on demo code..."
    
    exec codephreak-audit \
        --target /tmp \
        --workflow quick-check \
        --format json,html \
        --output /workspace/demo-results \
        --verbose
        
elif [ "${1:0:1}" = "-" ]; then
    # Command line arguments provided - pass to codephreak-audit
    print_status "Executing: codephreak-audit $*"
    exec codephreak-audit "$@"
else
    # Custom command provided
    print_status "Executing custom command: $*"
    exec "$@"
fi
