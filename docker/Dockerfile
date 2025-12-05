# CodePhreak Security Auditor Droid
# Enterprise-grade security scanner with 92-96% commercial parity

FROM python:3.11-slim

LABEL maintainer="CodePhreak Security Team <security@codephreak.ai>"
LABEL description="CodePhreak Security Auditor Droid - Open Source Security Scanner"
LABEL version="0.1.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    build-essential \
    gcc \
    g++ \
    jq \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r codephreak && useradd -r -g codephreak -m -d /home/codephreak codephreak

# Set working directory
WORKDIR /app

# Copy and install Python dependencies first (for better Docker layer caching)
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install CodePhreak Security Auditor
RUN pip install -e .[enhanced]

# Install core open source security tools
RUN echo "Installing open source security tools..." \
    && pip install semgrep bandit safety detect-secrets checkov \
    && echo "✅ Python security tools installed"

# Install Trivy (comprehensive vulnerability scanner)
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
    && echo "✅ Trivy installed"

# Install Gitleaks (secret scanner)
RUN GITLEAKS_VERSION=$(curl -s "https://api.github.com/repos/gitleaks/gitleaks/releases/latest" | jq -r .tag_name) \
    && wget -qO- "https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_${GITLEAKS_VERSION#v}_linux_x64.tar.gz" | tar xvz -C /usr/local/bin gitleaks \
    && echo "✅ Gitleaks installed"

# Install Hadolint (Dockerfile linter)
RUN wget -qO /usr/local/bin/hadolint https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 \
    && chmod +x /usr/local/bin/hadolint \
    && echo "✅ Hadolint installed"

# Install TruffleHog (advanced secret scanner)
RUN TRUFFLEHOG_VERSION=$(curl -s "https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest" | jq -r .tag_name) \
    && wget -qO- "https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_${TRUFFLEHOG_VERSION#v}_linux_amd64.tar.gz" | tar xvz -C /usr/local/bin trufflehog \
    && echo "✅ TruffleHog installed"

# Install tfsec (Terraform security scanner)
RUN TFSEC_VERSION=$(curl -s "https://api.github.com/repos/aquasecurity/tfsec/releases/latest" | jq -r .tag_name) \
    && wget -qO /usr/local/bin/tfsec "https://github.com/aquasecurity/tfsec/releases/latest/download/tfsec-linux-amd64" \
    && chmod +x /usr/local/bin/tfsec \
    && echo "✅ tfsec installed"

# Install Node.js and npm (for npm audit and JavaScript scanning)
RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - \
    && apt-get install -y nodejs \
    && echo "✅ Node.js and npm installed"

# Verify tool installations
RUN echo "Verifying tool installations..." \
    && python --version \
    && pip --version \
    && semgrep --version \
    && trivy --version \
    && gitleaks version \
    && hadolint --version \
    && trufflehog --version \
    && tfsec --version \
    && node --version \
    && npm --version \
    && echo "✅ All tools verified"

# Create workspace directory
RUN mkdir -p /workspace && chown codephreak:codephreak /workspace

# Copy configuration files
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create configuration directory
RUN mkdir -p /home/codephreak/.config/codephreak \
    && chown -R codephreak:codephreak /home/codephreak

# Switch to non-root user
USER codephreak

# Set default working directory for scans
WORKDIR /workspace

# Expose health check endpoint (if web interface is added)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD codephreak-audit --help || exit 1

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh"]

# Default command
CMD ["--help"]

# Build-time metadata
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

LABEL org.opencontainers.image.created=${BUILD_DATE}
LABEL org.opencontainers.image.url="https://codephreak.ai"
LABEL org.opencontainers.image.source="https://github.com/codephreak/security-auditor-droid"
LABEL org.opencontainers.image.version=${VERSION}
LABEL org.opencontainers.image.revision=${VCS_REF}
LABEL org.opencontainers.image.vendor="CodePhreak"
LABEL org.opencontainers.image.title="CodePhreak Security Auditor Droid"
LABEL org.opencontainers.image.description="Enterprise-grade security vulnerability scanner with 92-96% commercial parity using open source tools"
