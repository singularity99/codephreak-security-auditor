# Vulnerable Dockerfile - Test Fixture for CodePhreak Security Auditor
# 
# This intentionally vulnerable Dockerfile contains multiple security issues
# that should be detected by container security scanning tools.
# 
# ⚠️  WARNING: This Dockerfile contains intentional security vulnerabilities.
#     DO NOT use in production environments!

# VULNERABILITY 1: Using latest tag (should be detected by Hadolint)
FROM ubuntu:latest

# VULNERABILITY 2: Running as root user (implicit)
# No USER instruction to switch to non-root user

# VULNERABILITY 3: Not updating package lists (should be detected by Hadolint)
# Missing apt-get update

# VULNERABILITY 4: Installing unnecessary packages
RUN apt-get install -y \
    curl \
    wget \
    vim \
    nano \
    telnet \
    ftp \
    netcat \
    ssh \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# VULNERABILITY 5: Hardcoded secrets in environment variables
ENV API_KEY=sk-1234567890abcdef1234567890abcdef
ENV DATABASE_URL=postgresql://admin:password123@db:5432/myapp
ENV SECRET_TOKEN=super-secret-token-12345
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# VULNERABILITY 6: Using ADD instead of COPY (should be detected by Hadolint)
ADD https://github.com/just-containers/s6-overlay/releases/download/v1.21.8.0/s6-overlay-amd64.tar.gz /tmp/
RUN tar xzf /tmp/s6-overlay-amd64.tar.gz -C /

# VULNERABILITY 7: Not pinning package versions
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    nodejs \
    npm \
    git

# VULNERABILITY 8: Installing packages as root without cleanup
RUN pip3 install flask requests pyyaml

# VULNERABILITY 9: Exposing unnecessary ports
EXPOSE 22 23 80 443 3000 5000 8080 9000

# VULNERABILITY 10: Using COPY without specifying exact files
COPY . /app/

# VULNERABILITY 11: Setting insecure file permissions
RUN chmod 777 /app
RUN chmod 666 /etc/passwd

# VULNERABILITY 12: Installing from untrusted sources
RUN curl -sSL https://get.docker.com/ | sh

# VULNERABILITY 13: Not using multi-stage builds (bloated image)
WORKDIR /app

# VULNERABILITY 14: Hardcoded credentials in files
RUN echo "admin:password123" > /app/credentials.txt
RUN echo "root ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# VULNERABILITY 15: Using shell form of RUN (should be detected by Hadolint)
RUN echo "Starting application..."

# VULNERABILITY 16: Not specifying exact WORKDIR
# Already set, but could be more specific

# VULNERABILITY 17: Using privileged operations
RUN apt-get install -y sudo
RUN usermod -aG sudo root

# VULNERABILITY 18: Leaving debugging tools in production image
RUN apt-get install -y \
    strace \
    ltrace \
    gdb \
    tcpdump \
    wireshark \
    nmap

# VULNERABILITY 19: Not cleaning up caches and temporary files
# No cleanup commands after installations

# VULNERABILITY 20: Using COPY/ADD with wildcard
COPY *.txt /app/
ADD *.py /app/

# VULNERABILITY 21: Not setting proper labels
# Missing LABEL instructions for maintainer, version, etc.

# VULNERABILITY 22: Using shell in ENTRYPOINT (should be detected by Hadolint)
ENTRYPOINT ["/bin/bash", "-c", "cd /app && python3 app.py"]

# VULNERABILITY 23: Not using HEALTHCHECK
# Missing HEALTHCHECK instruction

# VULNERABILITY 24: Excessive capabilities (implicit)
# Not dropping unnecessary Linux capabilities

# VULNERABILITY 25: Using deprecated MAINTAINER (should be detected by Hadolint)
MAINTAINER vulnerable-app@example.com
