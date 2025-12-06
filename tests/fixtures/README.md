# Test Harness for CodePhreak Security Auditor

This directory contains comprehensive test fixtures with intentionally vulnerable applications to validate the CodePhreak Security Auditor's detection capabilities.

## 🎯 Purpose

These test applications allow you to:
- **Validate scanner functionality** - Ensure security tools detect known vulnerabilities
- **Benchmark performance** - Test scanning speed and efficiency
- **Demonstrate capabilities** - Show potential customers what the scanner can detect
- **Regression testing** - Verify that updates don't break detection capabilities
- **Training and education** - Learn about common security vulnerabilities

## 📁 Test Applications

### 🐍 Python Application (`vulnerable_apps/python_app/`)

**Contains 18+ vulnerability types:**
- Command injection (`subprocess.call`, `os.system`)
- SQL injection (string formatting, % formatting)
- Server-side template injection (`render_template_string`)
- Insecure deserialization (`pickle.loads`)
- Hardcoded secrets (API keys, passwords, AWS credentials)
- Weak cryptography (MD5, SHA1)
- Path traversal (unvalidated file access)
- Code injection (`eval`)
- YAML unsafe loading
- SSRF (Server-Side Request Forgery)
- Insecure random number generation
- Debug mode in production

**Vulnerable dependencies (15+ packages):**
- Flask 2.0.1 (CVE-2023-30861)
- requests 2.25.1 (CVE-2023-32681) 
- PyYAML 5.3.1 (CVE-2020-14343)
- And many more with known CVEs

### 🟨 JavaScript Application (`vulnerable_apps/javascript_app/`)

**Contains 20+ vulnerability types:**
- Command injection (`child_process.exec`)
- SQL injection (string concatenation)
- XSS (Cross-Site Scripting)
- Code injection (`eval`, `vm.runInThisContext`)
- Path traversal (`fs.readFile`)
- Open redirect (`res.redirect`)
- SSRF (unvalidated HTTP requests)
- Prototype pollution
- Insecure deserialization
- Weak random number generation
- Missing rate limiting
- Hardcoded secrets
- Missing security headers

**Vulnerable dependencies (25+ packages):**
- axios 0.21.0 (Multiple CVEs)
- lodash 4.17.19 (Prototype pollution)
- handlebars 4.5.3 (RCE vulnerabilities)
- And many more with known CVEs

### 🐳 Docker Application (`vulnerable_apps/docker_app/`)

**Dockerfile with 25+ security issues:**
- Using `latest` tag
- Running as root user
- Hardcoded secrets in ENV
- Excessive privileges
- Installing unnecessary packages
- Using `ADD` instead of `COPY`
- Exposing unnecessary ports
- Missing security updates
- No health checks
- Deprecated `MAINTAINER`

**docker-compose.yml with 40+ security issues:**
- Privileged containers
- Host network sharing
- Docker socket mounting
- Hardcoded credentials
- Missing resource limits
- Insecure port bindings
- No network segmentation
- Running databases without authentication

## 🚀 Usage

### Run Individual Tests

```bash
# Test Python application
python tests/fixtures/test_runner.py

# Or run the security auditor directly
codephreak-audit scan --path tests/fixtures/vulnerable_apps/python_app/

# Test JavaScript application  
codephreak-audit scan --path tests/fixtures/vulnerable_apps/javascript_app/

# Test Docker configuration
codephreak-audit scan --path tests/fixtures/vulnerable_apps/docker_app/
```

### Run Comprehensive Test Suite

```bash
# Run all tests with validation
cd tests/fixtures/
python test_runner.py
```

### Performance Testing

```bash
# Run performance benchmarks
codephreak-audit scan --path tests/fixtures/ --benchmark
```

## 📊 Expected Results

### Detection Rates by Tool Type

| Scanner Type | Expected Detection Rate | Key Vulnerabilities |
|--------------|------------------------|---------------------|
| **SAST (Semgrep/Bandit)** | 85-95% | Code injection, SQL injection, hardcoded secrets |
| **SCA (Trivy/pip-audit)** | 95-100% | Vulnerable dependencies with known CVEs |
| **Secrets (Gitleaks)** | 90-100% | API keys, passwords, AWS credentials |
| **Container (Hadolint)** | 80-90% | Dockerfile best practices, security issues |
| **IaC (Checkov)** | 75-85% | Docker Compose misconfigurations |

### Sample Output

```json
{
  "scan_summary": {
    "total_findings": 127,
    "critical": 23,
    "high": 45,
    "medium": 38,
    "low": 21,
    "scan_duration": "45.2s"
  },
  "findings_by_category": {
    "hardcoded_secrets": 15,
    "sql_injection": 8,
    "command_injection": 6,
    "vulnerable_dependencies": 67,
    "container_security": 31
  }
}
```

## 🔍 Validation Scripts

The test runner validates that:

1. **Expected vulnerabilities are detected** - Checks for specific patterns
2. **Performance is acceptable** - Scans complete within reasonable time
3. **Output format is correct** - JSON/SARIF format validation
4. **No false negatives** - Critical issues are not missed
5. **Minimal false positives** - Results are accurate

## 🎓 Educational Value

Each vulnerable application includes:
- **Inline comments** explaining each vulnerability
- **CVE references** for dependency issues
- **Real-world examples** of common security mistakes
- **Best practice alternatives** for secure coding

## ⚠️ Security Warning

**These applications are intentionally vulnerable!**

- 🚫 **Never deploy** these applications to production
- 🚫 **Never expose** them to the internet
- 🚫 **Never use** this code as a template for real applications
- ✅ **Only use** in isolated testing environments
- ✅ **Only use** for security testing and education

## 🧪 Adding New Test Cases

To add new vulnerability patterns:

1. **Add vulnerable code** to the appropriate application
2. **Update expected results** in `test_runner.py`
3. **Add CVE references** for dependency vulnerabilities
4. **Include documentation** explaining the vulnerability
5. **Test detection** with the security auditor

## 📈 Continuous Improvement

These test fixtures help ensure:
- **Comprehensive coverage** of vulnerability types
- **Realistic scenarios** matching real-world applications  
- **Performance benchmarks** for scaling
- **Quality assurance** for scanner updates
- **Customer confidence** in detection capabilities

## 🎯 Success Metrics

A successful test run should achieve:
- ✅ **80%+ overall detection rate**
- ✅ **95%+ critical vulnerability detection**
- ✅ **<60 second scan time** for all test apps
- ✅ **<5% false positive rate**
- ✅ **Zero crashes or errors**

This test harness provides comprehensive validation that CodePhreak Security Auditor delivers on its promise of enterprise-grade security scanning with 92-96% commercial parity!
