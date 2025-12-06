#!/usr/bin/env python3
"""
Test Runner for CodePhreak Security Auditor

This script runs the security auditor against vulnerable test applications
and validates that the expected vulnerabilities are detected.
"""

import os
import sys
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Set

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

def run_command(cmd: List[str], cwd: str = None) -> Dict:
    """Run a command and return the result."""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout": "",
            "stderr": "Command timed out",
            "returncode": -1
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
            "returncode": -1
        }

def test_python_app():
    """Test the vulnerable Python application."""
    print("🐍 Testing Python vulnerable application...")
    
    app_dir = Path(__file__).parent / "vulnerable_apps" / "python_app"
    
    # Expected vulnerabilities that should be detected
    expected_vulnerabilities = {
        "hardcoded_secrets": [
            "SECRET_API_KEY",
            "DATABASE_PASSWORD", 
            "AWS_ACCESS_KEY",
            "AWS_SECRET_KEY"
        ],
        "command_injection": [
            "subprocess.call",
            "os.system"
        ],
        "sql_injection": [
            "string formatting in SQL",
            "% formatting"
        ],
        "code_injection": [
            "eval(",
            "pickle.loads"
        ],
        "template_injection": [
            "render_template_string"
        ],
        "path_traversal": [
            "open(filename"
        ],
        "weak_crypto": [
            "hashlib.md5",
            "hashlib.sha1"
        ],
        "insecure_random": [
            "random.randint"
        ],
        "vulnerable_dependencies": [
            "Flask==2.0.1",
            "requests==2.25.1",
            "PyYAML==5.3.1"
        ]
    }
    
    # Run security scan on Python app
    result = run_command([
        "python", "-m", "codephreak.security_auditor.cli", 
        "scan", 
        "--path", str(app_dir),
        "--format", "json",
        "--output", "python_results.json"
    ])
    
    print(f"  📊 Scan result: {'✅ SUCCESS' if result['success'] else '❌ FAILED'}")
    if not result['success']:
        print(f"  ⚠️  Error: {result['stderr']}")
        return False
    
    # Validate results
    try:
        with open("python_results.json", "r") as f:
            scan_results = json.load(f)
        
        detected_issues = set()
        for finding in scan_results.get("findings", []):
            detected_issues.add(finding.get("rule_id", "").lower())
            detected_issues.add(finding.get("message", "").lower())
        
        print(f"  🔍 Detected {len(scan_results.get('findings', []))} issues")
        
        # Check if key vulnerability types were found
        categories_found = 0
        for category, patterns in expected_vulnerabilities.items():
            found = any(
                pattern.lower() in issue 
                for pattern in patterns 
                for issue in detected_issues
            )
            if found:
                categories_found += 1
                print(f"  ✅ {category}: Detected")
            else:
                print(f"  ❌ {category}: Not detected")
        
        success_rate = categories_found / len(expected_vulnerabilities)
        print(f"  📈 Detection rate: {success_rate:.1%} ({categories_found}/{len(expected_vulnerabilities)})")
        
        return success_rate > 0.6  # Expect at least 60% detection
        
    except Exception as e:
        print(f"  ❌ Failed to validate results: {e}")
        return False

def test_javascript_app():
    """Test the vulnerable JavaScript application."""
    print("🟨 Testing JavaScript vulnerable application...")
    
    app_dir = Path(__file__).parent / "vulnerable_apps" / "javascript_app"
    
    # Expected vulnerabilities
    expected_vulnerabilities = {
        "hardcoded_secrets": [
            "API_SECRET",
            "DB_PASSWORD",
            "JWT_SECRET"
        ],
        "command_injection": [
            "exec(",
            "child_process"
        ],
        "code_injection": [
            "eval(",
            "vm.runInThisContext"
        ],
        "xss": [
            "res.send(`<h1>Hello ${name}"
        ],
        "path_traversal": [
            "fs.readFile(filePath"
        ],
        "open_redirect": [
            "res.redirect(url)"
        ],
        "vulnerable_dependencies": [
            "express@4.17.1",
            "axios@0.21.0",
            "lodash@4.17.19"
        ]
    }
    
    # Run security scan
    result = run_command([
        "python", "-m", "codephreak.security_auditor.cli",
        "scan",
        "--path", str(app_dir),
        "--format", "json", 
        "--output", "javascript_results.json"
    ])
    
    print(f"  📊 Scan result: {'✅ SUCCESS' if result['success'] else '❌ FAILED'}")
    if not result['success']:
        print(f"  ⚠️  Error: {result['stderr']}")
        return False
    
    # Validate results (similar to Python test)
    try:
        with open("javascript_results.json", "r") as f:
            scan_results = json.load(f)
        
        print(f"  🔍 Detected {len(scan_results.get('findings', []))} issues")
        return len(scan_results.get("findings", [])) > 5
        
    except Exception as e:
        print(f"  ❌ Failed to validate results: {e}")
        return False

def test_docker_app():
    """Test the vulnerable Docker configuration."""
    print("🐳 Testing Docker vulnerable application...")
    
    app_dir = Path(__file__).parent / "vulnerable_apps" / "docker_app"
    
    # Expected Docker vulnerabilities
    expected_vulnerabilities = {
        "dockerfile_issues": [
            "FROM ubuntu:latest",
            "Running as root",
            "hardcoded secrets",
            "MAINTAINER is deprecated"
        ],
        "compose_issues": [
            "privileged: true",
            "network_mode: host",
            "mounting /var/run/docker.sock"
        ]
    }
    
    # Run security scan
    result = run_command([
        "python", "-m", "codephreak.security_auditor.cli",
        "scan", 
        "--path", str(app_dir),
        "--format", "json",
        "--output", "docker_results.json"
    ])
    
    print(f"  📊 Scan result: {'✅ SUCCESS' if result['success'] else '❌ FAILED'}")
    if not result['success']:
        print(f"  ⚠️  Error: {result['stderr']}")
        return False
    
    try:
        with open("docker_results.json", "r") as f:
            scan_results = json.load(f)
        
        print(f"  🔍 Detected {len(scan_results.get('findings', []))} issues")
        return len(scan_results.get("findings", [])) > 10
        
    except Exception as e:
        print(f"  ❌ Failed to validate results: {e}")
        return False

def test_performance():
    """Test performance with a larger codebase."""
    print("⚡ Testing performance with larger codebase...")
    
    # Create a temporary directory with multiple files
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create multiple Python files with some issues
        for i in range(50):
            file_path = Path(temp_dir) / f"test_{i}.py"
            file_path.write_text(f'''
import os
import subprocess

# Some vulnerable code
def execute_command():
    cmd = input("Enter command: ")
    subprocess.call(cmd, shell=True)  # Command injection
    
def get_password():
    return "hardcoded_password_123"  # Hardcoded secret
    
def sql_query(user_id):
    query = f"SELECT * FROM users WHERE id = {{user_id}}"  # SQL injection
    return query
''')
        
        # Run performance test
        import time
        start_time = time.time()
        
        result = run_command([
            "python", "-m", "codephreak.security_auditor.cli",
            "scan",
            "--path", temp_dir,
            "--format", "json",
            "--output", "performance_results.json"
        ])
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"  ⏱️  Scan duration: {duration:.2f} seconds")
        print(f"  📊 Scan result: {'✅ SUCCESS' if result['success'] else '❌ FAILED'}")
        
        if result['success']:
            try:
                with open("performance_results.json", "r") as f:
                    scan_results = json.load(f)
                
                findings_count = len(scan_results.get("findings", []))
                print(f"  🔍 Detected {findings_count} issues across 50 files")
                print(f"  📈 Performance: {findings_count/duration:.1f} findings per second")
                
                return duration < 60 and findings_count > 50  # Should find issues quickly
                
            except Exception as e:
                print(f"  ❌ Failed to parse results: {e}")
                return False
        else:
            print(f"  ⚠️  Error: {result['stderr']}")
            return False

def main():
    """Run all tests and report results."""
    print("🚀 CodePhreak Security Auditor Test Suite")
    print("=" * 50)
    
    # Change to the test directory
    os.chdir(Path(__file__).parent)
    
    tests = [
        ("Python App", test_python_app),
        ("JavaScript App", test_javascript_app), 
        ("Docker App", test_docker_app),
        ("Performance", test_performance)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        print(f"\n📋 Running {test_name} test...")
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"  💥 Test failed with exception: {e}")
            results[test_name] = False
        
        status = "✅ PASSED" if results[test_name] else "❌ FAILED"
        print(f"  🎯 {test_name}: {status}")
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Test Results Summary")
    print("=" * 50)
    
    passed = sum(results.values())
    total = len(results)
    
    for test_name, passed in results.items():
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"  {test_name}: {status}")
    
    print(f"\n🎯 Overall: {passed}/{total} tests passed ({passed/total:.1%})")
    
    if passed == total:
        print("🎉 All tests passed! CodePhreak Security Auditor is working correctly.")
        return 0
    else:
        print("⚠️  Some tests failed. Please check the implementation.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
