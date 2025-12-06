#!/usr/bin/env python3
"""
Vulnerable Python Application - Test Fixture for CodePhreak Security Auditor

This intentionally vulnerable application contains multiple security issues
that should be detected by various security scanning tools.

⚠️  WARNING: This code contains intentional security vulnerabilities.
    DO NOT use in production environments!
"""

import os
import subprocess
import sqlite3
import hashlib
import pickle
import yaml
from flask import Flask, request, render_template_string, session
import requests

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded Secret (should be detected by Gitleaks, TruffleHog, detect-secrets)
SECRET_API_KEY = "sk-1234567890abcdef0123456789abcdef"
DATABASE_PASSWORD = "admin123!@#"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdef1234567890abcdef1234567890abcdef
1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
-----END RSA PRIVATE KEY-----"""

# VULNERABILITY 2: Insecure Flask Secret Key
app.secret_key = "secret"  # Hardcoded, predictable secret key

# VULNERABILITY 3: Debug mode enabled (should be detected by Bandit)
app.config['DEBUG'] = True

@app.route('/')
def index():
    return '''
    <h1>Vulnerable Test Application</h1>
    <a href="/exec?cmd=ls">Execute Command</a><br>
    <a href="/user/1">View User</a><br>
    <a href="/template?name=World">Template Rendering</a><br>
    <a href="/upload">File Upload</a><br>
    '''

@app.route('/exec')
def execute_command():
    """VULNERABILITY 4: Command Injection (should be detected by Bandit, Semgrep)"""
    cmd = request.args.get('cmd', 'ls')
    
    # Dangerous: Direct shell execution with user input
    result = subprocess.call(cmd, shell=True)
    
    # Also vulnerable: os.system usage
    os.system(f"echo 'Executing: {cmd}'")
    
    return f"Command executed with result: {result}"

@app.route('/user/<user_id>')
def get_user(user_id):
    """VULNERABILITY 5: SQL Injection (should be detected by Bandit, Semgrep)"""
    conn = sqlite3.connect('users.db')
    
    # Dangerous: String formatting in SQL query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor = conn.execute(query)
    
    # Also vulnerable: % formatting
    query2 = "SELECT * FROM users WHERE name = '%s'" % request.args.get('name', '')
    cursor2 = conn.execute(query2)
    
    return str(cursor.fetchall())

@app.route('/template')
def template_injection():
    """VULNERABILITY 6: Server-Side Template Injection (should be detected by Bandit, Semgrep)"""
    name = request.args.get('name', 'World')
    
    # Dangerous: Direct template rendering with user input
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)

@app.route('/pickle')
def pickle_deserialization():
    """VULNERABILITY 7: Insecure Deserialization (should be detected by Bandit)"""
    data = request.args.get('data', '')
    
    if data:
        # Dangerous: Pickle deserialization of user data
        try:
            obj = pickle.loads(data.encode())
            return str(obj)
        except:
            return "Invalid data"
    
    return "No data provided"

@app.route('/yaml')
def yaml_load():
    """VULNERABILITY 8: Unsafe YAML Loading (should be detected by Bandit)"""
    yaml_data = request.args.get('yaml', 'test: value')
    
    # Dangerous: yaml.load without safe loader
    try:
        data = yaml.load(yaml_data, Loader=yaml.Loader)
        return str(data)
    except:
        return "Invalid YAML"

@app.route('/file')
def file_access():
    """VULNERABILITY 9: Path Traversal (should be detected by Bandit, Semgrep)"""
    filename = request.args.get('file', 'test.txt')
    
    # Dangerous: Direct file access without path validation
    try:
        with open(filename, 'r') as f:
            return f.read()
    except:
        return "File not found"

@app.route('/eval')
def code_execution():
    """VULNERABILITY 10: Code Injection (should be detected by Bandit)"""
    code = request.args.get('code', '1+1')
    
    # Dangerous: Direct eval of user input
    try:
        result = eval(code)
        return str(result)
    except:
        return "Invalid code"

@app.route('/request')
def external_request():
    """VULNERABILITY 11: SSRF (should be detected by Bandit, Semgrep)"""
    url = request.args.get('url', 'http://example.com')
    
    # Dangerous: Unvalidated external requests
    try:
        response = requests.get(url, verify=False)  # Also: SSL verification disabled
        return response.text[:1000]
    except:
        return "Request failed"

def weak_crypto():
    """VULNERABILITY 12: Weak Cryptography (should be detected by Bandit)"""
    import hashlib
    
    # Weak hashing algorithms
    md5_hash = hashlib.md5(b"password").hexdigest()
    sha1_hash = hashlib.sha1(b"password").hexdigest()
    
    return md5_hash, sha1_hash

def insecure_random():
    """VULNERABILITY 13: Weak Random Number Generation (should be detected by Bandit)"""
    import random
    
    # Insecure random for security purposes
    token = random.randint(1000000, 9999999)  # Should use secrets module
    return str(token)

def hardcoded_password():
    """VULNERABILITY 14: Hardcoded Passwords (should be detected by Bandit)"""
    passwords = [
        "password123",
        "admin",
        "root",
        "123456"
    ]
    return passwords[0]

# VULNERABILITY 15: Insecure HTTP Usage (should be detected by various tools)
def make_insecure_request():
    """Makes requests without proper security headers"""
    import urllib.request
    
    # Insecure HTTP request
    response = urllib.request.urlopen("http://api.insecure-site.com/data")
    return response.read()

if __name__ == '__main__':
    # VULNERABILITY 16: Running with debug=True in production
    # VULNERABILITY 17: Binding to all interfaces (0.0.0.0)
    # VULNERABILITY 18: Using default port without security
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
