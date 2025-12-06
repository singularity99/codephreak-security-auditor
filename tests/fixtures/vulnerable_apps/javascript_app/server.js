#!/usr/bin/env node
/**
 * Vulnerable Node.js Application - Test Fixture for CodePhreak Security Auditor
 * 
 * This intentionally vulnerable application contains multiple security issues
 * that should be detected by various security scanning tools.
 * 
 * ⚠️  WARNING: This code contains intentional security vulnerabilities.
 *     DO NOT use in production environments!
 */

const express = require('express');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const crypto = require('crypto');
const mysql = require('mysql2');
const vm = require('vm');
const http = require('http');
const https = require('https');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// VULNERABILITY 1: Hardcoded Secrets (should be detected by ESLint security plugin, Gitleaks)
const API_SECRET = "sk-live_1234567890abcdef1234567890abcdef";
const DB_PASSWORD = "SuperSecret123!@#";
const JWT_SECRET = "my-jwt-secret-key";
const STRIPE_SECRET = "sk_live_51234567890abcdef1234567890abcdef";

// VULNERABILITY 2: Insecure session configuration
app.use(require('express-session')({
    secret: 'keyboard cat',  // Hardcoded secret
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: false,      // Should be true for HTTPS
        httpOnly: false,    // Should be true to prevent XSS
        maxAge: null        // No expiration
    }
}));

// VULNERABILITY 3: Missing security headers
// No helmet.js usage, no CSP, etc.

app.get('/', (req, res) => {
    res.send(`
        <h1>Vulnerable Node.js Test Application</h1>
        <a href="/exec?cmd=ls">Execute Command</a><br>
        <a href="/user?id=1">View User</a><br>
        <a href="/eval?code=1+1">Evaluate Code</a><br>
        <a href="/file?path=test.txt">Read File</a><br>
        <a href="/redirect?url=http://google.com">Redirect</a><br>
    `);
});

// VULNERABILITY 4: Command Injection (should be detected by ESLint security plugin)
app.get('/exec', (req, res) => {
    const cmd = req.query.cmd || 'ls';
    
    // Dangerous: Direct command execution with user input
    exec(cmd, (error, stdout, stderr) => {
        if (error) {
            res.send(`Error: ${error.message}`);
            return;
        }
        res.send(`<pre>${stdout}</pre>`);
    });
});

// VULNERABILITY 5: SQL Injection (should be detected by ESLint security plugin)
app.get('/user', (req, res) => {
    const userId = req.query.id;
    
    // Dangerous: String concatenation in SQL query
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    
    // Simulate database connection (would be vulnerable if real)
    res.json({
        query: query,
        message: "This would execute: " + query
    });
});

// VULNERABILITY 6: Code Injection via eval (should be detected by ESLint security plugin)
app.get('/eval', (req, res) => {
    const code = req.query.code || '1+1';
    
    try {
        // Dangerous: Direct eval of user input
        const result = eval(code);
        res.json({ result: result });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// VULNERABILITY 7: VM Code Injection (should be detected by ESLint security plugin)
app.get('/vm', (req, res) => {
    const code = req.query.code || 'Math.random()';
    
    try {
        // Still dangerous: VM with access to require
        const result = vm.runInThisContext(code);
        res.json({ result: result });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// VULNERABILITY 8: Path Traversal (should be detected by ESLint security plugin)
app.get('/file', (req, res) => {
    const filePath = req.query.path || 'test.txt';
    
    // Dangerous: Direct file access without path validation
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            res.status(404).json({ error: 'File not found' });
            return;
        }
        res.send(`<pre>${data}</pre>`);
    });
});

// VULNERABILITY 9: Open Redirect (should be detected by ESLint security plugin)
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    
    // Dangerous: Unvalidated redirect
    if (url) {
        res.redirect(url);
    } else {
        res.send('No URL provided');
    }
});

// VULNERABILITY 10: XSS via template injection
app.get('/hello', (req, res) => {
    const name = req.query.name || 'World';
    
    // Dangerous: Direct HTML output without escaping
    res.send(`<h1>Hello ${name}!</h1>`);
});

// VULNERABILITY 11: Insecure randomness (should be detected by ESLint security plugin)
app.get('/token', (req, res) => {
    // Dangerous: Using Math.random() for security tokens
    const token = Math.random().toString(36).substring(2);
    res.json({ token: token });
});

// VULNERABILITY 12: Weak crypto implementation
app.get('/hash', (req, res) => {
    const password = req.query.password || 'test';
    
    // Dangerous: Weak hashing algorithms
    const md5Hash = crypto.createHash('md5').update(password).digest('hex');
    const sha1Hash = crypto.createHash('sha1').update(password).digest('hex');
    
    res.json({
        md5: md5Hash,
        sha1: sha1Hash
    });
});

// VULNERABILITY 13: SSRF (should be detected by ESLint security plugin)
app.get('/fetch', (req, res) => {
    const url = req.query.url;
    
    if (!url) {
        res.status(400).json({ error: 'No URL provided' });
        return;
    }
    
    // Dangerous: Unvalidated server-side requests
    const client = url.startsWith('https:') ? https : http;
    client.get(url, (response) => {
        let data = '';
        response.on('data', chunk => data += chunk);
        response.on('end', () => {
            res.json({ data: data.substring(0, 1000) }); // Limit response size
        });
    }).on('error', (err) => {
        res.status(500).json({ error: err.message });
    });
});

// VULNERABILITY 14: Prototype pollution
app.post('/config', (req, res) => {
    const config = {};
    
    // Dangerous: Unvalidated object merging
    function merge(target, source) {
        for (let key in source) {
            if (typeof source[key] === 'object' && source[key] !== null) {
                if (!target[key]) target[key] = {};
                merge(target[key], source[key]);
            } else {
                target[key] = source[key];
            }
        }
    }
    
    merge(config, req.body);
    res.json({ config: config });
});

// VULNERABILITY 15: Insecure deserialization
app.post('/deserialize', (req, res) => {
    try {
        // Dangerous: Direct JSON.parse without validation
        const data = JSON.parse(req.body.data);
        
        // Even more dangerous: Using the parsed data as code
        if (data.type === 'function') {
            const func = new Function(data.code);
            const result = func();
            res.json({ result: result });
        } else {
            res.json({ data: data });
        }
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// VULNERABILITY 16: Missing rate limiting
// No rate limiting middleware implemented

// VULNERABILITY 17: Verbose error messages
process.on('uncaughtException', (error) => {
    console.log('Uncaught Exception:', error);
    // Should not expose stack traces in production
});

// VULNERABILITY 18: Running with debug information
if (process.env.NODE_ENV !== 'production') {
    app.use((req, res, next) => {
        console.log(`${req.method} ${req.path}`, req.query, req.body);
        next();
    });
}

// VULNERABILITY 19: Insecure server configuration
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
    console.log(`Debug mode: ${process.env.NODE_ENV !== 'production'}`);
});

// VULNERABILITY 20: No graceful shutdown handling
// Server doesn't handle SIGTERM or SIGINT properly

module.exports = app;
