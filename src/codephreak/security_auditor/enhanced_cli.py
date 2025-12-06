#!/usr/bin/env python3
"""
CodePhreak Security Auditor - Enhanced CLI

Enhanced command-line interface with hybrid scanning capabilities.
Supports both local scanning (free) and cloud-enhanced analysis (premium).
"""

import asyncio
import click
import json
import sys
import os
from pathlib import Path
from typing import List, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

from .auth import get_auth, SubscriptionTier
from .hybrid_engine import HybridScanEngine, HybridScanOptions

console = Console()


def premium_feature_required(feature_name: str):
    """Decorator to check if premium feature is available."""
    def decorator(f):
        def wrapper(*args, **kwargs):
            auth = get_auth()
            if not auth.is_premium_feature(feature_name):
                tier = auth.get_tier().value
                console.print(
                    f"⚠️  [yellow]Premium feature '{feature_name}' not available in {tier} tier[/yellow]\n"
                    f"   Upgrade at: {auth.get_upgrade_url()}"
                )
                sys.exit(1)
            return f(*args, **kwargs)
        return wrapper
    return decorator


@click.group()
@click.version_option(version="0.1.0", prog_name="CodePhreak Security Auditor")
def cli():
    """🔒 CodePhreak Security Auditor - Enterprise-grade security vulnerability scanner
    
    Hybrid model: Free local scanning + Premium cloud enhancement
    """
    pass


@cli.command()
@click.option(
    "--path", 
    "-p", 
    default=".", 
    help="Path to scan (default: current directory)"
)
@click.option(
    "--output", 
    "-o", 
    help="Output file path"
)
@click.option(
    "--format", 
    "-f", 
    type=click.Choice(["json", "sarif", "html", "pdf"]), 
    default="json",
    help="Output format (default: json)"
)
@click.option(
    "--premium", 
    is_flag=True,
    help="Enable cloud-enhanced analysis (requires subscription)"
)
@click.option(
    "--ai-analysis", 
    is_flag=True,
    help="Enable AI-powered vulnerability analysis (Premium)"
)
@click.option(
    "--compliance", 
    multiple=True,
    help="Compliance frameworks to check (e.g., OWASP, PCI-DSS) (Premium)"
)
@click.option(
    "--priority", 
    is_flag=True,
    help="Enable priority scoring (Premium)"
)
@click.option(
    "--team-id", 
    help="Team ID for collaboration features (Premium)"
)
@click.option(
    "--severity", 
    "-s", 
    type=click.Choice(["all", "critical", "high", "medium"]), 
    default="all",
    help="Minimum severity level (default: all)"
)
@click.option(
    "--exclude", 
    "-e", 
    multiple=True,
    help="Exclude patterns (can be used multiple times)"
)
@click.option(
    "--quiet", 
    "-q", 
    is_flag=True, 
    help="Suppress progress output"
)
@click.option(
    "--verbose", 
    "-v", 
    is_flag=True, 
    help="Verbose output"
)
def scan(path, output, format, premium, ai_analysis, compliance, priority, team_id, severity, exclude, quiet, verbose):
    """Run hybrid security scan (local + optional cloud enhancement)"""
    
    if not quiet:
        _display_banner()
    
    # Prepare scan options
    scan_options = HybridScanOptions(
        path=path,
        include_cloud_analysis=premium,
        enable_ai_features=ai_analysis,
        compliance_frameworks=list(compliance),
        priority_mode=priority,
        generate_reports=[format] if format != "json" else ["json"],
        team_id=team_id
    )
    
    # Initialize hybrid engine
    engine = HybridScanEngine()
    
    try:
        # Validate premium features
        unavailable_features = asyncio.run(engine.validate_premium_features(scan_options))
        if unavailable_features and not quiet:
            console.print("⚠️  Some premium features are not available:")
            for feature in unavailable_features:
                console.print(f"   • {feature}")
            console.print(f"   Upgrade at: {get_auth().get_upgrade_url()}\n")
        
        # Run hybrid scan
        if not quiet:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Running security scan...", total=None)
                result = asyncio.run(engine.scan(scan_options))
        else:
            result = asyncio.run(engine.scan(scan_options))
        
        # Save results
        if output:
            with open(output, 'w') as f:
                json.dump(result.__dict__, f, indent=2, default=str)
            
            if not quiet:
                console.print(f"✅ Results saved to: {output}")
        else:
            print(json.dumps(result.__dict__, indent=2, default=str))
        
        # Display summary
        if not quiet:
            _display_scan_summary(result, scan_options)
    
    except PermissionError as e:
        console.print(f"🔒 [yellow]Premium feature required: {e}[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"❌ [red]Error during scan: {e}[/red]")
        if verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)


@cli.command()
@click.option("--path", "-p", default=".", help="Path to analyze")
@click.option("--output", "-o", help="Output file path")
def quick(path, output):
    """Quick security check (local tools only - always free)"""
    console.print("🚀 Running quick security check (free tier)")
    ctx = click.get_current_context()
    ctx.invoke(scan, path=path, output=output, premium=False)


@cli.command()
@click.option("--path", "-p", default=".", help="Path to audit")
@click.option("--output", "-o", help="Output file path")
@click.option("--framework", "-f", multiple=True, help="Compliance framework")
def audit(path, output, framework):
    """Full security audit with compliance checking (Premium)"""
    console.print("🔍 Running full security audit with premium features")
    ctx = click.get_current_context()
    ctx.invoke(scan, 
              path=path, 
              output=output, 
              premium=True, 
              ai_analysis=True, 
              compliance=framework,
              priority=True)


@cli.group()
def auth():
    """Authentication and subscription management"""
    pass


@auth.command()
@click.option("--api-key", prompt=True, hide_input=True, help="Your CodePhreak API key")
def login(api_key):
    """Login with CodePhreak API key"""
    
    console.print("🔐 Authenticating with CodePhreak...")
    
    auth_manager = get_auth()
    success = auth_manager.login(api_key)
    
    if success:
        console.print("✅ [green]Successfully logged in![/green]")
        
        # Show subscription info
        subscription = auth_manager.get_subscription()
        console.print(f"📋 Subscription: {subscription.tier.value}")
        if subscription.organization:
            console.print(f"🏢 Organization: {subscription.organization}")
        
    else:
        console.print("❌ [red]Invalid API key[/red]")
        sys.exit(1)


@auth.command()
def logout():
    """Logout and clear stored credentials"""
    
    auth_manager = get_auth()
    auth_manager.logout()
    console.print("👋 Successfully logged out")


@auth.command()
def status():
    """Show authentication and subscription status"""
    
    auth_manager = get_auth()
    subscription = auth_manager.get_subscription()
    feature_info = auth_manager.get_feature_info()
    
    # Create status table
    table = Table(title="CodePhreak Account Status")
    table.add_column("Property", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")
    
    table.add_row("Subscription Tier", subscription.tier.value.title())
    table.add_row("API Key", "✅ Configured" if auth_manager.get_api_key() else "❌ Not set")
    
    if subscription.organization:
        table.add_row("Organization", subscription.organization)
    
    if subscription.expires_at:
        table.add_row("Expires", subscription.expires_at.strftime("%Y-%m-%d %H:%M:%S"))
    
    table.add_row("Available Features", f"{feature_info['feature_count']}/{feature_info['total_features']}")
    
    console.print(table)
    
    # Show feature breakdown
    if subscription.tier != SubscriptionTier.FREE:
        console.print("\n📋 Available Features:")
        for feature in sorted(feature_info['available_features'])[:10]:  # Show first 10
            console.print(f"  ✅ {feature.replace('_', ' ').title()}")
        
        if len(feature_info['available_features']) > 10:
            console.print(f"  ... and {len(feature_info['available_features']) - 10} more")
    
    if feature_info['unavailable_features']:
        console.print(f"\n💎 Premium Features Available:")
        console.print(f"   Upgrade at: {auth_manager.get_upgrade_url()}")


@cli.command()
def features():
    """List all available features and their requirements"""
    
    engine = HybridScanEngine()
    available_features = engine.get_available_features()
    auth_manager = get_auth()
    current_tier = auth_manager.get_tier()
    
    table = Table(title="CodePhreak Features")
    table.add_column("Feature", style="cyan")
    table.add_column("Available", style="green")
    table.add_column("Required Tier", style="blue")
    table.add_column("Description")
    
    feature_descriptions = {
        "basic_scanning": ("Free", "Core security scanning with open source tools"),
        "json_reports": ("Free", "JSON format scan reports"),
        "sarif_reports": ("Free", "SARIF format reports for IDE integration"),
        "html_reports": ("Professional", "Rich HTML reports with visualizations"),
        "pdf_reports": ("Professional", "Professional PDF reports"),
        "ai_analysis": ("Enterprise", "AI-powered vulnerability pattern detection"),
        "compliance_reports": ("Professional", "Compliance framework checking"),
        "priority_scanning": ("Professional", "Risk-based vulnerability prioritization"),
        "vulnerability_trends": ("Professional", "Historical vulnerability trend analysis"),
        "auto_remediation": ("Enterprise", "Automated fix suggestions"),
        "team_collaboration": ("Professional", "Team dashboard and collaboration features")
    }
    
    for feature, available in available_features.items():
        required_tier, description = feature_descriptions.get(feature, ("Unknown", ""))
        status = "✅" if available else "❌"
        
        table.add_row(
            feature.replace('_', ' ').title(),
            status,
            required_tier,
            description
        )
    
    console.print(table)
    
    if current_tier == SubscriptionTier.FREE:
        console.print(f"\n💎 Upgrade to unlock premium features: {auth_manager.get_upgrade_url()}")


@cli.command()
def tools():
    """List available security tools and their status"""
    
    # This would check actual tool availability
    tools = [
        ("Bandit", "SAST", "✅", "Python security linting"),
        ("Semgrep", "SAST", "✅", "Multi-language static analysis"),
        ("Trivy", "SCA", "✅", "Vulnerability database scanning"),
        ("Gitleaks", "Secrets", "✅", "Git secret detection"),
        ("Hadolint", "Container", "✅", "Dockerfile linting"),
        ("Checkov", "IaC", "✅", "Infrastructure as Code security"),
        ("npm audit", "SCA", "✅", "Node.js dependency scanning"),
        ("pip-audit", "SCA", "✅", "Python dependency scanning")
    ]
    
    table = Table(title="Security Tools")
    table.add_column("Tool", style="cyan", no_wrap=True)
    table.add_column("Category", style="magenta")
    table.add_column("Status", style="green")
    table.add_column("Description")
    
    for name, category, status, description in tools:
        table.add_row(name, category, status, description)
    
    console.print(table)


@cli.command()
def pricing():
    """Show pricing tiers and feature comparison"""
    
    console.print(Panel.fit(
        "💰 [bold blue]CodePhreak Security Auditor Pricing[/bold blue]\n\n"
        "🆓 [bold green]Free Tier[/bold green]\n"
        "   • Local security scanning\n"
        "   • JSON & SARIF reports\n"
        "   • Community support\n"
        "   • All open source tools\n\n"
        "💎 [bold yellow]Professional - $49/month[/bold yellow]\n"
        "   • Everything in Free\n"
        "   • HTML & PDF reports\n"
        "   • Priority scoring\n"
        "   • Compliance reporting\n"
        "   • Team collaboration\n\n"
        "🏢 [bold red]Enterprise - $199/month[/bold red]\n"
        "   • Everything in Professional\n"
        "   • AI-powered analysis\n"
        "   • Auto-remediation\n"
        "   • Custom compliance\n"
        "   • SSO integration\n\n"
        "🚀 [bold purple]Enterprise+ - $499/month[/bold purple]\n"
        "   • Everything in Enterprise\n"
        "   • Runtime protection\n"
        "   • Continuous monitoring\n"
        "   • Incident response\n"
        "   • Dedicated support",
        border_style="green"
    ))
    
    console.print(f"\n🌐 Sign up at: https://codephreak.ai/pricing")


def _display_banner():
    """Display application banner."""
    auth_manager = get_auth()
    tier = auth_manager.get_tier()
    
    tier_colors = {
        SubscriptionTier.FREE: "green",
        SubscriptionTier.PROFESSIONAL: "yellow", 
        SubscriptionTier.ENTERPRISE: "red",
        SubscriptionTier.ENTERPRISE_PLUS: "purple"
    }
    
    tier_color = tier_colors.get(tier, "white")
    
    console.print(Panel.fit(
        f"🔒 [bold blue]CodePhreak Security Auditor[/bold blue]\n"
        f"Enterprise-grade hybrid security scanner\n"
        f"Current tier: [{tier_color}]{tier.value.title()}[/{tier_color}]",
        border_style="blue"
    ))


def _display_scan_summary(result, scan_options: HybridScanOptions):
    """Display formatted scan results summary."""
    
    findings = result.findings if hasattr(result, 'findings') else []
    metadata = result.metadata if hasattr(result, 'metadata') else None
    
    # Count findings by severity
    severity_counts = {}
    for finding in findings:
        severity = getattr(finding, 'severity', 'Unknown')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    # Create summary table
    table = Table(title="Scan Results Summary")
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")
    
    table.add_row("Total Findings", str(len(findings)))
    
    if metadata:
        table.add_row("Local Scan Time", f"{metadata.local_duration:.2f}s")
        if metadata.cloud_duration:
            table.add_row("Cloud Enhancement", f"{metadata.cloud_duration:.2f}s")
        table.add_row("Tools Used", str(len(metadata.tools_used)))
        if metadata.enhanced_features:
            table.add_row("Premium Features", ", ".join(metadata.enhanced_features))
    
    for severity, count in severity_counts.items():
        if count > 0:
            table.add_row(f"{severity} Severity", str(count))
    
    console.print(table)
    
    # Show top findings
    if findings:
        console.print("\n📋 Top Security Findings:")
        for i, finding in enumerate(findings[:5]):
            severity_color = {
                "CRITICAL": "red",
                "HIGH": "red", 
                "MEDIUM": "yellow",
                "LOW": "blue",
                "INFO": "green"
            }.get(getattr(finding, 'severity', ''), "white")
            
            message = getattr(finding, 'message', 'No message available')
            tool = getattr(finding, 'tool', 'Unknown')
            
            console.print(f"  {i+1}. [{severity_color}]{getattr(finding, 'severity', 'Unknown')}[/{severity_color}] ({tool}) - {message}")
    
    # Show upgrade prompt for free users
    if scan_options.include_cloud_analysis and get_auth().get_tier() == SubscriptionTier.FREE:
        console.print(f"\n💎 [yellow]Upgrade to unlock cloud-enhanced analysis: {get_auth().get_upgrade_url()}[/yellow]")


if __name__ == "__main__":
    # Enable mock mode for development
    if os.getenv("CODEPHREAK_DEVELOPMENT", "false").lower() == "true":
        os.environ["CODEPHREAK_MOCK_CLOUD"] = "true"
    
    cli()
