#!/usr/bin/env python3
"""
CodePhreak Security Auditor CLI

Main command-line interface for the CodePhreak Security Auditor Droid.
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .core import SecurityAuditorDroid
from .config import Config
from .utils.banner import print_banner
from .utils.logger import setup_logging


console = Console()


@click.group(invoke_without_command=True)
@click.option(
    "--target",
    "-t", 
    type=click.Path(exists=True, path_type=Path),
    default=Path.cwd(),
    help="Target directory or file to scan (default: current directory)"
)
@click.option(
    "--workflow",
    "-w",
    type=click.Choice(["quick-check", "full-audit", "compliance"], case_sensitive=False),
    default="full-audit",
    help="Security scan workflow to execute"
)
@click.option(
    "--format",
    "-f",
    "output_formats",
    multiple=True,
    type=click.Choice(["json", "html", "sarif", "pdf"], case_sensitive=False),
    default=["json", "html"],
    help="Output format(s) for the security report"
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output directory or file path"
)
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, path_type=Path),
    help="Configuration file path"
)
@click.option(
    "--framework",
    type=click.Choice(["owasp-asvs", "pci-dss", "nist-cybersecurity", "iso-27001"], case_sensitive=False),
    help="Compliance framework for assessment (used with compliance workflow)"
)
@click.option(
    "--fail-on",
    multiple=True,
    type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
    default=["critical"],
    help="Fail with non-zero exit code on specified severity levels"
)
@click.option(
    "--timeout",
    type=int,
    default=1800,  # 30 minutes
    help="Maximum execution timeout in seconds"
)
@click.option(
    "--verbose",
    "-v",
    count=True,
    help="Increase verbosity (use -v, -vv, or -vvv)"
)
@click.option(
    "--quiet",
    "-q",
    is_flag=True,
    help="Suppress non-essential output"
)
@click.option(
    "--no-banner",
    is_flag=True,
    help="Suppress CodePhreak banner"
)
@click.version_option(version="0.1.0", prog_name="CodePhreak Security Auditor")
@click.pass_context
async def cli(
    ctx: click.Context,
    target: Path,
    workflow: str,
    output_formats: tuple,
    output: Optional[Path],
    config: Optional[Path],
    framework: Optional[str],
    fail_on: tuple,
    timeout: int,
    verbose: int,
    quiet: bool,
    no_banner: bool
):
    """
    🔒 CodePhreak Security Auditor Droid
    
    Enterprise-grade security vulnerability scanner with 92-96% commercial parity
    using exclusively open source tools.
    
    Examples:
        codephreak-audit --target ./my-app
        codephreak-audit --workflow quick-check --format sarif
        codephreak-audit --workflow compliance --framework pci-dss
    """
    
    # Setup logging based on verbosity
    log_level = "ERROR" if quiet else ["WARNING", "INFO", "DEBUG"][min(verbose, 2)]
    setup_logging(level=log_level)
    
    # Print banner unless suppressed
    if not no_banner and not quiet:
        print_banner()
    
    # If no subcommand, run the main audit
    if ctx.invoked_subcommand is None:
        await run_audit(
            target=target,
            workflow=workflow,
            output_formats=list(output_formats),
            output=output,
            config=config,
            framework=framework,
            fail_on=list(fail_on),
            timeout=timeout,
            quiet=quiet
        )


@cli.command()
@click.option(
    "--format",
    type=click.Choice(["yaml", "json"], case_sensitive=False),
    default="yaml",
    help="Configuration format"
)
@click.argument("output_path", type=click.Path(path_type=Path))
def init_config(format: str, output_path: Path):
    """Generate a sample configuration file"""
    config = Config()
    config.generate_sample_config(output_path, format)
    console.print(f"✅ Sample configuration generated: {output_path}")


@cli.command()
@click.option(
    "--check-deps",
    is_flag=True,
    help="Check if required security tools are installed"
)
def doctor(check_deps: bool):
    """Diagnose system and tool installation"""
    from .utils.doctor import SystemDoctor
    
    doctor = SystemDoctor()
    doctor.run_diagnostics(check_dependencies=check_deps)


@cli.command()
def tools():
    """List available security tools and their status"""
    from .tools import ToolRegistry
    
    registry = ToolRegistry()
    tools_status = registry.get_all_tools_status()
    
    table = Table(title="CodePhreak Security Tools Status")
    table.add_column("Tool", style="cyan")
    table.add_column("Category", style="magenta")
    table.add_column("Status", style="green")
    table.add_column("Version", style="yellow")
    
    for tool_name, status in tools_status.items():
        table.add_row(
            tool_name,
            status.category,
            "✅ Installed" if status.available else "❌ Missing",
            status.version or "N/A"
        )
    
    console.print(table)


@cli.command()
@click.argument("target", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path"
)
def sbom(target: Path, output: Optional[Path]):
    """Generate Software Bill of Materials (SBOM)"""
    from .tools.sbom import SBOMGenerator
    
    with console.status("Generating SBOM..."):
        generator = SBOMGenerator()
        sbom_data = generator.generate(target)
    
    if output:
        output.write_text(json.dumps(sbom_data, indent=2))
        console.print(f"✅ SBOM generated: {output}")
    else:
        console.print_json(data=sbom_data)


async def run_audit(
    target: Path,
    workflow: str,
    output_formats: List[str],
    output: Optional[Path],
    config: Optional[Path],
    framework: Optional[str],
    fail_on: List[str],
    timeout: int,
    quiet: bool
) -> None:
    """Execute the main security audit workflow"""
    
    try:
        # Initialize the Security Auditor Droid
        droid_config = Config.load(config) if config else Config()
        droid = SecurityAuditorDroid(
            target_path=target,
            config=droid_config,
            workflow_type=workflow,
            compliance_framework=framework
        )
        
        if not quiet:
            console.print(f"🎯 Target: {target}")
            console.print(f"🔄 Workflow: {workflow}")
            console.print(f"📊 Output formats: {', '.join(output_formats)}")
            console.print()
        
        # Execute the security audit with progress tracking
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            disable=quiet
        ) as progress:
            
            # Add progress tasks
            main_task = progress.add_task("Running security audit...", total=100)
            
            # Run the audit
            results = await asyncio.wait_for(
                droid.execute_with_progress(progress, main_task),
                timeout=timeout
            )
            
            progress.update(main_task, completed=100, description="✅ Audit completed")
        
        # Generate reports
        if not quiet:
            console.print("\n📋 Generating reports...")
        
        reports = await droid.generate_reports(
            results,
            formats=output_formats,
            output_path=output
        )
        
        # Display summary
        if not quiet:
            display_results_summary(results)
        
        # Display report locations
        for format_type, report_path in reports.items():
            console.print(f"📄 {format_type.upper()} report: {report_path}")
        
        # Check exit conditions
        exit_code = determine_exit_code(results, fail_on)
        if exit_code != 0:
            console.print(f"\n❌ Audit failed: Found {results.get_severity_count('critical')} critical and {results.get_severity_count('high')} high severity issues")
            sys.exit(exit_code)
        
        if not quiet:
            console.print("\n✅ Security audit completed successfully!")
    
    except asyncio.TimeoutError:
        console.print(f"❌ Audit timed out after {timeout} seconds", style="red")
        sys.exit(2)
    except KeyboardInterrupt:
        console.print("\n⚠️ Audit interrupted by user", style="yellow")
        sys.exit(1)
    except Exception as e:
        console.print(f"❌ Audit failed with error: {e}", style="red")
        if not quiet:
            console.print_exception()
        sys.exit(1)


def display_results_summary(results) -> None:
    """Display a summary table of audit results"""
    
    table = Table(title="🔒 Security Audit Summary")
    table.add_column("Severity", style="cyan")
    table.add_column("Count", style="magenta")
    table.add_column("Percentage", style="green")
    
    total_findings = results.total_findings
    
    for severity in ["Critical", "High", "Medium", "Low"]:
        count = results.get_severity_count(severity.lower())
        percentage = (count / total_findings * 100) if total_findings > 0 else 0
        
        # Color code based on severity
        color = {
            "Critical": "red",
            "High": "orange1", 
            "Medium": "yellow",
            "Low": "green"
        }[severity]
        
        table.add_row(
            f"[{color}]{severity}[/{color}]",
            str(count),
            f"{percentage:.1f}%"
        )
    
    table.add_row("", "", "", style="dim")
    table.add_row(
        "[bold]Total[/bold]", 
        str(total_findings), 
        "100.0%",
        style="bold"
    )
    
    console.print(table)


def determine_exit_code(results, fail_on: List[str]) -> int:
    """Determine exit code based on results and fail-on criteria"""
    
    for severity in fail_on:
        if results.get_severity_count(severity) > 0:
            return 1
    
    return 0


def main():
    """Main entry point for the CLI"""
    try:
        # Run the async CLI
        asyncio.run(cli())
    except KeyboardInterrupt:
        console.print("\n⚠️ Interrupted by user", style="yellow")
        sys.exit(1)
    except Exception as e:
        console.print(f"❌ Unexpected error: {e}", style="red")
        sys.exit(1)


if __name__ == "__main__":
    main()
