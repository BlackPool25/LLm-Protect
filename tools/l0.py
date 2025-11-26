"""
Unified CLI for Layer-0 Security Filter System.
"""

import os
import sys
import time
import json
import typer
import requests
import uvicorn
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.json import JSON
from rich import box
from layer0.config import settings

# Initialize Typer app and Rich console
app = typer.Typer(
    name="layer0",
    help="Layer-0 Security Filter System CLI",
    add_completion=False,
    no_args_is_help=True
)
console = Console()

# Configuration
DEFAULT_PORT = int(os.getenv("L0_API_PORT", "8001"))
BASE_URL = f"http://localhost:{DEFAULT_PORT}"


def check_server(url: str = BASE_URL) -> bool:
    """Check if server is reachable."""
    try:
        requests.get(f"{url}/health", timeout=1)
        return True
    except:
        return False


@app.command()
def serve(
    port: int = typer.Option(DEFAULT_PORT, help="Port to run the server on"),
    host: str = typer.Option("0.0.0.0", help="Host to bind to"),
    workers: int = typer.Option(1, help="Number of worker processes"),
    reload: bool = typer.Option(False, help="Enable auto-reload"),
):
    """Start the Layer-0 API server."""
    console.print(Panel(f"Starting Layer-0 Server on [bold cyan]{host}:{port}[/]", title="System Startup", border_style="green"))
    
    # Set environment variable for the port so config picks it up if needed
    os.environ["L0_API_PORT"] = str(port)
    
    uvicorn.run(
        "layer0.api:app",
        host=host,
        port=port,
        workers=workers,
        reload=reload,
        log_level="info"
    )


@app.command()
def scan(
    input_text: str = typer.Argument(..., help="Text to scan (or @filename to read from file)"),
    url: str = typer.Option(BASE_URL, help="API URL"),
):
    """Scan input text for security threats."""
    # Handle file input
    if input_text.startswith("@"):
        filepath = input_text[1:]
        if not os.path.exists(filepath):
            console.print(f"[bold red]Error:[/bold red] File not found: {filepath}")
            raise typer.Exit(1)
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    else:
        content = input_text

    if not check_server(url):
        console.print(f"[bold red]Error:[/bold red] Could not connect to server at {url}")
        console.print("Run [bold green]python l0.py serve[/] to start the server.")
        raise typer.Exit(1)

    with console.status("[bold yellow]Scanning input...", spinner="dots"):
        try:
            start_time = time.perf_counter()
            response = requests.post(
                f"{url}/scan",
                json={"user_input": content},
                timeout=10
            )
            elapsed = (time.perf_counter() - start_time) * 1000
            
            if response.status_code != 200:
                console.print(f"[bold red]Error:[/bold red] API returned {response.status_code}")
                console.print(response.text)
                raise typer.Exit(1)
                
            result = response.json()
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            raise typer.Exit(1)

    # Display results
    status_color = "green" if result["status"] in ["CLEAN", "CLEAN_CODE"] else "red"
    if result["status"] == "WARN": status_color = "yellow"
    
    table = Table(title="Scan Results", box=box.ROUNDED)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Status", f"[{status_color}]{result['status']}[/{status_color}]")
    table.add_row("Severity", result.get("severity") or "-")
    table.add_row("Rule ID", result.get("rule_id") or "-")
    table.add_row("Dataset", result.get("dataset") or "-")
    table.add_row("Latency", f"{elapsed:.2f}ms")
    table.add_row("Audit Token", result.get("audit_token", "")[:20] + "...")
    
    console.print(table)
    
    if result.get("note"):
        console.print(Panel(result["note"], title="Note", border_style="blue"))


@app.command()
def stats(url: str = typer.Option(BASE_URL, help="API URL")):
    """View system statistics."""
    if not check_server(url):
        console.print(f"[bold red]Error:[/bold red] Could not connect to server at {url}")
        raise typer.Exit(1)

    try:
        response = requests.get(f"{url}/stats", timeout=5)
        data = response.json()
        
        # General Stats
        grid = Table.grid(expand=True)
        grid.add_column()
        grid.add_column(justify="right")
        grid.add_row("Total Rules", f"[bold green]{data.get('total_rules', 0)}[/]")
        grid.add_row("Total Datasets", str(data.get('total_datasets', 0)))
        grid.add_row("Total Matches", str(data.get('total_matches', 0)))
        grid.add_row("Version", data.get('version', 'N/A'))
        
        console.print(Panel(grid, title="System Statistics", border_style="cyan"))
        
        # Top Rules
        if data.get("top_matched_rules"):
            table = Table(title="Top Matched Rules", box=box.SIMPLE)
            table.add_column("Rule ID", style="cyan")
            table.add_column("Count", style="magenta")
            
            for rule in data["top_matched_rules"]:
                table.add_row(rule["rule_id"], str(rule["count"]))
            
            console.print(table)
            
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")


@app.command()
def test():
    """Run the comprehensive verification suite."""
    # Import here to avoid circular imports or dependency issues if not running test
    try:
        from cli_tester import main as run_tester
        run_tester()
    except ImportError:
        console.print("[bold red]Error:[/bold red] cli_tester.py not found.")
    except Exception as e:
        console.print(f"[bold red]Error running tests:[/bold red] {e}")


@app.command()
def reload(url: str = typer.Option(BASE_URL, help="API URL")):
    """Hot-reload all datasets."""
    if not check_server(url):
        console.print(f"[bold red]Error:[/bold red] Could not connect to server at {url}")
        raise typer.Exit(1)

    with console.status("[bold yellow]Reloading datasets...", spinner="arc"):
        try:
            start = time.perf_counter()
            response = requests.post(f"{url}/datasets/reload", timeout=60)
            elapsed = (time.perf_counter() - start) * 1000
            
            if response.status_code == 200:
                data = response.json()
                console.print(f"[bold green]✓ Reload Successful[/] in {elapsed:.0f}ms")
                console.print(f"Rules Loaded: {data.get('total_rules')}")
                console.print(f"Version: {data.get('rule_set_version')}")
            else:
                console.print(f"[bold red]Reload Failed:[/bold red] {response.text}")
                
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")


if __name__ == "__main__":
    app()
