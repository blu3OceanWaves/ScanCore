#!/usr/bin/env python3
import hashlib
import json
import os
import sys
import time
from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich.live import Live
from rich import box

DB_FILE = "file_hashes.json"
console = Console()

# ------------------ Banner ------------------
BANNER = r"""
 SSSS  CCC    A   N   N  CCC   OOO  RRRR  EEEEE 
S     C   C  A A  NN  N C   C O   O R   R E     
 SSS  C     AAAAA N N N C     O   O RRRR  EEEE  
    S C   C A   A N  NN C   C O   O R  R  E     
SSSS   CCC  A   A N   N  CCC   OOO  R   R EEEEE 
                                                                                                                            
"""

# ------------------ Core Functions ------------------

def sha256sum(filename):
    """Calculates the SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filename, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def load_db():
    """Loads the file hash database from a JSON file."""
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as f:
            return json.load(f)
    return {}

def save_db(data):
    """Saves the file hash database to a JSON file."""
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=4)

def init(files):
    """Creates a baseline of file hashes."""
    db = {f: sha256sum(f) for f in files if os.path.exists(f)}
    save_db(db)
    console.print(Align.center(Panel(
        "[bold green]Baseline successfully created![/bold green]",
        title="[bold cyan]ScanCore[/bold cyan]",
        box=box.DOUBLE
    )))

def check(json_output=False):
    """Checks monitored files against the baseline."""
    db = load_db()
    results = []

    for f, old_hash in db.items():
        if not os.path.exists(f):
            results.append(("❌", f, "MISSING"))
            continue
        new_hash = sha256sum(f)
        if new_hash != old_hash:
            results.append(("⚠️", f, "MODIFIED"))
        else:
            results.append(("✅", f, "UNCHANGED"))

    if json_output:
        print(json.dumps([{"file": f, "status": s} for _, f, s in results], indent=4))
        return results

    return results

def add(files):
    """Adds new files to the monitoring list."""
    db = load_db()
    for f in files:
        if os.path.exists(f):
            db[f] = sha256sum(f)
            console.print(Align.center(Panel(f"[green]File added:[/green] {f}", box=box.ROUNDED)))
    save_db(db)

def remove(files):
    """Removes files from the monitoring list."""
    db = load_db()
    for f in files:
        if f in db:
            del db[f]
            console.print(Align.center(Panel(f"[red]File removed:[/red] {f}", box=box.ROUNDED)))
    save_db(db)

# ------------------ Custom Help ------------------

def print_main_help():
    """Prints the main help menu."""
    table = Table(title="ScanCore - File Integrity Checker", show_header=True, header_style="bold cyan", box=box.DOUBLE_EDGE)
    table.add_column("Command", style="magenta", no_wrap=True)
    table.add_column("Description", style="yellow")
    table.add_row("init", "Create a baseline for one or more files to monitor")
    table.add_row("check", "Check monitored files for modifications")
    table.add_row("add", "Add files to the monitoring list")
    table.add_row("remove", "Remove files from the monitoring list")
    console.print(Align.center(table))
    console.print(Align.center("[bold green]Use './ScanCore <command> -h' for more details about a specific command[/bold green]"))

def print_subcommand_help(cmd):
    """Prints the help menu for a specific subcommand."""
    if cmd == "init":
        console.print(Align.center(Panel.fit(
            "[bold cyan]init[/bold cyan] - Create a baseline for files\n\n"
            "[bold]Arguments:[/bold]\n"
            "files       One or more file paths to monitor\n\n"
            "[bold]Example:[/bold] ./ScanCore init /etc/passwd /etc/shadow",
            title="[bold yellow]Help: init[/bold yellow]"
        )))
    elif cmd == "check":
        console.print(Align.center(Panel.fit(
            "[bold cyan]check[/bold cyan] - Check files for modifications\n\n"
            "[bold]Options:[/bold]\n"
            "--json      Output results in JSON format\n\n"
            "[bold]Example:[/bold] ./ScanCore check --json",
            title="[bold yellow]Help: check[/bold yellow]"
        )))
    elif cmd == "add":
        console.print(Align.center(Panel.fit(
            "[bold cyan]add[/bold cyan] - Add files to the monitoring list\n\n"
            "[bold]Arguments:[/bold]\n"
            "files       One or more file paths to add\n\n"
            "[bold]Example:[/bold] ./ScanCore add /etc/hosts",
            title="[bold yellow]Help: add[/bold yellow]"
        )))
    elif cmd == "remove":
        console.print(Align.center(Panel.fit(
            "[bold cyan]remove[/bold cyan] - Remove files from the monitoring list\n\n"
            "[bold]Arguments:[/bold]\n"
            "files       One or more file paths to remove\n\n"
            "[bold]Example:[/bold] ./ScanCore remove /etc/hosts",
            title="[bold yellow]Help: remove[/bold yellow]"
        )))
    else:
        print_main_help()

# ------------------ Live Dashboard ------------------

def live_check(results):
    """Generates the Rich panel for the live dashboard."""
    table = Table(expand=True, box=None)
    table.add_column("Status", justify="center", style="bold")
    table.add_column("File", justify="center", style="magenta")
    table.add_column("Result", justify="center", style="yellow")

    for icon, f, s in results:
        table.add_row(icon, f, s)
    
    # Use a Group to combine the centered banner and table
    content_group = Group(
        Align.center(BANNER),
        Align.center(table)
    )

    panel = Panel(
        content_group,
        border_style="cyan",
        padding=(1, 2)
    )
    return Align.center(panel)

# ------------------ CLI ------------------

def main():
    """Main function to handle command-line arguments."""
    if len(sys.argv) == 1:
        console.print(Align.center(BANNER))
        console.print(Align.center("[bold yellow]Please run with --help to see available commands[/bold yellow]"))
        return

    cmd = sys.argv[1]

    # Main help
    if cmd in ("-h", "--help"):
        console.print(Align.center(BANNER))
        print_main_help()
        return

    # Subcommand help
    if len(sys.argv) == 3 and sys.argv[2] in ("-h", "--help"):
        console.print(Align.center(BANNER))
        print_subcommand_help(cmd)
        return

    # Commands execution
    if cmd == "init":
        if len(sys.argv) < 3:
            console.print(Align.center(Panel("[red]Error:[/red] No files provided for init", box=box.ROUNDED)))
            return
        init(sys.argv[2:])
    elif cmd == "check":
        results = check()
        try:
            with Live(live_check(results), refresh_per_second=2, screen=True) as live:
                while True:
                    results = check() # Re-run check() to get updated results
                    live.update(live_check(results))
                    time.sleep(1)
        except KeyboardInterrupt:
            console.print(Align.center(Panel("[bold green]Monitoring stopped. Exiting.[/bold green]", box=box.DOUBLE)))
            return
    elif cmd == "add":
        if len(sys.argv) < 3:
            console.print(Align.center(Panel("[red]Error:[/red] No files provided to add", box=box.ROUNDED)))
            return
        add(sys.argv[2:])
    elif cmd == "remove":
        if len(sys.argv) < 3:
            console.print(Align.center(Panel("[red]Error:[/red] No files provided to remove", box=box.ROUNDED)))
            return
        remove(sys.argv[2:])
    else:
        console.print(Align.center(Panel(f"[red]Unknown command:[/red] {cmd}", box=box.ROUNDED)))
        print_main_help()

if __name__ == "__main__":
    main()
