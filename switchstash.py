#!/usr/bin/env python3

__version__ = "0.3.0"

import concurrent.futures
import ipaddress
import logging
import os
import random
import subprocess
import sys
import time
import zipfile
import re
import platform
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

import typer
import yaml
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
)
from rich.table import Table
from rich.logging import RichHandler
from rich.syntax import Syntax
from rich.prompt import Prompt, Confirm
from netmiko import (
    ConnectHandler,
    NetmikoTimeoutException,
    NetmikoAuthenticationException,
    NetmikoBaseException,
)
from netmiko.ssh_dispatcher import CLASS_MAPPER, ConnectHandler

from inventory import InventoryDB
from diff import compute_diff, diff_configs, has_config_changed

app = typer.Typer(
    name="switchstash",
    help="Backup running-config from network devices over SSH.",
    add_completion=False,
)
console = Console()


def print_version(version: bool):
    if version:
        console.print(f"SwitchStash v{__version__}")
        raise typer.Exit(0)


logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(console=console, rich_tracebacks=True, show_time=False)],
)
log = logging.getLogger("hosthoover")

DEVICE_TIMEOUTS: Dict[str, Dict[str, int]] = {
    "cisco_ios": {"connect": 10, "command": 30},
    "cisco_nxos": {"connect": 15, "command": 45},
    "cisco_xr": {"connect": 15, "command": 45},
    "cisco_asa": {"connect": 10, "command": 30},
    "juniper_junos": {"connect": 15, "command": 45},
    "aruba_os": {"connect": 10, "command": 30},
    "hp_procurve": {"connect": 10, "command": 30},
    "dell_force10": {"connect": 10, "command": 30},
    "huawei": {"connect": 10, "command": 30},
    "f5_tmsh": {"connect": 15, "command": 60},
    "fortinet": {"connect": 10, "command": 30},
}


def get_jitter(attempt: int, base: float = 1.0, max_jitter: float = 2.0) -> float:
    """Calculate sleep time with exponential backoff and jitter."""
    backoff = min(base * (2**attempt), 30)
    jitter = random.uniform(0, min(backoff, max_jitter))
    return backoff + jitter


def detect_device_type(
    host: str, username: str, password: str, key_file: Optional[str]
) -> Optional[str]:
    """Attempt to auto-detect device type from SSH banner."""
    device_types = [
        "cisco_ios",
        "cisco_nxos",
        "cisco_xr",
        "cisco_asa",
        "juniper_junos",
        "aruba_os",
        "hp_procurve",
        "dell_force10",
    ]

    for dtype in device_types:
        try:
            params = {
                "device_type": dtype,
                "host": host,
                "username": username,
                "password": password,
            }
            if key_file:
                params["ssh_key_file"] = key_file

            conn = ConnectHandler(**params)
            conn.disconnect()
            return dtype
        except Exception:
            continue

    return None


def is_reachable(host: str, count: int = 1, timeout: int = 1) -> bool:
    """Ping a host to check reachability in a cross-platform way."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), host]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(timeout), host]

    try:
        subprocess.run(
            cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return True
    except subprocess.CalledProcessError:
        return False


def load_config(config_file: Path) -> Dict[str, Any]:
    """Load configuration from YAML file."""
    with open(config_file) as f:
        return yaml.safe_load(f)


def process_host(
    host: str,
    username: str,
    password: Optional[str],
    key_file: Optional[str],
    device_type: Optional[str],
    output_dir: Path,
    commands: List[str],
    ping_count: int,
    ping_timeout: int,
    max_retries: int,
    dry_run: bool,
    auto_detect: bool,
    connect_timeout: Optional[int] = None,
    command_timeout: Optional[int] = None,
    db: Optional[InventoryDB] = None,
    no_diff: bool = False,
    pre_hook: Optional[str] = None,
    post_hook: Optional[str] = None,
    use_agent: bool = False,
) -> tuple[str, bool, str]:
    """Process a single host: ping, connect, save config."""
    if not is_reachable(host, count=ping_count, timeout=ping_timeout):
        log.warning(f"[red]{host}[/red] is unreachable, skipping.")
        return (host, False, "unreachable")

    if dry_run:
        log.info(f"[cyan]Dry run:[/cyan] would connect to {host}")
        return (host, True, f"dry_run_{host}")

    actual_device_type = device_type or "cisco_ios"

    if auto_detect and not device_type:
        console.print(f"[dim]Auto-detecting device type for {host}...[/dim]")
        detected = detect_device_type(host, username, password, key_file)
        if detected:
            actual_device_type = detected
            console.print(f"[green]Detected: {detected}[/green] for {host}")
        else:
            log.warning(
                f"[yellow]Could not auto-detect device type for {host}, using cisco_ios[/yellow]"
            )
            actual_device_type = "cisco_ios"

    timeouts = DEVICE_TIMEOUTS.get(actual_device_type, {})
    conn_timeout = connect_timeout or timeouts.get("connect", 10)
    cmd_timeout = command_timeout or timeouts.get("command", 30)

    device_params = {
        "device_type": actual_device_type,
        "host": host,
        "username": username,
        "timeout": conn_timeout,
    }
    if use_agent:
        device_params["use_agent"] = True
    elif password:
        device_params["password"] = password
    if key_file:
        device_params["ssh_key_file"] = key_file

    hostname = None
    for attempt in range(max_retries):
        try:
            if pre_hook:
                run_hook(pre_hook, host, None, "pre")

            log.info(
                f"Connecting to [bold]{host}[/bold]... (attempt {attempt + 1}/{max_retries})"
            )
            connection = ConnectHandler(**device_params)

            os.makedirs(output_dir, exist_ok=True)

            for cmd in commands:
                log.info(f"Running command: [dim]{cmd}[/dim] (timeout: {cmd_timeout}s)")
                try:
                    config = connection.send_command(cmd, cmd_timeout=cmd_timeout)
                except Exception as e:
                    if "timed out" in str(e).lower():
                        log.error(f"[red]Command timed out on {host}[/red]")
                        raise NetmikoTimeoutException(f"Command timeout: {cmd}")
                    raise

                match = re.search(r"^hostname\s+(\S+)", config, re.MULTILINE)
                hostname = match.group(1) if match else host
                filename_base = hostname

                if cmd == commands[0] and pre_hook:
                    run_hook(pre_hook, host, hostname, "pre")

                safe_cmd_name = re.sub(r"[^a-zA-Z0-9]", "_", cmd.lower())
                filename = output_dir / f"{filename_base}_{safe_cmd_name}.cfg"

                changed = False
                if db and not no_diff:
                    prev = db.get_latest_backup(hostname=filename_base, command=cmd)
                    if prev and prev.get("config_file"):
                        prev_path = Path(prev["config_file"])
                        if has_config_changed(prev_path, filename):
                            changed = True
                            console.print(
                                f"[yellow]Config changed for {filename_base}[/yellow]"
                            )
                            if db:
                                db.record_backup(
                                    hostname=filename_base,
                                    ip_address=host,
                                    device_type=actual_device_type,
                                    command=cmd,
                                    config_file=filename,
                                    status="changed",
                                )
                        else:
                            if db:
                                db.record_backup(
                                    hostname=filename_base,
                                    ip_address=host,
                                    device_type=actual_device_type,
                                    command=cmd,
                                    config_file=filename,
                                    status="unchanged",
                                )
                            console.print(f"[dim]No change for {filename_base}[/dim]")
                            continue

                with open(filename, "w") as file:
                    file.write(config)

                if changed:
                    log.info(f"[yellow]Saved (changed):[/yellow] {filename}")
                else:
                    log.info(f"[green]Saved:[/green] {filename}")

                if db:
                    db.record_backup(
                        hostname=filename_base,
                        ip_address=host,
                        device_type=actual_device_type,
                        command=cmd,
                        config_file=filename,
                        status="success",
                    )

            if post_hook:
                run_hook(post_hook, host, hostname, "post")

            connection.disconnect()
            return (host, True, "success")

        except (NetmikoTimeoutException, NetmikoAuthenticationException) as error:
            log.warning(
                f"[yellow]Attempt {attempt + 1} failed for {host}:[/yellow] {error}"
            )
            if attempt < max_retries - 1:
                sleep_time = get_jitter(attempt)
                log.info(f"[dim]Waiting {sleep_time:.1f}s before retry...[/dim]")
                time.sleep(sleep_time)
            else:
                log.error(f"[red]All attempts failed for {host}:[/red] {error}")
                if db:
                    db.record_backup(
                        hostname=host,
                        ip_address=host,
                        device_type=actual_device_type or "unknown",
                        command=commands[0] if commands else "show running-config",
                        config_file=Path(""),
                        status="failed",
                        error_message=str(error),
                    )
                return (host, False, str(error))
        except NetmikoBaseException as error:
            log.error(f"[red]Netmiko error on {host}:[/red] {error}")
            if db:
                db.record_backup(
                    hostname=host,
                    ip_address=host,
                    device_type=actual_device_type or "unknown",
                    command=commands[0] if commands else "show running-config",
                    config_file=Path(""),
                    status="failed",
                    error_message=str(error),
                )
            return (host, False, str(error))
        except Exception as error:
            log.error(f"[red]Error connecting to {host}:[/red] {error}")
            if db:
                db.record_backup(
                    hostname=host,
                    ip_address=host,
                    device_type=actual_device_type or "unknown",
                    command=commands[0] if commands else "show running-config",
                    config_file=Path(""),
                    status="failed",
                    error_message=str(error),
                )
            return (host, False, str(error))


def run_hook(hook: str, host: str, hostname: Optional[str], action: str) -> bool:
    """Run a pre/post hook script."""
    import subprocess

    env = {
        "SWITCHSTASH_HOST": host,
        "SWITCHSTASH_HOSTNAME": hostname or "",
        "SWITCHSTASH_ACTION": action,
    }

    try:
        result = subprocess.run(
            hook,
            shell=True,
            env={**os.environ, **env},
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            log.warning(
                f"[yellow]Hook {action} failed for {host}:[/yellow] {result.stderr}"
            )
            return False
        if result.stdout:
            log.debug(f"Hook output: {result.stdout}")
        return True
    except subprocess.TimeoutExpired:
        log.warning(f"[yellow]Hook {action} timed out for {host}[/yellow]")
        return False
    except Exception as e:
        log.warning(f"[yellow]Hook error for {host}:[/yellow] {e}")
        return False


def get_password_prompt() -> Optional[str]:
    """Prompt for password securely."""
    import getpass

    try:
        return getpass.getpass("SSH Password: ")
    except Exception:
        return None


def parse_networks(networks_arg: str) -> List[str]:
    """Parse networks from comma-separated string or file."""
    networks = []

    if networks_arg.startswith("@"):
        network_file = Path(networks_arg[1:])
        if network_file.exists():
            with open(network_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        networks.append(line)
        else:
            raise FileNotFoundError(f"Network file not found: {network_file}")
    else:
        networks = [n.strip() for n in networks_arg.split(",") if n.strip()]

    return networks


def render_template(template: str, hostname: str, ip: str) -> str:
    """Render template variables in command."""
    return template.replace("{{hostname}}", hostname).replace("{{ip}}", ip)


def validate_config(config_path: Path) -> Dict[str, Any]:
    """Validate configuration file and return errors."""
    errors = []
    warnings = []

    try:
        cfg = load_config(config_path)
    except Exception as e:
        return {
            "valid": False,
            "errors": [f"Failed to parse YAML: {e}"],
            "warnings": [],
        }

    # Validate groups
    groups = cfg.get("groups", {})
    for group_name, group_config in groups.items():
        if not group_config.get("networks"):
            errors.append(f"Group '{group_name}': missing networks")

        if not group_config.get("username"):
            errors.append(f"Group '{group_name}': missing username")

        if (
            not group_config.get("password")
            and not group_config.get("key_file")
            and not group_config.get("use_agent")
        ):
            errors.append(f"Group '{group_name}': missing authentication")

        # Validate group networks
        for net in group_config.get("networks", []):
            try:
                ipaddress.ip_network(net, strict=False)
            except ValueError as e:
                errors.append(f"Group '{group_name}': invalid network {net}: {e}")

    # Only validate global settings if no groups or if not using groups
    if not groups:
        if not cfg.get("username"):
            warnings.append("Missing global username (will be required if no groups)")

        if (
            not cfg.get("password")
            and not cfg.get("key_file")
            and not cfg.get("use_agent")
        ):
            warnings.append("Missing global auth (will be required if no groups)")

    # Validate timeouts
    if cfg.get("connect_timeout") is not None and cfg["connect_timeout"] < 1:
        errors.append("connect_timeout must be >= 1")

    if cfg.get("command_timeout") is not None and cfg["command_timeout"] < 1:
        errors.append("command_timeout must be >= 1")

    if cfg.get("max_retries") is not None and cfg["max_retries"] < 0:
        errors.append("max_retries must be >= 0")

    # Warnings
    if cfg.get("auto_detect"):
        warnings.append("auto_detect may slow down initial connection")

    if not cfg.get("database"):
        warnings.append("No database configured - backup history will not be saved")

    return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings}


@app.command()
def validate(
    config: Path = typer.Argument(..., help="Config file to validate"),
):
    """Validate a configuration file."""
    if not config.exists():
        console.print(f"[red]Config file not found: {config}[/red]")
        raise typer.Exit(1)

    result = validate_config(config)

    if result["valid"]:
        console.print(f"[green]Config file is valid[/green]")
    else:
        console.print(f"[red]Config file has errors:[/red]")
        for error in result["errors"]:
            console.print(f"  [red]•[/red] {error}")

    if result["warnings"]:
        console.print(f"\n[yellow]Warnings:[/yellow]")
        for warning in result["warnings"]:
            console.print(f"  [yellow]•[/yellow] {warning}")

    if not result["valid"]:
        raise typer.Exit(1)


@app.command()
def list_groups(
    config: Path = typer.Argument(..., help="Config file to list groups from"),
):
    """List available device groups in a configuration file."""
    if not config.exists():
        console.print(f"[red]Config file not found: {config}[/red]")
        raise typer.Exit(1)

    cfg = load_config(config)
    groups = cfg.get("groups", {})

    if not groups:
        console.print("[yellow]No device groups defined in config[/yellow]")
        return

    table = Table(title="Device Groups")
    table.add_column("Group", style="cyan")
    table.add_column("Networks", style="green")
    table.add_column("Device Type", style="dim")
    table.add_column("Username", style="dim")

    for name, group_config in groups.items():
        networks = ", ".join(group_config.get("networks", []))
        device_type = group_config.get("device_type", "-")
        username = group_config.get("username", "-")
        table.add_row(name, networks, device_type, username)

    console.print(table)


def discover_hosts(
    networks: List[str],
    ping_count: int = 1,
    ping_timeout: int = 1,
    max_workers: int = 50,
) -> List[Dict[str, Any]]:
    """Discover reachable hosts in networks using parallel ping."""
    all_ips = []
    for net_str in networks:
        try:
            net = ipaddress.ip_network(net_str, strict=False)
            all_ips.extend([str(ip) for ip in net.hosts()])
        except ValueError:
            continue

    console.print(f"[dim]Pinging {len(all_ips)} hosts...[/dim]")

    reachable = []

    def check_host(ip: str) -> Optional[Dict[str, Any]]:
        if is_reachable(ip, count=ping_count, timeout=ping_timeout):
            return {"ip": ip, "status": "up"}
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(check_host, all_ips))

    reachable = [r for r in results if r is not None]
    return reachable


def generate_html_report(
    output_path: Path,
    successes: List[str],
    failures: List[tuple],
    output_dir: Path,
    network: str,
) -> None:
    """Generate HTML report of backup results."""
    import hashlib

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    device_rows = []
    for host in successes:
        config_files = list(output_dir.glob(f"{host}*.cfg"))
        files_info = []
        for f in config_files:
            with open(f, "rb") as fp:
                checksum = hashlib.md5(fp.read()).hexdigest()[:8]
            files_info.append(f"{f.name} ({checksum})")

        device_rows.append(f"""
            <tr class="success">
                <td>{host}</td>
                <td><span class="badge success">Success</span></td>
                <td>{", ".join(files_info) if files_info else "-"}</td>
                <td>-</td>
            </tr>
        """)

    for host, reason in failures:
        device_rows.append(f"""
            <tr class="failed">
                <td>{host}</td>
                <td><span class="badge failed">Failed</span></td>
                <td>-</td>
                <td>{reason}</td>
            </tr>
        """)

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>HostHoover Report - {timestamp}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #0066cc; padding-bottom: 10px; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat {{ background: #f0f0f0; padding: 15px 25px; border-radius: 6px; text-align: center; }}
        .stat .value {{ font-size: 32px; font-weight: bold; }}
        .stat .label {{ color: #666; font-size: 14px; }}
        .success .value {{ color: #28a745; }}
        .failed .value {{ color: #dc3545; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        .badge {{ padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; }}
        .badge.success {{ background: #d4edda; color: #155724; }}
        .badge.failed {{ background: #f8d7da; color: #721c24; }}
        .meta {{ color: #666; font-size: 14px; margin-top: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>HostHoover Backup Report</h1>
        
        <div class="summary">
            <div class="stat success">
                <div class="value">{len(successes)}</div>
                <div class="label">Successful</div>
            </div>
            <div class="stat failed">
                <div class="value">{len(failures)}</div>
                <div class="label">Failed</div>
            </div>
            <div class="stat">
                <div class="value">{len(successes) + len(failures)}</div>
                <div class="label">Total</div>
            </div>
        </div>

        <h2>Devices</h2>
        <table>
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Status</th>
                    <th>Files</th>
                    <th>Error</th>
                </tr>
            </thead>
            <tbody>
                {"".join(device_rows)}
            </tbody>
        </table>

        <div class="meta">
            <p>Network: {network}</p>
            <p>Generated: {timestamp}</p>
            <p>Output directory: {output_dir}</p>
        </div>
    </div>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)

    console.print(f"[green]HTML report saved to {output_path}[/green]")


@app.command()
def main(
    network: Optional[str] = typer.Argument(
        None, help="Network(s): CIDR, comma-separated, or @file.txt"
    ),
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="YAML config file"
    ),
    group: Optional[str] = typer.Option(
        None, "--group", "-g", help="Device group from config (requires config file)"
    ),
    username: Optional[str] = typer.Option(
        None, "--username", "-u", help="SSH username"
    ),
    password: Optional[str] = typer.Option(
        None, "--password", "-p", help="SSH password"
    ),
    key_file: Optional[Path] = typer.Option(
        None, "--key-file", "-k", help="SSH key file"
    ),
    use_agent: bool = typer.Option(
        False, "--use-agent", help="Use SSH agent for authentication"
    ),
    password_prompt: bool = typer.Option(
        False, "--password-prompt", help="Prompt for password interactively"
    ),
    pre_hook: Optional[str] = typer.Option(
        None, "--pre-hook", help="Script to run before each backup"
    ),
    post_hook: Optional[str] = typer.Option(
        None, "--post-hook", help="Script to run after each backup"
    ),
    device_type: Optional[str] = typer.Option(
        None, "--device-type", "-d", help="Netmiko device type"
    ),
    auto_detect: bool = typer.Option(
        False, "--auto-detect", help="Auto-detect device type"
    ),
    output_dir: Path = typer.Option(
        "configs", "--output", "-o", help="Output directory"
    ),
    zip_name: str = typer.Option("configs.zip", "--zip", "-z", help="Zip file name"),
    database: Optional[Path] = typer.Option(
        None, "--database", "-b", help="SQLite database file for inventory"
    ),
    no_diff: bool = typer.Option(
        False, "--no-diff", help="Skip diff check against previous backup"
    ),
    command: Optional[List[str]] = typer.Option(
        None, "--command", help="CLI command(s) to run"
    ),
    ping_count: int = typer.Option(1, "--ping-count", help="Number of ping attempts"),
    ping_timeout: int = typer.Option(
        1, "--ping-timeout", help="Ping timeout in seconds"
    ),
    connect_timeout: Optional[int] = typer.Option(
        None, "--connect-timeout", help="SSH connection timeout in seconds"
    ),
    command_timeout: Optional[int] = typer.Option(
        None, "--command-timeout", help="Command execution timeout in seconds"
    ),
    max_retries: int = typer.Option(3, "--max-retries", help="Max connection retries"),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Simulate without connecting"
    ),
    interactive: bool = typer.Option(
        False,
        "--interactive",
        "-i",
        help="Interactive mode: discover hosts and select which to backup",
    ),
    html_report: Optional[Path] = typer.Option(
        None, "--html-report", help="Generate HTML report to file"
    ),
    workers: int = typer.Option(
        10, "--workers", "-w", help="Number of concurrent workers"
    ),
    version: bool = typer.Option(False, "--version", help="Show version and exit"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """Backup network device configurations."""
    if version:
        console.print(f"SwitchStash v{__version__}")
        raise typer.Exit(0)

    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    cfg: Dict[str, Any] = {}

    if config and config.exists():
        console.print(f"[dim]Loading config from {config}[/dim]")
        cfg = load_config(config)

    username = username or cfg.get("username") or os.getenv("SSH_USERNAME")
    password = password or cfg.get("password") or os.getenv("SSH_PASSWORD")
    key_file = key_file or cfg.get("key_file")
    use_agent = use_agent or cfg.get("use_agent", False)
    pre_hook = pre_hook or cfg.get("pre_hook")
    post_hook = post_hook or cfg.get("post_hook")

    if password_prompt and not password:
        password = get_password_prompt()
        if not password:
            console.print("[red]No password entered[/red]")
            raise typer.Exit(1)

    device_type = device_type or cfg.get("device_type")
    auto_detect = auto_detect or cfg.get("auto_detect", False)
    command = command or cfg.get("commands", ["show running-config"])
    output_dir = Path(cfg.get("output_dir", output_dir))
    zip_name = cfg.get("zip_name", zip_name)
    connect_timeout = connect_timeout or cfg.get("connect_timeout")
    command_timeout = command_timeout or cfg.get("command_timeout")
    max_retries = max_retries or cfg.get("max_retries", 3)
    no_diff = no_diff or cfg.get("no_diff", False)

    db = None
    if database:
        database = Path(cfg.get("database", database))
        db = InventoryDB(database)
        console.print(f"[dim]Using inventory database: {database}[/dim]")

    # Handle device groups
    if group:
        if not config or not config.exists():
            console.print("[red]Error:[/red] --group requires --config file")
            raise typer.Exit(1)

        groups = cfg.get("groups", {})
        if group not in groups:
            console.print(f"[red]Error:[/red] Group '{group}' not found in config")
            console.print(
                f"Available groups: {', '.join(groups.keys()) if groups else 'none'}"
            )
            raise typer.Exit(1)

        group_config = groups[group]
        network = ",".join(group_config.get("networks", []))

        # Override settings with group-specific values
        username = username or group_config.get("username") or os.getenv("SSH_USERNAME")
        password = password or group_config.get("password") or os.getenv("SSH_PASSWORD")
        key_file = key_file or group_config.get("key_file")
        use_agent = use_agent or group_config.get("use_agent", False)
        device_type = device_type or group_config.get("device_type")
        command = command or group_config.get("commands", ["show running-config"])

        console.print(f"[dim]Using group: {group}[/dim]")

    if not network and not group:
        console.print("[red]Error:[/red] Network or --group required")
        raise typer.Exit(1)

    if not username:
        console.print(
            "[red]Error:[/red] SSH username required (--username, config file, or SSH_USERNAME env var)"
        )
        raise typer.Exit(1)

    if not password and not key_file and not use_agent:
        console.print(
            "[red]Error:[/red] SSH password, key file, or --use-agent required (--password, --key-file, config file, SSH_PASSWORD env var, or --use-agent)"
        )
        raise typer.Exit(1)

    networks = parse_networks(network)
    all_hosts = []
    for net_str in networks:
        try:
            net = ipaddress.ip_network(net_str, strict=False)
            all_hosts.extend([str(ip) for ip in net.hosts()])
        except ValueError as e:
            console.print(f"[red]Invalid network:[/red] {net_str}: {e}")
            raise typer.Exit(1)

    if interactive:
        console.print("\n[bold]Discovering hosts...[/bold]\n")
        reachable = discover_hosts(networks, ping_count, ping_timeout)

        if not reachable:
            console.print("[yellow]No reachable hosts found[/yellow]")
            raise typer.Exit(0)

        table = Table(title="Reachable Hosts")
        table.add_column("#", justify="right", style="dim")
        table.add_column("IP Address", style="cyan")
        table.add_column("Status", style="green")

        for i, h in enumerate(reachable, 1):
            table.add_row(str(i), h["ip"], "✓")

        console.print(table)

        selection = Prompt.ask(
            "\n[bold]Select hosts to backup[/bold] (comma-separated numbers, 'all', or Enter for all)",
            default="all",
        )

        if selection.lower() == "all":
            all_hosts = [h["ip"] for h in reachable]
        else:
            selected = []
            for part in selection.split(","):
                part = part.strip()
                if "-" in part:
                    start, end = part.split("-")
                    selected.extend(
                        [h["ip"] for h in reachable[int(start) - 1 : int(end)]]
                    )
                else:
                    idx = int(part) - 1
                    if 0 <= idx < len(reachable):
                        selected.append(reachable[idx]["ip"])
            all_hosts = selected

        console.print(f"\n[green]Selected {len(all_hosts)} hosts for backup[/green]\n")

    console.print(
        f"[bold]Starting backup of {len(all_hosts)} hosts from {network}[/bold]"
    )

    templated_commands = []
    for cmd in command:
        if "{{hostname}}" in cmd or "{{ip}}" in cmd:
            for host in all_hosts:
                rendered = render_template(cmd, host, host)
                if rendered not in templated_commands:
                    templated_commands.append(rendered)
        else:
            if cmd not in templated_commands:
                templated_commands.append(cmd)

    commands_to_run = templated_commands or command

    console.print(f"[dim]Commands: {', '.join(commands_to_run)}[/dim]")
    if key_file:
        console.print(f"[dim]Auth: SSH key ({key_file})[/dim]")
    else:
        console.print(f"[dim]Auth: password[/dim]")
    console.print()

    os.makedirs(output_dir, exist_ok=True)

    successes = []
    failures = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Processing hosts", total=len(all_hosts))

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    process_host,
                    ip,
                    username,
                    password,
                    str(key_file) if key_file else None,
                    device_type,
                    output_dir,
                    command,
                    ping_count,
                    ping_timeout,
                    max_retries,
                    dry_run,
                    auto_detect,
                    connect_timeout,
                    command_timeout,
                    db,
                    no_diff,
                    pre_hook,
                    post_hook,
                    use_agent,
                ): ip
                for ip in all_hosts
            }

            for future in concurrent.futures.as_completed(futures):
                host, success, info = future.result()
                if success:
                    successes.append(host)
                else:
                    failures.append((host, info))
                progress.update(task, advance=1)

    zip_path = output_dir / zip_name
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for cfg_file in output_dir.glob("*.cfg"):
            zipf.write(cfg_file, cfg_file.name)
    console.print(f"[green]Zipped all configs to {zip_path}[/green]\n")

    table = Table(title="Results")
    table.add_column("Status", style="green", no_wrap=True)
    table.add_column("Host", style="cyan")
    table.add_column("Details", style="dim")

    for host in successes:
        table.add_row("✓", host, "Success")

    for host, reason in failures:
        table.add_row("✗", host, reason)

    console.print(table)

    console.print(
        f"\n[bold]Summary:[/bold] [green]{len(successes)}[/green] successful, [red]{len(failures)}[/red] failed"
    )

    if db:
        stats = db.get_stats()
        console.print(f"\n[bold]Inventory:[/bold]")
        console.print(f"  Total devices: {stats['total_devices']}")
        console.print(f"  Successful: [green]{stats['successful']}[/green]")
        console.print(f"  Failed: [red]{stats['failed']}[/red]")
        console.print(f"  Total backups: {stats['total_backups']}")

    if html_report:
        generate_html_report(
            html_report,
            successes,
            failures,
            output_dir,
            network,
        )


@app.command()
def diff(
    hostname: str = typer.Argument(..., help="Device hostname to diff"),
    database: Path = typer.Option(
        "hosthoover.db", "--database", "-b", help="SQLite database"
    ),
    command: str = typer.Option(
        "show running-config", "--command", help="Command to diff"
    ),
    output_a: Optional[Path] = typer.Option(
        None, "--old", "-o", help="Old config file (optional)"
    ),
    output_b: Optional[Path] = typer.Option(
        None, "--new", "-n", help="New config file (optional)"
    ),
):
    """Show diff between previous and current config for a device."""
    if not database.exists():
        console.print(f"[red]Database not found: {database}[/red]")
        raise typer.Exit(1)

    db = InventoryDB(database)

    if output_a and output_b:
        path_a, path_b = Path(output_a), Path(output_b)
    else:
        latest = db.get_latest_backup(hostname, command)
        if not latest:
            console.print(f"[red]No backup found for {hostname}[/red]")
            raise typer.Exit(1)

        path_b = Path(latest["config_file"])

        history = db.get_backup_history(hostname, limit=2)
        if len(history) < 2:
            console.print("[yellow]Only one backup found, cannot diff[/yellow]")
            with open(path_b) as f:
                console.print(Syntax(f.read(), "diff"))
            return

        path_a = Path(history[1]["config_file"])

    same, diff_lines = diff_configs(path_a, path_b)

    if same:
        console.print(
            f"[green]No changes between {path_a.name} and {path_b.name}[/green]"
        )
    else:
        console.print(
            f"[yellow]Changes between {path_a.name} and {path_b.name}:[/yellow]\n"
        )
        syntax = Syntax(
            "\n".join(diff_lines), "diff", theme="monokai", line_numbers=True
        )
        console.print(syntax)


@app.command()
def stats(
    database: Path = typer.Option(
        "hosthoover.db", "--database", "-b", help="SQLite database"
    ),
):
    """Show inventory statistics."""
    if not database.exists():
        console.print(f"[red]Database not found: {database}[/red]")
        raise typer.Exit(1)

    db = InventoryDB(database)

    stats_data = db.get_stats()

    table = Table(title="Inventory Statistics")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Total Devices", str(stats_data["total_devices"]))
    table.add_row("Successful", str(stats_data["successful"]))
    table.add_row("Failed", str(stats_data["failed"]))
    table.add_row("Total Backups", str(stats_data["total_backups"]))

    console.print(table)

    devices = db.get_all_devices()
    if devices:
        console.print("\n[bold]Recent Devices:[/bold]")
        dev_table = Table()
        dev_table.add_column("Hostname", style="cyan")
        dev_table.add_column("IP", style="dim")
        dev_table.add_column("Type", style="dim")
        dev_table.add_column("Last Backup", style="dim")
        dev_table.add_column("Status", style="green")

        for d in devices[:10]:
            status_style = "green" if d["last_status"] == "success" else "red"
            dev_table.add_row(
                d["hostname"],
                d["ip_address"] or "-",
                d["device_type"] or "-",
                d["last_backup"] or "-",
                f"[{status_style}]{d['last_status']}[/{status_style}]",
            )

        console.print(dev_table)


@app.command()
def history(
    hostname: str = typer.Argument(..., help="Device hostname"),
    database: Path = typer.Option(
        "hosthoover.db", "--database", "-b", help="SQLite database"
    ),
    limit: int = typer.Option(10, "--limit", "-n", help="Number of entries"),
):
    """Show backup history for a device."""
    if not database.exists():
        console.print(f"[red]Database not found: {database}[/red]")
        raise typer.Exit(1)

    db = InventoryDB(database)

    history = db.get_backup_history(hostname, limit=limit)

    if not history:
        console.print(f"[yellow]No history found for {hostname}[/yellow]")
        return

    table = Table(title=f"Backup History: {hostname}")
    table.add_column("Time", style="dim")
    table.add_column("Command", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("File", style="dim")

    for h in history:
        status_style = "green" if h["status"] == "success" else "red"
        table.add_row(
            h["backup_time"],
            h["command"],
            f"[{status_style}]{h['status']}[/{status_style}]",
            Path(h["config_file"]).name if h["config_file"] else "-",
        )

    console.print(table)


if __name__ == "__main__":
    app()
