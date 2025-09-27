#!/usr/bin/env python3

import argparse
import concurrent.futures
import ipaddress
import logging
import os
import time
import typing
import zipfile
import re
import subprocess
import platform
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from tqdm import tqdm

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def is_reachable(host: str, count: int = 1, timeout: int = 1) -> bool:
    """Ping a host to check reachability in a cross-platform way."""
    system = platform.system().lower()
    if system == 'windows':
        # Windows ping uses milliseconds for timeout
        cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), host]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(timeout), host]

    try:
        subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True
    except subprocess.CalledProcessError:
        return False


def process_host(host: str, username: str, password: str, device_type: str, output_dir: str, command: typing.Optional[str], ping_count: int, ping_timeout: int, max_retries: int, dry_run: bool) -> typing.Tuple[str, bool, str]:
    """Process a single host: ping, connect, save config."""
    # Skip if host is unreachable
    if not is_reachable(host, count=ping_count, timeout=ping_timeout):
        logging.warning(f"{host} is unreachable, skipping.")
        return (host, False, "unreachable")

    if dry_run:
        logging.info(f"Dry run: would connect to {host}")
        return (host, True, f"dry_run_{host}")

    device_params = {
        'device_type': device_type,
        'host': host,
        'username': username,
        'password': password,
    }
    for attempt in range(max_retries):
        try:
            logging.info(f"Connecting to {host}... (attempt {attempt + 1}/{max_retries})")
            connection = ConnectHandler(**device_params)
            cmd = command if command else 'show running-config'
            logging.info(f"Running command: {cmd}")
            config = connection.send_command(cmd)

            # Extract hostname from running-config, fallback to IP
            match = re.search(r'^hostname\s+(\S+)', config, re.MULTILINE)
            filename_base = match.group(1) if match else host

            # Save running config to file named after hostname
            filename = os.path.join(output_dir, f"{filename_base}.cfg")
            with open(filename, 'w') as file:
                file.write(config)
            logging.info(f"Config saved: {filename}")
            connection.disconnect()
            return (host, True, filename)

        except (NetmikoTimeoutException, NetmikoAuthenticationException) as error:
            logging.warning(f"Attempt {attempt + 1} failed for {host}: {error}")
            if attempt < max_retries - 1:
                time.sleep(1)  # Wait before retry
            else:
                logging.error(f"All attempts failed for {host}: {error}")
                return (host, False, str(error))


def backup_configs(network: str, username: str, password: str, device_type: str, output_dir: str,
                    zip_name: str, command: typing.Optional[str], ping_count: int = 1, ping_timeout: int = 1, max_retries: int = 1, dry_run: bool = False) -> None:
    # Parse network and get all hosts in the subnet
    net = ipaddress.ip_network(network, strict=False)
    hosts = list(net.hosts())

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    successes = []
    failures = []

    # Process hosts concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(process_host, str(ip), username, password, device_type, output_dir, command, ping_count, ping_timeout, max_retries, dry_run) for ip in hosts]
        with tqdm(total=len(futures), desc="Processing hosts") as pbar:
            for future in concurrent.futures.as_completed(futures):
                host, success, info = future.result()
                if success:
                    successes.append(host)
                else:
                    failures.append((host, info))
                pbar.update(1)

    # Create zip archive of all .cfg files
    zip_path = os.path.join(output_dir, zip_name)
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for cfg_file in os.listdir(output_dir):
            if cfg_file.endswith('.cfg'):
                zipf.write(os.path.join(output_dir, cfg_file), cfg_file)
    logging.info(f"All configs zipped into {zip_path}")

    # Print summary of results
    print("\nSummary:")
    print(f"  Successful: {len(successes)}")
    if successes:
        print("    " + ", ".join(successes))
    print(f"  Failed/Skipped: {len(failures)}")
    if failures:
        for host, reason in failures:
            print(f"    {host}: {reason}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Backup running-config from all reachable hosts in a subnet, naming files by hostname, and zip them."
    )
    parser.add_argument('network', help='Network in CIDR notation, e.g., 192.168.1.0/24')
    parser.add_argument(
        '-u', '--username',
        default=os.getenv('SSH_USERNAME'),
        help='SSH username (or set SSH_USERNAME env var)'
    )
    parser.add_argument(
        '-p', '--password',
        default=os.getenv('SSH_PASSWORD'),
        help='SSH password (or set SSH_PASSWORD env var)'
    )
    parser.add_argument('-d', '--device-type', default='cisco_ios', help='Netmiko device type (default: cisco_ios)')
    parser.add_argument('-o', '--output', default='configs', help='Directory to save configs (default: configs)')
    parser.add_argument('-z', '--zip-name', default='configs.zip', help='Name of the zip file (default: configs.zip)')
    parser.add_argument('-c', '--command', help="CLI command to run (default: 'show running-config')")
    parser.add_argument('--ping-count', type=int, default=1, help='Number of ping attempts (default: 1)')
    parser.add_argument('--ping-timeout', type=int, default=1, help='Ping timeout in seconds (default: 1)')
    parser.add_argument('--max-retries', type=int, default=1, help='Maximum number of connection retries (default: 1)')
    parser.add_argument('--dry-run', action='store_true', help='Simulate operations without actually connecting')
    args = parser.parse_args()

    if not args.username or not args.password:
        parser.error('SSH username and password required via options or environment variables')

    backup_configs(
        args.network,
        args.username,
        args.password,
        args.device_type,
        args.output,
        args.zip_name,
        args.command,
        ping_count=args.ping_count,
        ping_timeout=args.ping_timeout,
        max_retries=args.max_retries,
        dry_run=args.dry_run
    )
