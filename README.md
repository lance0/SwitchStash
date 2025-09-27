# HostHoover

HostHoover is a Python 3 utility that collects running configuration files from network devices and archives them.

## Features

- Pings each host in the provided subnet and skips unreachable devices.
- Connects over SSH using [Netmiko](https://github.com/ktbyers/netmiko).
- Saves each configuration to a file named after the device hostname.
- Creates a ZIP archive containing all collected configuration files.
- Works on Linux and Windows thanks to a cross-platform ping check.
- Concurrent processing for faster execution on large subnets.
- Configurable retry logic for robust connections.
- Progress bar for long-running operations.
- Dry run mode for testing without actual connections.
- Comprehensive logging for debugging.

## Requirements

- Python 3.8 or higher
- `netmiko` Python package
- `tqdm` for progress bars

Install the dependencies with:

```bash
pip install -r requirements.txt
```

## Testing

Run the tests with:

```bash
pytest
```

## Usage

```bash
python3 hosthoover.py <network_cidr> -u <username> -p <password> [options]
```
You can also set credentials via the `SSH_USERNAME` and `SSH_PASSWORD` environment variables instead of using `-u` and `-p`.

Common options:

- `-d`, `--device-type`  Netmiko device type (default: `cisco_ios`)
- `-o`, `--output`       Directory to save configs (default: `configs`)
- `-z`, `--zip-name`     Name of the zip file (default: `configs.zip`)
- `-c`, `--command`      CLI command to run (default: `show running-config`)
- `--ping-count`         Number of ping attempts before giving up (default: `1`)
- `--ping-timeout`       Ping timeout in seconds (default: `1`)
- `--max-retries`        Maximum number of connection retries (default: `1`)
- `--dry-run`            Simulate operations without actually connecting

Example:

```bash
python3 hosthoover.py 192.168.1.0/24 -u admin -p password
```

The script processes the hosts in the `/24` network and stores the results in the specified output directory.
At the end, a brief summary lists which hosts succeeded or failed.

## Supported Device Types

HostHoover relies on [Netmiko](https://github.com/ktbyers/netmiko), which
supports a large number of network device platforms. To see the complete list of
supported device types on your system, run the following Python snippet:

```bash
python - <<'EOF'
from netmiko.ssh_dispatcher import CLASS_MAPPER
for device_type in sorted(CLASS_MAPPER):
    print(device_type)
EOF
```
 
Common device type names for the `--device-type` option include:

- `aruba_os` - ArubaOS switches and controllers
- `cisco_ios` - Cisco IOS / IOS XE devices
- `cisco_nxos` - Cisco NX-OS (Nexus) devices
- `cisco_xr` - Cisco IOS-XR routers
- `juniper_junos` - Juniper Junos platforms

Refer to the Netmiko documentation for details on each device type and any
special configuration that may be required.
