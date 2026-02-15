# SwitchStash

Network device configuration backup tool. Stash away configs from your switches, routers, and firewalls with ease.

## Features

- **SSH Connectivity** - Uses Netmiko to connect to network devices
- **Multiple Auth Methods** - Password, SSH keys, SSH agent, or interactive prompt
- **Auto-Detection** - Automatically detect device type from SSH banner
- **Concurrent Processing** - Parallel backups with configurable workers
- **Config Diffing** - Track changes between backup runs
- **Inventory Database** - SQLite-backed device tracking
- **Interactive Mode** - Discover hosts and select which to backup
- **Pre/Post Hooks** - Run scripts before and after backups
- **HTML Reports** - Generate pretty reports
- **Templated Commands** - Use variables like `{{hostname}}`
- **Device Groups** - Different credentials per group
- **Config Validation** - Validate config before running
- **Reliability** - Exponential backoff, timeouts, retries

## Quick Start

```bash
# Install with uv
uv sync

# Run a backup
python switchstash.py main 192.168.1.0/24 -u admin -p password
```

## Installation

### Requirements

- Python 3.8+
- uv (recommended) or pip

### Install

```bash
# Clone and install
uv sync

# Or install globally
uv pip install -e .
```

## Usage

### Basic Backup

```bash
# Single network
python switchstash.py main 192.168.1.0/24 -u admin -p password

# Multiple networks
python switchstash.py main "192.168.1.0/24,10.0.0.0/24" -u admin -p password

# From file
python switchstash.py main @networks.txt -u admin -p password
```

### Device Groups

```bash
# Using groups from config
python switchstash.py main --config config.yaml --group prod-cisco

# List available groups
python switchstash.py list-groups config.yaml
```

### Authentication

```bash
# Password
python switchstash.py main 192.168.1.0/24 -u admin -p password

# SSH key
python switchstash.py main 192.168.1.0/24 -u admin -k ~/.ssh/id_rsa

# SSH agent
python switchstash.py main 192.168.1.0/24 -u admin --use-agent

# Interactive password prompt
python switchstash.py main 192.168.1.0/24 -u admin --password-prompt
```

### Configuration File

```bash
# Create config.yaml from the example
cp config.example.yaml config.yaml
# Edit with your settings

# Run with config
python switchstash.py main 192.168.1.0/24 -c config.yaml
```

### Validate Config

```bash
python switchstash.py validate config.yaml
```

## Commands

| Command | Description |
|---------|-------------|
| `main` | Run backup |
| `validate` | Validate config file |
| `list-groups` | List device groups |
| `stats` | Show inventory stats |
| `history` | Show backup history |
| `diff` | Show config diff |

## Common Options

| Option | Alias | Description |
|--------|-------|-------------|
| `--config` | `-c` | YAML config file |
| `--username` | `-u` | SSH username |
| `--password` | `-p` | SSH password |
| `--key-file` | `-k` | SSH private key |
| `--use-agent` | | Use SSH agent |
| `--password-prompt` | | Prompt for password |
| `--group` | `-g` | Device group from config |
| `--device-type` | `-d` | Netmiko device type |
| `--output` | `-o` | Output directory |
| `--database` | `-b` | SQLite database |
| `--workers` | `-w` | Concurrent workers |
| `--html-report` | | HTML report file |
| `--dry-run` | | Test without connecting |
| `--version` | | Show version |
| `--verbose` | `-v` | Verbose output |

## Examples

### Full Example

```bash
python switchstash.py main 192.168.1.0/24 \
  -u admin \
  -p password \
  -d cisco_ios \
  -o configs \
  -b switchstash.db \
  -w 20 \
  --html-report report.html
```

### Interactive Mode

```bash
python switchstash.py main 192.168.1.0/24 -u admin -p password --interactive
```

### With Hooks

```bash
python switchstash.py main 192.168.1.0/24 \
  -u admin -p password \
  --pre-hook "./hooks/pre.sh" \
  --post-hook "./hooks/post.sh"
```

## Configuration

See [config.example.yaml](./config.example.yaml) for all options.

## Development

```bash
# Install dependencies
uv sync

# Run tests
uv run pytest

# Run with specific test
uv run pytest test_switchstash.py -v
```
