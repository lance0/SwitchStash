# Configuration File

SwitchStash uses YAML configuration files for flexible settings.

## Example

```yaml
# Credentials
username: admin
password: changeme
# key_file: ~/.ssh/id_rsa

# Connection
device_type: cisco_ios
auto_detect: false

# Timeouts (seconds)
connect_timeout: 10
command_timeout: 30

# Retry settings
max_retries: 3

# Commands to run
commands:
  - show running-config
  - show version
  - show interfaces

# Output
output_dir: configs
zip_name: backup.zip
database: switchstash.db

# Hooks
# pre_hook: ./hooks/pre.sh
# post_hook: ./hooks/post.sh
```

## Options

### Credentials

| Option | Description |
|--------|-------------|
| `username` | SSH username |
| `password` | SSH password |
| `key_file` | Path to SSH private key |
| `use_agent` | Use SSH agent (true/false) |

### Connection

| Option | Default | Description |
|--------|---------|-------------|
| `device_type` | cisco_ios | Netmiko device type |
| `auto_detect` | false | Auto-detect device type |
| `connect_timeout` | device-specific | SSH connection timeout |
| `command_timeout` | device-specific | Command execution timeout |
| `max_retries` | 3 | Connection retry attempts |
| `ping_count` | 1 | Ping attempts before skip |
| `ping_timeout` | 1 | Ping timeout in seconds |

### Commands

| Option | Description |
|--------|-------------|
| `commands` | List of commands to run on each device |

### Output

| Option | Default | Description |
|--------|---------|-------------|
| `output_dir` | configs | Directory for config files |
| `zip_name` | configs.zip | Zip archive name |
| `database` | switchstash.db | SQLite database path |
| `no_diff` | false | Skip diff checking |

### Hooks

| Option | Description |
|--------|-------------|
| `pre_hook` | Script to run before each backup |
| `post_hook` | Script to run after each backup |

## Using Multiple Networks

```yaml
# networks.txt
192.168.1.0/24
10.0.0.0/24
172.16.0.0/16
```

```bash
python switchstash.py main @networks.txt -c config.yaml
```

## Device Groups

Define groups with their own credentials and target networks:

```yaml
username: global_admin
password: global_pass

groups:
  # Production Cisco switches
  prod-cisco:
    networks:
      - 10.1.0.0/16
    username: admin
    password: prodpassword
    device_type: cisco_ios
    commands:
      - show running-config
      - show version

  # Juniper devices
  juniper:
    networks:
      - 10.2.0.0/24
    username: admin
    password: juniperpass
    device_type: juniper_junos
    commands:
      - show configuration | display set

  # Lab devices with SSH key
  lab:
    networks:
      - 172.16.0.0/24
    username: admin
    key_file: ~/.ssh/lab_key
    device_type: cisco_ios
```

### Running with Groups

```bash
# List available groups
python switchstash.py list-groups config.yaml

# Run specific group
python switchstash.py main --config config.yaml --group prod-cisco
```
