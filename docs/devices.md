# Device Types & Commands

SwitchStash uses [Netmiko](https://github.com/ktbyers/netmiko) which supports many platforms.

## Supported Devices

### Common Device Types

| Device Type | Common Commands | Description |
|-------------|-----------------|-------------|
| `cisco_ios` | `show running-config`, `show version`, `show interfaces` | Cisco IOS/IOS XE |
| `cisco_nxos` | `show running-config`, `show version` | Cisco Nexus |
| `cisco_xr` | `show running-config`, `show version` | Cisco IOS-XR |
| `cisco_asa` | `show running-config`, `show version` | Cisco ASA |
| `juniper_junos` | `show configuration`, `show version`, `show chassis hardware` | Juniper Junos |
| `juniper_junos` | `show configuration \| display set` | Juniper Junos (set format) |
| `aruba_os` | `show running-config`, `show version` | Aruba |
| `hp_procurve` | `show running-config` | HP ProCurve |
| `dell_force10` | `show running-config` | Dell |
| `huawei` | `display current-configuration` | Huawei |
| `f5_tmsh` | `show running-config` | F5 BIG-IP |

## Juniper Example

```bash
# CLI
python switchstash.py main 10.0.0.0/24 \
  -u admin -p password \
  -d juniper_junos \
  -c "show configuration | display set"

# Config
device_type: juniper_junos
commands:
  - show configuration | display set
  - show version
  - show chassis hardware
```

## Multiple Commands

```bash
python switchstash.py main 192.168.1.0/24 \
  -u admin -p password \
  -c "show running-config" \
  -c "show version" \
  -c "show interfaces"
```

## Templated Commands

Use variables in commands:

| Variable | Description |
|----------|-------------|
| `{{hostname}}` | Device hostname from config |
| `{{ip}}` | Device IP address |

```bash
# Run different commands per device
python switchstash.py main 192.168.1.0/24 \
  -u admin -p password \
  -c "show interface {{hostname}}"
```

## Auto-Detection

Let SwitchStash detect the device type automatically:

```bash
python switchstash.py main 192.168.1.0/24 \
  -u admin -p password \
  --auto-detect
```

This tries each device type until one works.
