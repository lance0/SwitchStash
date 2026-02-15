# Hooks

Run custom scripts before and after each device backup.

## Environment Variables

Hooks receive these environment variables:

| Variable | Description |
|----------|-------------|
| `SWITCHSTASH_HOST` | Device IP address |
| `SWITCHSTASH_HOSTNAME` | Device hostname (from config) |
| `SWITCHSTASH_ACTION` | "pre" or "post" |

## Pre-Hook Examples

### Slack Notification

```bash
#!/bin/bash
# pre-backup.sh
curl -X POST "$SLACK_WEBHOOK" \
  -H 'Content-type: application/json' \
  --data "{\"text\": \"Starting backup for $SWITCHSTASH_HOST ($SWITCHSTASH_HOSTNAME)\"}"
```

### Database Check

```bash
#!/bin/bash
# pre-backup.sh
# Verify device is in monitoring
python -c "import sqlite3; conn = sqlite3.connect('switchstash.db'); ..."
```

## Post-Hook Examples

### Upload to S3

```bash
#!/bin/bash
# post-backup.sh
if [ "$SWITCHSTASH_ACTION" = "post" ]; then
  aws s3 cp /path/to/configs/*.cfg s3://bucket/configs/
fi
```

### Send Alert on Failure

```bash
#!/bin/bash
# post-backup.sh  
# Check exit code
if [ $? -ne 0 ]; then
  echo "Backup failed for $SWITCHSTASH_HOST" | mail -s "SwitchStash Error" admin@example.com
fi
```

## Usage

```bash
python switchstash.py main 192.168.1.0/24 \
  -u admin -p password \
  --pre-hook "./hooks/pre.sh" \
  --post-hook "./hooks/post.sh"
```

Or in config:

```yaml
pre_hook: ./hooks/pre.sh
post_hook: ./hooks/post.sh
```
