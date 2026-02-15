# Authentication

SwitchStash supports multiple authentication methods.

## Password Authentication

```bash
# CLI
python switchstash.py main 192.168.1.0/24 -u admin -p secret

# Config file
# config.yaml
username: admin
password: secret
```

## SSH Key Authentication

```bash
# CLI
python switchstash.py main 192.168.1.0/24 -u admin -k ~/.ssh/id_rsa

# Config file
username: admin
key_file: ~/.ssh/id_rsa
```

## SSH Agent

Uses your running SSH agent (no password needed in command):

```bash
python switchstash.py main 192.168.1.0/24 -u admin --use-agent
```

## Interactive Password Prompt

Prompts for password without showing it on command line:

```bash
python switchstash.py main 192.168.1.0/24 -u admin --password-prompt
```

## Environment Variables

```bash
export SSH_USERNAME=admin
export SSH_PASSWORD=secret

python switchstash.py main 192.168.1.0/24
```

## Vault Integration

For production, consider using HashiCorp Vault. Example wrapper:

```bash
#!/bin/bash
# vault-creds.sh
vault kv get -field=password secret/switchstash/prod
```

Then reference in config or use a tool like `hvac` Python library for direct integration.
