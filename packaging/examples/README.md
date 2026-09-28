# Configuration examples

## controllers.example.json

The example configuration references `/etc/unifimcp/api.key` as the API key file. This file does not exist by default, so the example configuration cannot be used for a local smoke test without first creating it:

```bash
# Create the API key file (replace with your actual API key)
echo "your-api-key-here" > /etc/unifimcp/api.key
chmod 0600 /etc/unifimcp/api.key
chown root:unifimcp /etc/unifimcp/api.key
```

For production deployments, follow the installer's output instructions.

## Audit log rotation

`packaging/lxc/install.sh` does not install `packaging/logrotate/rustunifimcp-audit`.
If you enable the audit file sink (`--audit-log-file`), copy the fragment in by hand:

```bash
install -m 0644 -o root -g root packaging/logrotate/rustunifimcp-audit /etc/logrotate.d/rustunifimcp-audit
```
