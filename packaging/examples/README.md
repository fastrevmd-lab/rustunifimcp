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
