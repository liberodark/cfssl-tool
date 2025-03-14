# CFSSL Tool

A simple command-line tool to manage SSL/TLS certificates using the CFSSL API.

## Overview

CFSSL Tool simplifies certificate operations including:
- Generating new certificates
- Revoking certificates
- Checking certificate status
- Verifying revocation status via CRL
- Retrieving CA information

## Prerequisites

- Bash shell
- curl
- jq
- openssl
- Python3
- base64
- A running CFSSL server

## Installation

1. Download the script:
```bash
curl -O https://raw.githubusercontent.com/liberodark/cfssl-tool/main/cfssl-tool.sh
```

2. Make it executable:
```bash
chmod +x cfssl-tool.sh
```

## Usage

```bash
./cfssl-tool.sh [command] [params] [options]
```

### Commands

- `generate` - Create a new certificate
- `revoke` - Revoke an existing certificate
- `renew-custom` - Generate a new certificate for the same domain
- `check` - Check certificate details
- `check-revocation` - Check if a certificate is in the CRL
- `info` - Show CA information

## Examples

### Generate a certificate

Basic usage:
```bash
./cfssl-tool.sh generate example.com server
```

With custom parameters:
```bash
./cfssl-tool.sh generate example.com server -c US -s California -l "San Francisco" -o "My Company"
```

Interactive mode:
```bash
./cfssl-tool.sh generate example.com server -i
```

### Revoke a certificate

```bash
./cfssl-tool.sh revoke 567894780611517373554735158137087297011809058178 E9:0D:75:BA:FF:B9:74:39:0E:1F:8F:58:E5:F4:0B:36:4A:27:2A:E0 keyCompromise
```

### Check certificate status

```bash
./cfssl-tool.sh check example.com.crt
```

### Check revocation status

```bash
./cfssl-tool.sh check-revocation 566897563731316780990587952188820716605210348809
```

## Configuration Options

### Certificate Generation Options

| Option | Description | Default |
|--------|-------------|---------|
| -c, --country | Country code | FR |
| -s, --state | State/Province | Île-de-France |
| -l, --city | City/Locality | Paris |
| -o, --org | Organization | My Organization |
| -u, --unit | Organizational Unit | IT |
| -a, --algo | Key algorithm | ecdsa |
| -b, --bits | Key size | 256 |
| -d, --domains | Additional domains (comma-separated) | |
| -n, --no-www | Don't add www subdomain automatically | |
| -f, --config | Load certificate request from JSON file | |
| -i, --interactive | Use interactive mode | |

### Global Configuration

Create a `~/.cfssl-tool.conf` file to set default values:

```bash
CFSSL_SERVER="http://192.168.0.185:8888"
DEFAULT_COUNTRY="FR"
DEFAULT_STATE="Île-de-France"
DEFAULT_CITY="Paris"
DEFAULT_ORGANIZATION="My Company"
DEFAULT_UNIT="IT"
DEFAULT_KEY_ALGO="ecdsa"
DEFAULT_KEY_SIZE="256"
```

## Using Custom Certificate Requests

You can create a JSON configuration file for complex certificate requests:

```json
{
  "request": {
    "hosts": [
      "example.com",
      "www.example.com",
      "api.example.com"
    ],
    "names": [
      {
        "C": "US",
        "ST": "California",
        "L": "San Francisco",
        "O": "Example Company",
        "OU": "IT Department"
      }
    ],
    "CN": "example.com",
    "key": {
      "algo": "ecdsa",
      "size": 384
    }
  }
}
```

Then use it with:
```bash
./cfssl-tool.sh generate example.com server -f my-request.json
```

## Troubleshooting

### Invalid Authority Key ID

When revoking certificates, ensure you use the correct format for the Authority Key ID:
- Either with colons: `E9:0D:75:BA:FF:B9:74:39:0E:1F:8F:58:E5:F4:0B:36:4A:27:2A:E0`
- Or plain format: `e90d75baffb974390e1f8f58e5f40b364a272ae0`

### Communication Errors

If you're experiencing connection issues, verify:
1. CFSSL server is running
2. The server URL is correct in your command or config file
3. There are no network issues or firewalls blocking connections

## Acknowledgments

- Based on the CFSSL project by CloudFlare
