# CFSSL Tool

A simple command-line tool to manage SSL/TLS certificates using the CFSSL API with OCSP server integration.

## Overview

CFSSL Tool simplifies certificate operations including:
- Generating new certificates
- Revoking certificates
- Checking certificate status
- Verifying revocation status via CRL
- Retrieving CA information
- OCSP server integration for certificate status management

## Prerequisites

- Bash shell
- curl
- jq
- openssl
- Python3
- base64
- A running CFSSL server
- (Optional) A running OCSP server

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

### Global Options

Options like `-ocsp` or `--ocsp` can be placed anywhere in the command:

```bash
# These commands are equivalent:
./cfssl-tool.sh --ocsp check example.com.crt
./cfssl-tool.sh check example.com.crt --ocsp
```

## Certificate Serial Numbers

CFSSL Tool handles different serial number formats:

- **CFSSL** uses decimal format (e.g., `601501047091833657479508898813397337221994383748`)
- **OpenSSL** outputs hexadecimal format (e.g., `695C3D632CE3EED8607D0566878B14247ED80984`)
- **OCSP** requires hexadecimal with `0x` prefix (e.g., `0x695c3d632ce3eed8607d0566878b14247ed80984`)

The tool automatically converts between formats. To manually extract a certificate's serial number:

```bash
# Extract serial in decimal format (for CFSSL)
openssl x509 -in your_certificate.crt -serial -noout | sed 's/serial=//' |
  python3 -c "import sys; print(int(sys.stdin.read().strip(), 16))"

# Extract serial in 0x hexadecimal format (for OCSP)
openssl x509 -in your_certificate.crt -serial -noout | sed 's/serial=/0x/' | tr 'A-F' 'a-f'
```

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

With OCSP integration:
```bash
./cfssl-tool.sh generate example.com server --ocsp
```

Interactive mode:
```bash
./cfssl-tool.sh generate example.com server -i
```

### Revoke a certificate

```bash
./cfssl-tool.sh revoke 567894780611517373554735158137087297011809058178 E9:0D:75:BA:FF:B9:74:39:0E:1F:8F:58:E5:F4:0B:36:4A:27:2A:E0 keyCompromise
```

With OCSP integration:
```bash
./cfssl-tool.sh revoke 567894780611517373554735158137087297011809058178 E9:0D:75:BA:FF:B9:74:39:0E:1F:8F:58:E5:F4:0B:36:4A:27:2A:E0 keyCompromise --ocsp
```

### Check certificate status

```bash
./cfssl-tool.sh check example.com.crt
```

With OCSP status check:
```bash
./cfssl-tool.sh check example.com.crt --ocsp
```

### Check revocation status in CRL

```bash
./cfssl-tool.sh check-revocation 566897563731316780990587952188820716605210348809
```

With OCSP check:
```bash
./cfssl-tool.sh check-revocation 566897563731316780990587952188820716605210348809 --ocsp
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

### OCSP Server Options

| Option | Description | Default |
|--------|-------------|---------|
| -ocsp, --ocsp | Enable OCSP integration | disabled |
| --ocsp-server URL | OCSP API server URL | from config |
| --ocsp-key KEY | OCSP API key | from config |

### Global Configuration

Create a `~/.cfssl-tool.conf` file to set default values:

```bash
CFSSL_SERVER="http://192.168.0.185:8888"
OCSP_SERVER="http://192.168.0.185:9000"
OCSP_API_KEY="your-secure-api-key"
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

### Certificate Status Inconsistencies

If the certificate status differs between CFSSL and OCSP:
- CFSSL stores certificate status in its database and CRL
- OCSP Server maintains its own record of certificate status
- Use `check-revocation` to verify CRL status directly
- Use `check` with `--ocsp` to see both systems' status

### Serial Number Format Issues

When working with certificate serial numbers:
- Ensure you're using the correct format (decimal for CFSSL, hex with `0x` prefix for OCSP)
- For CFSSL operations, use decimal format without any prefix
- For OCSP operations, use lowercase hexadecimal with `0x` prefix
- The `check` and `check-revocation` commands will handle conversion automatically

### Authority Key ID Format

When revoking certificates, the Authority Key ID (AKI) can be provided in either format:
- With colons: `E9:0D:75:BA:FF:B9:74:39:0E:1F:8F:58:E5:F4:0B:36:4A:27:2A:E0`
- Plain format: `e90d75baffb974390e1f8f58e5f40b364a272ae0`

The tool automatically converts the AKI to the format required by CFSSL (plain format).

### Communication Errors

If you're experiencing connection issues, verify:
1. CFSSL server is running
2. The server URL is correct in your command or config file
3. There are no network issues or firewalls blocking connections
4. For OCSP errors, check that your API key is valid

## Acknowledgments

- Based on the CFSSL project by CloudFlare
