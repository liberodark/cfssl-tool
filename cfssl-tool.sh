#! /usr/bin/env bash
#
# About: CFSSL Tool
# Author: liberodark
# Thanks :
# License: GNU GPLv3

version="1.0"

echo "Welcome on CFSSL Tool Script $version"

#=================================================
# RETRIEVE ARGUMENTS FROM THE MANIFEST AND VAR
#=================================================

CFSSL_SERVER="http://192.168.0.185:8888"
ACTION=$1
DEFAULT_COUNTRY=${DEFAULT_COUNTRY:-FR}
DEFAULT_STATE=${DEFAULT_STATE:-"Île-de-France"}
DEFAULT_CITY=${DEFAULT_CITY:-Paris}
DEFAULT_ORGANIZATION=${DEFAULT_ORGANIZATION:-"My Organization"}
DEFAULT_UNIT=${DEFAULT_UNIT:-IT}
DEFAULT_KEY_ALGO=${DEFAULT_KEY_ALGO:-ecdsa}
DEFAULT_KEY_SIZE=${DEFAULT_KEY_SIZE:-256}

CONFIG_FILE="$HOME/.cfssl-tool.conf"
[ -f "$CONFIG_FILE" ] && source "$CONFIG_FILE"

show_help() {
  echo "Usage: $0 [generate|revoke|check|info|renew-custom|check-revocation] [params]"
  echo ""
  echo "Commands:"
  echo "  generate domain.com [profile] [options]     - Generate certificate for domain"
  echo "  revoke serial aki [reason]                  - Revoke certificate"
  echo "  renew-custom domain.com [profile] [options] - Create new certificate for the same domain"
  echo "  check serial|cert_file                      - Check certificate status"
  echo "  check-revocation serial                     - Check if certificate is in CRL"
  echo "  info                                        - Show CA information"
  echo ""
  echo "Certificate generation options:"
  echo "  -c, --country CODE       Country code (default: $DEFAULT_COUNTRY)"
  echo "  -s, --state STATE        State/Province (default: $DEFAULT_STATE)"
  echo "  -l, --city CITY          City/Locality (default: $DEFAULT_CITY)"
  echo "  -o, --org ORG            Organization (default: $DEFAULT_ORGANIZATION)"
  echo "  -u, --unit UNIT          Organizational Unit (default: $DEFAULT_UNIT)"
  echo "  -a, --algo ALGO          Key algorithm (default: $DEFAULT_KEY_ALGO)"
  echo "  -b, --bits SIZE          Key size/bits (default: $DEFAULT_KEY_SIZE)"
  echo "  -d, --domains LIST       Additional domain names (comma-separated)"
  echo "  -n, --no-www             Don't add www subdomain automatically"
  echo "  -f, --config FILE        Load certificate request from JSON file"
  echo "  -i, --interactive        Use interactive mode"
  echo ""
  echo "Examples:"
  echo "  $0 generate example.com server"
  echo "  $0 generate example.com server -c US -s California -l 'San Francisco' -o 'My Company'"
  echo "  $0 generate example.com server -d 'api.example.com,admin.example.com'"
  echo "  $0 revoke 567894780611517373554735158137087297011809058178 E9:0D:75:BA:FF:B9:74:39:0E:1F:8F:58:E5:F4:0B:36:4A:27:2A:E0 keyCompromise"
  echo "  $0 check example.com.crt"
  echo "  $0 check-revocation 566897563731316780990587952188820716605210348809"
  exit 1
}

get_ca_info() {
  echo "Getting CA information..."
  curl -s -X POST -H "Content-Type: application/json" -d '{}' $CFSSL_SERVER/api/v1/cfssl/info | jq
}

generate_interactive() {
  echo "==== Interactive Certificate Generation ===="

  read -r "Domain name: " DOMAIN
  read -r "Profile [server]: " PROFILE
  PROFILE=${PROFILE:-server}

  read -r "Country code [$DEFAULT_COUNTRY]: " COUNTRY
  COUNTRY=${COUNTRY:-$DEFAULT_COUNTRY}

  read -r "State/Province [$DEFAULT_STATE]: " STATE
  STATE=${STATE:-$DEFAULT_STATE}

  read -r "City [$DEFAULT_CITY]: " CITY
  CITY=${CITY:-$DEFAULT_CITY}

  read -r "Organization [$DEFAULT_ORGANIZATION]: " ORGANIZATION
  ORGANIZATION=${ORGANIZATION:-$DEFAULT_ORGANIZATION}

  read -r "Organizational Unit [$DEFAULT_UNIT]: " UNIT
  UNIT=${UNIT:-$DEFAULT_UNIT}

  read -r "Key algorithm [$DEFAULT_KEY_ALGO]: " KEY_ALGO
  KEY_ALGO=${KEY_ALGO:-$DEFAULT_KEY_ALGO}

  read -r "Key size [$DEFAULT_KEY_SIZE]: " KEY_SIZE
  KEY_SIZE=${KEY_SIZE:-$DEFAULT_KEY_SIZE}

  read -r "Additional domains (comma-separated): " ADDITIONAL_DOMAINS

  read -r "Add www subdomain? [Y/n]: " WWW_CHOICE
  [[ "$WWW_CHOICE" == [Nn]* ]] && ADD_WWW=false || ADD_WWW=true

  create_cert_request
  generate_certificate
}

create_cert_request() {
  HOSTS_JSON="[\"$DOMAIN\""

  [ "$ADD_WWW" = true ] && HOSTS_JSON="$HOSTS_JSON, \"www.$DOMAIN\""

  if [ -n "$ADDITIONAL_DOMAINS" ]; then
    IFS=',' read -ra ADDR <<< "$ADDITIONAL_DOMAINS"
    for domain in "${ADDR[@]}"; do
      HOSTS_JSON="$HOSTS_JSON, \"$domain\""
    done
  fi

  HOSTS_JSON="$HOSTS_JSON]"

  cat > request_temp.json << EOF
{
  "request": {
    "hosts": $HOSTS_JSON,
    "names": [
      {
        "C": "$COUNTRY",
        "ST": "$STATE",
        "L": "$CITY",
        "O": "$ORGANIZATION",
        "OU": "$UNIT"
      }
    ],
    "CN": "$DOMAIN",
    "key": {
      "algo": "$KEY_ALGO",
      "size": $KEY_SIZE
    }
  },
  "profile": "$PROFILE"
}
EOF
}

generate_certificate() {
  echo "Generating certificate for $DOMAIN..."
  RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d @request_temp.json $CFSSL_SERVER/api/v1/cfssl/newcert)

  echo "$RESPONSE" | jq -r .result.certificate > "${DOMAIN}".crt
  echo "$RESPONSE" | jq -r .result.private_key > "${DOMAIN}".key

  if [ -s "${DOMAIN}.crt" ] && [ -s "${DOMAIN}.key" ]; then
    echo "Certificate and key successfully generated:"
    echo " - ${DOMAIN}.crt"
    echo " - ${DOMAIN}.key"

    cat > cert_info_request.json << EOF
{
  "certificate": "$(cat "${DOMAIN}".crt | sed 's/$/\\n/' | tr -d '\n')"
}
EOF

    CERT_INFO=$(curl -s -X POST -H "Content-Type: application/json" -d @cert_info_request.json $CFSSL_SERVER/api/v1/cfssl/certinfo)
    SERIAL=$(echo "$CERT_INFO" | jq -r .result.serial_number)
    AKI=$(echo "$CERT_INFO" | jq -r .result.authority_key_id)
    AKI_PLAIN=$(echo "$AKI" | tr -d ':' | tr '[:upper:]' '[:lower:]')

    echo ""
    echo "==== Certificate Information ===="
    if [ "$SERIAL" != "null" ] && [ -n "$SERIAL" ]; then
      echo "Serial Number: $SERIAL"
    else
      echo "Serial Number: [Not extracted]"
    fi

    if [ "$AKI" != "null" ] && [ -n "$AKI" ]; then
      echo "Authority Key ID: $AKI"
      echo "Authority Key ID (plain): $AKI_PLAIN"
    else
      echo "Authority Key ID: [Not extracted]"
    fi

    VALIDITY=$(echo "$CERT_INFO" | jq -r '.result.not_after')
    echo "Valid until: $VALIDITY"
    echo "Save this information for future revocation/renewal"

    rm cert_info_request.json
  else
    echo "Error generating certificate"
    echo "Server response:"
    echo "$RESPONSE"
  fi

  rm request_temp.json
}

revoke_certificate() {
  SERIAL=$1
  AKI=$2
  REASON=${3:-unspecified}

  echo "Revoking certificate with serial $SERIAL..."
  RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d "{\"serial\": \"$SERIAL\", \"authority_key_id\": \"$AKI\", \"reason\": \"$REASON\"}" $CFSSL_SERVER/api/v1/cfssl/revoke)

  if echo "$RESPONSE" | grep -q "\"success\":true"; then
    echo "Certificate successfully revoked"
  else
    echo "Error revoking certificate:"
    echo "$RESPONSE"
  fi
}

check_certificate() {
  CERT_ID=$1

  if [ -f "$CERT_ID" ]; then
    echo "Checking certificate file $CERT_ID..."
    cat > cert_check_request.json << EOF
{
  "certificate": "$(cat "$CERT_ID" | sed 's/$/\\n/' | tr -d '\n')"
}
EOF
    RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d @cert_check_request.json $CFSSL_SERVER/api/v1/cfssl/certinfo)
    rm cert_check_request.json
  else
    echo "Checking certificate with serial $CERT_ID..."
    RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d "{\"serial\": \"$CERT_ID\"}" $CFSSL_SERVER/api/v1/cfssl/certinfo)
  fi

  if echo "$RESPONSE" | grep -q "result"; then
    echo "==== Certificate Details ===="
    echo "Subject: $(echo "$RESPONSE" | jq -r '.result.subject.common_name')"
    echo "Issuer: $(echo "$RESPONSE" | jq -r '.result.issuer.common_name')"
    echo "Serial: $(echo "$RESPONSE" | jq -r '.result.serial_number')"
    echo "Not Before: $(echo "$RESPONSE" | jq -r '.result.not_before')"
    echo "Not After: $(echo "$RESPONSE" | jq -r '.result.not_after')"
    echo "AKI: $(echo "$RESPONSE" | jq -r '.result.authority_key_id')"

    REVOKED=$(echo "$RESPONSE" | jq -r '.result.revoked')
    if [ "$REVOKED" == "true" ]; then
      REVOCATION_TIME=$(echo "$RESPONSE" | jq -r '.result.revocation_time')
      REASON=$(echo "$RESPONSE" | jq -r '.result.revocation_reason')
      echo "Status: REVOKED"
      echo "Revocation time: $REVOCATION_TIME"
      echo "Reason: $REASON"
    else
      echo "Status: VALID"
    fi
  else
    echo "Error checking certificate:"
    echo "$RESPONSE"
  fi
}

check_revocation() {
  SERIAL_DEC=$1

  if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    echo "Error: Python is required for converting decimal to hex."
    exit 1
  fi

  PY_CMD=$(command -v python3 || command -v python)

  SERIAL_HEX=$($PY_CMD -c "print(hex(int('$SERIAL_DEC'))[2:].upper())")
  echo "Serial number (hex): $SERIAL_HEX"

  echo "Retrieving CRL from $CFSSL_SERVER/api/v1/cfssl/crl..."
  CRL_JSON=$(curl -s "$CFSSL_SERVER/api/v1/cfssl/crl")

  SUCCESS=$(echo "$CRL_JSON" | jq -r '.success')
  if [ "$SUCCESS" != "true" ]; then
    echo "Error retrieving CRL:"
    echo "$CRL_JSON"
    exit 1
  fi

  CRL_BASE64=$(echo "$CRL_JSON" | jq -r '.result')
  if [ -z "$CRL_BASE64" ] || [ "$CRL_BASE64" == "null" ]; then
    echo "The 'result' field is empty in the CRL response."
    exit 1
  fi

  TEMP_DIR=$(mktemp -d)
  CRL_BASE64_FILE="$TEMP_DIR/crl_base64.txt"
  CRL_DER_FILE="$TEMP_DIR/crl.der"

  echo "$CRL_BASE64" > "$CRL_BASE64_FILE"
  base64 -d "$CRL_BASE64_FILE" > "$CRL_DER_FILE"

  echo "Analyzing CRL..."
  if ! command -v openssl &> /dev/null; then
    echo "Error: OpenSSL is required for CRL analysis."
    rm -rf "$TEMP_DIR"
    exit 1
  fi

  if ! CRL_CONTENT=$(openssl crl -inform DER -text -noout -in "$CRL_DER_FILE" 2>/dev/null)
  then
    echo "Error analyzing CRL."
    rm -rf "$TEMP_DIR"
    exit 1
  fi

  if echo "$CRL_CONTENT" | grep -iq "$SERIAL_HEX"; then
    echo "Certificate with serial number $SERIAL_HEX is REVOKED."
  else
    echo "Certificate with serial number $SERIAL_HEX is NOT found in the CRL."
  fi

  rm -rf "$TEMP_DIR"
}

parse_generate_options() {
  DOMAIN=$1
  PROFILE=${2:-server}
  shift 2

  COUNTRY="$DEFAULT_COUNTRY"
  STATE="$DEFAULT_STATE"
  CITY="$DEFAULT_CITY"
  ORGANIZATION="$DEFAULT_ORGANIZATION"
  UNIT="$DEFAULT_UNIT"
  KEY_ALGO="$DEFAULT_KEY_ALGO"
  KEY_SIZE="$DEFAULT_KEY_SIZE"
  ADD_WWW=true
  ADDITIONAL_DOMAINS=""
  CONFIG_JSON=""
  INTERACTIVE=false

  while [[ $# -gt 0 ]]; do
    case $1 in
      -c|--country) COUNTRY="$2"; shift 2 ;;
      -s|--state) STATE="$2"; shift 2 ;;
      -l|--city) CITY="$2"; shift 2 ;;
      -o|--org) ORGANIZATION="$2"; shift 2 ;;
      -u|--unit) UNIT="$2"; shift 2 ;;
      -a|--algo) KEY_ALGO="$2"; shift 2 ;;
      -b|--bits) KEY_SIZE="$2"; shift 2 ;;
      -d|--domains) ADDITIONAL_DOMAINS="$2"; shift 2 ;;
      -n|--no-www) ADD_WWW=false; shift ;;
      -f|--config) CONFIG_JSON="$2"; shift 2 ;;
      -i|--interactive) INTERACTIVE=true; shift ;;
      *) echo "Unknown option: $1"; exit 1 ;;
    esac
  done

  if [ "$INTERACTIVE" = true ]; then
    generate_interactive
    exit 0
  fi

  if [ -n "$CONFIG_JSON" ]; then
    if [ ! -f "$CONFIG_JSON" ]; then
      echo "Error: Config file $CONFIG_JSON not found"
      exit 1
    fi
    cp "$CONFIG_JSON" request_temp.json
    if ! grep -q "\"profile\"" request_temp.json; then
      sed -i "s/}$/,\"profile\":\"$PROFILE\"}/" request_temp.json
    fi
  else
    create_cert_request
  fi
}

[ -z "$ACTION" ] && show_help

case "$ACTION" in
  info)
    get_ca_info
    ;;

  generate)
    [ -z "$2" ] && { echo "Error: Domain name required"; exit 1; }
    parse_generate_options "$2" "$3" "${@:4}"
    generate_certificate
    ;;

  renew-custom)
    [ -z "$2" ] && { echo "Error: Domain name required"; exit 1; }
    DOMAIN=$2
    [ -f "${DOMAIN}.crt" ] && {
      echo "Backing up existing certificate and key..."
      timestamp=$(date +%Y%m%d%H%M%S)
      cp "${DOMAIN}.crt" "${DOMAIN}.crt.${timestamp}.bak"
      cp "${DOMAIN}.key" "${DOMAIN}.key.${timestamp}.bak"
    }
    parse_generate_options "$2" "$3" "${@:4}"
    generate_certificate
    ;;

  revoke)
    [ -z "$2" ] || [ -z "$3" ] && {
      echo "Error: Serial number and Authority Key ID required"
      echo "Usage: $0 revoke serial aki [reason]"
      echo "Valid reasons: unspecified, keyCompromise, CACompromise, affiliationChanged,"
      echo "               superseded, cessationOfOperation, certificateHold, removeFromCRL"
      exit 1
    }
    revoke_certificate "$2" "$3" "$4"
    ;;

  check)
    [ -z "$2" ] && {
      echo "Error: Certificate file or serial number required"
      echo "Usage: $0 check certificate.crt | serial"
      exit 1
    }
    check_certificate "$2"
    ;;

  check-revocation)
    [ -z "$2" ] && {
      echo "Error: Serial number required"
      echo "Usage: $0 check-revocation serial_number"
      exit 1
    }
    check_revocation "$2"
    ;;

  *)
    echo "Unknown action: $ACTION"
    show_help
    ;;
esac
