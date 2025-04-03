#! /usr/bin/env bash
#
# About: CFSSL Tool with OCSP API Support
# Author: liberodark
# License: GNU GPLv3

version="1.6"

#=================================================
# RETRIEVE ARGUMENTS FROM THE MANIFEST AND VAR
#=================================================

CFSSL_SERVER="http://192.168.0.185:8888"
OCSP_SERVER="http://192.168.0.185:9000"
OCSP_API_KEY="API_KEY"
DEFAULT_COUNTRY=${DEFAULT_COUNTRY:-FR}
DEFAULT_STATE=${DEFAULT_STATE:-"Île-de-France"}
DEFAULT_CITY=${DEFAULT_CITY:-Paris}
DEFAULT_ORGANIZATION=${DEFAULT_ORGANIZATION:-"My Organization"}
DEFAULT_UNIT=${DEFAULT_UNIT:-IT}
DEFAULT_KEY_ALGO=${DEFAULT_KEY_ALGO:-ecdsa}
DEFAULT_KEY_SIZE=${DEFAULT_KEY_SIZE:-256}
USE_OCSP=false
RAW_OUTPUT=false

CONFIG_FILE="$HOME/.cfssl-tool.conf"

for arg in "$@"; do
  case $arg in
    -F=*|--config-file=*)
      CONFIG_FILE="${arg#*=}"
      shift
      ;;
    -F|--config-file)
      if [[ "$2" == -* ]] || [ -z "$2" ]; then
        echo "Error: --config-file requires a path argument"
        exit 1
      fi
      CONFIG_FILE="$2"
      shift 2
      ;;
    -R|--raw)
      RAW_OUTPUT=true
      shift
      ;;
  esac
done

[ -f "$CONFIG_FILE" ] && {
  #echo "Loading configuration from $CONFIG_FILE"
  source "$CONFIG_FILE"
}

if [ "$RAW_OUTPUT" = false ]; then
  echo "Welcome on CFSSL-OCSP Tool Script $version"
fi

process_global_options() {
  local args=("$@")
  local i=0
  local new_args=()

  while [ $i -lt ${#args[@]} ]; do
    case "${args[$i]}" in
      -ocsp|--ocsp)
        USE_OCSP=true
        ;;
      --ocsp-server=*)
        OCSP_SERVER="${args[$i]#*=}"
        ;;
      --ocsp-key=*)
        OCSP_API_KEY="${args[$i]#*=}"
        ;;
      --no-ocsp)
        USE_OCSP=false
        ;;
      --ocsp-server)
        if [ $((i+1)) -lt ${#args[@]} ]; then
          OCSP_SERVER="${args[$i+1]}"
          i=$((i+1))
        fi
        ;;
      --ocsp-key)
        if [ $((i+1)) -lt ${#args[@]} ]; then
          OCSP_API_KEY="${args[$i+1]}"
          i=$((i+1))
        fi
        ;;
      *)
        new_args+=("${args[$i]}")
        ;;
    esac
    i=$((i+1))
  done

  for arg in "${new_args[@]}"; do
    echo "$arg"
  done
}

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
  echo "General options:"
  echo "  -F, --config-file FILE     Use custom configuration file (default: $HOME/.cfssl-tool.conf)"
  echo "  -R, --raw                  Output only the raw JSON response from the server"
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
  echo "  -f, --config-json FILE   Load certificate request from JSON file"
  echo "  -i, --interactive        Use interactive mode"
  echo ""
  echo "OCSP Server options:"
  echo "  -ocsp, --ocsp            Enable OCSP integration (disabled by default)"
  echo "  --ocsp-server URL        OCSP API server URL (default: $OCSP_SERVER)"
  echo "  --ocsp-key KEY           OCSP API key (default: from .cfssl-tool.conf)"
  echo ""
  echo "Examples:"
  echo "  $0 generate example.com server"
  echo "  $0 generate example.com server -c US -s California -l 'San Francisco' -o 'My Company'"
  echo "  $0 generate example.com server -d 'api.example.com,admin.example.com'"
  echo "  $0 generate example.com server -ocsp"
  echo "  $0 -F /path/to/custom/config.conf generate example.com server"
  echo "  $0 revoke 567894780611517373554735158137087297011809058178 E9:0D:75:BA:FF:B9:74:39:0E:1F:8F:58:E5:F4:0B:36:4A:27:2A:E0 keyCompromise -ocsp"
  echo "  $0 check example.com.crt -ocsp"
  echo "  $0 check-revocation 566897563731316780990587952188820716605210348809 -ocsp"
  exit 1
}

get_ca_info() {
  if [ "$RAW_OUTPUT" = false ]; then
    echo "Getting CA information..."
  fi
  RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d '{}' $CFSSL_SERVER/api/v1/cfssl/info)
  if [ "$RAW_OUTPUT" = true ]; then
    echo "$RESPONSE"
  else
    echo "$RESPONSE" | jq
  fi
}

ocsp_add_certificate() {
  local CERT_NUM=$1

  if [ "$USE_OCSP" = false ]; then
    return 0
  fi

  if [ "$RAW_OUTPUT" = false ]; then
    echo "Adding certificate $CERT_NUM to OCSP server..."
  fi

  local RESPONSE
  RESPONSE=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $OCSP_API_KEY" \
    -d "{\"cert_num\": \"$CERT_NUM\"}" \
    "$OCSP_SERVER"/api/certificates)

  if [ "$RAW_OUTPUT" = false ]; then
    if echo "$RESPONSE" | grep -q "Certificate added successfully"; then
      echo "Certificate successfully added to OCSP server"
    else
      echo "Error adding certificate to OCSP server:"
      echo "$RESPONSE"
    fi
  fi
}

ocsp_revoke_certificate() {
  local CERT_NUM=$1
  local REASON=$2

  if [ "$USE_OCSP" = false ]; then
    return 0
  fi

  if [ "$RAW_OUTPUT" = false ]; then
    echo "Revoking certificate $CERT_NUM in OCSP server..."
  fi

  local REQUEST_DATA="{\"cert_num\": \"$CERT_NUM\", \"reason\": \"$REASON\"}"

  local RESPONSE
  RESPONSE=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $OCSP_API_KEY" \
    -d "$REQUEST_DATA" \
    "$OCSP_SERVER"/api/certificates/revoke)

  if [ "$RAW_OUTPUT" = false ]; then
    if echo "$RESPONSE" | grep -q "Certificate revoked successfully"; then
      echo "Certificate successfully revoked in OCSP server"
    else
      echo "Error revoking certificate in OCSP server:"
      echo "$RESPONSE"
    fi
  fi
}

ocsp_check_certificate() {
  local CERT_NUM=$1

  if [ "$USE_OCSP" = false ]; then
    return 0
  fi

  if [ "$RAW_OUTPUT" = false ]; then
    echo "Checking certificate $CERT_NUM in OCSP server..."
  fi

  local RESPONSE
  RESPONSE=$(curl -s -X GET \
    -H "X-API-Key: $OCSP_API_KEY" \
    "$OCSP_SERVER"/api/certificates/"$CERT_NUM")

  if [ "$RAW_OUTPUT" = false ]; then
    if echo "$RESPONSE" | grep -q "Certificate status retrieved"; then
      echo "==== OCSP Status ===="
      echo "Status: $(echo "$RESPONSE" | jq -r '.status')"
      echo "Message: $(echo "$RESPONSE" | jq -r '.message')"
    else
      echo "Error checking certificate in OCSP server:"
      echo "$RESPONSE"
    fi
  fi
}

generate_interactive() {
  echo "==== Interactive Certificate Generation ===="

  read -r -p "Domain name: " DOMAIN
  read -r -p "Profile [server]: " PROFILE
  PROFILE=${PROFILE:-server}

  read -r -p "Country code [$DEFAULT_COUNTRY]: " COUNTRY
  COUNTRY=${COUNTRY:-$DEFAULT_COUNTRY}

  read -r -p "State/Province [$DEFAULT_STATE]: " STATE
  STATE=${STATE:-$DEFAULT_STATE}

  read -r -p "City [$DEFAULT_CITY]: " CITY
  CITY=${CITY:-$DEFAULT_CITY}

  read -r -p "Organization [$DEFAULT_ORGANIZATION]: " ORGANIZATION
  ORGANIZATION=${ORGANIZATION:-$DEFAULT_ORGANIZATION}

  read -r -p "Organizational Unit [$DEFAULT_UNIT]: " UNIT
  UNIT=${UNIT:-$DEFAULT_UNIT}

  read -r -p "Key algorithm [$DEFAULT_KEY_ALGO]: " KEY_ALGO
  KEY_ALGO=${KEY_ALGO:-$DEFAULT_KEY_ALGO}

  read -r -p "Key size [$DEFAULT_KEY_SIZE]: " KEY_SIZE
  KEY_SIZE=${KEY_SIZE:-$DEFAULT_KEY_SIZE}

  read -r -p "Additional domains (comma-separated): " ADDITIONAL_DOMAINS

  read -r -p "Add www subdomain? [Y/n]: " WWW_CHOICE
  [[ "$WWW_CHOICE" == [Nn]* ]] && ADD_WWW=false || ADD_WWW=true

  read -r -p "Use OCSP integration? [y/N]: " OCSP_CHOICE
  [[ "$OCSP_CHOICE" == [Yy]* ]] && USE_OCSP=true || USE_OCSP=false

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
  if [ "$RAW_OUTPUT" = false ]; then
    echo "Generating certificate for $DOMAIN..."
  fi
  RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d @request_temp.json $CFSSL_SERVER/api/v1/cfssl/newcert)

  if [ "$RAW_OUTPUT" = true ]; then
    echo "$RESPONSE"

    if [ "$USE_OCSP" = true ] && echo "$RESPONSE" | jq -e '.result.certificate' > /dev/null 2>&1; then
      TEMP_DIR=$(mktemp -d)
      TEMP_CRT="$TEMP_DIR/${DOMAIN}.crt"

      echo "$RESPONSE" | jq -r '.result.certificate' > "$TEMP_CRT" 2>/dev/null

      if [ -s "$TEMP_CRT" ]; then
        cat > "$TEMP_DIR/cert_info_request.json" << EOF
{
  "certificate": "$(cat "$TEMP_CRT" | sed 's/$/\\n/' | tr -d '\n')"
}
EOF

        CERT_INFO=$(curl -s -X POST -H "Content-Type: application/json" -d @"$TEMP_DIR/cert_info_request.json" $CFSSL_SERVER/api/v1/cfssl/certinfo)
        SERIAL=$(echo "$CERT_INFO" | jq -r '.result.serial_number')

        if [ "$SERIAL" != "null" ] && [ -n "$SERIAL" ]; then
          SERIAL_HEX=$(convert_serial "$SERIAL" "0xhex")
          ocsp_add_certificate "$SERIAL_HEX"
        fi
      fi

      rm -rf "$TEMP_DIR"
    fi

    rm -f request_temp.json
    return
  fi

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

    if [ "$USE_OCSP" = true ] && [ "$SERIAL" != "null" ] && [ -n "$SERIAL" ]; then
      SERIAL_HEX=$(convert_serial "$SERIAL" "0xhex")
      ocsp_add_certificate "$SERIAL_HEX"
    fi

    rm -f cert_info_request.json
  else
    echo "Error generating certificate"
    echo "Server response:"
    echo "$RESPONSE"
  fi

  rm -f request_temp.json
}

revoke_certificate() {
  SERIAL=$1
  AKI=$2
  REASON=${3:-unspecified}

  if [[ "$AKI" == *:* ]]; then
    AKI_PLAIN=$(echo "$AKI" | tr -d ':' | tr '[:upper:]' '[:lower:]')
    if [ "$RAW_OUTPUT" = false ]; then
      echo "Converting AKI from '$AKI' to plain format '$AKI_PLAIN'"
    fi
    AKI="$AKI_PLAIN"
  fi

  if [ "$RAW_OUTPUT" = false ]; then
    echo "Revoking certificate with serial $SERIAL..."
  fi

  RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d "{\"serial\": \"$SERIAL\", \"authority_key_id\": \"$AKI\", \"reason\": \"$REASON\"}" $CFSSL_SERVER/api/v1/cfssl/revoke)

  if [ "$RAW_OUTPUT" = true ]; then
    echo "$RESPONSE"
    return
  fi

  if echo "$RESPONSE" | grep -q "\"success\":true"; then
    echo "Certificate successfully revoked in CFSSL"

    if [ "$USE_OCSP" = true ]; then
      case "$REASON" in
        keyCompromise) OCSP_REASON="key_compromise" ;;
        CACompromise) OCSP_REASON="ca_compromise" ;;
        affiliationChanged) OCSP_REASON="affiliation_changed" ;;
        superseded) OCSP_REASON="superseded" ;;
        cessationOfOperation) OCSP_REASON="cessation_of_operation" ;;
        certificateHold) OCSP_REASON="certificate_hold" ;;
        removeFromCRL) OCSP_REASON="unspecified" ;;
        *) OCSP_REASON="unspecified" ;;
      esac

      SERIAL_HEX=$(convert_serial "$SERIAL" "0xhex")
      ocsp_revoke_certificate "$SERIAL_HEX" "$OCSP_REASON"
    fi
  else
    echo "Error revoking certificate:"
    echo "$RESPONSE"
  fi
}

check_certificate() {
  CERT_ID=$1

  if [ -f "$CERT_ID" ]; then
    if [ "$RAW_OUTPUT" = false ]; then
      echo "Checking certificate file $CERT_ID..."
    fi
    cat > cert_check_request.json << EOF
{
  "certificate": "$(cat "$CERT_ID" | sed 's/$/\\n/' | tr -d '\n')"
}
EOF
    RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d @cert_check_request.json $CFSSL_SERVER/api/v1/cfssl/certinfo)
    rm cert_check_request.json
  else
    if [ "$RAW_OUTPUT" = false ]; then
      echo "Checking certificate with serial $CERT_ID..."
    fi
    RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d "{\"serial\": \"$CERT_ID\"}" $CFSSL_SERVER/api/v1/cfssl/certinfo)
  fi

  if [ "$RAW_OUTPUT" = true ]; then
    echo "$RESPONSE"
    return
  fi

  if echo "$RESPONSE" | grep -q "result"; then
    echo "==== Certificate Details ===="
    echo "Subject: $(echo "$RESPONSE" | jq -r '.result.subject.common_name')"
    echo "Issuer: $(echo "$RESPONSE" | jq -r '.result.issuer.common_name')"
    echo "Serial: $(echo "$RESPONSE" | jq -r '.result.serial_number')"
    echo "Not Before: $(echo "$RESPONSE" | jq -r '.result.not_before')"
    echo "Not After: $(echo "$RESPONSE" | jq -r '.result.not_after')"
    echo "AKI: $(echo "$RESPONSE" | jq -r '.result.authority_key_id')"

    SERIAL=$(echo "$RESPONSE" | jq -r '.result.serial_number')
    REVOKED=$(echo "$RESPONSE" | jq -r '.result.revoked')

    if [ "$REVOKED" == "true" ]; then
      REVOCATION_TIME=$(echo "$RESPONSE" | jq -r '.result.revocation_time')
      REASON=$(echo "$RESPONSE" | jq -r '.result.revocation_reason')
      echo "Status: REVOKED"
      echo "Revocation time: $REVOCATION_TIME"
      echo "Reason: $REASON"
    else
      if [ -n "$SERIAL" ] && [ "$SERIAL" != "null" ]; then
        if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
          echo "Python is required for CRL verification"
          echo "Status: UNKNOWN (cannot verify CRL)"
        else
          PY_CMD=$(command -v python3 || command -v python)
          SERIAL_HEX=$(convert_serial "$SERIAL" "HEX")

          CRL_JSON=$(curl -s "$CFSSL_SERVER/api/v1/cfssl/crl")
          SUCCESS=$(echo "$CRL_JSON" | jq -r '.success')

          if [ "$SUCCESS" == "true" ]; then
            TEMP_DIR=$(mktemp -d)
            CRL_BASE64_FILE="$TEMP_DIR/crl_base64.txt"
            CRL_DER_FILE="$TEMP_DIR/crl.der"

            echo "$CRL_JSON" | jq -r '.result' > "$CRL_BASE64_FILE"
            base64 -d "$CRL_BASE64_FILE" > "$CRL_DER_FILE"

            CRL_CONTENT=$(openssl crl -inform DER -text -noout -in "$CRL_DER_FILE" 2>/dev/null)
            if echo "$CRL_CONTENT" | grep -iq "$SERIAL_HEX"; then
              echo "Status: REVOKED (listed in CRL)"
            else
              echo "Status: VALID"
            fi

            rm -rf "$TEMP_DIR"
          else
            echo "Status: VALID (could not verify CRL)"
          fi
        fi
      else
        echo "Status: VALID"
      fi
    fi

    if [ "$USE_OCSP" = true ]; then
      if [ "$SERIAL" != "null" ] && [ -n "$SERIAL" ]; then
        SERIAL_HEX=$(convert_serial "$SERIAL" "0xhex")
        ocsp_check_certificate "$SERIAL_HEX"
      fi
    fi
  else
    echo "Error checking certificate:"
    echo "$RESPONSE"
  fi
}

check_revocation() {
  SERIAL_DEC=$1

  if [ "$RAW_OUTPUT" = false ]; then
    if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
      echo "Error: Python is required for converting decimal to hex."
      exit 1
    fi
    PY_CMD=$(command -v python3 || command -v python)
    SERIAL_HEX=$(convert_serial "$SERIAL_DEC" "HEX")
    echo "Serial number (hex): $SERIAL_HEX"
    echo "Retrieving CRL from $CFSSL_SERVER/api/v1/cfssl/crl..."
  fi

  CRL_JSON=$(curl -s "$CFSSL_SERVER/api/v1/cfssl/crl")

  if [ "$RAW_OUTPUT" = true ]; then
    echo "$CRL_JSON"
    return
  fi

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

  if [ "$USE_OCSP" = true ]; then
    OCSP_SERIAL_HEX=$(convert_serial "$SERIAL_HEX" "0xhex")
    ocsp_check_certificate "$OCSP_SERIAL_HEX"
  fi

  rm -rf "$TEMP_DIR"
}

convert_serial() {
  local SERIAL=$1
  local FORMAT=$2

  if [[ $SERIAL =~ ^[0-9]+$ ]]; then
    # The number is in decimal
    case $FORMAT in
      "hex") python3 -c "print(hex(int('$SERIAL'))[2:].lower())" ;;
      "HEX") python3 -c "print(hex(int('$SERIAL'))[2:].upper())" ;;
      "0xhex") python3 -c "print('0x' + hex(int('$SERIAL'))[2:].lower())" ;;
      "dec") echo "$SERIAL" ;;
      *) echo "$SERIAL" ;;
    esac
  elif [[ $SERIAL =~ ^0x ]]; then
    # The number is in hex with 0x prefix
    SERIAL=${SERIAL#0x}
    case $FORMAT in
      "hex") echo "$SERIAL" | tr 'A-F' 'a-f' ;;
      "HEX") echo "$SERIAL" | tr 'a-f' 'A-F' ;;
      "0xhex") echo "0x$SERIAL" | tr 'A-F' 'a-f' ;;
      "dec") python3 -c "print(int('$SERIAL', 16))" ;;
      *) echo "$SERIAL" ;;
    esac
  else
    # The number is in hex without a prefix
    case $FORMAT in
      "hex") echo "$SERIAL" | tr 'A-F' 'a-f' ;;
      "HEX") echo "$SERIAL" | tr 'a-f' 'A-F' ;;
      "0xhex") echo "0x$SERIAL" | tr 'A-F' 'a-f' ;;
      "dec") python3 -c "print(int('$SERIAL', 16))" ;;
      *) echo "$SERIAL" ;;
    esac
  fi
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
      -f|--config-json) CONFIG_JSON="$2"; shift 2 ;;
      -i|--interactive) INTERACTIVE=true; shift ;;
      -ocsp|--ocsp) USE_OCSP=true; shift ;;
      --ocsp-server) OCSP_SERVER="$2"; shift 2 ;;
      --ocsp-key) OCSP_API_KEY="$2"; shift 2 ;;
      --no-ocsp) USE_OCSP=false; shift ;;
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

[ -z "$1" ] && show_help

for arg in "$@"; do
  case $arg in
    -ocsp|--ocsp)
      USE_OCSP=true
      ;;
    --ocsp-server=*)
      OCSP_SERVER="${arg#*=}"
      ;;
    --ocsp-key=*)
      OCSP_API_KEY="${arg#*=}"
      ;;
    --no-ocsp)
      USE_OCSP=false
      ;;
    --ocsp-server)
      ;;
    --ocsp-key)
      ;;
  esac
done

ACTION=$1

[ -z "$ACTION" ] && show_help

case "$ACTION" in
  info)
    get_ca_info
    ;;

  generate)
    if [ -z "$2" ]; then
      echo "Error: Domain name required"
      exit 1
    fi
    DOMAIN=$2
    PROFILE=${3:-server}
    parse_generate_options "$DOMAIN" "$PROFILE" "${@:4}"
    generate_certificate
    ;;

  renew-custom)
    if [ -z "$2" ]; then
      echo "Error: Domain name required"
      exit 1
    fi
    DOMAIN=$2
    PROFILE=${3:-server}

    [ -f "${DOMAIN}.crt" ] && {
      echo "Backing up existing certificate and key..."
      timestamp=$(date +%Y%m%d%H%M%S)
      cp "${DOMAIN}.crt" "${DOMAIN}.crt.${timestamp}.bak"
      cp "${DOMAIN}.key" "${DOMAIN}.key.${timestamp}.bak"
    }

    parse_generate_options "$DOMAIN" "$PROFILE" "${@:4}"
    generate_certificate
    ;;

  revoke)
    if [ -z "$2" ] || [ -z "$3" ]; then
      echo "Error: Serial number and Authority Key ID required"
      echo "Usage: $0 revoke serial aki [reason] [-ocsp]"
      echo "Valid reasons: unspecified, keyCompromise, CACompromise, affiliationChanged,"
      echo "               superseded, cessationOfOperation, certificateHold, removeFromCRL"
      exit 1
    fi
    REASON=""
    for arg in "${@:4}"; do
      if [[ ! "$arg" == -* ]]; then
        REASON="$arg"
        break
      fi
    done
    revoke_certificate "$2" "$3" "$REASON"
    ;;

  check)
    if [ -z "$2" ]; then
      echo "Error: Certificate file or serial number required"
      echo "Usage: $0 check certificate.crt | serial [-ocsp]"
      exit 1
    fi
    check_certificate "$2"
    ;;

  check-revocation)
    if [ -z "$2" ]; then
      echo "Error: Serial number required"
      echo "Usage: $0 check-revocation serial_number [-ocsp]"
      exit 1
    fi
    check_revocation "$2"
    ;;

  *)
    echo "Unknown action: $ACTION"
    show_help
    ;;
esac
