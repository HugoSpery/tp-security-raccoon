#!/bin/sh
set -e

CERT=/app/certs/server.crt
KEY=/app/certs/server.key
DHPARAM=/app/certs/dhparam.pem

# Generate credentials if missing
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
  echo "Generating self-signed certificate..."
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "$KEY" -out "$CERT" -subj "/CN=localhost"
fi

if [ ! -f "$DHPARAM" ]; then
  echo "Generating dhparam (1024 bits for faster demo)..."
  openssl dhparam -out "$DHPARAM" 1024
fi

# Defaults: TLS1.2 + DHE_RSA with DH reuse enabled
export TLS_VERSION=${TLS_VERSION:-1.2}
export KX=${KX:-DHE_RSA}
export HOST=${HOST:-0.0.0.0}
export PORT=${PORT:-443}
export DH_REUSE_KEYS=${DH_REUSE_KEYS:-1}
export DH_FIXED_PRIV=${DH_FIXED_PRIV:-123456789}
export DEBUG=${DEBUG:-1}

# Run the server
exec /app/tls_vuln_server "$HOST" "$PORT" "$CERT" "$KEY" "$DHPARAM" "$TLS_VERSION" "$KX" "$DH_REUSE_KEYS" "$DH_FIXED_PRIV" "$DEBUG"