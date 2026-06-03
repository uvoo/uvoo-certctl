#!/bin/bash
set -eux

./uvoo-certctl get \
  --common-name "$FQDN" \
  --sans "$FQDN" \
  --provider namecheap \
  --email "$ACME_EMAIL" \
  --storage-password "$STORAGE_PASSWORD" \
  --api-user "$NAMECHEAP_API_USER" \
  --api-key "$NAMECHEAP_API_KEY" \
  --client-ip "$NAMECHEAP_CLIENT_IP" \
  --dns-resolver 8.8.8.8
