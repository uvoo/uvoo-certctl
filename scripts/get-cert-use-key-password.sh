#!/bin/bash
set -eux

./certctl get \
  --domain test6.uvoo.io \
  --san test6.uvoo.io \
  --email $ACME_EMAIL \
  --provider namecheap \
  --api-user $NAMECHEAP_API_USER \
  --api-key $NAMECHEAP_API_KEY \
  --client-ip "$NAMECHEAP_CLIENT_IP" \
  --key-password $KEY_PASSWORD \
  --key-type ec256

# remove --key-password and add below if you just want storage password
#   --storage-password shared-fallback-secret \
#   --key-type rsa2048
