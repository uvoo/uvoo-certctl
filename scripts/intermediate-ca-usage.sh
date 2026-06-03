#!/bin/bash
set -eu

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <ROOT_ID>"
    exit 1
fi

ROOT_ID=$1

uvoo-certctl create-intermediate-ca \
  --root-id $ROOT_ID \
  --name corp-ica-1 \
  --common-name "Corp Intermediate CA 1" \
  --key-type ec256 \
  --days 1825 \
  --parent-key-password rootsecret \
  --key-password icasecret

# Or with storage-password fallback:

uvoo-certctl create-intermediate-ca \
  --root-id $ROOT_ID \
  --name corp-ica-1 \
  --common-name "Corp Intermediate CA 1" \
  --storage-password fallbacksecret
