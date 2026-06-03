#!/bin/bash
 set -eu


uvoo-certctl create-root-ca \
  --name corp-root-1 \
  --common-name "Corp Root CA 1" \
  --key-type ec256 \
  --days 3650 \
  --key-password root-secret

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <ROOT_ID>"
    exit 1
fi

ROOT_ID=$1

echo "Processing Root ID: $ROOT_ID"

uvoo-certctl create-intermediate-ca \
  --root-id <root-id> \
  --name corp-ica-1 \
  --common-name "Corp Intermediate CA 1" \
  --key-type ec256 \
  --days 1825 \
  --key-password ica-secret \
  --parent-password root-secret

uvoo-certctl issue-private-cert \
  --intermediate-id <ica-id> \
  --common-name host1.example.internal \
  --san host1.example.internal,host1 \
  --cert-type server \
  --days 825 \
  --key-type ec256 \
  --key-password leaf-secret \
  --issuer-password ica-secret

uvoo-certctl issue-private-cert \
  --intermediate-id <ica-id> \
  --common-name workstation-123 \
  --cert-type client \
  --days 365 \
  --key-type ed25519 \
  --key-password client-secret \
  --issuer-password ica-secret
