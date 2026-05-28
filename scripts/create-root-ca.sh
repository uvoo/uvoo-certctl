#!/bin/bash
 set -eu

uvoocertctl create-root-ca \
  --name corp-root-1 \
  --common-name "Corp Root CA 1" \
  --key-type ec256 \
  --days 3650 \
  --key-password root-secret
