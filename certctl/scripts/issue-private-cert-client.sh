if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <ICA_ID>"
    exit 1
fi

ICA_ID=$1

echo "Issueing private client cert from ICA ID: $ICA_ID"

certctl issue-private-cert \
  --intermediate-id $ICA_ID \
  --common-name workstation-123 \
  --cert-type client \
  --days 365 \
  --key-type ed25519 \
  --key-password client-secret \
  --issuer-password ica-secret
