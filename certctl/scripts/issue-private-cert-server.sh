if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <ICA_ID>"
    exit 1
fi

ICA_ID=$1

echo "Issueing private server cert from ICA ID: $ICA_ID"

certctl issue-private-cert \
  --intermediate-id $ICA_ID \
  --common-name host1.example.internal \
  --san host1.example.internal,host1 \
  --cert-type server \
  --days 825 \
  --key-type ec256 \
  --key-password leaf-secret \
  --issuer-password ica-secret
