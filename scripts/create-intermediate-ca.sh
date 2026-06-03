if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <ROOT_ID>"
    exit 1
fi

ROOT_ID=$1

echo "Processing Root ID: $ROOT_ID"

uvoo-certctl create-intermediate-ca \
  --root-id $ROOT_ID \
  --name corp-ica-1 \
  --common-name "Corp Intermediate CA 1" \
  --key-type ec256 \
  --days 1825 \
  --key-password ica-secret \
  --parent-key-password root-secret
