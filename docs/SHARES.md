./certctl share-cert \
  --domain example.com \
  --mode cert \
  --share-password 'abc123' \
  --expires-in 7d \
  --base-url https://certs.example.com

./certctl share-cert \
  --domain example.com \
  --mode cert \
  --share-password 'abc123' \
  --expires-in 7d \
  --base-url https://certs.example.com

./certctl list-shares --domain example.com

./certctl list-shares --domain example.com
