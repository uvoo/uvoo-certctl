./certctl share-cert \
  --kind public \
  --name test13.uvoo.io \
  --mode cert \
  --share-password 'sharepass' \
  --expires-in 7d \
  --base-url https://certs.example.com
exit

./certctl share-cert \
  --kind private \
  --name host1.example.internal \
  --mode cert_key \
  --share-password 'sharepass' \
  --key-password 'leaf-server-secret-please-change' \
  --expires-in 24h \
  --max-views 3 \
  --base-url https://certs.example.com
