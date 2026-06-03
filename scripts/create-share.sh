
cert(){
./uvoo-certctl share-cert \
  --domain test3.uvoo.io \
  --mode cert \
  --share-password 'abc123' \
  --expires-in 7d \
  --base-url https://certs.uvoo.io
}

cert_and_key(){
./uvoo-certctl share-cert \
  --domain test3.uvoo.io \
  --mode cert_key \
  --share-password 'abc123' \
  --key-password 'def456' \
  --expires-in 1d \
  --base-url https://certs.uvoo.io
}
cert_and_key
