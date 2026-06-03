./uvoo-certctl check-precursors \
  --provider namecheap \
  --domain 'jj3test.uvoo.io' \
  --api-user "$NAMECHEAP_API_USER" \
  --api-key "$NAMECHEAP_API_KEY" \
  --client-ip "$NAMECHEAP_CLIENT_IP" \
  --write-test
  # --domain '*.example.com' \
