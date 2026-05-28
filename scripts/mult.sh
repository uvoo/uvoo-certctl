# ./certctl get \
go run . get \
  --db './tmp/certs.db' \
  --provider namecheap \
  --domain 'uvoo.io' \
  --san test3.uvoo.io \
  --san test4.uvoo.io \
  --email jeremybusk@gmail.com \
  --password 'changeit' \
  --client-ip "$NAMECHEAP_CLIENT_IP" \
  --api-user "$NAMECHEAP_API_USER" \
  --api-key "$NAMECHEAP_API_KEY" 

  # --db '/home/busk/certs/certs.db' \
