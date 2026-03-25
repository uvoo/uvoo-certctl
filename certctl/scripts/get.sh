# ./certctl get \
go run . get \
  --db '/home/busk/certs/certs.db' \
  --provider namecheap \
  --domain 'test5.uvoo.io' \
  --san 'test5.uvoo.io' \
  --email jeremybusk@gmail.com \
  --password 'changeit' \
  --client-ip "$NAMECHEAP_CLIENT_IP" \
  --api-user "$NAMECHEAP_API_USER" \
  --api-key "$NAMECHEAP_API_KEY" 

/home/busk
