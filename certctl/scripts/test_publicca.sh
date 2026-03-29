  ./certctl get \
  --provider namecheap \
  --common-name 'test11.uvoo.io' \
  --san test11.uvoo.io \
  --email jeremybusk@gmail.com \
  --key-password 'changeit' \
  --client-ip "$NAMECHEAP_CLIENT_IP" \
  --api-user "$NAMECHEAP_API_USER" \
  --api-key "$NAMECHEAP_API_KEY"
