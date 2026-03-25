go run . create-record \
  --provider namecheap \
  --domain uvoo.io \
  --name xxtest1 \
  --type CNAME \
  --value fip2.uvoo.io \
  --ttl 60 \
  --client-ip "$NAMECHEAP_CLIENT_IP" \
  --api-user "$NAMECHEAP_API_USER" \
  --api-key "$NAMECHEAP_API_KEY" 

