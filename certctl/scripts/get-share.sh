# curl -X POST http://127.0.0.1:8181/share/SHARETOKEN/access \
get_cert(){
curl -X POST http://127.0.0.1:8181/share/nM6g87HJ4Q9i9STfsAh8RohZ7utdCuL6eiq_UCu5i_c/access \
  -H 'Content-Type: application/json' \
  -d '{
    "share_password": "abc123",
    "password": "changeit"
  }' | jq -r ".certificate_pem"
}

get_cert_and_key(){
curl -X POST http://127.0.0.1:8181/share/d43d7926-fb59-4242-b537-bebe7ad46e68/access \
  -H 'Content-Type: application/json' \
  -d '{
    "share_password": "abc123",
    "key_password": "def456",
    "password": "changeit"
  }' 
}
# get_cert
get_cert_and_key
 #  }' | jq -r ".certificate_pem"
