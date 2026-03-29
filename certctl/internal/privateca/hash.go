package privateca

import "crypto/sha1"

func sha1Array(b []byte) [20]byte {
	return sha1.Sum(b)
}
