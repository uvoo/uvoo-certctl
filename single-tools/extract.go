package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"uvoo-certctl/internal/cli"
	_ "modernc.org/sqlite"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatalf("usage: %s <db> <domain> <password>", os.Args[0])
	}

	dbPath := os.Args[1]
	domain := os.Args[2]
	password := os.Args[3]

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var certEnc, keyEnc []byte
	err = db.QueryRow(`SELECT cert, privkey FROM certs WHERE domain = ?`, domain).Scan(&certEnc, &keyEnc)
	if err != nil {
		log.Fatal(err)
	}

	cert, err := cli.Decrypt(certEnc, password)
	if err != nil {
		log.Fatal(err)
	}
	key, err := cli.Decrypt(keyEnc, password)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("----- CERT -----\n%s\n", cert)
	fmt.Printf("----- KEY -----\n%s\n", key)
}
