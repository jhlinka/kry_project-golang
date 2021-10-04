package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"net"
	"strings"
)

func ecdsaClient(conn net.Conn, curveType, input string) {
	privKey := generateKey(curveType)
	pubKey := privKey.PublicKey

	if input == "" {
		input = "random string"
	}

	h := sha256.New()
	h.Write([]byte(input))
	hash := h.Sum(nil)

	r, s, _ := ecdsa.Sign(rand.Reader, privKey, hash)

	fmt.Fprintf(conn, "ecdsa,"+curveType+","+pubKey.X.String()+","+pubKey.Y.String()+","+r.String()+","+s.String()+","+string(hash)+"\n")

	fmt.Println("Public key: \nx:\t", pubKey.X.String(), "\ny:\t", pubKey.Y.String())
	fmt.Printf("\nHash:\t %x", hash)
	fmt.Println("\nr:\t", r.String())
	fmt.Println("s:\t", s.String())

	verify := ecdsa.Verify(&pubKey, hash, r, s)
	fmt.Println("\nVerified:", verify)

	//conn.Write([]byte("STOP"))
}

func ecdsaServer(conn net.Conn, netData string) {
	var pubKey ecdsa.PublicKey

	data := strings.Split(netData, ",")
	curveType := data[1]

	tmp := new(big.Int)

	tmp.SetString(data[2], 10)
	pubKey.X = tmp
	tmp = new(big.Int)
	tmp.SetString(data[3], 10)
	pubKey.Y = tmp
	tmp = new(big.Int)
	tmp.SetString(data[4], 10)
	r := tmp
	tmp = new(big.Int)
	tmp.SetString(data[5], 10)
	s := tmp
	signHash := []byte(data[6])

	switch curveType {
	case "p224":
		pubKey.Curve = elliptic.P224()
	case "p256":
		pubKey.Curve = elliptic.P256()
	case "p384":
		pubKey.Curve = elliptic.P384()
	case "p521":
		pubKey.Curve = elliptic.P521()
	}

	fmt.Println("Public key: \nx:\t", pubKey.X.String(), "\ny:\t", pubKey.Y.String())
	fmt.Printf("\nHash:\t %x", signHash[:len(signHash)-1])
	fmt.Println("\nr:\t", r.String())
	fmt.Println("s:\t", s)
	verify := ecdsa.Verify(&pubKey, signHash[:len(signHash)-1], r, s)
	fmt.Println("\nVerified:", verify)
}
