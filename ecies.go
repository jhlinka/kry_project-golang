package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"

	"golang.org/x/crypto/hkdf"
)

func eciesClient(conn net.Conn, secret *big.Int, input string) {

	if input == "" {
		input = "random string"
	}

	hash := sha256.New
	//secret := getSharedC(conn, curveType)
	salt := make([]byte, hash().Size())

	hkdf := hkdf.New(hash, secret.Bytes(), salt, nil)

	key := make([]byte, 32)
	keyM := make([]byte, 32)
	io.ReadFull(hkdf, key)
	io.ReadFull(hkdf, keyM)

	fmt.Println(key)
	fmt.Println(keyM)

	c, _ := encrypt(key, input)
	result, _ := decrypt(key, c)

	fmt.Println("c:", c)
	fmt.Println("result:", result)

	hmac := hmac.New(sha256.New, []byte(keyM))
	// Write Data to it
	hmac.Write([]byte(c))
	// Get result and encode as hexadecimal string
	cmac := hmac.Sum(nil)

	sha := hex.EncodeToString(cmac)
	fmt.Println("Result: " + sha)
	fmt.Fprintf(conn, string(c)+","+sha+"\n")
}

func eciesServer(conn net.Conn, secret *big.Int, netData string) {
	hash := sha256.New
	salt := make([]byte, hash().Size())

	hkdf := hkdf.New(hash, secret.Bytes(), salt, nil)

	key := make([]byte, 32)
	keyM := make([]byte, 32)
	io.ReadFull(hkdf, key)
	io.ReadFull(hkdf, keyM)

	message, _ := bufio.NewReader(conn).ReadString('\n')
	data := strings.Split(message, ",")
	c := []byte(data[0])
	cmacC := []byte(data[1])

	hmac := hmac.New(sha256.New, []byte(keyM))
	hmac.Write([]byte(c))
	cmac := hmac.Sum(nil)
	sha := hex.EncodeToString(cmac)
	//fmt.Println("Result: " + sha)

	if sha == string(cmacC[:len(cmacC)-1]) {
		fmt.Println("HMAC Verified")
	}

	m, _ := decrypt(key, string(c))
	fmt.Println(m)
}
