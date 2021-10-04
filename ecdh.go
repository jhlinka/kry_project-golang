package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strings"
)

func generateKey(curveType string) (keyPair *ecdsa.PrivateKey) {
	switch curveType {
	case "p224":
		keyPair, _ = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "p256":
		keyPair, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "p384":
		keyPair, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "p521":
		keyPair, _ = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	}
	return keyPair
}

func getSharedSecret(privKey ecdsa.PrivateKey, pubKey ecdsa.PublicKey) *big.Int {
	shared, _ := pubKey.Curve.ScalarMult(pubKey.X, pubKey.Y, privKey.D.Bytes())
	return shared
}

func ecdhClient(conn net.Conn, curveType string, protocol string) *big.Int {
	var pubS ecdsa.PublicKey
	tmp := new(big.Int)

	switch curveType {
	case "p224":
		pubS.Curve = elliptic.P224()
	case "p256":
		pubS.Curve = elliptic.P256()
	case "p384":
		pubS.Curve = elliptic.P384()
	case "p521":
		pubS.Curve = elliptic.P521()
	}

	privC := generateKey(curveType)
	pubC := privC.PublicKey

	if protocol == "ecdh" {
		fmt.Println("Private key: \n\t", privC.D.String())
		fmt.Println("Public key: \nx:\t", privC.PublicKey.X.String(), "\ny:\t", privC.PublicKey.Y.String())
	}

	fmt.Fprintf(conn, protocol+","+curveType+","+pubC.X.String()+","+pubC.Y.String()+"\n")
	message, _ := bufio.NewReader(conn).ReadString('\n')

	if message != "" {
		data := strings.Split(message, ",")

		tmp.SetString(data[0], 10)
		pubS.X = tmp
		tmp = new(big.Int)
		tmp.SetString(data[1], 10)
		pubS.Y = tmp

		shared := getSharedSecret(*privC, pubS)
		return shared
	}
	return nil
}

func ecdhServer(conn net.Conn, netData string) *big.Int {
	var pubC ecdsa.PublicKey

	data := strings.Split(netData, ",")
	curveType := data[1]

	tmp := new(big.Int)

	tmp.SetString(data[2], 10)
	pubC.X = tmp
	tmp = new(big.Int)
	tmp.SetString(data[3], 10)
	pubC.Y = tmp

	switch curveType {
	case "p224":
		pubC.Curve = elliptic.P224()
	case "p256":
		pubC.Curve = elliptic.P256()
	case "p384":
		pubC.Curve = elliptic.P384()
	case "p521":
		pubC.Curve = elliptic.P521()
	}

	privS := generateKey(curveType)

	if data[0] == "ecdh" {
		fmt.Println("Private key: \n\t", privS.D.String())
		fmt.Println("Public key: \nx:\t", privS.PublicKey.X.String(), "\ny:\t", privS.PublicKey.Y.String())
	}

	shared := getSharedSecret(*privS, pubC)
	fmt.Fprintf(conn, privS.PublicKey.X.String()+","+privS.PublicKey.Y.String()+"\n")
	return shared
}

/*
func getSharedC(conn net.Conn, curveType string) *big.Int {
	var pubS ecdsa.PublicKey
	tmp := new(big.Int)

	switch curveType {
	case "p224":
		pubS.Curve = elliptic.P224()
	case "p256":
		pubS.Curve = elliptic.P256()
	case "p384":
		pubS.Curve = elliptic.P384()
	case "p521":
		pubS.Curve = elliptic.P521()
	}

	privC := generateKey(curveType)
	pubC := privC.PublicKey

	fmt.Fprintf(conn, "ecies,"+curveType+","+pubC.X.String()+","+pubC.Y.String()+"\n")
	message, _ := bufio.NewReader(conn).ReadString('\n')

	if message != "" {
		data := strings.Split(message, ",")

		tmp.SetString(data[0], 10)
		pubS.X = tmp
		tmp = new(big.Int)
		tmp.SetString(data[1], 10)
		pubS.Y = tmp

		shared := generateSharedSecret(*privC, pubS)
		return shared
	}
	return nil
}

func getSharedS(conn net.Conn, netData string) *big.Int {
	var pubC ecdsa.PublicKey

	data := strings.Split(netData, ",")
	curveType := data[1]

	tmp := new(big.Int)

	tmp.SetString(data[2], 10)
	pubC.X = tmp
	tmp = new(big.Int)
	tmp.SetString(data[3], 10)
	pubC.Y = tmp

	switch curveType {
	case "p224":
		pubC.Curve = elliptic.P224()
	case "p256":
		pubC.Curve = elliptic.P256()
	case "p384":
		pubC.Curve = elliptic.P384()
	case "p521":
		pubC.Curve = elliptic.P521()
	}

	privS := generateKey(curveType)
	shared := generateSharedSecret(*privS, pubC)
	fmt.Fprintf(conn, privS.PublicKey.X.String()+","+privS.PublicKey.Y.String()+"\n")

	return shared
}
*/
