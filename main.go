package main

import (
	"flag"
	"strings"
)

func main() {

	flagMode := flag.String("mode", "client", "start in client or server mode")
	protocol := flag.String("p", "ecdh", "select protocol: ECDH, ECIES, ECDSA")
	curveType := flag.String("c", "p256", "select curve type: P224, P256, P384, P521")
	input := flag.String("i", "", "input for EDSA or ECIES")

	flag.Parse()

	if strings.ToLower(*flagMode) == "server" {
		startServerMode()
	} else {
		startClientMode(strings.ToLower(*protocol), strings.ToLower(*curveType), *input)
	}
}
