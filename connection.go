package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

func startClientMode(protocol string, curveType string, input string) {

	conn, err := net.Dial("tcp", ":12345")
	if err != nil {
		fmt.Println(err)
		return
	}

	//reader := bufio.NewReader(os.Stdin)
	//fmt.Print(">> ")
	//text, _ := reader.ReadString('\n')
	switch protocol {
	case "ecdh":
		fmt.Println("\nshared:\t", ecdhClient(conn, curveType, protocol))
	case "ecdsa":
		ecdsaClient(conn, curveType, input)
	case "ecies":
		eciesClient(conn, ecdhClient(conn, curveType, protocol), input)
	default:
		fmt.Println("error: invalid protocol")
		return
	}

	//message, _ := bufio.NewReader(conn).ReadString('\n')
	//fmt.Print("->: " + message)

	/*
		if strings.TrimSpace(string(text)) == "STOP" {
			fmt.Println("TCP client exiting...")
			return
		}*/
}

func startServerMode() {

	ln, err := net.Listen("tcp", ":12345")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer ln.Close()

	conn, err := ln.Accept()
	if err != nil {
		fmt.Println(err)
		return
	}

	//for {
	netData, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Println(err)
		return
	}
	/*
		if strings.TrimSpace(string(netData)) == "STOP" {
			fmt.Println("Exiting TCP server!")
			return
		}
	*/
	//fmt.Print("-> ", string(netData))
	protocol := strings.Split(netData, ",")[0]

	switch protocol {
	case "ecdh":
		fmt.Println("shared:", ecdhServer(conn, netData))
	case "ecdsa":
		ecdsaServer(conn, netData)
	case "ecies":
		eciesServer(conn, ecdhServer(conn, netData), netData)
	default:
		fmt.Print("random")
	}
	//}
}
