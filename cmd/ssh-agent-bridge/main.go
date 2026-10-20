// Command ssh-agent-bridge is the standalone CLI for the bridge library: it
// listens on a Unix socket to act as SSH_AUTH_SOCK, forwarding every
// ssh-agent request to the termux-ssh-agent-app Android app. See the bridge
// package doc comment (../../bridge.go) for how and why.
package main

import (
	"flag"
	"log"
	"os"

	bridge "termux-ssh-agent-bridge"
)

func main() {
	socketPath := flag.String("socket", defaultSocketPath(), "unix socket path to listen on (use as SSH_AUTH_SOCK)")
	keyPath := flag.String("key", defaultKeyPath(), "PEM file with this bridge's X25519 private key (see README.md)")
	flag.Parse()

	privateKey, err := bridge.LoadPrivateKey(*keyPath)
	if err != nil {
		log.Fatalf("load private key: %v", err)
	}

	log.Printf("listening on %s", *socketPath)
	if err := bridge.Serve(*socketPath, privateKey); err != nil {
		log.Fatal(err)
	}
}

func defaultSocketPath() string {
	if prefix := os.Getenv("PREFIX"); prefix != "" {
		return prefix + "/var/run/ssh-agent.sock"
	}
	return "/tmp/ssh-agent.sock"
}

func defaultKeyPath() string {
	if home := os.Getenv("HOME"); home != "" {
		return home + "/.config/termux-ssh-agent/response-key.pem"
	}
	return "response-key.pem"
}
