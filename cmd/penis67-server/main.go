// penis67-server is the reference P67 server: one port, one static key,
// any number of user UUIDs, and a decoy site that swallows every
// unauthorized visitor with a genuine TLS handshake.
//
// Generate a deployment:
//
//	penis67-server -gen -host vps.example.com:443 -uuid <uuid>
//
// Run:
//
//	penis67-server -listen :443 -uuid <uuid>[,<uuid2>] -priv <b64url> -decoy www.bing.com:443
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	p67 "net.meowxd.plugin.penis67/internal/p67"
)

func main() {
	var (
		listen = flag.String("listen", ":443", "listen address")
		uuids  = flag.String("uuid", "", "user UUIDs, comma separated (repeat with commas)")
		priv   = flag.String("priv", "", "base64url X25519 static private key (generate with -gen)")
		decoy  = flag.String("decoy", "www.bing.com:443", "decoy site relayed to unauthorized clients")
		quic   = flag.String("quic", "", "QUIC carrier UDP listen address (e.g. :443); empty = off")
		gen    = flag.Bool("gen", false, "generate keys, print a sample link, exit")
		host   = flag.String("host", "", "sample host:port for the -gen link")
	)
	flag.Parse()

	if *gen {
		generate(*host, *decoy, *uuids)
		return
	}
	if *uuids == "" {
		fmt.Fprintln(os.Stderr, "p67: -uuid is required (see -gen)")
		os.Exit(64)
	}
	var users []p67.UserKey
	for _, raw := range strings.Split(*uuids, ",") {
		user, err := p67.ParseUUID(raw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "p67: bad uuid:", err)
			os.Exit(64)
		}
		users = append(users, user)
	}
	if *priv == "" {
		fmt.Fprintln(os.Stderr, "p67: -priv is required (generate one with -gen and keep it)")
		os.Exit(64)
	}
	staticPriv, err := p67.DecodePrivateKey(*priv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "p67:", err)
		os.Exit(64)
	}

	logLine := func(msg string) { fmt.Println(time.Now().UTC().Format(time.RFC3339), msg) }
	server, err := p67.NewServer(p67.ServerConfig{
		Listen:    *listen,
		Users:     users,
		StaticKey: staticPriv,
		Decoy:     *decoy,
		QuicAddr:  *quic,
		Log:       logLine,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "p67:", err)
		os.Exit(1)
	}
	linkHost, linkPort := *listen, 443
	if head, tail, ok := strings.Cut(*listen, ":"); ok {
		if head != "" {
			linkHost = head
		}
		fmt.Sscanf(tail, "%d", &linkPort)
	}
	link := &p67.Link{
		User:        users[0],
		Host:        linkHost,
		Port:        linkPort,
		Fingerprint: "chrome",
		Hide:        p67.HideSID,
		Net:         p67.NetTCP,
		SNI:         decoyHost(*decoy),
		PBK:         p67.EncodePublicKey(staticPriv.PublicKey()),
		Decoy:       decoyHost(*decoy),
		DecoyPort:   443,
		Pad:         true,
		Name:        "penis67",
	}
	fmt.Println("penis67-server listening on", server.Addr().String(), "decoy", *decoy)
	if addr := server.QUICAddr(); addr != nil {
		fmt.Println("quic carrier on", addr.String())
	}
	fmt.Println("sample link:", link.Build())
	if err := server.Serve(); err != nil {
		fmt.Fprintln(os.Stderr, "p67:", err)
		os.Exit(1)
	}
}

func generate(host, decoy, uuids string) {
	static, err := p67.GenerateStaticKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, "p67:", err)
		os.Exit(1)
	}
	privRaw := static.Bytes()
	fmt.Println("static private key (-priv):", base64.RawURLEncoding.EncodeToString(privRaw))
	fmt.Println("static public  key (pbk=):", p67.EncodePublicKey(static.PublicKey()))
	if uuids == "" {
		fmt.Println("(pass -uuid <uuid> to also print a share link)")
		return
	}
	user, err := p67.ParseUUID(strings.Split(uuids, ",")[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "p67: bad uuid:", err)
		os.Exit(1)
	}
	if host == "" {
		host = "your.server:443"
	}
	hostPart, port := "your.server", 443
	if head, tail, ok := strings.Cut(host, ":"); ok {
		hostPart = head
		fmt.Sscanf(tail, "%d", &port)
	}
	link := &p67.Link{
		User:        user,
		Host:        hostPart,
		Port:        port,
		Fingerprint: "chrome",
		Hide:        p67.HideSID,
		Net:         p67.NetTCP,
		SNI:         decoyHost(decoy),
		PBK:         p67.EncodePublicKey(static.PublicKey()),
		Decoy:       decoyHost(decoy),
		DecoyPort:   443,
		Pad:         true,
		Name:        "penis67",
	}
	fmt.Println("share link:", link.Build())
}

func decoyHost(decoy string) string {
	if head, _, ok := strings.Cut(decoy, ":"); ok {
		return head
	}
	return decoy
}
