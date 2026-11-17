// Disposable VM test peer. Credentials created by setup belong only to this
// isolated stand; they are never used as production keys or trust roots.
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type receipt struct {
	Kind   string `json:"kind"`
	Stage  string `json:"stage"`
	Nonce  string `json:"nonce"`
	Hash   string `json:"sha256"`
	Bytes  int    `json:"bytes"`
	Peer   string `json:"peer,omitempty"`
	Result string `json:"result"`
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
func write(path string, value any) {
	data, err := json.MarshalIndent(value, "", "  ")
	check(err)
	check(os.WriteFile(path, append(data, '\n'), 0600))
}

func setup(root string) {
	check(os.Mkdir(root, 0700))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(err)
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vm.test"},
		DNSNames: []string{"vm.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(7 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	check(err)
	encoded, err := x509.MarshalECPrivateKey(key)
	check(err)
	check(os.WriteFile(filepath.Join(root, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	check(os.WriteFile(filepath.Join(root, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded}), 0600))
	reality, err := ecdh.X25519().GenerateKey(rand.Reader)
	check(err)
	private := base64.RawURLEncoding.EncodeToString(reality.Bytes())
	public := base64.RawURLEncoding.EncodeToString(reality.PublicKey().Bytes())
	write(filepath.Join(root, "server.json"), map[string]any{
		"log": map[string]any{"loglevel": "warning", "access": "/tmp/xray-access.log"},
		"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": 29600, "protocol": "vless",
			"settings": map[string]any{"clients": []any{map[string]any{"id": "00000000-0000-4000-8000-000000000001", "flow": "xtls-rprx-vision", "email": "vm-test"}}, "decryption": "none"},
			"streamSettings": map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{
				"target": "127.0.0.1:29622", "serverNames": []string{"vm.test"}, "privateKey": private, "shortIds": []string{"0123abcd"},
				"minClientVer": "26.10.31", "maxClientVer": "26.10.31"}}}},
		"outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{
			map[string]any{"action": "allow", "ip": []string{"198.51.100.9/32"}}}}}},
	})
	write(filepath.Join(root, "reference.json"), map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{
			map[string]any{"listen": "127.0.0.1", "port": 29900, "protocol": "dokodemo-door", "settings": map[string]any{"address": "198.51.100.9", "port": 80, "network": "tcp"}},
			map[string]any{"listen": "127.0.0.1", "port": 29901, "protocol": "dokodemo-door", "settings": map[string]any{"address": "198.51.100.9", "port": 443, "network": "tcp"}},
			map[string]any{"listen": "127.0.0.1", "port": 29902, "protocol": "dokodemo-door", "settings": map[string]any{"address": "198.51.100.9", "port": 443, "network": "udp"}},
		},
		"outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{
			"address": "127.0.0.1", "port": 29600, "users": []any{map[string]any{"id": "00000000-0000-4000-8000-000000000001", "encryption": "none", "flow": "xtls-rprx-vision-udp443"}},
		}}}, "streamSettings": map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{
			"serverName": "vm.test", "password": public, "shortId": "0123abcd", "fingerprint": "firefox",
		}}}},
	})
	config := "config lite-client 'main'\n\toption enabled '1'\n\toption plane 'reality'\n\toption node '127.0.0.1'\n\toption port '29600'\n\toption sni 'vm.test'\n\toption public_key '" + public + "'\n\toption short_id '0123abcd'\n\toption listen_port '19099'\n\toption udp_port '19098'\n\toption flow 'xtls-rprx-vision-udp443'\n\toption clients '192.0.2.7'\n\toption workers '1'\n"
	check(os.WriteFile(filepath.Join(root, "client.uci"), []byte(config), 0600))
	check(os.WriteFile(filepath.Join(root, "uuid"), []byte("00000000-0000-4000-8000-000000000001\n"), 0600))
}

func serve(root string, cover bool) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(root, "cert.pem"), filepath.Join(root, "key.pem"))
	check(err)
	if cover {
		server := &http.Server{Addr: "127.0.0.1:29622", TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}},
			ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("fixture\n")) })}
		listener, err := net.Listen("tcp", server.Addr)
		check(err)
		fmt.Println("LC_COVER_READY")
		check(server.ServeTLS(listener, "", ""))
		return
	}
	file, err := os.OpenFile("/tmp/backend.jsonl", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	check(err)
	var lock sync.Mutex
	journal := func(row receipt) { lock.Lock(); defer lock.Unlock(); check(json.NewEncoder(file).Encode(row)) }
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		data, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		if err != nil {
			http.Error(w, "read", 400)
			return
		}
		kind := "tcp"
		if r.TLS != nil {
			kind = "tls"
		}
		peer, _, err := net.SplitHostPort(r.RemoteAddr)
		check(err)
		journal(receipt{Kind: kind, Stage: r.Header.Get("X-LC-Stage"), Nonce: r.Header.Get("X-LC-Nonce"), Hash: fmt.Sprintf("%x", sha256.Sum256(data)), Bytes: len(data), Peer: peer, Result: "echo"})
		w.Header().Set("Connection", "close")
		_, _ = w.Write(data)
	})
	udp, err := net.ListenPacket("udp", "198.51.100.9:443")
	check(err)
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, peer, err := udp.ReadFrom(buffer)
			check(err)
			data := append([]byte(nil), buffer[:n]...)
			if len(data) < 32 {
				panic("short UDP fixture")
			}
			ip, _, err := net.SplitHostPort(peer.String())
			check(err)
			journal(receipt{Kind: "udp", Nonce: hex.EncodeToString(data[:32]), Hash: fmt.Sprintf("%x", sha256.Sum256(data)), Bytes: n, Peer: ip, Result: "echo"})
			_, err = udp.WriteTo(data, peer)
			check(err)
		}
	}()
	httpListener, err := net.Listen("tcp", "198.51.100.9:80")
	check(err)
	tlsListener, err := net.Listen("tcp", "198.51.100.9:443")
	check(err)
	go func() { check(http.Serve(httpListener, handler)) }()
	server := &http.Server{Addr: "198.51.100.9:443", Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}}
	fmt.Println("LC_BACKEND_READY")
	check(server.ServeTLS(tlsListener, "", ""))
}

func probe(root, stage string, blocked, reference bool) {
	cert, err := os.ReadFile(filepath.Join(root, "cert.pem"))
	check(err)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cert) {
		panic("fixture certificate")
	}
	deadline := 10 * time.Second
	if blocked {
		deadline = 500 * time.Millisecond
	}
	client := &http.Client{Timeout: deadline, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "vm.test", MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}}}
	for _, kind := range []string{"tcp", "tls", "udp"} {
		data := make([]byte, 64<<10)
		if kind == "udp" {
			data = make([]byte, 1024)
		}
		_, err = rand.Read(data)
		check(err)
		nonce := hex.EncodeToString(data[:32])
		var reply []byte
		if kind == "udp" {
			address := "198.51.100.9:443"
			if reference {
				address = "127.0.0.1:29902"
			}
			connection, dialErr := net.DialTimeout("udp", address, deadline)
			err = dialErr
			if err == nil {
				check(connection.SetDeadline(time.Now().Add(deadline)))
				_, err = connection.Write(data)
				if err == nil {
					buffer := make([]byte, 2048)
					var n int
					n, err = connection.Read(buffer)
					reply = buffer[:n]
				}
				check(connection.Close())
			}
		} else {
			address := "http://198.51.100.9:80/echo"
			if kind == "tls" {
				address = "https://198.51.100.9:443/echo"
			}
			if reference {
				address = "http://127.0.0.1:29900/echo"
				if kind == "tls" {
					address = "https://127.0.0.1:29901/echo"
				}
			}
			request, requestErr := http.NewRequest("POST", address, bytes.NewReader(data))
			check(requestErr)
			request.Header.Set("X-LC-Nonce", nonce)
			request.Header.Set("X-LC-Stage", stage)
			var response *http.Response
			response, err = client.Do(request)
			if err == nil {
				reply, err = io.ReadAll(io.LimitReader(response.Body, 2<<20))
				check(response.Body.Close())
				if response.StatusCode != 200 {
					panic("HTTP status")
				}
			}
		}
		row := receipt{Kind: kind, Stage: stage, Nonce: nonce, Hash: fmt.Sprintf("%x", sha256.Sum256(data)), Bytes: len(data)}
		if blocked {
			if err == nil {
				panic("bypass: stopped tunnel still delivered traffic")
			}
			row.Result = "blocked"
		} else {
			check(err)
			if !bytes.Equal(reply, data) {
				panic("corrupt echo")
			}
			row.Result = "echo"
		}
		check(json.NewEncoder(os.Stdout).Encode(row))
	}
}

func main() {
	if len(os.Args) < 3 {
		panic("expected mode and fixture directory")
	}
	switch os.Args[1] {
	case "occupy":
		listener, err := net.Listen("tcp", "[::]:19099")
		check(err)
		defer listener.Close()
		packet, err := net.ListenPacket("udp", "[::]:19098")
		check(err)
		defer packet.Close()
		fmt.Println("LC_OCCUPY_READY")
		for {
			time.Sleep(time.Hour)
		}
	case "setup":
		setup(os.Args[2])
	case "cover":
		serve(os.Args[2], true)
	case "serve":
		serve(os.Args[2], false)
	case "probe", "blocked", "reference":
		if len(os.Args) != 4 {
			panic("expected stage")
		}
		probe(os.Args[2], os.Args[3], os.Args[1] == "blocked", os.Args[1] == "reference")
	default:
		panic("unknown mode")
	}
}
