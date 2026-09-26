// sni-router: a minimal TLS SNI passthrough proxy. It peeks the ClientHello on
// :443, reads the SNI hostname, and forwards the raw TLS stream to the right
// backend (MK8 auth vs SSBU auth) WITHOUT terminating TLS — so both games' NEX
// auth servers can share :443. The backends terminate TLS themselves (WSS).
//
//	g2b309e01-...srv.nintendo.net  -> MK8 auth   (BACKEND_MK8)
//	g23380901-...srv.nintendo.net  -> SSBU auth  (BACKEND_SSBU)
//	g25c08801-...srv.nintendo.net  -> ARMS auth  (BACKEND_ARMS)
//	g2ee2e300-...srv.nintendo.net  -> ACNH auth  (BACKEND_ACNH)
//	g21f12900-...srv.nintendo.net  -> SMB35 auth (BACKEND_SMB35)
//	g23932a00-...srv.nintendo.net  -> Mario Tennis Aces auth (BACKEND_TENNIS)
//	g22306d00-...srv.nintendo.net  -> Super Mario Maker 2 auth (BACKEND_SMM2)
//	*.acbaa.srv.nintendo.net       -> ACNH REST companion API (BACKEND_ACNH_API)
//	*.ndas.srv.nintendo.net        -> nx-dauth   (BACKEND_DAUTH)
//	*.dragons.nintendo.net         -> nx-dauth   (BACKEND_DAUTH)
//	*.demonware.net                -> Diablo III auth, diablo-3 (BACKEND_D3)
//	anything else                  -> BACKEND_DEFAULT (MK8 by default)
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	listen := envOr("SNI_LISTEN", ":443")
	mk8 := envOr("BACKEND_MK8", "127.0.0.1:8443")
	ssbu := envOr("BACKEND_SSBU", "127.0.0.1:8444")
	arms := envOr("BACKEND_ARMS", "127.0.0.1:8445")
	acnh := envOr("BACKEND_ACNH", "127.0.0.1:8447")
	acnhAPI := envOr("BACKEND_ACNH_API", "127.0.0.1:8448")
	smb35 := envOr("BACKEND_SMB35", "127.0.0.1:8449")
	tennis := envOr("BACKEND_TENNIS", "127.0.0.1:8450")
	smm2 := envOr("BACKEND_SMM2", "127.0.0.1:8451")
	dauth := envOr("BACKEND_DAUTH", "127.0.0.1:8446")
	// Diablo III parle Demonware, pas NEX : son auth HTTPS
	// (crimson-switch-auth3.*.demonware.net) va au serveur diablo-3. Le lobby
	// (TCP/UDP 3074) ne passe pas par ici.
	d3 := envOr("BACKEND_D3", "127.0.0.1:8460")
	// Comptes : quand BACKEND_BAASPROXY est renseigné, tout le trafic
	// accounts.nintendo.com / *.baas.nintendo.com / penne / vermillion part vers
	// baas-proxy, qui relaie vers le vrai Nextendo (51.178.29.194) en gardant le
	// Host d'origine -> on peut utiliser un compte Nextendo légitime avec la
	// console pointée sur le stack local. Sinon on retombe sur BACKEND_BAAS
	// (baas-jwks local) pour la vérification de la signature des tokens.
	baas := envOr("BACKEND_BAAS", "127.0.0.1:8453")
	baasproxy := envOr("BACKEND_BAASPROXY", "")
	catchall := os.Getenv("BAASPROXY_CATCHALL") == "1"
	def := envOr("BACKEND_DEFAULT", mk8)
	proxyProto := envOr("SNI_PROXY_PROTOCOL", "") == "1"

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalf("listen %s: %v", listen, err)
	}
	log.Printf("SNI router on %s -> mk8=%s ssbu=%s arms=%s acnh=%s acnhAPI=%s smb35=%s tennis=%s smm2=%s dauth=%s d3=%s baas=%s baasproxy=%s catchall=%v default=%s", listen, mk8, ssbu, arms, acnh, acnhAPI, smb35, tennis, smm2, dauth, d3, baas, baasproxy, catchall, def)

	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(c, mk8, ssbu, arms, acnh, acnhAPI, smb35, tennis, smm2, dauth, d3, baas, baasproxy, catchall, def, proxyProto)
	}
}

func handle(c net.Conn, mk8, ssbu, arms, acnh, acnhAPI, smb35, tennis, smm2, dauth, d3, baas, baasproxy string, catchall bool, def string, proxyProto bool) {
	defer c.Close()

	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	hello, sni, err := peekClientHello(c)
	_ = c.SetReadDeadline(time.Time{})

	backend := def
	// Les serveurs d'auth NEX corrèlent l'auth et la connexion secure par IP
	// source. Nous étant un relais, ils voient la nôtre (127.0.0.1) alors que la
	// secure arrive en direct depuis la console : « ticketless CONNECT with no
	// recent auth from this address ». On préfixe donc l'en-tête PROXY pour leur
	// donner la vraie adresse (ils écoutent en ListenSecureProxy). Réservé aux
	// backends NEX : nx-dauth et l'upstream ne comprennent pas cet en-tête.
	wantProxy := false
	if err == nil {
		switch {
		case strings.Contains(sni, "g2b309e01"):
			backend, wantProxy = mk8, proxyProto
		case strings.Contains(sni, "g23380901"):
			backend, wantProxy = ssbu, proxyProto
		case strings.Contains(sni, "g25c08801"):
			backend, wantProxy = arms, proxyProto
		case strings.Contains(sni, "g2ee2e300"):
			backend, wantProxy = acnh, proxyProto
		case strings.Contains(sni, "g21f12900"):
			backend, wantProxy = smb35, proxyProto
		case strings.Contains(sni, "g23932a00"):
			backend, wantProxy = tennis, proxyProto
		case strings.Contains(sni, "g22306d00"):
			backend, wantProxy = smm2, proxyProto
		case strings.Contains(sni, "acbaa.srv.nintendo.net"):
			// REST companion API, not NEX: no PROXY header.
			backend = acnhAPI
		case strings.Contains(sni, "ndas.srv.nintendo.net"), strings.Contains(sni, "dragons.nintendo.net"):
			if baasproxy != "" {
				backend = baasproxy
			} else {
				backend = dauth
			}
		case strings.Contains(sni, "baas.nintendo.com"), strings.Contains(sni, "penne.srv.nintendo.net"), strings.Contains(sni, "vermillion.srv.nintendo.net"):
			if baasproxy != "" {
				backend = baasproxy
			} else {
				backend = baas
			}
		case strings.Contains(sni, "nintendo.com"), strings.Contains(sni, "nintendo.net"), strings.Contains(sni, "cdn.nintendo.net"):
			// accounts.nintendo.com (nnAccount link), bcat-topics-list / bcat-list
			// CDN, etc. — anything else Nintendo-branded that a game hits while
			// going online. Route to baas-proxy so these don't fall into the dead
			// default backend (MK8) and hang the connection.
			if baasproxy != "" {
				backend = baasproxy
			} else {
				backend = def
			}
		case strings.Contains(sni, "demonware.net"):
			// L'auth diablo-3 lit l'en-tete PROXY comme les auth NEX
			// (NEXTENDO_PROXY_PROTOCOL=1) : il sert a l'online-check.
			backend, wantProxy = d3, proxyProto
		}
	}
	// La console omet parfois le SNI (connexions vides). Si un baas-proxy est
	// configuré avec catch-all actif, on lui envoie quand même ces appels pour
	// capter les connexions BAAS login/federation sans SNI.
	if sni == "" && baasproxy != "" && catchall {
		backend = baasproxy
	}
	log.Printf("conn from %s sni=%q -> %s", c.RemoteAddr(), sni, backend)

	up, err := net.Dial("tcp", backend)
	if err != nil {
		log.Printf("dial %s: %v", backend, err)
		return
	}
	defer up.Close()

	if wantProxy {
		if err := writeProxyHeader(up, c); err != nil {
			return
		}
	}
	if _, err := up.Write(hello); err != nil { // replay the buffered ClientHello
		return
	}
	go func() { _, _ = io.Copy(up, c) }()
	_, _ = io.Copy(c, up)
}

// peekClientHello reads the first TLS record (the ClientHello), returns the raw
// bytes (to replay to the backend) and the parsed SNI host.
func peekClientHello(c net.Conn) ([]byte, string, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return hdr, "", err
	}
	if hdr[0] != 0x16 { // not a TLS handshake record
		return hdr, "", errors.New("not a TLS handshake")
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	body := make([]byte, recLen)
	if _, err := io.ReadFull(c, body); err != nil {
		return append(hdr, body...), "", err
	}
	full := append(append([]byte{}, hdr...), body...)
	return full, parseSNI(body), nil
}

// parseSNI extracts the server_name from a TLS ClientHello handshake message.
func parseSNI(b []byte) string {
	// b[0]=HandshakeType(1=ClientHello), b[1:4]=len, b[4:6]=version, b[6:38]=random
	if len(b) < 38 || b[0] != 0x01 {
		return ""
	}
	p := 38
	if p >= len(b) {
		return ""
	}
	sidLen := int(b[p])
	p += 1 + sidLen
	if p+2 > len(b) {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(b[p:]))
	p += 2 + csLen
	if p+1 > len(b) {
		return ""
	}
	compLen := int(b[p])
	p += 1 + compLen
	if p+2 > len(b) {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	end := p + extLen
	for p+4 <= end && p+4 <= len(b) {
		etype := binary.BigEndian.Uint16(b[p:])
		elen := int(binary.BigEndian.Uint16(b[p+2:]))
		p += 4
		if etype == 0x0000 { // server_name
			if p+5 <= len(b) {
				nameLen := int(binary.BigEndian.Uint16(b[p+3:]))
				if p+5+nameLen <= len(b) {
					return string(b[p+5 : p+5+nameLen])
				}
			}
		}
		p += elen
	}
	return ""
}

// writeProxyHeader émet l'en-tête PROXY v1 attendu par ListenSecureProxy :
// "PROXY TCP4 <ip client> <ip locale> <port client> <port local>\r\n".
func writeProxyHeader(up, c net.Conn) error {
	src, ok1 := c.RemoteAddr().(*net.TCPAddr)
	dst, ok2 := c.LocalAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		return nil
	}
	fam := "TCP4"
	if src.IP.To4() == nil {
		fam = "TCP6"
	}
	_, err := fmt.Fprintf(up, "PROXY %s %s %s %d %d\r\n", fam, src.IP.String(), dst.IP.String(), src.Port, dst.Port)
	return err
}
