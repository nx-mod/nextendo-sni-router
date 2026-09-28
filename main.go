// sni-router: a minimal TLS SNI passthrough proxy. It peeks the ClientHello on
// :443, reads the SNI hostname, and forwards the raw TLS stream to the right
// backend WITHOUT terminating TLS, so every game's NEX auth server, the account
// hosts and the BCAT/SCSI services can share :443. The backends terminate TLS
// themselves (WSS).
//
// Routes, first match wins (the SNI is matched as a substring):
//
//	g2b309e01  Mario Kart 8 Deluxe        BACKEND_MK8      (NEX, PROXY header)
//	g23380901  Super Smash Bros. Ultimate BACKEND_SSBU     (NEX, PROXY header)
//	g25c08801  ARMS                       BACKEND_ARMS     (NEX, PROXY header)
//	g2ee2e300  Animal Crossing NH         BACKEND_ACNH     (NEX, PROXY header)
//	g21f12900  Super Mario Bros. 35       BACKEND_SMB35    (NEX, PROXY header)
//	g23932a00  Mario Tennis Aces          BACKEND_TENNIS   (NEX, PROXY header)
//	g22306d00  Super Mario Maker 2        BACKEND_SMM2     (NEX, PROXY header)
//	g241c6800  Borderlands GOTY           BACKEND_BL1      (NEX, PROXY header)
//	g2e608000  Torchlight II              BACKEND_TL2      (NEX, PROXY header)
//	g27723500  Advance Wars 1+2           BACKEND_AW       (NEX, PROXY header)
//	acbaa.srv.nintendo.net                BACKEND_ACNH_API (ACNH REST API)
//	ndas.srv / dragons.nintendo.net       baas-proxy if set, else BACKEND_DAUTH
//	baas / penne / vermillion             baas-proxy if set, else BACKEND_BAAS
//	accounts.nintendo.com                 BACKEND_ACCOUNT, else baas-proxy
//	scsi.srv.nintendo.net                 BACKEND_SCSI
//	bcat-*                                BACKEND_BCAT
//	demonware.net                         BACKEND_D3 (PROXY header)
//	other nintendo.com / nintendo.net     baas-proxy if set, else BACKEND_DEFAULT
//	anything else                         BACKEND_DEFAULT ("drop" or empty closes)
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

// route maps an SNI substring to a backend. nex marks the backends that read
// the PROXY header (NEX auth servers correlate the auth and the secure
// connection by source IP; behind a relay they would otherwise see 127.0.0.1
// and refuse with "ticketless CONNECT with no recent auth from this address").
// nx-dauth, baas-proxy and the REST services do not understand it.
type route struct {
	match   string
	name    string
	backend string
	nex     bool
}

func main() {
	listen := envOr("SNI_LISTEN", ":443")
	mk8 := envOr("BACKEND_MK8", "127.0.0.1:8443")
	def := envOr("BACKEND_DEFAULT", mk8)
	proxyProto := envOr("SNI_PROXY_PROTOCOL", "") == "1"
	catchall := os.Getenv("BAASPROXY_CATCHALL") == "1"

	// Accounts: when BACKEND_BAASPROXY is set, every account host goes to
	// baas-proxy, which relays to the real Nextendo keeping the original Host,
	// so a legitimate Nextendo account works with the console pointed at the
	// local stack. baas-proxy terminates its own TLS, so the stream is raw.
	// Without it we fall back to baas-jwks (BACKEND_BAAS), which only serves
	// /1.0.0/certificates and is enough for token signature checks.
	baasproxy := envOr("BACKEND_BAASPROXY", "")
	baas := envOr("BACKEND_BAAS", "127.0.0.1:8453")
	dauth := envOr("BACKEND_DAUTH", "127.0.0.1:8446")
	account := envOr("BACKEND_ACCOUNT", "")
	pick := func(fallback string) string {
		if baasproxy != "" {
			return baasproxy
		}
		return fallback
	}
	if account == "" {
		// accounts.nintendo.com arrives over TLS; the local account service
		// only speaks HTTP, so tls-front terminates TLS in front of it.
		account = pick("127.0.0.1:8455")
	}

	routes := []route{
		{"g2b309e01", "mk8", mk8, true},
		{"g23380901", "ssbu", envOr("BACKEND_SSBU", "127.0.0.1:8445"), true},
		{"g25c08801", "arms", envOr("BACKEND_ARMS", ""), true},
		{"g2ee2e300", "acnh", envOr("BACKEND_ACNH", "127.0.0.1:8447"), true},
		{"g21f12900", "smb35", envOr("BACKEND_SMB35", ""), true},
		{"g23932a00", "tennis", envOr("BACKEND_TENNIS", ""), true},
		{"g22306d00", "smm2", envOr("BACKEND_SMM2", "127.0.0.1:8449"), true},
		{"g241c6800", "bl1", envOr("BACKEND_BL1", "127.0.0.1:8456"), true},
		{"g2e608000", "tl2", envOr("BACKEND_TL2", "127.0.0.1:8458"), true},
		{"g27723500", "aw", envOr("BACKEND_AW", "127.0.0.1:8459"), true},
		{"g2df33d01", "splatoon2", envOr("BACKEND_SPLATOON2", ""), true},
		{"g26cfaf00", "strikers", envOr("BACKEND_STRIKERS", ""), true},
		{"g20de2100", "lm3", envOr("BACKEND_LM3", ""), true},
		{"g2035bb00", "clubhouse", envOr("BACKEND_CLUBHOUSE", ""), true},
		{"g211a3f00", "golf", envOr("BACKEND_GOLF", ""), true},
		{"g28abaa00", "party", envOr("BACKEND_PARTY", ""), true},
		{"g2896bd04", "mhgu", envOr("BACKEND_MHGU", ""), true},
		{"g255ba201", "odyssey", envOr("BACKEND_ODYSSEY", ""), true},
		// NPLN games terminate TLS themselves and read no PROXY header.
		{"npln.srv.nintendo.net", "peacewalker", envOr("BACKEND_PEACEWALKER", ""), false},
		{"gamesync.npln.nintendo.net", "splatoon3-gamesync", envOr("BACKEND_SPLATOON3_GAMESYNC", ""), false},
		{"npln.nintendo.net", "splatoon3", envOr("BACKEND_SPLATOON3", ""), false},
		{"acbaa.srv.nintendo.net", "acnh-api", envOr("BACKEND_ACNH_API", ""), false},
		{"ndas.srv.nintendo.net", "dauth", pick(dauth), false},
		{"dragons.nintendo.net", "dauth", pick(dauth), false},
		{"baas.nintendo.com", "baas", pick(baas), false},
		{"penne.srv.nintendo.net", "baas", pick(baas), false},
		{"vermillion.srv.nintendo.net", "baas", pick(baas), false},
		{"accounts.nintendo.com", "account", account, false},
		{"scsi.srv.nintendo.net", "scsi", envOr("BACKEND_SCSI", "127.0.0.1:8452"), false},
		// The console's connection test (api.hac.lp1.ctest.srv.nintendo.net since 18.0.0): dropped, Test
		// Connection fails. baas-jwks answers it.
		{"ctest.srv.nintendo.net", "ctest", envOr("BACKEND_CTEST", pick(baas)), false},
		// Play and error reports (receive-*.dg / receive-*.er.srv.nintendo.net) go to the telemetry sink, never
		// to Nintendo. Null-routed instead, the console's Test Connection failed (2160-6000).
		{"receive-", "telemetry", envOr("BACKEND_TELEMETRY", "127.0.0.1:8472"), false},
		// Title version list (tagaya.hac.lp1.eshop.nintendo.net): tagaya-nx serves its own TLS.
		{"tagaya.hac", "tagaya", envOr("BACKEND_TAGAYA", "127.0.0.1:8471"), false},
		// bcat-list / bcat-topics / bcat-data on cdn.nintendo.net: the bcat
		// server has its own TLS listener.
		{"bcat-", "bcat", envOr("BACKEND_BCAT", ""), false},
		// The diablo-3 auth reads the PROXY header like the NEX auths
		// (NEXTENDO_PROXY_PROTOCOL=1); it serves the online check.
		{"demonware.net", "d3", envOr("BACKEND_D3", "127.0.0.1:8460"), true},
		// Anything else Nintendo-branded a game hits while going online (nnAccount
		// link, CDN...) must not fall on the default backend and hang there.
		{"nintendo.com", "nintendo", pick(def), false},
		{"nintendo.net", "nintendo", pick(def), false},
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalf("listen %s: %v", listen, err)
	}
	// A route with no backend is off: its hosts fall through to the default
	// (baas-proxy in proxy mode, so a game with no local server still reaches
	// the real Nextendo instead of a wrong local one).
	live := routes[:0]
	for _, r := range routes {
		if r.backend == "" {
			log.Printf("  %-26s %-9s off (no BACKEND_*)", r.match, r.name)
			continue
		}
		live = append(live, r)
	}
	routes = live

	log.Printf("SNI router on %s proxy-protocol=%v catchall=%v default=%s", listen, proxyProto, catchall, def)
	for _, r := range routes {
		log.Printf("  %-26s %-9s -> %s", r.match, r.name, r.backend)
	}

	// The console sometimes omits the SNI (empty connections). With a
	// baas-proxy and catch-all on, send those to it too, to catch the BAAS
	// login/federation calls that carry no SNI.
	noSNI := def
	if catchall && baasproxy != "" {
		noSNI = baasproxy
	}

	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(c, routes, def, noSNI, proxyProto)
	}
}

func handle(c net.Conn, routes []route, def, noSNI string, proxyProto bool) {
	defer c.Close()

	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	hello, sni, err := peekClientHello(c)
	_ = c.SetReadDeadline(time.Time{})

	backend := def
	wantProxy := false
	if err == nil {
		for _, r := range routes {
			if strings.Contains(sni, r.match) {
				backend, wantProxy = r.backend, r.nex && proxyProto
				break
			}
		}
	}
	if sni == "" {
		backend = noSNI
	}

	// A host with no route used to land on the MK8 auth server, which cannot
	// answer it and refused. BACKEND_DEFAULT=drop (or empty) closes instead.
	if backend == "" || backend == "drop" {
		log.Printf("conn from %s sni=%q -> drop (no route)", c.RemoteAddr(), sni)
		return
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
	// SNI_TRACE=<host part>: log each TLS record header both ways for matching connections (and plaintext
	// alerts in full), to see where a client's handshake stops without decrypting anything.
	if t := os.Getenv("SNI_TRACE"); t != "" && strings.Contains(sni, t) {
		id := c.RemoteAddr().String()
		go func() { _, _ = io.Copy(up, io.TeeReader(c, &recordTrace{tag: id + " c->s"})) }()
		_, _ = io.Copy(c, io.TeeReader(up, &recordTrace{tag: id + " s->c"}))
		log.Printf("trace %s: closed", id)
		return
	}
	go func() { _, _ = io.Copy(up, c) }()
	_, _ = io.Copy(c, up)
}

// recordTrace parses a TLS record stream as it passes and logs the first records' headers.
type recordTrace struct {
	tag  string
	buf  []byte
	seen int
}

func (t *recordTrace) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	for len(t.buf) >= 5 && t.seen < 40 {
		n := int(t.buf[3])<<8 | int(t.buf[4])
		if len(t.buf) < 5+n {
			break
		}
		typ := t.buf[0]
		detail := ""
		switch {
		case typ == 21 && n == 2:
			detail = fmt.Sprintf(" ALERT level=%d desc=%d", t.buf[5], t.buf[6])
		case typ == 22 && n > 0:
			detail = fmt.Sprintf(" handshake msg=%d", t.buf[5])
		}
		log.Printf("trace %s: record type=%d ver=%02x%02x len=%d%s", t.tag, typ, t.buf[1], t.buf[2], n, detail)
		t.buf = t.buf[5+n:]
		t.seen++
	}
	if t.seen >= 40 {
		t.buf = nil
	}
	return len(p), nil
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
