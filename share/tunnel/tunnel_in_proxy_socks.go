package tunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/jpillora/chisel/share/cio"
	"golang.org/x/crypto/ssh"
)

// SOCKS5 protocol constants per RFC 1928
const (
	socks5Ver = 0x05

	// Authentication methods
	sAuthNone     = 0x00
	sAuthNoAccept = 0xFF

	// Commands
	sCmdConnect      = 0x01
	sCmdUDPAssociate = 0x03

	// Address types
	sAtypIPv4   = 0x01
	sAtypDomain = 0x03
	sAtypIPv6   = 0x04

	// Reply codes
	sRepSuccess        = 0x00
	sRepGeneralFailure = 0x01
	sRepHostUnreach    = 0x04
	sRepCmdNotSupport  = 0x07
)

// handleSocksConn implements SOCKS5 protocol on the client side.
// This handles both CONNECT (TCP) and UDP ASSOCIATE commands locally,
// opening SSH channels to the server for actual data forwarding.
func (p *Proxy) handleSocksConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	p.mu.Lock()
	p.count++
	cid := p.count
	p.mu.Unlock()

	l := p.Fork("socks#%d", cid)

	// Step 1: Version & method negotiation
	buf := make([]byte, 258)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		l.Debugf("read version: %s", err)
		return
	}
	if buf[0] != socks5Ver {
		l.Debugf("unsupported SOCKS version: %d", buf[0])
		return
	}
	nMethods := int(buf[1])
	if nMethods == 0 {
		return
	}
	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		l.Debugf("read methods: %s", err)
		return
	}
	hasNoAuth := false
	for i := 0; i < nMethods; i++ {
		if buf[i] == sAuthNone {
			hasNoAuth = true
			break
		}
	}
	if !hasNoAuth {
		conn.Write([]byte{socks5Ver, sAuthNoAccept})
		return
	}
	if _, err := conn.Write([]byte{socks5Ver, sAuthNone}); err != nil {
		l.Debugf("write auth reply: %s", err)
		return
	}

	// Step 2: Read request
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		l.Debugf("read request: %s", err)
		return
	}
	if buf[0] != socks5Ver {
		return
	}
	cmd := buf[1]
	// buf[2] is RSV (reserved)
	atyp := buf[3]

	dstAddr, err := socksReadAddr(conn, atyp)
	if err != nil {
		l.Debugf("read addr: %s", err)
		socksReply(conn, sRepGeneralFailure, nil)
		return
	}

	switch cmd {
	case sCmdConnect:
		p.socksConnect(ctx, l, conn, dstAddr)
	case sCmdUDPAssociate:
		p.socksUDPAssociate(ctx, l, conn, dstAddr)
	default:
		socksReply(conn, sRepCmdNotSupport, nil)
	}
}

// socksConnect handles SOCKS5 CONNECT by opening an SSH channel to the destination.
func (p *Proxy) socksConnect(ctx context.Context, l *cio.Logger, conn net.Conn, dstAddr string) {
	l.Debugf("CONNECT %s", dstAddr)

	sshConn := p.sshTun.getSSH(ctx)
	if sshConn == nil {
		l.Debugf("no SSH connection")
		socksReply(conn, sRepGeneralFailure, nil)
		return
	}

	dst, reqs, err := sshConn.OpenChannel("chisel", []byte(dstAddr))
	if err != nil {
		l.Debugf("open channel: %s", err)
		socksReply(conn, sRepHostUnreach, nil)
		return
	}
	go ssh.DiscardRequests(reqs)
	defer dst.Close()

	// Success: bind address is not meaningful for tunnels
	socksReply(conn, sRepSuccess, &net.TCPAddr{IP: net.IPv4zero, Port: 0})

	// Bidirectional pipe
	cio.Pipe(conn, dst)
}

// socksUDPAssociate handles SOCKS5 UDP ASSOCIATE (RFC 1928 section 7).
// Opens a local UDP relay port and bridges datagrams through a shared SSH channel
// via socksUDPMux. This allows hundreds of concurrent UDP flows (e.g., recursive DNS)
// to share a single SSH channel instead of each opening their own.
//
// Routing key: each session uses its unique relay port as the mux routing key
// ("r<port>"). This avoids collisions when tun2socks reuses source addresses
// across different SOCKS5 sessions.
func (p *Proxy) socksUDPAssociate(ctx context.Context, l *cio.Logger, conn net.Conn, clientHint string) {
	l.Debugf("UDP ASSOCIATE request (client hint: %s)", clientHint)

	// Open local UDP relay on a random port
	udpRelay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		l.Debugf("UDP ASSOCIATE failed: listen relay: %s", err)
		socksReply(conn, sRepGeneralFailure, nil)
		return
	}
	defer udpRelay.Close()

	// Reply with the relay address the client should send UDP to.
	relayPort := udpRelay.LocalAddr().(*net.UDPAddr).Port
	localIP := conn.LocalAddr().(*net.TCPAddr).IP
	bindAddr := &net.TCPAddr{IP: localIP, Port: relayPort}
	socksReply(conn, sRepSuccess, bindAddr)

	// Use relay port as a unique routing key for this session
	rkey := relayKey(relayPort)
	l.Infof("UDP ASSOCIATE ready: relay %s, key %s (ctrl from %s)", bindAddr, rkey, conn.RemoteAddr())

	// Ensure shared SSH channel is open
	if err := p.udpMux.ensureChannel(ctx); err != nil {
		l.Debugf("UDP mux: ensure channel: %s", err)
		return
	}

	// Goroutine: UDP relay -> shared SSH channel (client datagrams to server)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, srcAddr, err := udpRelay.ReadFromUDP(buf)
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed") {
					l.Debugf("read UDP relay: %s", err)
				}
				return
			}
			// Parse SOCKS5 UDP datagram header
			dst, payload, err := socksUDPParseHeader(buf[:n])
			if err != nil {
				l.Debugf("UDP relay: bad SOCKS5 UDP header from %s: %s", srcAddr, err)
				continue
			}

			// Register/update this session's relay mapping in the mux.
			// Key is the relay port (unique per session), value includes
			// the client address for sending responses back.
			p.udpMux.register(rkey, udpRelay, srcAddr)

			// Send through shared channel. Src = relay key so the server
			// echoes it back and the mux can route the response correctly.
			pkt := &socksUDPDatagram{
				Src:     rkey,
				Dst:     dst,
				Payload: append([]byte(nil), payload...),
			}
			l.Infof("UDP relay: send %s -> %s (%d bytes) via %s", srcAddr, dst, len(payload), rkey)
			if err := p.udpMux.send(pkt); err != nil {
				l.Infof("UDP relay: mux send error: %s", err)
				return
			}
		}
	}()

	// The UDP association lives until the TCP control connection closes.
	io.Copy(io.Discard, conn)
	l.Infof("UDP ASSOCIATE ended (TCP control closed)")

	// Cleanup: remove this session from the mux
	p.udpMux.unregister(rkey)
}

// socksReadAddr reads a SOCKS5 address (ATYP + addr + port) from the stream.
func socksReadAddr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case sAtypIPv4:
		buf := make([]byte, 4+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		ip := net.IP(buf[:4])
		port := binary.BigEndian.Uint16(buf[4:])
		return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), nil

	case sAtypDomain:
		buf := make([]byte, 1)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		dlen := int(buf[0])
		domain := make([]byte, dlen+2)
		if _, err := io.ReadFull(r, domain); err != nil {
			return "", err
		}
		host := string(domain[:dlen])
		port := binary.BigEndian.Uint16(domain[dlen:])
		return net.JoinHostPort(host, strconv.Itoa(int(port))), nil

	case sAtypIPv6:
		buf := make([]byte, 16+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		ip := net.IP(buf[:16])
		port := binary.BigEndian.Uint16(buf[16:])
		return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), nil

	default:
		return "", fmt.Errorf("unsupported SOCKS5 address type: 0x%02x", atyp)
	}
}

// socksReply sends a SOCKS5 reply message.
func socksReply(w io.Writer, rep byte, addr net.Addr) {
	reply := []byte{socks5Ver, rep, 0x00} // VER, REP, RSV

	if addr == nil {
		reply = append(reply, sAtypIPv4, 0, 0, 0, 0, 0, 0)
	} else {
		tcpAddr, ok := addr.(*net.TCPAddr)
		if !ok {
			reply = append(reply, sAtypIPv4, 0, 0, 0, 0, 0, 0)
		} else if ip4 := tcpAddr.IP.To4(); ip4 != nil {
			reply = append(reply, sAtypIPv4)
			reply = append(reply, ip4...)
			pb := make([]byte, 2)
			binary.BigEndian.PutUint16(pb, uint16(tcpAddr.Port))
			reply = append(reply, pb...)
		} else {
			reply = append(reply, sAtypIPv6)
			reply = append(reply, tcpAddr.IP.To16()...)
			pb := make([]byte, 2)
			binary.BigEndian.PutUint16(pb, uint16(tcpAddr.Port))
			reply = append(reply, pb...)
		}
	}
	w.Write(reply)
}

// socksUDPParseHeader parses a SOCKS5 UDP datagram header (RFC 1928 section 7).
// Returns the destination address and the payload data.
func socksUDPParseHeader(data []byte) (dst string, payload []byte, err error) {
	if len(data) < 4 {
		return "", nil, fmt.Errorf("UDP datagram too short (%d bytes)", len(data))
	}
	// RSV(2) + FRAG(1) + ATYP(1)
	frag := data[2]
	if frag != 0 {
		return "", nil, fmt.Errorf("fragmented UDP not supported (frag=%d)", frag)
	}
	atyp := data[3]
	off := 4

	switch atyp {
	case sAtypIPv4:
		if len(data) < off+6 {
			return "", nil, fmt.Errorf("short IPv4 UDP datagram")
		}
		ip := net.IP(data[off : off+4])
		port := binary.BigEndian.Uint16(data[off+4:])
		dst = net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
		off += 6

	case sAtypDomain:
		if len(data) < off+1 {
			return "", nil, fmt.Errorf("short domain length")
		}
		dlen := int(data[off])
		off++
		if len(data) < off+dlen+2 {
			return "", nil, fmt.Errorf("short domain UDP datagram")
		}
		host := string(data[off : off+dlen])
		port := binary.BigEndian.Uint16(data[off+dlen:])
		dst = net.JoinHostPort(host, strconv.Itoa(int(port)))
		off += dlen + 2

	case sAtypIPv6:
		if len(data) < off+18 {
			return "", nil, fmt.Errorf("short IPv6 UDP datagram")
		}
		ip := net.IP(data[off : off+16])
		port := binary.BigEndian.Uint16(data[off+16:])
		dst = net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
		off += 18

	default:
		return "", nil, fmt.Errorf("unsupported address type in UDP: 0x%02x", atyp)
	}

	return dst, data[off:], nil
}

// socksUDPBuildHeader builds a SOCKS5 UDP datagram header for the given address.
func socksUDPBuildHeader(addr string) []byte {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return []byte{0, 0, 0, sAtypIPv4, 0, 0, 0, 0, 0, 0}
	}
	port, _ := strconv.Atoi(portStr)

	// RSV(2 bytes, 0x0000) + FRAG(1 byte, 0x00)
	header := []byte{0, 0, 0}

	ip := net.ParseIP(host)
	if ip == nil {
		// Domain name
		header = append(header, sAtypDomain)
		header = append(header, byte(len(host)))
		header = append(header, []byte(host)...)
	} else if ip4 := ip.To4(); ip4 != nil {
		header = append(header, sAtypIPv4)
		header = append(header, ip4...)
	} else {
		header = append(header, sAtypIPv6)
		header = append(header, ip.To16()...)
	}

	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(port))
	header = append(header, pb...)

	return header
}
