package tunnel

import (
	"encoding/gob"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/jpillora/chisel/share/cio"
	"github.com/jpillora/chisel/share/settings"
)

func (t *Tunnel) handleUDP(l *cio.Logger, rwc io.ReadWriteCloser, hostPort string) error {
	conns := &udpConns{
		Logger: l,
		m:      map[string]*udpConn{},
	}
	defer conns.closeAll()
	h := &udpHandler{
		Logger:   l,
		hostPort: hostPort,
		udpChannel: &udpChannel{
			r: gob.NewDecoder(rwc),
			w: gob.NewEncoder(rwc),
			c: rwc,
		},
		udpConns: conns,
		maxMTU:   settings.EnvInt("UDP_MAX_SIZE", 9012),
	}
	h.Debugf("UDP max size: %d bytes", h.maxMTU)
	for {
		p := udpPacket{}
		if err := h.handleWrite(&p); err != nil {
			return err
		}
	}
}

type udpHandler struct {
	*cio.Logger
	hostPort string
	*udpChannel
	*udpConns
	maxMTU int
}

func (h *udpHandler) handleWrite(p *udpPacket) error {
	if err := h.r.Decode(&p); err != nil {
		return err
	}
	//dial now, we know we must write
	conn, exists, err := h.udpConns.dial(p.Src, h.hostPort)
	if err != nil {
		return err
	}
	//however, we dont know if we must read...
	//spawn up to <max-conns> go-routines to wait
	//for a reply.
	//TODO configurable
	//TODO++ dont use go-routines, switch to pollable
	//  array of listeners where all listeners are
	//  sweeped periodically, removing the idle ones
	const maxConns = 100
	if !exists {
		if h.udpConns.len() <= maxConns {
			go h.handleRead(p, conn)
		} else {
			h.Debugf("exceeded max udp connections (%d)", maxConns)
		}
	}
	_, err = conn.Write(p.Payload)
	if err != nil {
		return err
	}
	return nil
}

func (h *udpHandler) handleRead(p *udpPacket, conn *udpConn) {
	//ensure connection is cleaned up
	defer h.udpConns.remove(conn.id)
	buff := make([]byte, h.maxMTU)
	for {
		//response must arrive within 15 seconds
		deadline := settings.EnvDuration("UDP_DEADLINE", 15*time.Second)
		conn.SetReadDeadline(time.Now().Add(deadline))
		//read response
		n, err := conn.Read(buff)
		if err != nil {
			if !os.IsTimeout(err) && err != io.EOF {
				h.Debugf("read error: %s", err)
			}
			break
		}
		b := buff[:n]
		//encode back over ssh connection
		err = h.udpChannel.encode(p.Src, b)
		if err != nil {
			h.Debugf("encode error: %s", err)
			return
		}
	}
}

type udpConns struct {
	*cio.Logger
	sync.Mutex
	m map[string]*udpConn
}

func (cs *udpConns) dial(id, addr string) (*udpConn, bool, error) {
	cs.Lock()
	defer cs.Unlock()
	conn, ok := cs.m[id]
	if !ok {
		c, err := net.Dial("udp", addr)
		if err != nil {
			return nil, false, err
		}
		conn = &udpConn{
			id:   id,
			Conn: c, // cnet.MeterConn(cs.Logger.Fork(addr), c),
		}
		cs.m[id] = conn
	}
	return conn, ok, nil
}

func (cs *udpConns) len() int {
	cs.Lock()
	l := len(cs.m)
	cs.Unlock()
	return l
}

func (cs *udpConns) remove(id string) {
	cs.Lock()
	delete(cs.m, id)
	cs.Unlock()
}

func (cs *udpConns) closeAll() {
	cs.Lock()
	for id, conn := range cs.m {
		conn.Close()
		delete(cs.m, id)
	}
	cs.Unlock()
}

type udpConn struct {
	id string
	net.Conn
}

// handleSocksUDP handles SOCKS5 UDP ASSOCIATE on the server (exit) side.
// Each packet carries a dynamic destination address, unlike regular UDP
// forwarding where the destination is fixed per channel.
func (t *Tunnel) handleSocksUDP(l *cio.Logger, rwc io.ReadWriteCloser) error {
	l.Infof("SOCKS UDP handler started")
	conns := &udpConns{
		Logger: l,
		m:      map[string]*udpConn{},
	}
	defer conns.closeAll()

	enc := gob.NewEncoder(rwc)
	dec := gob.NewDecoder(rwc)
	var encMu sync.Mutex
	maxMTU := settings.EnvInt("UDP_MAX_SIZE", 9012)
	maxConns := settings.EnvInt("UDP_MAX_CONNS", 2048)

	for {
		var pkt socksUDPDatagram
		if err := dec.Decode(&pkt); err != nil {
			l.Infof("SOCKS UDP handler ended: %s", err)
			return err
		}

		// Key by src|dst for proper per-flow connection tracking
		connKey := pkt.Src + "|" + pkt.Dst
		conn, exists, err := conns.dial(connKey, pkt.Dst)
		if err != nil {
			l.Infof("SOCKS UDP: dial %s failed: %s", pkt.Dst, err)
			continue
		}

		if !exists {
			if conns.len() > maxConns {
				l.Infof("SOCKS UDP: exceeded max connections (%d)", maxConns)
				continue
			}
			l.Debugf("SOCKS UDP: new flow %s -> %s", pkt.Src, pkt.Dst)
			// Start reader goroutine for responses from this destination
			go func(key, src, dst string, conn *udpConn) {
				defer conns.remove(key)
				buf := make([]byte, maxMTU)
				for {
					deadline := settings.EnvDuration("UDP_DEADLINE", 15*time.Second)
					conn.SetReadDeadline(time.Now().Add(deadline))
					n, err := conn.Read(buf)
					if err != nil {
						if !os.IsTimeout(err) && err != io.EOF {
							l.Debugf("SOCKS UDP: read from %s: %s", dst, err)
						}
						return
					}
					l.Debugf("SOCKS UDP: response from %s (%d bytes) -> %s", dst, n, src)
					resp := socksUDPDatagram{
						Src:     src,
						Dst:     dst,
						Payload: append([]byte(nil), buf[:n]...),
					}
					encMu.Lock()
					err = enc.Encode(&resp)
					encMu.Unlock()
					if err != nil {
						l.Debugf("SOCKS UDP: encode response error: %s", err)
						return
					}
				}
			}(connKey, pkt.Src, pkt.Dst, conn)
		}

		if _, err := conn.Write(pkt.Payload); err != nil {
			l.Debugf("SOCKS UDP: write to %s: %s", pkt.Dst, err)
		}
	}
}
