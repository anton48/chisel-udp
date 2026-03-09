package tunnel

import (
	"context"
	"encoding/gob"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/jpillora/chisel/share/cio"
	"golang.org/x/crypto/ssh"
)

// socksUDPMux multiplexes all SOCKS5 UDP ASSOCIATE sessions over a single
// SSH channel. Without this, each UDP flow (e.g., a single DNS query from
// a recursive resolver) opens its own SSH channel. Recursive DNS can easily
// create 300+ channels per second, overwhelming SSH multiplexing.
//
// Routing: each session has a unique relay port. The relay port is used as the
// routing key (pkt.Src = "r<port>"). The server echoes this key back in
// responses, allowing the mux to dispatch to the correct relay.
type socksUDPMux struct {
	logger *cio.Logger
	sshTun sshTunnel

	// Protects sshChan/enc/dec lifecycle (open/close)
	chanMu  sync.Mutex
	sshChan ssh.Channel
	enc     *gob.Encoder
	dec     *gob.Decoder

	// Serializes writes to the shared encoder
	encMu sync.Mutex

	// Maps relay key ("r<port>") -> relay entry for response routing
	relaysMu sync.RWMutex
	relays   map[string]*relayEntry
}

type relayEntry struct {
	relay      *net.UDPConn
	clientAddr *net.UDPAddr
}

func newSocksUDPMux(logger *cio.Logger, sshTun sshTunnel) *socksUDPMux {
	return &socksUDPMux{
		logger: logger.Fork("udp-mux"),
		sshTun: sshTun,
		relays: make(map[string]*relayEntry),
	}
}

// relayKey returns a unique routing key for a session based on its relay port.
func relayKey(port int) string {
	return fmt.Sprintf("r%d", port)
}

// ensureChannel lazily opens the shared SSH channel, or returns the existing one.
func (m *socksUDPMux) ensureChannel(ctx context.Context) error {
	m.chanMu.Lock()
	defer m.chanMu.Unlock()

	if m.sshChan != nil {
		return nil
	}

	sshConn := m.sshTun.getSSH(ctx)
	if sshConn == nil {
		return io.ErrClosedPipe
	}

	ch, reqs, err := sshConn.OpenChannel("chisel", []byte("socks/udp"))
	if err != nil {
		return err
	}
	go ssh.DiscardRequests(reqs)

	m.sshChan = ch
	m.enc = gob.NewEncoder(ch)
	m.dec = gob.NewDecoder(ch)

	// Start reader goroutine that dispatches responses to relays
	go m.readLoop()

	m.logger.Debugf("shared SSH channel opened")
	return nil
}

// readLoop reads responses from the shared SSH channel and dispatches them
// to the correct relay based on pkt.Src (which is the relay key "r<port>").
func (m *socksUDPMux) readLoop() {
	m.logger.Infof("readLoop started")
	var count int64
	for {
		var pkt socksUDPDatagram
		if err := m.dec.Decode(&pkt); err != nil {
			if err != io.EOF {
				m.logger.Infof("readLoop: decode error: %s", err)
			}
			m.logger.Infof("readLoop ended after %d responses", count)
			m.closeChannel()
			return
		}
		count++

		m.relaysMu.RLock()
		entry, ok := m.relays[pkt.Src]
		m.relaysMu.RUnlock()

		if !ok {
			m.logger.Infof("readLoop: no relay for key %s from %s (stale response?)", pkt.Src, pkt.Dst)
			continue
		}

		if entry.clientAddr == nil {
			m.logger.Infof("readLoop: relay %s has no client address yet", pkt.Src)
			continue
		}

		// Build SOCKS5 UDP response header and send to client via its relay
		header := socksUDPBuildHeader(pkt.Dst)
		data := make([]byte, len(header)+len(pkt.Payload))
		copy(data, header)
		copy(data[len(header):], pkt.Payload)

		if _, err := entry.relay.WriteToUDP(data, entry.clientAddr); err != nil {
			m.logger.Infof("readLoop: write to client via %s failed: %s", pkt.Src, err)
		} else {
			m.logger.Infof("readLoop: response from %s -> relay %s -> client %s (%d bytes)", pkt.Dst, pkt.Src, entry.clientAddr, len(pkt.Payload))
		}
	}
}

// closeChannel tears down the shared SSH channel (called when readLoop exits).
// Next ensureChannel call will open a fresh one.
func (m *socksUDPMux) closeChannel() {
	m.chanMu.Lock()
	defer m.chanMu.Unlock()
	if m.sshChan != nil {
		m.sshChan.Close()
		m.sshChan = nil
		m.enc = nil
		m.dec = nil
		m.logger.Debugf("shared SSH channel closed")
	}
}

// send encodes a datagram through the shared channel.
// Thread-safe: multiple relay goroutines call this concurrently.
func (m *socksUDPMux) send(pkt *socksUDPDatagram) error {
	m.encMu.Lock()
	defer m.encMu.Unlock()
	if m.enc == nil {
		return io.ErrClosedPipe
	}
	return m.enc.Encode(pkt)
}

// register associates a relay key with its relay port and client address.
// Called on each incoming packet to keep clientAddr up to date.
func (m *socksUDPMux) register(key string, relay *net.UDPConn, clientAddr *net.UDPAddr) {
	m.relaysMu.Lock()
	m.relays[key] = &relayEntry{relay: relay, clientAddr: clientAddr}
	m.relaysMu.Unlock()
}

// unregister removes a relay mapping (called on session close).
func (m *socksUDPMux) unregister(key string) {
	m.relaysMu.Lock()
	delete(m.relays, key)
	m.relaysMu.Unlock()
}
