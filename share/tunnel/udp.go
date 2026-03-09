package tunnel

import (
	"context"
	"encoding/gob"
	"io"
)

type udpPacket struct {
	Src     string
	Payload []byte
}

// socksUDPDatagram carries UDP data through SSH for SOCKS5 UDP ASSOCIATE.
// Unlike udpPacket (fixed destination), each datagram has a dynamic destination.
type socksUDPDatagram struct {
	Src     string // client's UDP source address (for routing responses back)
	Dst     string // destination address host:port (dynamic per packet)
	Payload []byte
}

func init() {
	gob.Register(&udpPacket{})
	gob.Register(&socksUDPDatagram{})
}

//udpChannel encodes/decodes udp payloads over a stream
type udpChannel struct {
	r *gob.Decoder
	w *gob.Encoder
	c io.Closer
}

func (o *udpChannel) encode(src string, b []byte) error {
	return o.w.Encode(udpPacket{
		Src:     src,
		Payload: b,
	})
}

func (o *udpChannel) decode(p *udpPacket) error {
	return o.r.Decode(p)
}

func isDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
