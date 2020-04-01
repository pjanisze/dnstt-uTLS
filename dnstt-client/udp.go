package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

type UDPPacketConn struct {
	clientID turbotunnel.ClientID
	domain   dns.Name
	pollChan chan struct{}
	*turbotunnel.QueuePacketConn
}

func NewUDPPacketConn(udpConn net.PacketConn, addr net.Addr, domain dns.Name) *UDPPacketConn {
	// Generate a new random ClientID.
	var clientID turbotunnel.ClientID
	rand.Read(clientID[:])
	c := &UDPPacketConn{
		clientID:        clientID,
		domain:          domain,
		pollChan:        make(chan struct{}),
		QueuePacketConn: turbotunnel.NewQueuePacketConn(clientID, idleTimeout),
	}
	go func() {
		err := c.recvLoop(udpConn)
		if err != nil {
			log.Printf("recvLoop: %v", err)
		}
	}()
	go func() {
		err := c.sendLoop(udpConn, addr)
		if err != nil {
			log.Printf("sendLoop: %v", err)
		}
	}()
	return c
}

func (c *UDPPacketConn) recvLoop(udpConn net.PacketConn) error {
	for {
		var buf [4096]byte
		n, addr, err := udpConn.ReadFrom(buf[:])
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Printf("ReadFrom temporary error: %v", err)
				continue
			}
			return err
		}

		// Got a UDP packet. Try to parse it as a DNS message.
		resp, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			log.Printf("MessageFromWireFormat: %v", err)
			continue
		}

		payload := dnsResponsePayload(&resp, c.domain)
		// Reading anything gives sendLoop license to poll immediately.
		if len(payload) > 0 {
			select {
			case c.pollChan <- struct{}{}:
			default:
			}
			select {
			case c.pollChan <- struct{}{}:
			default:
			}
		}

		// Pull out the packets contained in the payload.
		r := bytes.NewReader(payload)
		for {
			p, err := nextPacket(r)
			if err != nil {
				break
			}
			c.QueuePacketConn.QueueIncoming(p, addr)
		}
	}
}

// send sends a single packet in a DNS query.
func (c *UDPPacketConn) send(udpConn net.PacketConn, p []byte, addr net.Addr) error {
	var decoded []byte
	{
		if len(p) >= 224 {
			return fmt.Errorf("too long")
		}
		var buf bytes.Buffer
		// ClientID
		buf.Write(c.clientID[:])
		// Padding / cache inhibition
		buf.WriteByte(224 + numPadding)
		io.CopyN(&buf, rand.Reader, numPadding)
		// Packet contents
		if len(p) > 0 {
			buf.WriteByte(byte(len(p)))
			buf.Write(p)
		}
		decoded = buf.Bytes()
	}

	encoded := make([]byte, base32Encoding.EncodedLen(len(decoded)))
	base32Encoding.Encode(encoded, decoded)
	labels := chunks(encoded, 63)
	labels = append(labels, c.domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return err
	}

	var id uint16
	binary.Read(rand.Reader, binary.BigEndian, &id)
	query := &dns.Message{
		ID:    id,
		Flags: 0x0100, // QR = 0, RD = 1
		Question: []dns.Question{
			{
				Name:  name,
				Type:  dns.RRTypeTXT,
				Class: dns.ClassIN,
			},
		},
		// EDNS(0)
		Additional: []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
				Class: 4096, // requestor's UDP payload size
				TTL:   0,    // extended RCODE and flags
				Data:  []byte{},
			},
		},
	}
	buf, err := query.WireFormat()
	if err != nil {
		return err
	}

	_, err = udpConn.WriteTo(buf, addr)
	return err
}

func (c *UDPPacketConn) sendLoop(udpConn net.PacketConn, addr net.Addr) error {
	pollDelay := initPollDelay
	pollTimer := time.NewTimer(pollDelay)
	for {
		var p []byte
		select {
		case <-c.pollChan:
			if !pollTimer.Stop() {
				<-pollTimer.C
			}
			p = nil
		case p = <-c.QueuePacketConn.OutgoingQueue(addr):
			if !pollTimer.Stop() {
				<-pollTimer.C
			}
			pollDelay = initPollDelay
		case <-pollTimer.C:
			p = nil
			pollDelay = time.Duration(float64(pollDelay) * pollDelayMultiplier)
			if pollDelay > maxPollDelay {
				pollDelay = maxPollDelay
			}
		}
		pollTimer.Reset(pollDelay)
		err := c.send(udpConn, p, addr)
		if err != nil {
			log.Printf("send: %v", err)
			continue
		}
	}
}
