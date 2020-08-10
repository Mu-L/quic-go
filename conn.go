package quic

import (
	"fmt"
	"io"
	"log"
	"net"
	"syscall"
	"time"

	"github.com/lucas-clemente/quic-go/internal/utils"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

const ecnMask uint8 = 0x3

type connection interface {
	ReadPacket() (*receivedPacket, error)
	WriteTo([]byte, net.Addr) (int, error)
	LocalAddr() net.Addr
	io.Closer
}

func wrapConn(pc net.PacketConn) (connection, error) {
	udpConn, ok := pc.(*net.UDPConn)
	if !ok {
		log.Printf("PacketConn is not a UDP conn. ECN support will be disabled.")
		return &basicConn{PacketConn: pc}, nil
	}
	return newECNConn(udpConn)
}

type basicConn struct {
	net.PacketConn
}

var _ connection = &basicConn{}

func (c *basicConn) ReadPacket() (*receivedPacket, error) {
	buffer := getPacketBuffer()
	// The packet size should not exceed protocol.MaxReceivePacketSize bytes
	// If it does, we only read a truncated packet, which will then end up undecryptable
	buffer.Data = buffer.Data[:protocol.MaxReceivePacketSize]
	n, addr, err := c.PacketConn.ReadFrom(buffer.Data)
	if err != nil {
		return nil, err
	}
	return &receivedPacket{
		remoteAddr: addr,
		rcvTime:    time.Now(),
		data:       buffer.Data[:n],
		buffer:     buffer,
	}, nil
}

type ecnConnIPv4 struct {
	*net.UDPConn
	oobBuffer []byte
}

var _ connection = &ecnConnIPv4{}

func newECNConnIPv4(c *net.UDPConn) (*ecnConnIPv4, error) {
	utils.DefaultLogger.Debugf("Activating reading of ECN bits on an IPv4 connection.")
	rawConn, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var serr error
	if err := rawConn.Control(func(fd uintptr) {
		if err := setRECVTOS(fd); err != nil {
			serr = err
		}
	}); err != nil {
		return nil, err
	}
	if serr != nil {
		return nil, serr
	}
	return &ecnConnIPv4{
		UDPConn:   c,
		oobBuffer: make([]byte, 128),
	}, nil
}

func (c *ecnConnIPv4) ReadPacket() (*receivedPacket, error) {
	buffer := getPacketBuffer()
	// The packet size should not exceed protocol.MaxReceivePacketSize bytes
	// If it does, we only read a truncated packet, which will then end up undecryptable
	buffer.Data = buffer.Data[:protocol.MaxReceivePacketSize]
	c.oobBuffer = c.oobBuffer[:cap(c.oobBuffer)]
	n, oobn, _, addr, err := c.UDPConn.ReadMsgUDP(buffer.Data, c.oobBuffer)
	if err != nil {
		return nil, err
	}
	ctrlMsgs, err := syscall.ParseSocketControlMessage(c.oobBuffer[:oobn])
	if err != nil {
		return nil, err
	}
	var ecn protocol.ECN
	for _, ctrlMsg := range ctrlMsgs {
		if ctrlMsg.Header.Level == syscall.IPPROTO_IP && ctrlMsg.Header.Type == msgTypeIPTOS {
			ecn = protocol.ECN(ctrlMsg.Data[0] & ecnMask)
			break
		}
	}
	return &receivedPacket{
		remoteAddr: addr,
		rcvTime:    time.Now(),
		data:       buffer.Data[:n],
		ecn:        ecn,
		buffer:     buffer,
	}, nil
}

type ecnConnIPv6 struct {
	*net.UDPConn
	oobBuffer []byte
}

var _ connection = &ecnConnIPv6{}

func newECNConnIPv6(c *net.UDPConn) (*ecnConnIPv6, error) {
	utils.DefaultLogger.Debugf("Activating reading of ECN bits on an IPv6 connection.")
	rawConn, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var serr error
	if err := rawConn.Control(func(fd uintptr) {
		if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_RECVTCLASS, 1); err != nil {
			serr = err
		}
	}); err != nil {
		return nil, err
	}
	if serr != nil {
		return nil, serr
	}
	return &ecnConnIPv6{
		UDPConn:   c,
		oobBuffer: make([]byte, 128),
	}, nil
}

func (c *ecnConnIPv6) ReadPacket() (*receivedPacket, error) {
	buffer := getPacketBuffer()
	// The packet size should not exceed protocol.MaxReceivePacketSize bytes
	// If it does, we only read a truncated packet, which will then end up undecryptable
	buffer.Data = buffer.Data[:protocol.MaxReceivePacketSize]
	c.oobBuffer = c.oobBuffer[:cap(c.oobBuffer)]
	n, oobn, _, addr, err := c.UDPConn.ReadMsgUDP(buffer.Data, c.oobBuffer)
	if err != nil {
		return nil, err
	}
	ctrlMsgs, err := syscall.ParseSocketControlMessage(c.oobBuffer[:oobn])
	if err != nil {
		return nil, err
	}
	var ecn protocol.ECN
	for _, ctrlMsg := range ctrlMsgs {
		if ctrlMsg.Header.Level == syscall.IPPROTO_IPV6 && ctrlMsg.Header.Type == syscall.IPV6_TCLASS {
			ecn = protocol.ECN(ctrlMsg.Data[0] & ecnMask)
			break
		}
	}
	return &receivedPacket{
		remoteAddr: addr,
		rcvTime:    time.Now(),
		data:       buffer.Data[:n],
		ecn:        ecn,
		buffer:     buffer,
	}, nil
}

func newECNConn(c *net.UDPConn) (connection, error) {
	fmt.Printf("new ECN Conn: %#v (%s)\n", c.LocalAddr(), c.LocalAddr().String())
	if utils.IsIPv4(c.LocalAddr().(*net.UDPAddr).IP) {
		return newECNConnIPv4(c)
	}
	return newECNConnIPv6(c)
}
