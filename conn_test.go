package quic

import (
	"net"
	"syscall"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Conn Test", func() {
	Context("basic conn", func() {
		It("reads a packet", func() {
			c := newMockPacketConn()
			addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}
			c.dataReadFrom = addr
			c.dataToRead <- []byte("foobar")

			conn, err := wrapConn(c)
			Expect(err).ToNot(HaveOccurred())
			p, err := conn.ReadPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p.data).To(Equal([]byte("foobar")))
			Expect(p.rcvTime).To(BeTemporally("~", time.Now(), scaleDuration(100*time.Millisecond)))
			Expect(p.remoteAddr).To(Equal(addr))
		})
	})

	Context("ECN conn", func() {
		runTest := func(network, address string, setECN func(fd uintptr) error) {
			addr, err := net.ResolveUDPAddr(network, address)
			Expect(err).ToNot(HaveOccurred())
			udpConn, err := net.ListenUDP(network, addr)
			Expect(err).ToNot(HaveOccurred())
			ecnConn, err := newECNConn(udpConn)
			Expect(err).ToNot(HaveOccurred())

			packetChan := make(chan *receivedPacket, 1)
			go func() {
				defer GinkgoRecover()
				p, err := ecnConn.ReadPacket()
				Expect(err).ToNot(HaveOccurred())
				packetChan <- p
			}()

			sender, err := net.DialUDP(network, nil, udpConn.LocalAddr().(*net.UDPAddr))
			Expect(err).ToNot(HaveOccurred())
			rawConn, err := sender.SyscallConn()
			Expect(err).ToNot(HaveOccurred())
			Expect(rawConn.Control(func(fd uintptr) {
				Expect(setECN(fd)).To(Succeed())
			})).To(Succeed())
			_, err = sender.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())

			var p *receivedPacket
			Eventually(packetChan).Should(Receive(&p))
			Expect(p.rcvTime).To(BeTemporally("~", time.Now(), scaleDuration(20*time.Millisecond)))
			Expect(p.data).To(Equal([]byte("foobar")))
			Expect(p.remoteAddr).To(Equal(sender.LocalAddr()))
			Expect(p.ecn).To(Equal(protocol.ECT1))
		}

		It("reads ECN flags on IPv4", func() {
			runTest(
				"udp4",
				"localhost:0",
				func(fd uintptr) error {
					return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, 2)
				},
			)
		})

		It("reads ECN flags on IPv6", func() {
			runTest(
				"udp6",
				"[::]:0",
				func(fd uintptr) error {
					return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, 2)
				},
			)
		})

	})
})
