package quic

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Basic Conn Test", func() {
	Context("ECN conn", func() {
		runTest := func(network, address string, setECN func(fd uintptr)) {
			addr, err := net.ResolveUDPAddr(network, address)
			Expect(err).ToNot(HaveOccurred())
			udpConn, err := net.ListenUDP(network, addr)
			Expect(err).ToNot(HaveOccurred())
			ecnConn, err := newConn(udpConn)
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
				setECN(fd)
			})).To(Succeed())
			_, err = sender.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())

			var p *receivedPacket
			Eventually(packetChan).Should(Receive(&p))
			Expect(p.rcvTime).To(BeTemporally("~", time.Now(), scaleDuration(20*time.Millisecond)))
			Expect(p.data).To(Equal([]byte("foobar")))
			Expect(p.remoteAddr).To(Equal(sender.LocalAddr()))
			Expect(p.ecn).To(Equal(protocol.ECT0))
		}

		It("reads ECN flags on IPv4", func() {
			runTest(
				"udp4",
				"localhost:0",
				func(fd uintptr) {
					Expect(syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, 2)).To(Succeed())
				},
			)
		})

		It("reads ECN flags on IPv6", func() {
			runTest(
				"udp6",
				"[::]:0",
				func(fd uintptr) {
					Expect(syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, 2)).To(Succeed())
				},
			)
		})

		It("reads ECN flags on a connection that supports both IPv4 and IPv6", func() {
			const network = "udp"
			const address = "0.0.0.0:0"
			addr, err := net.ResolveUDPAddr(network, address)
			Expect(err).ToNot(HaveOccurred())
			udpConn, err := net.ListenUDP(network, addr)
			Expect(err).ToNot(HaveOccurred())
			ecnConn, err := newConn(udpConn)
			Expect(err).ToNot(HaveOccurred())

			packetChan := make(chan *receivedPacket, 2)
			go func() {
				defer GinkgoRecover()
				defer fmt.Println("read returned")
				p, err := ecnConn.ReadPacket()
				Expect(err).ToNot(HaveOccurred())
				packetChan <- p
				p, err = ecnConn.ReadPacket()
				Expect(err).ToNot(HaveOccurred())
				packetChan <- p
			}()

			port := udpConn.LocalAddr().(*net.UDPAddr).Port
			// IPv4
			sender, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
			Expect(err).ToNot(HaveOccurred())
			rawConn, err := sender.SyscallConn()
			Expect(err).ToNot(HaveOccurred())
			Expect(rawConn.Control(func(fd uintptr) {
				Expect(syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, 2)).To(Succeed())
			})).To(Succeed())
			_, err = sender.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())

			var p *receivedPacket
			Eventually(packetChan).Should(Receive(&p))
			Expect(p.rcvTime).To(BeTemporally("~", time.Now(), scaleDuration(20*time.Millisecond)))
			Expect(p.data).To(Equal([]byte("foobar")))
			fmt.Println(p.remoteAddr)
			Expect(p.ecn).To(Equal(protocol.ECT0))

			// IPv6
			sender, err = net.DialUDP("udp6", nil, &net.UDPAddr{IP: net.IPv6loopback, Port: port})
			Expect(err).ToNot(HaveOccurred())
			rawConn, err = sender.SyscallConn()
			Expect(err).ToNot(HaveOccurred())
			Expect(rawConn.Control(func(fd uintptr) {
				Expect(syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, 2)).To(Succeed())
			})).To(Succeed())
			_, err = sender.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())

			Eventually(packetChan).Should(Receive(&p))
			Expect(p.rcvTime).To(BeTemporally("~", time.Now(), scaleDuration(20*time.Millisecond)))
			Expect(p.data).To(Equal([]byte("foobar")))
			fmt.Println(p.remoteAddr)
			Expect(p.ecn).To(Equal(protocol.ECT0))
		})
	})
})
