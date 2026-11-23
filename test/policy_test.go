package test

import (
	"net"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

// TestPolicyRouting verifies source-IP based policy routing across three
// client configurations: two client networks matched by policy blocks and a
// catch-all block for every other source.
func TestPolicyRouting(t *testing.T) {
	sources := []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"}
	for _, source := range sources {
		probe, err := net.ListenPacket("udp4", net.JoinHostPort(source, "0"))
		if err != nil {
			t.Skipf("loopback address %s is unavailable: %v", source, err)
		}
		probe.Close()
	}

	corefile := `.:0 {
	policy group-a {
		client 127.0.0.1
	}
	cache 30
	hosts {
		10.0.0.1 policy.example
	}
}
.:0 {
	policy group-b {
		client 127.0.0.2
	}
	cache 30
	hosts {
		10.0.0.2 policy.example
	}
}
.:0 {
	cache 30
	hosts {
		10.0.0.3 policy.example
	}
}`

	instance, udp, _, err := CoreDNSServerAndPorts(corefile)
	if err != nil {
		t.Fatalf("Could not get CoreDNS serving instance: %s", err)
	}
	defer instance.Stop()

	want := map[string]string{
		"127.0.0.1": "10.0.0.1",
		"127.0.0.2": "10.0.0.2",
		"127.0.0.3": "10.0.0.3",
	}

	for source, expected := range want {
		resp := exchangeFrom(t, udp, source, "policy.example.", dns.TypeA)
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("client %s: expected one NOERROR answer, got %v", source, resp)
		}
		answer, ok := resp.Answer[0].(*dns.A)
		if !ok || !answer.A.Equal(net.ParseIP(expected)) {
			t.Fatalf("client %s: expected answer %s, got %v", source, expected, resp.Answer)
		}
	}
}

// TestPolicyCacheIsolation verifies that the cache of each policy block is
// independent: repeated queries from one client are served from its own cache
// and never leak the answer cached for another client.
func TestPolicyCacheIsolation(t *testing.T) {
	sources := []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"}
	for _, source := range sources {
		probe, err := net.ListenPacket("udp4", net.JoinHostPort(source, "0"))
		if err != nil {
			t.Skipf("loopback address %s is unavailable: %v", source, err)
		}
		probe.Close()
	}

	corefile := `.:0 {
	prometheus localhost:9157
	policy group-a {
		client 127.0.0.1
	}
	cache 30
	hosts {
		10.0.0.1 policy.example
	}
}
.:0 {
	prometheus localhost:9157
	policy group-b {
		client 127.0.0.2
	}
	cache 30
	hosts {
		10.0.0.2 policy.example
	}
}
.:0 {
	prometheus localhost:9157
	cache 30
	hosts {
		10.0.0.3 policy.example
	}
}`

	instance, udp, _, err := CoreDNSServerAndPorts(corefile)
	if err != nil {
		t.Fatalf("Could not get CoreDNS serving instance: %s", err)
	}
	defer instance.Stop()

	want := map[string]string{
		"127.0.0.1": "10.0.0.1",
		"127.0.0.2": "10.0.0.2",
		"127.0.0.3": "10.0.0.3",
	}

	// Populate every block's cache with a first round of queries.
	for source, expected := range want {
		resp := exchangeFrom(t, udp, source, "policy.example.", dns.TypeA)
		assertA(t, source, expected, resp)
	}

	// Repeat the queries. Each answer must still come from the block selected
	// by the source address, proving the caches do not cross, and the second
	// query must be answered from the local cache.
	for source, expected := range want {
		resp := exchangeFrom(t, udp, source, "policy.example.", dns.TypeA)
		assertA(t, source, expected, resp)
	}

	entries := test.ScrapeMetricAsInt("localhost:9157", "coredns_cache_entries", "", 0)
	if entries < 3 {
		t.Fatalf("expected independent cache entries across three blocks (>= 3), got %d", entries)
	}

	// Each block must expose its own cache metric series: the two policy
	// blocks carry distinct view labels, while the catch-all block uses an
	// empty view label.
	families := test.Scrape("http://localhost:9157/metrics")
	for _, view := range []string{"group-a", "group-b", ""} {
		value, labels := test.MetricValueLabel("coredns_cache_entries", view, families)
		if value == "" {
			t.Fatalf("expected a coredns_cache_entries series for view %q", view)
		}
		if got := labels["view"]; got != view {
			t.Fatalf("cache entries series view label: got %q, want %q", got, view)
		}

		hits := test.ScrapeMetricAsInt("localhost:9157", "coredns_cache_hits_total", view, -1)
		if hits < 1 {
			t.Fatalf("expected at least one cache hit for view %q, got %d", view, hits)
		}
	}
}

// TestPolicyCIDR verifies that whole subnets, rather than individual host
// addresses, can be used as client networks.
func TestPolicyCIDR(t *testing.T) {
	for _, source := range []string{"127.0.0.1", "127.0.0.2"} {
		probe, err := net.ListenPacket("udp4", net.JoinHostPort(source, "0"))
		if err != nil {
			t.Skipf("loopback address %s is unavailable: %v", source, err)
		}
		probe.Close()
	}

	corefile := `.:0 {
	policy loopback {
		client 127.0.0.0/8
	}
	hosts {
		10.1.1.1 cidr.example
	}
}
.:0 {
	hosts {
		10.2.2.2 cidr.example
	}
}`

	instance, udp, _, err := CoreDNSServerAndPorts(corefile)
	if err != nil {
		t.Fatalf("Could not get CoreDNS serving instance: %s", err)
	}
	defer instance.Stop()

	for _, source := range []string{"127.0.0.1", "127.0.0.2"} {
		resp := exchangeFrom(t, udp, source, "cidr.example.", dns.TypeA)
		assertA(t, source, "10.1.1.1", resp)
	}
}

// TestPolicyRejectsViewSibling ensures a server block cannot register two
// Viewer plugins at once, since the server only supports one view per block.
func TestPolicyRejectsViewSibling(t *testing.T) {
	corefile := `.:0 {
	policy p1 {
		client 127.0.0.1
	}
	view v1 {
		expr type() == 'A'
	}
	hosts {
		10.0.0.1 x.example
	}
}`
	instance, _, _, err := CoreDNSServerAndPorts(corefile)
	if err == nil {
		instance.Stop()
		t.Fatal("expected startup error when policy and view share a block, got none")
	}
}

func assertA(t *testing.T, source, expected string, resp *dns.Msg) {
	t.Helper()
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("client %s: expected one NOERROR answer, got %v", source, resp)
	}
	answer, ok := resp.Answer[0].(*dns.A)
	if !ok || !answer.A.Equal(net.ParseIP(expected)) {
		t.Fatalf("client %s: expected answer %s, got %v", source, expected, resp.Answer)
	}
}

func exchangeFrom(t *testing.T, server, source, qname string, qtype uint16) *dns.Msg {
	t.Helper()

	remoteAddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		t.Fatalf("resolve server address %q: %v", server, err)
	}
	conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP(source).To4()}, remoteAddr)
	if err != nil {
		t.Skipf("dial from %s unavailable: %v", source, err)
	}
	defer conn.Close()

	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)

	client := &dns.Client{Net: "udp4", Timeout: 2 * time.Second}
	resp, _, err := client.ExchangeWithConn(m, &dns.Conn{Conn: conn})
	if err != nil {
		t.Fatalf("query from %s to %s: %v", source, server, err)
	}
	return resp
}
