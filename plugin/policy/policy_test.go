package policy

import (
	"context"
	"errors"
	"net"
	"testing"

	ptest "github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"

	"github.com/infobloxopen/go-trees/iptree"
	"github.com/miekg/dns"
)

func TestFilter(t *testing.T) {
	p := &Policy{viewName: "intranet", clients: iptree.NewTree()}
	for _, cidr := range []string{"10.0.0.0/8", "192.168.1.0/24", "2001:db8::/32"} {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		p.clients.InplaceInsertNet(network, struct{}{})
	}

	tests := []struct {
		name   string
		client string
		zone   string
		want   bool
	}{
		{"ipv4 in subnet", "10.2.3.4", "", true},
		{"ipv4 exact host", "192.168.1.50", "", true},
		{"ipv4 outside subnet", "172.16.0.1", "", false},
		{"ipv6 in subnet", "2001:db8::123", "", true},
		{"ipv6 outside subnet", "2001:db9::1", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := makeState(tc.client, tc.zone)
			if got := p.Filter(context.Background(), state); got != tc.want {
				t.Fatalf("Filter() for client %q: got %v, want %v", tc.client, got, tc.want)
			}
		})
	}
}

func TestFilter_UnparseableAddress(t *testing.T) {
	p := &Policy{viewName: "intranet", clients: iptree.NewTree()}

	// net.UDPAddr with a nil IP renders as "<nil>:40212", which cannot be parsed.
	w := &ptest.ResponseWriter{}
	w.RemoteIP = "not-an-ip"
	state := &request.Request{W: w, Req: new(dns.Msg)}
	if p.Filter(context.Background(), state) {
		t.Fatalf("Filter() expected false for an unparseable source address")
	}

	// An IPv6 link-local address carrying a zone identifier must be stripped
	// before parsing and therefore must not match the configured networks.
	linkLocal := &ptest.ResponseWriter{
		RemoteIP: "fe80::1",
		Zone:     "eth0",
	}
	stateZone := &request.Request{W: linkLocal, Req: new(dns.Msg)}
	if p.Filter(context.Background(), stateZone) {
		t.Fatalf("Filter() expected false for a link-local source with zone identifier")
	}
}

func TestViewNameAndName(t *testing.T) {
	p := &Policy{viewName: "intranet"}
	if got := p.ViewName(); got != "intranet" {
		t.Fatalf("ViewName(): got %q, want %q", got, "intranet")
	}
	if got := p.Name(); got != pluginName {
		t.Fatalf("Name(): got %q, want %q", got, pluginName)
	}
}

func TestServeDNS_DelegatesToNext(t *testing.T) {
	p := &Policy{viewName: "intranet", clients: iptree.NewTree()}
	wantCode := dns.RcodeNameError
	wantErr := errors.New("boom")
	p.Next = ptest.NextHandler(wantCode, wantErr)

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	w := &ptest.ResponseWriter{}

	gotCode, gotErr := p.ServeDNS(context.Background(), w, m)
	if gotCode != wantCode {
		t.Fatalf("rcode: got %d, want %d", gotCode, wantCode)
	}
	if gotErr != wantErr {
		t.Fatalf("error: got %v, want %v", gotErr, wantErr)
	}
}

func makeState(client, zone string) *request.Request {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	w := &ptest.ResponseWriter{RemoteIP: client, Zone: zone}
	return &request.Request{W: w, Req: m}
}
