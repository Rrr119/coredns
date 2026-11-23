package policy

import (
	"context"
	"net"
	"strings"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"

	"github.com/infobloxopen/go-trees/iptree"
	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("policy")

// Policy routes DNS requests to the enclosing server block based on the
// client source address. It implements dnsserver.Viewer so that each server
// block gets its own filter and its own independent cache.
type Policy struct {
	Next plugin.Handler

	viewName string
	clients  *iptree.Tree
}

// Filter implements dnsserver.Viewer. It returns true when the request
// originates from a client network configured on this policy.
func (p *Policy) Filter(_ context.Context, state *request.Request) bool {
	ip := parseIP(state.IP())
	if ip == nil {
		log.Errorf("Unable to parse client source address %q", state.IP())
		return false
	}
	_, contained := p.clients.GetByIP(ip)
	return contained
}

// ViewName implements dnsserver.Viewer. It returns the policy name used as
// the view label in metrics.
func (p *Policy) ViewName() string { return p.viewName }

// Name implements the plugin.Handler interface.
func (p *Policy) Name() string { return pluginName }

// ServeDNS implements the plugin.Handler interface. Routing decisions are
// made by the server through Filter, so requests reaching here are forwarded.
func (p *Policy) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
}

// parseIP parses a client address, tolerating IPv6 zone identifiers such as
// the ones returned for link-local addresses.
func parseIP(raw string) net.IP {
	if idx := strings.IndexByte(raw, '%'); idx >= 0 {
		raw = raw[:idx]
	}
	return net.ParseIP(raw)
}
