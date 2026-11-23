package policy

import (
	"net"
	"strings"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	"github.com/infobloxopen/go-trees/iptree"
)

const pluginName = "policy"

func init() { plugin.Register(pluginName, setup) }

func setup(c *caddy.Controller) error {
	p, err := parse(c)
	if err != nil {
		return plugin.Error(pluginName, err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		p.Next = next
		return p
	})

	return nil
}

func parse(c *caddy.Controller) (*Policy, error) {
	p := &Policy{clients: iptree.NewTree()}

	i := 0
	for c.Next() {
		i++
		if i > 1 {
			return nil, plugin.ErrOnce
		}

		args := c.RemainingArgs()
		if len(args) != 1 {
			return nil, c.ArgErr()
		}
		p.viewName = args[0]

		for c.NextBlock() {
			switch c.Val() {
			case "client":
				nets := c.RemainingArgs()
				if len(nets) == 0 {
					return nil, c.Errf("no client network specified")
				}
				for _, raw := range nets {
					_, network, err := net.ParseCIDR(normalize(raw))
					if err != nil {
						return nil, c.Errf("illegal CIDR notation %q: %v", raw, err)
					}
					p.clients.InplaceInsertNet(network, struct{}{})
				}
			default:
				return nil, c.Errf("unknown property %q; expect 'client'", c.Val())
			}
		}
	}

	if p.viewName == "" {
		return nil, c.Errf("policy requires a view name")
	}

	return p, nil
}

// normalize appends '/32' for a bare IPv4 address and '/128' for a bare
// IPv6 address, so single hosts can be written without a prefix length.
func normalize(rawNet string) string {
	if idx := strings.IndexByte(rawNet, '/'); idx >= 0 {
		return rawNet
	}
	if idx := strings.IndexByte(rawNet, ':'); idx >= 0 {
		return rawNet + "/128"
	}
	return rawNet + "/32"
}
