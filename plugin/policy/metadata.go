package policy

import (
	"context"

	"github.com/coredns/coredns/plugin/metadata"
	"github.com/coredns/coredns/request"
)

// Metadata implements the metadata.Provider interface.
func (p *Policy) Metadata(ctx context.Context, _ request.Request) context.Context {
	metadata.SetValueFunc(ctx, "policy/name", func() string {
		return p.viewName
	})
	return ctx
}
