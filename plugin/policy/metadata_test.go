package policy

import (
	"context"
	"testing"

	"github.com/coredns/coredns/plugin/metadata"
	"github.com/coredns/coredns/request"
)

func TestMetadata_PublishesPolicyName(t *testing.T) {
	p := &Policy{viewName: "intranet"}
	ctx := metadata.ContextWithMetadata(context.Background())

	ctx = p.Metadata(ctx, request.Request{})

	f := metadata.ValueFunc(ctx, "policy/name")
	if f == nil {
		t.Fatalf("metadata value func is nil")
	}
	if got := f(); got != "intranet" {
		t.Fatalf("metadata value: got %q, want %q", got, "intranet")
	}
}
