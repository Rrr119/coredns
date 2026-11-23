package policy

import (
	"testing"

	"github.com/coredns/caddy"
)

func TestSetup(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		shouldErr bool
	}{
		{
			name:      "single cidr",
			input:     "policy intranet {\n client 10.0.0.0/8\n}",
			shouldErr: false,
		},
		{
			name:      "multiple networks in one client line",
			input:     "policy intranet {\n client 10.0.0.0/8 192.168.1.0/24\n}",
			shouldErr: false,
		},
		{
			name:      "multiple client lines mixed bare addresses and cidrs",
			input:     "policy intranet {\n client 10.0.0.1\n client 2001:db8::1 2001:db8::/32\n}",
			shouldErr: false,
		},
		{name: "missing name", input: "policy {\n client 10.0.0.0/8\n}", shouldErr: true},
		{name: "too many args", input: "policy a b {\n client 10.0.0.0/8\n}", shouldErr: true},
		{name: "client without network", input: "policy intranet {\n client\n}", shouldErr: true},
		{name: "illegal cidr", input: "policy intranet {\n client not-a-network\n}", shouldErr: true},
		{name: "unknown property", input: "policy intranet {\n expr true\n}", shouldErr: true},
		{name: "twice", input: "policy a {\n client 10.0.0.0/8\n}\npolicy b {\n client 10.1.0.0/16\n}", shouldErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parse(caddy.NewTestController("dns", tc.input))
			if tc.shouldErr && err == nil {
				t.Fatalf("expected error but found none for input %q", tc.input)
			}
			if !tc.shouldErr && err != nil {
				t.Fatalf("expected no error but got %v for input %q", err, tc.input)
			}
			if tc.shouldErr {
				return
			}
			if p.viewName != "intranet" {
				t.Fatalf("view name: got %q, want %q", p.viewName, "intranet")
			}
			if p.clients == nil {
				t.Fatalf("client tree is nil")
			}
		})
	}
}

func TestNormalize(t *testing.T) {
	tests := []struct{ in, want string }{
		{"10.0.0.1", "10.0.0.1/32"},
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"2001:db8::1", "2001:db8::1/128"},
		{"2001:db8::/32", "2001:db8::/32"},
	}
	for _, tc := range tests {
		if got := normalize(tc.in); got != tc.want {
			t.Fatalf("normalize(%q): got %q, want %q", tc.in, got, tc.want)
		}
	}
}
