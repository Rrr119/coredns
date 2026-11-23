# policy

## Name

*policy* - routes DNS requests to the enclosing server block based on the client source IP network.

## Description

*policy* matches the client source address against a configured list of IP networks. When the
source address belongs to one of the networks, CoreDNS routes the request to the server block
containing the plugin. It implements the server `Viewer` interface, which means each filtered
server block runs its own plugin chain, including a fully independent *cache*: entries stored for
one client group are never served to another group.

For unmatched queries the next server block (top to bottom) is evaluated, so an unfiltered
catch-all block can be declared last.

## Syntax

```
policy NAME {
	client CIDR [CIDR...]
}
```

* **NAME** - the policy name, used as the view label of cache metrics and exported as metadata.
* `client` **CIDR** - one or more client networks in CIDR notation. A bare IP address is accepted
  and normalized to a `/32` (IPv4) or `/128` (IPv6) prefix. The property may be repeated and each
  line may list several networks.

## Server Block Ordering

As with *view*, server blocks sharing the same zone and port are evaluated top to bottom and the
first matching block handles the query. Declare filtered blocks first and an unfiltered
catch-all block last, otherwise the catch-all would shadow every policy block.

Only one *policy* plugin may be defined per server block, and it cannot be combined with *view*
in the same block.

## Examples

Split-horizon DNS with isolated caches. Clients in `10.0.0.0/8` receive internal answers,
clients in `192.168.0.0/16` receive partner answers, and every other client receives the public
answer. Each block has its own cache, so a response cached for one group can never leak into
another group.

```
. {
	policy intranet {
		client 10.0.0.0/8
	}
	cache 30
	forward . 10.0.0.53
}

. {
	policy partners {
		client 192.168.0.0/16
	}
	cache 30
	hosts {
		172.16.0.1 app.example
	}
}

. {
	cache 30
	forward . 8.8.8.8
}
```

Single hosts can be listed without a prefix length, and multiple networks can share one line:

```
. {
	policy admins {
		client 192.0.2.10 192.0.2.11 2001:db8::/32
	}
	cache
	hosts {
		10.1.1.1 admin.example
	}
}
```

## Metadata

If the *metadata* plugin is enabled, the following metadata is published:

* `policy/name`: the name of the policy handling the current request.

## Metrics

The plugin adds no metrics of its own. Because every block is a distinct view, the standard
cache metrics carry its name in the `view` label, for example
`coredns_cache_entries{view="intranet"}`.
