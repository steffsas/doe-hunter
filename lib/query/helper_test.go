package query_test

import (
	"net"
	"testing"

	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/stretchr/testify/assert"
)

func TestResoleHost(t *testing.T) {
	t.Parallel()

	t.Run("real world", func(t *testing.T) {
		t.Parallel()

		hostname := "dns.google."
		resolver := net.IPv4(8, 8, 8, 8)
		qh := query.NewConventionalDNSQueryHandler(nil)

		ip, err := query.ResolveHost(hostname, resolver, qh)

		assert.Nil(t, err)
		assert.NotEmpty(t, ip)
	})
}
