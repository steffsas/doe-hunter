package query_test

import (
	"testing"

	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/stretchr/testify/assert"
)

func TestDNSQuery_SetDNSSEC(t *testing.T) {
	t.Parallel()

	t.Run("set dnssec on empty query", func(t *testing.T) {
		t.Parallel()

		q := &query.DNSQuery{
			DNSSEC: true,
		}

		q.SetDNSSEC()

		assert.NotNil(t, q.QueryMsg)
		assert.NotNil(t, q.QueryMsg.IsEdns0())
	})
}
