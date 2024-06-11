package query_test

import (
	"net"
	"testing"

	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/stretchr/testify/assert"
)

func TestNewDefaultQueryHandler(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		la := net.IPv4(127, 0, 0, 1)

		config := &query.QueryConfig{
			LocalAddr: la,
		}

		qh := query.NewDefaultQueryHandler(config)

		assert.Equal(t, la, qh.DialerUDP.LocalAddr.(*net.UDPAddr).IP)
		assert.Equal(t, la, qh.DialerTCP.LocalAddr.(*net.TCPAddr).IP)
	})
}
