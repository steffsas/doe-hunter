package query_test

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDNSSECQuery(t *testing.T) {
	t.Parallel()

	t.Run("real world query with host IP", func(t *testing.T) {
		t.Parallel()

		qh := query.NewDNSSECQueryHandler(nil)

		q := query.NewDNSSECQuery("one.one.one.one.")
		q.Host = "1.1.1.1"

		res, err := qh.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		require.NotNil(t, res, "should have returned a result")
		require.NotNil(t, res.Response, "should have returned a DNS response")
		require.NotNil(t, res.Response.ResponseMsg, "should have returned at least one DNS answer")
		require.NotNil(t, res.Response.ResponseMsg.Answer, "should have returned at least one DNS answer")

		svcbDetected := false
		rrsigDetected := false
		for _, answer := range res.Response.ResponseMsg.Answer {
			switch answer.(type) {
			case *dns.SVCB:
				svcbDetected = true
			case *dns.RRSIG:
				rrsigDetected = true
			default:
				assert.Fail(t, "should only have returned an SVCB or RRSIG record")
			}
		}
		assert.True(t, svcbDetected, "should only have returned an SVCB record")
		assert.True(t, rrsigDetected, "should only have returned an SVCB record")
	})

	t.Run("real world query with hostname", func(t *testing.T) {
		t.Parallel()

		qh := query.NewDNSSECQueryHandler(nil)

		q := query.NewDNSSECQuery("one.one.one.one.")
		q.Host = "one.one.one.one."

		res, err := qh.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		require.NotNil(t, res, "should have returned a result")
		require.NotNil(t, res.Response, "should have returned a DNS response")
		require.NotNil(t, res.Response.ResponseMsg, "should have returned at least one DNS answer")
		require.NotNil(t, res.Response.ResponseMsg.Answer, "should have returned at least one DNS answer")

		svcbDetected := false
		rrsigDetected := false
		for _, answer := range res.Response.ResponseMsg.Answer {
			switch answer.(type) {
			case *dns.SVCB:
				svcbDetected = true
			case *dns.RRSIG:
				rrsigDetected = true
			default:
				assert.Fail(t, "should only have returned an SVCB or RRSIG record")
			}
		}
		assert.True(t, svcbDetected, "should only have returned an SVCB record")
		assert.True(t, rrsigDetected, "should only have returned an SVCB record")
	})
}
