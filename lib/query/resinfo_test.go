package query_test

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewResInfoQuery(t *testing.T) {
	t.Parallel()

	qh := query.NewResInfoQueryHandler(nil)

	q := query.NewResInfoQuery("resolver.dns4all.eu.")
	q.Host = "resolver.dns4all.eu"

	res, err := qh.Query(q)

	assert.Nil(t, err, "should not have returned an error")
	require.NotNil(t, res, "should have returned a result")
	require.NotNil(t, res.Response, "should have returned a DNS response")
	require.NotNil(t, res.Response.ResponseMsg, "should have returned at least one DNS answer")
	require.NotNil(t, res.Response.ResponseMsg.Answer, "should have returned at least one DNS answer")
	for _, answer := range res.Response.ResponseMsg.Answer {
		rrtype := answer.Header().Rrtype
		rrtypeCorrect := rrtype == query.TypeRESINFO || rrtype == dns.TypeRRSIG
		assert.True(t, rrtypeCorrect, "should only return RRSIG or RESINFO records")
	}
}
