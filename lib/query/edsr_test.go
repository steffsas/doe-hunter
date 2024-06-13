package query_test

import (
	"fmt"
	"testing"

	"github.com/miekg/dns"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEDSRQuery(t *testing.T) {
	t.Parallel()

	// p := &DDRParser{}
	qh := query.NewEDSRQueryHandler(nil)

	q := query.NewEDSRQuery("dns.google.")
	q.Host = "8.8.8.8"

	res, err := qh.Query(q)

	fmt.Println(res.Response.ResponseMsg)

	assert.Nil(t, err, "should not have returned an error")
	require.NotNil(t, res, "should have returned a result")
	require.NotNil(t, res.Response, "should have returned a DNS response")
	require.NotNil(t, res.Response.ResponseMsg, "should have returned at least one DNS answer")
	require.NotNil(t, res.Response.ResponseMsg.Answer, "should have returned at least one DNS answer")

	for _, answer := range res.Response.ResponseMsg.Answer {
		_, ok := answer.(*dns.SVCB)
		assert.True(t, ok, "should only have returned an SVCB record")
	}
}
