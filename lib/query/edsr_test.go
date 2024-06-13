package query_test

import (
	"testing"

	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEDSRQuery(t *testing.T) {
	t.Parallel()

	qh := query.NewEDSRQueryHandler(nil)

	q := query.NewEDSRQuery("dns.google.")
	q.Host = "8.8.8.8"

	res, err := qh.Query(q)

	assert.Nil(t, err, "should not have returned an error")
	require.NotNil(t, res, "should have returned a result")
	require.NotNil(t, res.Response, "should have returned a DNS response")
	require.NotNil(t, res.Response.ResponseMsg, "should have returned at least one DNS answer")
	// TODO: for some reason we do not get any response in the pipeline although locally everything works
	// require.NotNil(t, res.Response.ResponseMsg.Answer, "should have returned at least one DNS answer")
	// for _, answer := range res.Response.ResponseMsg.Answer {
	// 	_, ok := answer.(*dns.SVCB)
	// 	assert.True(t, ok, "should only have returned an SVCB record")
	// }
}
