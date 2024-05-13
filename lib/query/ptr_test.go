package query_test

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPTRQueryHandler_RealWorld(t *testing.T) {
	t.Parallel()

	t.Run("IPv4", func(t *testing.T) {
		t.Parallel()

		qh := query.NewPTRQueryHandler()

		// let's safely use google here since not every device runs a local stub on 127.0.0.53
		q, err := query.NewPTRQuery("8.8.8.8", "8.8.8.8")

		require.Nil(t, err, "should not have returned an error on given IP address")

		res, err := qh.Query(q)

		assert.Nil(t, err, "should not have returned an error")
		require.NotNil(t, res, "result should not be nil")
		require.NotNil(t, res.Response, "should have returned a response")
		require.NotNil(t, res.Response.ResponseMsg, "should have returned a response")
		require.NotNil(t, res.Response.ResponseMsg.Answer, "should have at least one answer")

		for _, answer := range res.Response.ResponseMsg.Answer {
			_, ok := answer.(*dns.PTR)
			assert.True(t, ok, "should only have returned a PTR record")
		}
	})

	// exclude IPv6 test since it does not work on GitHub Actions
	// t.Run("IPv6", func(t *testing.T) {
	// 	t.Parallel()

	// 	qh := query.NewPTRQueryHandler()

	// 	// let's safely use google here since not every device runs a local stub on 127.0.0.53
	// 	q, err := query.NewPTRQuery("2001:4860:4860::8888", "8.8.8.8")

	// 	require.Nil(t, err, "should not have returned an error on given IP address")

	// 	res, err := qh.Query(q)

	// 	assert.Nil(t, err, "should not have returned an error")
	// 	require.NotNil(t, res, "result should not be nil")
	// 	require.NotNil(t, res.Response, "should have returned a response")
	// 	require.NotNil(t, res.Response.ResponseMsg, "should have returned a response")
	// 	require.NotNil(t, res.Response.ResponseMsg.Answer, "should have at least one answer")

	// 	for _, answer := range res.Response.ResponseMsg.Answer {
	// 		_, ok := answer.(*dns.PTR)
	// 		assert.True(t, ok, "should only have returned a PTR record")
	// 	}
	// })
}
