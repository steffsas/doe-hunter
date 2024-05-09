package query_test

import (
	"testing"

	"github.com/steffsas/doe-hunter/lib/query"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPTRQuery_RealWorld(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		q, err := query.NewPTRQuery("8.8.8.8")
		// let's safely use google here since not every device runs a local stub on 127.0.0.53
		q.Host = "8.8.8.8"

		require.Nil(t, err, "should not have returned an error on given IP address")

		res, err := q.Query()

		assert.Nil(t, err, "should not have returned an error")
		require.NotNil(t, res, "result should not be nil")
		assert.NotNilf(t, res.ResponseMsg, "should have returned a response")
		require.NotNil(t, res.ResponseMsg.Answer, "should have at least one answer")

		for _, answer := range res.ResponseMsg.Answer {
			_, ok := answer.(*dns.PTR)
			assert.True(t, ok, "should only have returned a PTR record")
		}
	})

	// t.Run("IPv6", func(t *testing.T) {
	// 	q, err := query.NewPTRQuery("2001:4860:4860::8888")

	// 	// let's safely use google here since not every device runs a local stub on 127.0.0.53
	// 	q.Host = "8.8.8.8"

	// 	require.Nil(t, err, "should not have returned an error on given IP address")

	// 	res, err := q.Query()

	// 	assert.Nil(t, err, "should not have returned an error")
	// 	require.NotNil(t, res, "result should not be nil")
	// 	assert.NotNilf(t, res.ResponseMsg, "should have returned a response")
	// 	require.NotNil(t, res.ResponseMsg.Answer, "should have at least one answer")

	// 	for _, answer := range res.ResponseMsg.Answer {
	// 		_, ok := answer.(*dns.PTR)
	// 		assert.True(t, ok, "should only have returned a PTR record")
	// 	}
	// })
}
